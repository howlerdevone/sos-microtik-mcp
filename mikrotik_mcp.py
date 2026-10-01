"""
MikroTik MCP server for on-site IT work.

Tools
  Connection : discover_routers, connect, reconnect, list_sessions, disconnect
  Read       : router_overview, run_command, collect_info
  Wi-Fi      : configure_wifi
  Bridge     : setup_bridge_with_wifi_subnet
  Security   : audit_security, harden_services, firewall_baseline
  Validate   : validate_network
  WireGuard  : wireguard_status, wireguard_create_interface, wireguard_add_peer,
               wireguard_update_peer, wireguard_remove_peer
  Changes    : apply_changes, confirm_changes, rollback_now

Every write tool defaults to dry_run=True (returns the plan only). When applied,
changes run with a "commit confirmed" safety net: local export + on-router
backup + a rollback timer that restores the backup unless confirm_changes is
called.

Install: see README.md (uv tool install git+https://github.com/howlerdevone/sos-microtik-mcp)
"""
import base64
import datetime
import ipaddress
import pathlib
import re
import secrets
import socket
import struct
import time

import paramiko
try:  # MCP Python SDK 2.x
    from mcp.server.mcpserver import MCPServer as FastMCP
except ImportError:  # SDK 1.x
    from mcp.server.fastmcp import FastMCP

INSTRUCTIONS = """
You manage MikroTik RouterOS devices for an on-site IT technician.

WORKFLOW
1. discover_routers, then connect. Never ask the user to type the router password in
   chat: leave `password` empty so a local popup appears on their computer.
   Right after connecting, read the "Technician PC" line that connect returns: it says
   whether the technician's PC is on the same network as the router (and gets its IP
   from the router's DHCP). Tell the user. If the customer asks to change that
   network's IP/subnet, warn BEFORE applying: the PC will lose the connection, and
   after applying it must release/renew its IP (Windows: ipconfig /release, then
   ipconfig /renew) to get an address in the new subnet, then reconnect(new_host=<new
   router IP>) and confirm_changes before the rollback timer runs out. Use
   rollback_minutes=10 for these changes, and make sure the LAN DHCP server/pool is
   moved to the new subnet too, or the renew will not get a valid address.
2. router_overview, then collect_info(site) BEFORE changing anything.
3. Every write tool defaults to dry_run=True. Run it dry first, explain the plan in plain
   language, show the commands, and only call again with dry_run=False after the user
   explicitly approves.
4. Applied changes arm an automatic rollback (default 5 min). After applying, verify
   (prints, ping, ask the user whether clients/internet still work), then call
   confirm_changes. If anything is wrong, call rollback_now. If SSH drops because an IP
   changed, use reconnect(new_host=...) and then confirm.
5. Never disable SSH or remove the technician's access path: this server depends on SSH.
6. Never repeat secrets (Wi-Fi passwords, private keys, preshared keys) in chat.

ADDRESSES, SUBNETS AND KEYS: ALWAYS ASK THE USER
- Never invent or assume IP addresses, subnets, masks, DHCP ranges, VPN ports or
  endpoints. The tools have no default addresses: ask the user for each value.
- Users may give masks as /24 or 255.255.255.0 (e.g. '192.168.20.1 255.255.255.0').
  Call validate_network on what they gave (with the session name, to check overlaps)
  and explain the result (mask in both formats, usable range) before planning.
- This server never generates WireGuard keys. Ask the user for the remote peer's
  public key (in chat or the popup). Private and preshared keys are entered only in
  the local popup: leave those parameters empty and never ask for them in chat.

ROUTEROS KNOW-HOW
- Check the version first. v6 and v7 differ in syntax; WireGuard exists only in v7.
- Wi-Fi drivers: legacy 'wireless' (/interface wireless, wlanX, security-profiles, WPA2
  only); new 'wifi' (/interface wifi, 7.13+, packages wifi-qcom / wifi-qcom-ac, supports
  WPA3); 'wifiwave2' (v7 before 7.13). configure_wifi detects which one is in use.
- If Wi-Fi is managed by CAPsMAN, configure it on the controller, not on the AP.
- Wi-Fi in a separate subnet while all ports share ONE bridge requires bridge VLAN
  filtering (Wi-Fi ports get their own PVID + a VLAN interface with the gateway IP).
  On many non-CRS3xx devices (hAP, hEX, RB4011...) enabling vlan-filtering disables
  hardware offloading, so LAN switching goes through the CPU. mode='separate_bridge'
  avoids that. Explain this trade-off to the user before choosing.
- Default config uses interface lists LAN and WAN; firewall rules reference them.
- Firewall rules are evaluated top-down; changes on chain=input can lock you out.
- Compromise indicators: unknown schedulers/scripts (especially using /tool fetch),
  SOCKS or web proxy enabled, unknown users, static DNS entries for popular domains.
"""

mcp = FastMCP("mikrotik", instructions=INSTRUCTIONS)
OUTPUT_ROOT = pathlib.Path.home() / "mikrotik-sites"
SESSIONS: dict[str, dict] = {}  # credentials kept in memory only

WIFI_TYPES = {"wlan", "wifi", "wifiwave2"}
WRITE_PATTERN = re.compile(
    r"\b(set|add|remove|disable|enable|reset|reboot|shutdown|upgrade|import|"
    r"load|reset-configuration|move|unset|comment|edit|run|execute|fetch|send|"
    r"release|renew)\b(?![=~])")  # (?![=~]) lets 'where comment~...' through
ERROR_PATTERN = re.compile(
    r"(failure:|bad command name|syntax error|expected |input does not match|"
    r"no such item|invalid value|ambiguous value|already have|not enough permissions|"
    r"value of .* out of range)", re.IGNORECASE)
BACKUP_NAME = "mcp-pre"
ROLLBACK_SCHED = "mcp-rollback"


# =====================================================================
# helpers
# =====================================================================

def q(value) -> str:
    """Quote a value for the RouterOS CLI."""
    s = str(value)
    for a, b in (("\\", "\\\\"), ('"', '\\"'), ("$", "\\$"), ("?", "\\?")):
        s = s.replace(a, b)
    return f'"{s}"'


def _popup(title: str, prompt: str, hidden: bool = True, optional: bool = False) -> str:
    """Ask the user for a value in a local window (keeps it out of the chat)."""
    import tkinter as tk
    from tkinter import simpledialog
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    val = simpledialog.askstring(title, prompt, show="*" if hidden else "", parent=root)
    root.destroy()
    if val is None:
        if optional:
            return ""
        raise RuntimeError("Entry cancelled by user")
    return val


def _popup_secret(title: str, prompt: str) -> str:
    return _popup(title, prompt, hidden=True)


def _popup_info(title: str, message: str) -> None:
    try:
        import tkinter as tk
        from tkinter import messagebox
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        messagebox.showinfo(title, message, parent=root)
        root.destroy()
    except Exception:
        pass


def _open(host, user, port, password) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # "+ct": no colors, no terminal auto-detection -> clean output
    client.connect(host, port=port, username=user + "+ct", password=password,
                   look_for_keys=False, allow_agent=False, timeout=10)
    return client


def _session(name: str) -> dict:
    s = SESSIONS.get(name)
    if s is None:
        raise RuntimeError(f"No session '{name}'. Call connect first.")
    return s


def _run(name: str, command: str, timeout: int = 30) -> str:
    s = _session(name)
    transport = s["client"].get_transport()
    if transport is None or not transport.is_active():
        s["client"] = _open(s["host"], s["user"], s["port"], s["password"])
    _, stdout, stderr = s["client"].exec_command(command, timeout=timeout)
    out = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace")
    return (out + ("\n" + err if err.strip() else "")).strip()


def _try(name: str, command: str) -> str:
    """Run a read command; return '' if the menu doesn't exist on this router."""
    try:
        out = _run(name, command)
    except Exception:
        return ""
    if re.search(r"bad command name|syntax error|no such command", out, re.I):
        return ""
    return out


_KV = re.compile(r'([\w.-]+)=("(?:[^"\\]|\\.)*"|.*?)(?=\s+[\w.-]+=|\s*$)')


def _parse_terse(text: str) -> list[dict]:
    """Parse 'print terse' output into dicts. '_flags' holds flag letters (X=disabled, D=dynamic)."""
    rows = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith(("Flags:", "#", ";;;", "Columns:")):
            continue
        m = re.search(r"[\w.-]+=", line)
        if not m:
            continue
        prefix = line[:m.start()]
        row = {"_flags": "".join(c for c in prefix if c.isalpha())}
        for k, v in _KV.findall(line[m.start():]):
            if v.startswith('"') and v.endswith('"') and len(v) >= 2:
                v = v[1:-1].replace('\\"', '"').replace("\\\\", "\\")
            row[k] = v
        row["_disabled"] = "X" in row["_flags"] or row.get("disabled") == "yes"
        row["_dynamic"] = "D" in row["_flags"] or row.get("dynamic") == "yes"
        rows.append(row)
    return rows


def _terse(name: str, command: str) -> list[dict]:
    return _parse_terse(_try(name, command))


def _version(name: str) -> tuple:
    res = _run(name, "/system resource print")
    m = re.search(r"version:\s*([\d.]+)", res)
    return tuple(int(x) for x in m.group(1).split(".")) if m else (0,)


def _facts(name: str) -> dict:
    res = _run(name, "/system resource print")
    ver = re.search(r"version:\s*([\d.]+\S*)", res)
    board = re.search(r"board-name:\s*(.+)", res)
    ifaces = _terse(name, "/interface print terse")
    members = _terse(name, "/interface list member print terse")
    lists: dict[str, list[str]] = {}
    for m in members:
        lists.setdefault(m.get("list", ""), []).append(m.get("interface", ""))
    types = {i.get("name"): i.get("type") for i in ifaces}
    wifi = [n for n, t in types.items() if t in WIFI_TYPES]
    driver = None
    for t in ("wifi", "wifiwave2", "wlan"):
        if t in types.values():
            driver = {"wlan": "wireless"}.get(t, t)
            break
    version_str = ver.group(1) if ver else "unknown"
    return {
        "version": version_str,
        "major": int(version_str.split(".")[0]) if version_str[0].isdigit() else 0,
        "board": board.group(1).strip() if board else "unknown",
        "interfaces": types,
        "ethernet": [n for n, t in types.items() if t == "ether"],
        "wifi_interfaces": wifi,
        "wifi_driver": driver,
        "bridges": [n for n, t in types.items() if t == "bridge"],
        "interface_lists": lists,
    }


def _site_folder(*parts: str) -> pathlib.Path:
    stamp = datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S")
    clean = [re.sub(r"[^\w.-]", "_", p) for p in parts]
    folder = OUTPUT_ROOT.joinpath(*clean, stamp)
    folder.mkdir(parents=True, exist_ok=True)
    return folder


def _redact(text: str, hide) -> str:
    for h in hide:
        if h:
            text = text.replace(q(h)[1:-1], "***").replace(h, "***")
    return text


def _ensure_list(lst: str) -> str:
    return f':if ([:len [/interface list find name={q(lst)}]] = 0) do={{/interface list add name={q(lst)}}}'


def _ensure_member(lst: str, iface: str) -> str:
    return (f':if ([:len [/interface list member find list={q(lst)} interface={q(iface)}]] = 0) '
            f'do={{/interface list member add list={q(lst)} interface={q(iface)}}}')


def _bridge_port(port: str, bridge: str, pvid: int = 1) -> str:
    return (f':if ([:len [/interface bridge port find interface={q(port)}]] > 0) '
            f'do={{/interface bridge port set [find interface={q(port)}] bridge={q(bridge)} pvid={pvid}}} '
            f'else={{/interface bridge port add bridge={q(bridge)} interface={q(port)} pvid={pvid}}}')


def _top_filter_rule(args: str) -> str:
    """Add a filter rule at the top of the (non-dynamic) rule list."""
    return ('{:local f [/ip firewall filter find dynamic=no]; '
            f':if ([:len $f] > 0) do={{/ip firewall filter add {args} place-before=[:pick $f 0]}} '
            f'else={{/ip firewall filter add {args}}}}}')


def _apply(name, commands, description, rollback_minutes=5, hide=()) -> tuple[str, bool]:
    s = _session(name)
    folder = _site_folder("_changes", s["host"])
    (folder / "description.txt").write_text(description, encoding="utf-8")
    (folder / "commands.rsc").write_text("\n".join(commands), encoding="utf-8")
    (folder / "before.rsc").write_text(_run(name, "/export show-sensitive terse", 90),
                                       encoding="utf-8")
    _run(name, f"/system backup save name={BACKUP_NAME} dont-encrypt=yes", 60)
    time.sleep(2)
    _run(name, f"/system scheduler remove [find name={ROLLBACK_SCHED}]")
    if rollback_minutes > 0:
        on_event = (f'/system scheduler remove [find name={ROLLBACK_SCHED}]; '
                    f'/system backup load name={BACKUP_NAME} password=\\"\\"')
        _run(name, f'/system scheduler add name={ROLLBACK_SCHED} '
                   f'interval={rollback_minutes}m on-event="{on_event}"')

    log, ok = [], True
    for i, cmd in enumerate(commands, 1):
        shown = _redact(cmd, hide)
        try:
            out = _run(name, cmd, timeout=60)
        except Exception as e:
            ok = False
            log.append(f"[{i}] {shown}\n    CONNECTION LOST: {e}")
            log.append("SSH dropped. If the router's IP changed use reconnect(new_host=...) "
                       f"then confirm_changes; otherwise it rolls back in {rollback_minutes} min.")
            break
        bad = bool(ERROR_PATTERN.search(out))
        log.append(f"[{i}] {'ERROR' if bad else 'ok'}: {shown}" +
                   (f"\n    {_redact(out, hide)}" if out else ""))
        if bad:
            ok = False
            log.append("Stopped at first error. Fix and re-apply, or call rollback_now.")
            break
    (folder / "result.txt").write_text("\n".join(log), encoding="utf-8")
    if rollback_minutes > 0:
        tail = (f"\n\nRollback ARMED: router restores in {rollback_minutes} min unless "
                "confirm_changes is called. Verify first.")
    else:
        tail = "\n\nNo rollback armed."
    return "\n".join(log) + tail + f"\nLog: {folder}", ok


def _plan(name, commands, description, dry_run, rollback_minutes, hide=(), notes="") -> str:
    if dry_run:
        body = "\n".join(f"{i}. {_redact(c, hide)}" for i, c in enumerate(commands, 1))
        return (f"DRY RUN: nothing was changed.\n\nPlan: {description}\n"
                + (f"\nNotes:\n{notes}\n" if notes else "")
                + f"\nCommands:\n{body}\n\n"
                "Explain this to the user. After they approve, call again with dry_run=False.")
    text, _ = _apply(name, commands, description, rollback_minutes, hide)
    return (notes + "\n\n" if notes else "") + text


# =====================================================================
# address / key validation
# =====================================================================

_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def _mask_to_prefix(mask: str) -> int:
    """'255.255.255.0' -> 24, with helpful errors for wildcard / invalid masks."""
    try:
        m = int(ipaddress.IPv4Address(mask))
    except ValueError:
        raise ValueError(f"'{mask}' is not a valid subnet mask.")
    bits = f"{m:032b}"
    if re.fullmatch(r"1*0*", bits):
        return bits.count("1")
    if re.fullmatch(r"0*1*", bits):
        real = ipaddress.IPv4Address(m ^ 0xFFFFFFFF)
        raise ValueError(f"'{mask}' looks like a wildcard (inverse) mask. "
                         f"The subnet mask would be {real} (/{32 - bits.count('1')}).")
    raise ValueError(f"'{mask}' is not a valid subnet mask (the 1-bits must be contiguous, "
                     "e.g. 255.255.255.0, 255.255.252.0).")


def _parse_addr(value: str, kind: str = "interface") -> dict:
    """Parse '10.0.0.1/24', '10.0.0.1/255.255.255.0' or '10.0.0.1 255.255.255.0'.
    kind='interface': an address assigned to the router (gateway, tunnel IP).
    kind='network'  : a subnet/route (allowed-address, LAN range); host bits cleared."""
    r = {"input": value, "ok": False, "errors": [], "warnings": []}
    v = " ".join((value or "").split())
    if not v:
        r["errors"].append("Empty value.")
        return r
    if "/" in v:
        ip_s, mask_s = (p.strip() for p in v.split("/", 1))
    elif len(v.split(" ")) == 2:
        ip_s, mask_s = v.split(" ")
    else:
        ip_s, mask_s = v, None
    try:
        ip = ipaddress.ip_address(ip_s)
    except ValueError:
        r["errors"].append(f"'{ip_s}' is not a valid IP address.")
        return r
    maxlen = ip.max_prefixlen
    if mask_s is None:
        if kind == "interface":
            r["errors"].append("Subnet mask missing. Use e.g. 192.168.20.1/24 or 192.168.20.1 255.255.255.0.")
            return r
        prefix = maxlen
        r["warnings"].append(f"No mask given for {ip}: treated as a single host (/{maxlen}).")
    elif mask_s.isdigit():
        prefix = int(mask_s)
        if not 0 <= prefix <= maxlen:
            r["errors"].append(f"Prefix /{prefix} is out of range (0-{maxlen}).")
            return r
    else:
        if ip.version != 4:
            r["errors"].append("IPv6 needs a prefix length, e.g. /64.")
            return r
        try:
            prefix = _mask_to_prefix(mask_s)
        except ValueError as e:
            r["errors"].append(str(e))
            return r

    net = ipaddress.ip_interface(f"{ip}/{prefix}").network
    if ip.is_loopback or ip.is_multicast or (ip.is_unspecified and kind == "interface") or \
            (ip.version == 4 and int(ip) == 0xFFFFFFFF):
        r["errors"].append(f"{ip} can't be used here (loopback, multicast or reserved address).")
        return r

    if kind == "interface":
        if prefix < maxlen - 1 and ip in (net.network_address, net.broadcast_address):
            which = "network" if ip == net.network_address else "broadcast"
            r["errors"].append(f"{ip} is the {which} address of {net} and can't be assigned. "
                               f"Use a host address, e.g. {net.network_address + 1}/{prefix}.")
            return r
        r["cidr"] = f"{ip}/{prefix}"
        if prefix == maxlen:
            r["warnings"].append(f"/{maxlen} is a single address with no subnet. Usually you want e.g. /24.")
    else:
        if ip != net.network_address:
            r["warnings"].append(f"'{value.strip()}' has host bits set; the network is {net}. Using {net}.")
        r["cidr"] = str(net)

    r["network"], r["prefix"] = str(net), prefix
    if ip.version == 4:
        r["netmask"] = str(net.netmask)
        r["broadcast"] = str(net.broadcast_address)
        if prefix <= 30:
            r["usable_range"] = f"{net.network_address + 1} - {net.broadcast_address - 1}"
            r["usable_hosts"] = net.num_addresses - 2
        else:
            r["usable_range"] = f"{net.network_address} - {net.broadcast_address}"
            r["usable_hosts"] = net.num_addresses
    if net.prefixlen == 0:
        r["scope"] = "default route (all traffic)"
    elif ip.version == 4 and ip in _CGNAT:
        r["scope"] = "CGNAT / shared address space (100.64.0.0/10)"
    elif ip.is_private:
        r["scope"] = "private"
    elif ip.is_link_local:
        r["scope"] = "link-local"
    else:
        r["scope"] = "PUBLIC"
        if kind == "interface":
            r["warnings"].append("This is a public IP. Make sure it is really assigned to this router.")
    r["ok"] = True
    return r


def _parse_list(value: str, kind: str) -> list[dict]:
    return [_parse_addr(x, kind) for x in re.split(r"[,;]", value or "") if x.strip()]


def _fmt_addr(r: dict) -> str:
    if not r.get("ok"):
        return f"[X] '{r['input'].strip()}': " + " ".join(r["errors"])
    s = f"[OK] '{r['input'].strip()}' -> {r['cidr']}"
    if "netmask" in r:
        s += f"\n     mask /{r['prefix']} = {r['netmask']} | network {r['network']} | broadcast {r['broadcast']}"
        s += f"\n     usable {r['usable_range']} ({r['usable_hosts']} host{'s' if r['usable_hosts'] != 1 else ''}) | {r['scope']}"
    else:
        s += f"\n     network {r['network']} | {r['scope']}"
    for w in r["warnings"]:
        s += f"\n     note: {w}"
    return s


def _check(value: str | None, kind: str, label: str) -> tuple[list[dict], str | None]:
    """Validate user input; return (results, error_message_or_None)."""
    res = _parse_list(value, kind) if value else []
    if not res:
        return [], f"{label} is required. Ask the user for it (formats: 10.0.0.1/24 or 10.0.0.1 255.255.255.0)."
    if any(not r["ok"] for r in res):
        return res, f"{label} is not valid:\n" + "\n".join(_fmt_addr(r) for r in res) + \
            "\nAsk the user to correct it."
    return res, None


def _router_networks(name: str, exclude_interface: str | None = None) -> list[tuple]:
    out = []
    for a in _terse(name, "/ip address print terse"):
        if exclude_interface and a.get("interface") == exclude_interface:
            continue
        try:
            out.append((ipaddress.ip_interface(a.get("address", "")), a.get("interface")))
        except ValueError:
            pass
    return out


def _overlaps(name: str, net, exclude_interface: str | None = None) -> list[str]:
    return [f"{a.network} ({a.ip}) on {i}" for a, i in _router_networks(name, exclude_interface)
            if a.network.version == net.version and a.network.overlaps(net)]


def _key_error(key: str, label: str) -> str | None:
    k = (key or "").strip()
    try:
        raw = base64.b64decode(k, validate=True)
    except Exception:
        return f"{label} is not valid: WireGuard keys are base64 text (44 characters ending in '=')."
    if len(raw) != 32 or len(k) != 44:
        return f"{label} is not valid: expected 44 characters (32 bytes), got {len(k)} characters."
    return None


def _pub_from_priv(priv: str) -> str:
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    k = X25519PrivateKey.from_private_bytes(base64.b64decode(priv.strip()))
    return base64.b64encode(k.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)).decode()


def _get_key(given: str | None, label: str, secret: bool) -> str:
    """Use the given key or ask in a local popup; validate format."""
    k = given if given else _popup("WireGuard", f"{label}:", hidden=secret)
    err = _key_error(k, label)
    if err:
        raise ValueError(err)
    return k.strip()


def _parse_endpoint(ep: str, default_port: int | None = None) -> tuple[str, int]:
    s = ep.strip()
    m = re.fullmatch(r"\[([0-9a-fA-F:]+)\](?::(\d+))?|([^:\s]+)(?::(\d+))?", s)
    if not m:
        raise ValueError(f"Endpoint '{ep}' must be host:port, e.g. 203.0.113.10:13231 or vpn.example.com:13231.")
    host = m.group(1) or m.group(3)
    port_s = m.group(2) or m.group(4)
    if port_s is None:
        if default_port is None:
            raise ValueError(f"Endpoint '{ep}' is missing the port (host:port).")
        port = default_port
    else:
        port = int(port_s)
    if not 1 <= port <= 65535:
        raise ValueError(f"Port {port} is out of range (1-65535).")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not re.fullmatch(r"(?=.{1,253}$)([A-Za-z0-9-]{1,63}\.)*[A-Za-z0-9-]{1,63}", host) or \
                re.fullmatch(r"[\d.]+", host):
            raise ValueError(f"'{host}' is not a valid IP address or hostname.")
    return host, port


@mcp.tool()
def validate_network(value: str, purpose: str = "interface", name: str | None = None) -> str:
    """Check IP addresses / subnets the user provided BEFORE using them, and explain
    the result to the user. Accepts '/prefix' or dotted masks:
      '192.168.20.1/24', '192.168.20.1 255.255.255.0', '192.168.20.1/255.255.255.0'.
    Several values can be separated by commas.
    purpose='interface': an address for the router itself (gateway, tunnel IP).
    purpose='network'  : a subnet or route (LAN range, WireGuard allowed-address).
    If `name` is a connected router session, also checks overlap with its subnets.
    Reports mask in both formats, network, broadcast, usable range and host count."""
    if purpose not in ("interface", "network"):
        return "purpose must be 'interface' or 'network'."
    results = _parse_list(value, purpose)
    if not results:
        return "Nothing to validate."
    lines = []
    for r in results:
        lines.append(_fmt_addr(r))
        if r["ok"] and name and name in SESSIONS:
            ov = _overlaps(name, ipaddress.ip_network(r["network"]))
            if ov:
                lines.append("     WARNING overlaps existing router subnet(s): " + ", ".join(ov))
    good = [ipaddress.ip_network(r["network"]) for r in results if r["ok"]]
    for i, a in enumerate(good):
        for b in good[i + 1:]:
            if a.overlaps(b) and a.prefixlen and b.prefixlen:
                lines.append(f"WARNING {a} and {b} overlap each other.")
    return "\n".join(lines)


# =====================================================================
# connection tools
# =====================================================================

def _parse_mndp(data: bytes) -> dict:
    names = {1: "mac", 5: "identity", 7: "version", 8: "platform", 10: "uptime",
             11: "software_id", 12: "board", 16: "interface", 17: "ipv4"}
    info, i = {}, 4
    while i + 4 <= len(data):
        t, length = struct.unpack(">HH", data[i:i + 4])
        val = data[i + 4:i + 4 + length]
        i += 4 + length
        if t not in names:
            continue
        if t == 1:
            info["mac"] = ":".join(f"{b:02X}" for b in val)
        elif t == 10 and len(val) == 4:
            info["uptime_s"] = struct.unpack("<I", val)[0]
        elif t == 17 and len(val) == 4:
            info["ipv4"] = socket.inet_ntoa(val)
        else:
            info[names[t]] = val.decode(errors="replace")
    return info


@mcp.tool()
def discover_routers(seconds: int = 5) -> list[dict]:
    """Find MikroTik devices on the local network via MNDP (like Winbox Neighbors)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(("", 5678))
    sock.settimeout(0.5)
    sock.sendto(b"\x00\x00\x00\x00", ("255.255.255.255", 5678))
    found, end = {}, time.time() + seconds
    while time.time() < end:
        try:
            data, addr = sock.recvfrom(2048)
        except socket.timeout:
            continue
        if len(data) > 4:
            info = _parse_mndp(data)
            info.setdefault("ipv4", addr[0])
            found[info.get("mac", addr[0])] = info
    sock.close()
    return list(found.values())


@mcp.tool()
def connect(host: str, username: str = "admin", name: str = "router",
            port: int = 22, password: str | None = None) -> str:
    """Open an SSH session to a router under `name`. Leave `password` empty so the
    user is prompted in a local popup (keeps it out of the conversation)."""
    if password is None:
        password = _popup_secret("MikroTik login", f"Password for {username}@{host}:")
    client = _open(host, username, port, password)
    if name in SESSIONS:
        SESSIONS[name]["client"].close()
    SESSIONS[name] = {"client": client, "host": host, "user": username,
                      "port": port, "password": password}
    return (f"Connected to {host} as '{name}'.\n" + _run(name, "/system identity print")
            + "\n\n" + _local_link(name)["text"])


RENEW_STEPS = ("Windows: ipconfig /release then ipconfig /renew | "
               "macOS: sudo ipconfig set <en0> DHCP | "
               "Linux: sudo dhclient -r <iface> && sudo dhclient <iface> "
               "(or unplug/replug the cable)")


def _local_link(name: str) -> dict:
    """Where the technician's PC sits relative to the router: its IP, whether it is
    inside one of the router's subnets, and whether it got that IP from the router's DHCP."""
    info = {"local_ip": None, "interface": None, "network": None, "dhcp": False}
    try:
        ip = ipaddress.ip_address(_session(name)["client"].get_transport().sock.getsockname()[0])
    except Exception:
        info["text"] = "Technician PC: could not determine its IP address."
        return info
    info["local_ip"] = str(ip)
    for a, iface in _router_networks(name):
        if a.version == ip.version and ip in a.network:
            info["interface"], info["network"] = iface, str(a.network)
            break
    if info["network"]:
        info["dhcp"] = any(l.get("address") == str(ip)
                           for l in _terse(name, "/ip dhcp-server lease print terse"))
        how = "an IP leased by this router's DHCP" if info["dhcp"] else \
            "a STATIC IP (no DHCP lease found on this router)"
        text = (f"Technician PC: {ip} is ON the router's network {info['network']} "
                f"(interface {info['interface']}) with {how}.\n"
                "IMPORTANT: if the customer asks to change this network's IP/subnet, this PC "
                "loses the connection when the change is applied. ")
        text += (f"After applying, release/renew the PC's IP ({RENEW_STEPS}), then "
                 "reconnect(new_host=<new router IP>) and confirm_changes before the rollback timer ends."
                 if info["dhcp"] else
                 "After applying, set a static IP on the PC inside the new subnet, then "
                 "reconnect(new_host=<new router IP>) and confirm_changes before the rollback timer ends.")
    else:
        text = (f"Technician PC: {ip} is NOT in any of the router's subnets (reached through "
                "routing). Changing the LAN IP should not cut this PC off, but verify the route.")
    info["text"] = text
    _session(name)["local_link"] = info
    return info


@mcp.tool()
def reconnect(name: str = "router", new_host: str | None = None) -> str:
    """Reconnect a session (optionally to a new IP) reusing the stored credentials."""
    s = _session(name)
    if new_host:
        s["host"] = new_host
    try:
        s["client"].close()
    except Exception:
        pass
    s["client"] = _open(s["host"], s["user"], s["port"], s["password"])
    return f"Reconnected '{name}' to {s['host']}."


@mcp.tool()
def list_sessions() -> list[str]:
    """List open router sessions."""
    return [f"{n} -> {s['host']}" for n, s in SESSIONS.items()]


@mcp.tool()
def disconnect(name: str = "router") -> str:
    """Close a session and forget its credentials."""
    s = SESSIONS.pop(name, None)
    if s:
        s["client"].close()
        return f"Closed '{name}'."
    return f"No session '{name}'."


# =====================================================================
# read tools
# =====================================================================

@mcp.tool()
def router_overview(name: str = "router") -> dict:
    """Version, board, interfaces by type, Wi-Fi driver, bridges and interface lists.
    Call this before planning any change."""
    return _facts(name)


@mcp.tool()
def run_command(command: str, name: str = "router") -> str:
    """Run a READ-ONLY RouterOS command (print, export, monitor, ping count=4...).
    For changes use the dedicated tools or apply_changes."""
    if WRITE_PATTERN.search(command):
        return "This looks like a config change. Use a config tool or apply_changes."
    return _run(name, command)


@mcp.tool()
def collect_info(site: str, name: str = "router") -> str:
    """Save full export + hardware/status/Wi-Fi/VPN/firewall info to
    ~/mikrotik-sites/<site>/<timestamp>/. Read-only."""
    commands = {
        "export.rsc": "/export show-sensitive terse",
        "routerboard.txt": "/system routerboard print",
        "resource.txt": "/system resource print",
        "packages.txt": "/system package print",
        "license.txt": "/system license print",
        "interfaces.txt": "/interface print detail",
        "bridge_ports.txt": "/interface bridge port print detail",
        "bridge_vlans.txt": "/interface bridge vlan print detail",
        "ip_addresses.txt": "/ip address print",
        "routes.txt": "/ip route print detail",
        "dhcp_leases.txt": "/ip dhcp-server lease print",
        "neighbors.txt": "/ip neighbor print detail",
        "firewall_filter.txt": "/ip firewall filter print stats",
        "firewall_nat.txt": "/ip firewall nat print stats",
        "wireless_legacy.txt": "/interface wireless print detail",
        "wifi.txt": "/interface wifi print detail",
        "wireguard.txt": "/interface wireguard print detail",
        "wireguard_peers.txt": "/interface wireguard peers print detail",
        "users.txt": "/user print",
        "services.txt": "/ip service print",
    }
    folder = _site_folder(site)
    for fname, cmd in commands.items():
        try:
            out = _run(name, cmd, timeout=60)
        except Exception as e:
            out = f"ERROR running {cmd}: {e}"
        (folder / fname).write_text(out, encoding="utf-8")
    return f"Saved {len(commands)} files to {folder} (menus missing on this router contain an error line)."


# =====================================================================
# Wi-Fi
# =====================================================================

@mcp.tool()
def configure_wifi(ssid: str, name: str = "router", interfaces: list[str] | None = None,
                   password: str | None = None, generate_password: bool = False,
                   security: str = "wpa2-wpa3", country: str | None = None,
                   ensure_ap_mode: bool = True, site: str | None = None,
                   dry_run: bool = True, rollback_minutes: int = 5) -> str:
    """Set SSID and Wi-Fi password on the router's Wi-Fi interfaces.

    interfaces: which Wi-Fi interfaces (default: all, e.g. both 2.4 and 5 GHz).
    password: leave empty to have the user type it in a local popup (preferred),
      or set generate_password=True to create a strong one (shown in a local popup
      and saved under ~/mikrotik-sites/<site>/, never returned to chat).
    security: 'wpa2', 'wpa2-wpa3' (mixed, default) or 'wpa3'. Legacy 'wireless'
      driver only supports WPA2; mixed falls back to WPA2 there.
    country: regulatory country, e.g. 'Costa Rica'. Recommended on first setup.
    Works with legacy wireless, new wifi (7.13+) and wifiwave2 drivers."""
    facts = _facts(name)
    types = facts["interfaces"]
    targets = interfaces or facts["wifi_interfaces"]
    if not targets:
        return "No Wi-Fi interfaces found. Check the driver package (/system package print)."
    unknown = [t for t in targets if types.get(t) not in WIFI_TYPES]
    if unknown:
        return f"Not Wi-Fi interfaces on this router: {unknown}. Wi-Fi: {facts['wifi_interfaces']}"
    if security not in ("wpa2", "wpa2-wpa3", "wpa3"):
        return "security must be 'wpa2', 'wpa2-wpa3' or 'wpa3'."
    has_legacy = any(types[t] == "wlan" for t in targets)
    if has_legacy and security == "wpa3":
        return "Legacy 'wireless' driver doesn't support WPA3. Use 'wpa2' or 'wpa2-wpa3'."

    notes = []
    pw = "<password>"
    if not dry_run:
        if generate_password:
            alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"
            pw = "".join(secrets.choice(alphabet) for _ in range(16))
        elif password is None:
            pw = _popup_secret("Wi-Fi password", f"New Wi-Fi password for '{ssid}' (8-63 chars):")
        else:
            pw = password
        if not (8 <= len(pw) <= 63) or not pw.isprintable():
            return "Wi-Fi password must be 8-63 printable characters."
    elif generate_password:
        notes.append("A random 16-character password will be generated on apply.")
    elif password is None:
        notes.append("The user will be asked for the Wi-Fi password in a local popup on apply.")

    cmds = []
    auth_new = {"wpa2": "wpa2-psk", "wpa2-wpa3": "wpa2-psk,wpa3-psk", "wpa3": "wpa3-psk"}[security]
    if has_legacy:
        if security == "wpa2-wpa3":
            notes.append("Legacy wireless driver: using WPA2 (no WPA3 support).")
        cmds.append(':if ([:len [/interface wireless security-profiles find name="mcp-wifi"]] = 0) '
                    'do={/interface wireless security-profiles add name="mcp-wifi"}')
        cmds.append('/interface wireless security-profiles set [find name="mcp-wifi"] '
                    'mode=dynamic-keys authentication-types=wpa2-psk unicast-ciphers=aes-ccm '
                    f'group-ciphers=aes-ccm wpa2-pre-shared-key={q(pw)}')
    for t in targets:
        typ = types[t]
        if typ == "wlan":
            c = (f'/interface wireless set [find name={q(t)}] ssid={q(ssid)} '
                 'security-profile=mcp-wifi disabled=no')
            if ensure_ap_mode:
                c += " mode=ap-bridge"
            if country:
                c += f" frequency-mode=regulatory-domain country={q(country.lower())}"
        else:
            menu = "/interface wifi" if typ == "wifi" else "/interface wifiwave2"
            c = (f'{menu} set [find name={q(t)}] configuration.ssid={q(ssid)} '
                 f'security.authentication-types={auth_new} security.passphrase={q(pw)} disabled=no')
            if ensure_ap_mode:
                c += " configuration.mode=ap"
            if country:
                c += f" configuration.country={q(country)}"
        cmds.append(c)

    result = _plan(name, cmds, f"Set SSID '{ssid}' ({security}) on {', '.join(targets)}",
                   dry_run, rollback_minutes, hide=[pw] if pw != "<password>" else [],
                   notes="\n".join(notes))
    if not dry_run and generate_password and "ERROR" not in result:
        folder = _site_folder(site or _session(name)["host"], "wifi")
        (folder / "wifi-password.txt").write_text(f"SSID: {ssid}\nPassword: {pw}\n", encoding="utf-8")
        _popup_info("New Wi-Fi password", f"SSID: {ssid}\nPassword: {pw}\n\nSaved to {folder}")
        result += f"\nGenerated password shown in a local popup and saved to {folder}."
    return result


# =====================================================================
# Bridge + Wi-Fi subnet
# =====================================================================

@mcp.tool()
def setup_bridge_with_wifi_subnet(
        wifi_gateway: str, name: str = "router", mode: str = "vlan",
        bridge: str = "bridge", wan_interface: str | None = None,
        lan_ports: list[str] | None = None, wifi_ports: list[str] | None = None,
        lan_address: str | None = None, wifi_vlan_id: int = 20,
        wifi_bridge: str = "bridge-wifi", dhcp: bool = True, dhcp_range: str | None = None,
        isolate_wifi_from_lan: bool = True,
        dry_run: bool = True, rollback_minutes: int = 5) -> str:
    """Put all LAN ports and Wi-Fi in a bridge, with Wi-Fi in its own subnet.

    wifi_gateway (REQUIRED, ask the user, never invent): router IP + mask for the
      Wi-Fi subnet, as '192.168.20.1/24' or '192.168.20.1 255.255.255.0'.
    lan_address: only if the user wants to set/change the LAN gateway (same formats).
      If omitted, the current LAN address is kept (shown in the dry run; confirm it).
    dhcp_range: optional pool 'first-last' (e.g. '192.168.20.100-192.168.20.200').
      Default: the usable range after the first 9 addresses. Confirm with the user.
    mode='vlan' (default): ONE bridge with VLAN filtering. LAN ports untagged on
      VLAN 1, Wi-Fi ports on wifi_vlan_id, router IP on a VLAN interface.
      Caution: on many non-CRS3xx models this disables hardware offload (CPU switching).
    mode='separate_bridge': LAN ports in `bridge`, Wi-Fi in `wifi_bridge`.
    wan_interface: excluded from bridging (default: members of the WAN interface list).
    lan_ports / wifi_ports: default all Ethernet (minus WAN) / all Wi-Fi interfaces.
    isolate_wifi_from_lan: block traffic between Wi-Fi and LAN; Wi-Fi gets internet,
      DNS and DHCP only (no router management from Wi-Fi)."""
    if mode not in ("vlan", "separate_bridge"):
        return "mode must be 'vlan' or 'separate_bridge'."
    if not 2 <= wifi_vlan_id <= 4094:
        return "wifi_vlan_id must be 2-4094."
    facts = _facts(name)
    wan = [wan_interface] if wan_interface else facts["interface_lists"].get("WAN", [])
    if not wan:
        return "Could not detect the WAN interface. Ask the user which port is WAN (e.g. 'ether1')."
    wifi_ports = wifi_ports or facts["wifi_interfaces"]
    lan_ports = lan_ports or [e for e in facts["ethernet"] if e not in wan]
    if not wifi_ports:
        return "No Wi-Fi interfaces found to put in the Wi-Fi subnet."
    if any(p in wan for p in lan_ports + wifi_ports):
        return f"WAN interface {wan} cannot be a bridge port."

    res, err = _check(wifi_gateway, "interface", "wifi_gateway")
    if err:
        return err
    if len(res) != 1:
        return "wifi_gateway must be a single address."
    gw = ipaddress.ip_interface(res[0]["cidr"])
    net = gw.network
    if gw.version != 4:
        return "Only IPv4 is supported for the Wi-Fi subnet."
    if net.prefixlen > 29:
        return (f"/{net.prefixlen} ({net.netmask}) leaves only {net.num_addresses - 2} usable addresses; "
                "too small for Wi-Fi. Ask the user for something like /24 (255.255.255.0).")
    wifi_if = f"vlan{wifi_vlan_id}-wifi" if mode == "vlan" else wifi_bridge

    conflicts = _overlaps(name, net, exclude_interface=wifi_if)
    if conflicts:
        return (f"Wi-Fi subnet {net} overlaps: {', '.join(conflicts)}. "
                "Ask the user for a different subnet.")
    lan_res = None
    if lan_address:
        lan_res, lerr = _check(lan_address, "interface", "lan_address")
        if lerr:
            return lerr
        lan_if = ipaddress.ip_interface(lan_res[0]["cidr"])
        if lan_if.network.overlaps(net):
            return f"LAN {lan_if.network} and Wi-Fi {net} overlap. They must be different subnets."
        lc = _overlaps(name, lan_if.network, exclude_interface=bridge)
        if lc:
            return f"LAN {lan_if.network} overlaps: {', '.join(lc)}. Ask the user."
    current_lan = [str(a) for a, i in _router_networks(name) if i == bridge]

    if dhcp_range:
        m = re.fullmatch(r"\s*([\d.]+)\s*-\s*([\d.]+)\s*", dhcp_range)
        if not m:
            return "dhcp_range must look like '192.168.20.100-192.168.20.200'."
        try:
            a, b = ipaddress.IPv4Address(m.group(1)), ipaddress.IPv4Address(m.group(2))
        except ValueError:
            return "dhcp_range contains an invalid IP address."
        usable = (net.network_address + 1, net.broadcast_address - 1)
        if not (usable[0] <= a <= usable[1] and usable[0] <= b <= usable[1]):
            return f"dhcp_range must be inside {net} (usable {usable[0]} - {usable[1]})."
        if a > b:
            return "dhcp_range start is after its end."
        if a <= gw.ip <= b:
            return f"dhcp_range includes the gateway {gw.ip}. Exclude it."
        pool = f"{a}-{b}"
    else:
        start = int(net.network_address) + (10 if net.num_addresses > 32 else 2)
        end = int(net.broadcast_address) - 1
        if start <= int(gw.ip) <= end:
            start = int(gw.ip) + 1
        pool = f"{ipaddress.ip_address(start)}-{ipaddress.ip_address(end)}"

    C = [f':if ([:len [/interface bridge find name={q(bridge)}]] = 0) '
         f'do={{/interface bridge add name={q(bridge)}}}']
    for p in lan_ports:
        C.append(_bridge_port(p, bridge, 1))
    if mode == "vlan":
        for p in wifi_ports:
            C.append(_bridge_port(p, bridge, wifi_vlan_id))
        C.append(f'/interface bridge vlan remove [find bridge={q(bridge)} vlan-ids={wifi_vlan_id}]')
        C.append(f'/interface bridge vlan add bridge={q(bridge)} vlan-ids={wifi_vlan_id} '
                 f'tagged={q(bridge)} untagged={q(",".join(wifi_ports))}')
        C.append(f':if ([:len [/interface vlan find name={q(wifi_if)}]] = 0) '
                 f'do={{/interface vlan add name={q(wifi_if)} interface={q(bridge)} vlan-id={wifi_vlan_id}}}')
    else:
        C.append(f':if ([:len [/interface bridge find name={q(wifi_if)}]] = 0) '
                 f'do={{/interface bridge add name={q(wifi_if)}}}')
        for p in wifi_ports:
            C.append(_bridge_port(p, wifi_if, 1))

    if lan_res:
        lan_cidr = lan_res[0]["cidr"]
        C.append(f'/ip address remove [find interface={q(bridge)} address!={q(lan_cidr)}]')
        C.append(f':if ([:len [/ip address find address={q(lan_cidr)} interface={q(bridge)}]] = 0) '
                 f'do={{/ip address add address={q(lan_cidr)} interface={q(bridge)}}}')
    C.append(f'/ip address remove [find interface={q(wifi_if)}]')
    C.append(f'/ip address add address={q(str(gw))} interface={q(wifi_if)} comment="mcp-wifi"')

    if dhcp:
        C.append('/ip dhcp-server remove [find name="dhcp-wifi"]')
        C.append('/ip pool remove [find name="pool-wifi"]')
        C.append(f'/ip pool add name="pool-wifi" ranges={pool}')
        C.append(f'/ip dhcp-server add name="dhcp-wifi" interface={q(wifi_if)} '
                 'address-pool="pool-wifi" lease-time=1h disabled=no')
        C.append(f'/ip dhcp-server network remove [find address="{net}"]')
        C.append(f'/ip dhcp-server network add address="{net}" gateway={gw.ip} '
                 f'dns-server={gw.ip} comment="mcp-wifi"')
        C.append('/ip dns set allow-remote-requests=yes')

    C += [_ensure_list("LAN"), _ensure_list("WIFI"), _ensure_member("LAN", bridge),
          f'/interface list member remove [find list="LAN" interface={q(wifi_if)}]',
          _ensure_member("WIFI", wifi_if)]

    C.append('/ip firewall filter remove [find comment~"^mcp-wifi"]')
    rules = [
        'chain=input action=accept in-interface-list=WIFI protocol=udp dst-port=67 comment="mcp-wifi: dhcp"',
        'chain=input action=accept in-interface-list=WIFI protocol=tcp dst-port=53 comment="mcp-wifi: dns tcp"',
        'chain=input action=accept in-interface-list=WIFI protocol=udp dst-port=53 comment="mcp-wifi: dns udp"',
    ]
    if isolate_wifi_from_lan:
        rules += [
            'chain=forward action=drop in-interface-list=LAN out-interface-list=WIFI comment="mcp-wifi: isolate lan->wifi"',
            'chain=forward action=drop in-interface-list=WIFI out-interface-list=LAN comment="mcp-wifi: isolate wifi->lan"',
        ]
    C += [_top_filter_rule(r) for r in rules]
    if mode == "vlan":
        C.append(f'/interface bridge set [find name={q(bridge)}] vlan-filtering=yes')

    notes = [f"WAN (excluded): {', '.join(wan)}",
             f"LAN ports -> {bridge}: {', '.join(lan_ports) or '(none)'}",
             f"Wi-Fi ports -> {wifi_if}: {', '.join(wifi_ports)}",
             "Validated Wi-Fi gateway:\n" + _fmt_addr(res[0]),
             f"DHCP pool: {pool}" if dhcp else "No DHCP server.",
             ("Validated new LAN gateway:\n" + _fmt_addr(lan_res[0])) if lan_res else
             f"LAN address kept as-is: {', '.join(current_lan) or 'NONE on ' + bridge} (confirm with the user).",
             "Wi-Fi interface goes in list WIFI (not LAN): internet + DNS/DHCP only, no router management."]
    if mode == "vlan":
        notes.append("VLAN filtering is enabled LAST. On non-CRS3xx models this may disable "
                     "hardware offload (LAN switching via CPU).")
    if lan_res:
        link = _local_link(name)
        if link["interface"] == bridge and link["network"] != str(lan_if.network):
            notes.append(f"YOUR PC ({link['local_ip']}) IS ON THE LAN BEING CHANGED: it will lose the "
                         f"connection. After applying, release/renew its IP ({RENEW_STEPS}), then "
                         f"reconnect(new_host='{lan_if.ip}') and confirm_changes. Consider "
                         "rollback_minutes=10. The LAN DHCP server/pool must also be moved to "
                         f"{lan_if.network} (this tool does not change it), or the renew will fail.")
    if isolate_wifi_from_lan:
        notes.append("Wi-Fi and LAN cannot reach each other.")
    notes.append("If you are connected over Wi-Fi you will move to the new subnet. "
                 "Connect via a LAN port for this change.")
    if not facts["interface_lists"].get("WAN"):
        notes.append("No WAN interface list exists: run firewall_baseline afterwards so Wi-Fi gets NAT.")
    return _plan(name, C, f"Bridge ({mode}) with Wi-Fi subnet {net}", dry_run,
                 rollback_minutes, notes="\n".join(notes))


# =====================================================================
# Security audit, hardening, firewall
# =====================================================================

@mcp.tool()
def audit_security(name: str = "router", site: str | None = None) -> str:
    """Read-only security audit: version, users, exposed services, firewall, DNS
    resolver, proxies, MAC access, SNMP, Wi-Fi encryption, IPv6 firewall, and
    compromise indicators (schedulers/scripts, socks/proxy, static DNS).
    Optionally saves the report to ~/mikrotik-sites/<site>/."""
    F: list[tuple[str, str, str]] = []

    def add(sev, finding, fix):
        F.append((sev, finding, fix))

    facts = _facts(name)
    ver = _version(name)
    wan = facts["interface_lists"].get("WAN", [])

    if ver < (6, 43):
        add("CRITICAL", f"RouterOS {facts['version']} is very old with known critical "
                        "exploits (e.g. Winbox credential theft).", "Upgrade immediately, then change all passwords.")
    elif ver[0] == 6:
        add("MEDIUM", f"RouterOS {facts['version']} (v6).", "Plan an upgrade to current v7 stable.")
    else:
        add("INFO", f"RouterOS {facts['version']}.", "Check System > Packages > Check For Updates.")

    users = _terse(name, "/user print terse")
    if any(u.get("name") == "admin" and not u["_disabled"] for u in users):
        add("MEDIUM", "Default 'admin' username is active.", "Create a named admin user, then disable or remove 'admin'.")
    full = [u.get("name") for u in users if u.get("group") == "full" and not u["_disabled"]]
    add("INFO", f"Users with full rights: {', '.join(full) or 'none'}.", "Confirm every account is known.")

    for s in _terse(name, "/ip service print terse"):
        if s["_disabled"]:
            continue
        n, addr = s.get("name"), s.get("address", "")
        if n in ("telnet", "ftp"):
            add("HIGH", f"{n} enabled (cleartext passwords).", f"/ip service disable {n}")
        elif n in ("www", "api"):
            add("MEDIUM", f"{n} enabled (unencrypted).", f"Disable {n} or use the -ssl variant.")
        if not addr:
            add("LOW", f"Service {n} accepts any source address.",
                f"/ip service set {n} address=<LAN/mgmt subnets>")

    ssh = _try(name, "/ip ssh print")
    if re.search(r"strong-crypto:\s*no", ssh):
        add("LOW", "SSH strong-crypto disabled.", "/ip ssh set strong-crypto=yes")

    rules = [r for r in _terse(name, "/ip firewall filter print terse") if not r["_dynamic"]]
    active = [r for r in rules if not r["_disabled"]]
    inp = [r for r in active if r.get("chain") == "input"]
    fwd = [r for r in active if r.get("chain") == "forward"]
    catchall_keys = {"chain", "action", "in-interface", "in-interface-list", "comment", "log", "log-prefix"}
    has_input_drop = any(r.get("action") == "drop" and set(k for k in r if not k.startswith("_")) <= catchall_keys
                         for r in inp)
    if not inp:
        add("CRITICAL", "No input firewall rules: router management may be reachable from the internet.",
            "Run firewall_baseline.")
    elif not has_input_drop:
        add("HIGH", "Input chain has no final catch-all drop.", "Run firewall_baseline or add a final drop for non-LAN.")
    if inp and not any("established" in r.get("connection-state", "") for r in inp):
        add("LOW", "Input chain doesn't accept established/related first.", "Add it at the top for performance.")
    if wan and not any(r.get("action") == "drop" and (r.get("in-interface-list") == "WAN"
                                                      or r.get("in-interface") in wan) for r in fwd):
        add("HIGH", "Forward chain doesn't drop new connections from WAN.", "Run firewall_baseline.")
    dis = [r for r in rules if r["_disabled"]]
    if dis:
        add("INFO", f"{len(dis)} disabled firewall rule(s).", "Review and remove if unneeded.")
    if wan and not any(r.get("action") in ("masquerade", "src-nat") for r in _terse(name, "/ip firewall nat print terse")):
        add("INFO", "No masquerade/src-nat rule.", "LAN clients may have no internet; check NAT.")

    dns = _try(name, "/ip dns print")
    if re.search(r"allow-remote-requests:\s*yes", dns) and not has_input_drop:
        add("HIGH", "DNS remote requests enabled without input firewall (open resolver).",
            "Add input firewall drop for WAN, or disable allow-remote-requests.")
    static_dns = [d for d in _terse(name, "/ip dns static print terse") if not d["_dynamic"]]
    if static_dns:
        add("INFO", f"{len(static_dns)} static DNS entr(ies): "
                    + ", ".join(d.get("name", d.get("regexp", "?")) for d in static_dns[:10]),
            "Confirm none redirect popular domains (compromise indicator).")

    if re.search(r"enabled:\s*yes", _try(name, "/ip socks print")):
        add("HIGH", "SOCKS proxy enabled (common in compromised routers).", "/ip socks set enabled=no; investigate.")
    if re.search(r"enabled:\s*yes", _try(name, "/ip proxy print")):
        add("HIGH", "Web proxy enabled (common in compromised routers).", "/ip proxy set enabled=no unless intentional.")
    if re.search(r"enabled:\s*yes", _try(name, "/ip upnp print")):
        add("MEDIUM", "UPnP enabled (LAN devices can open ports).", "Disable unless required.")
    if re.search(r"enabled:\s*yes", _try(name, "/tool bandwidth-server print")):
        add("LOW", "Bandwidth-test server enabled.", "/tool bandwidth-server set enabled=no")
    if re.search(r"enabled:\s*yes", _try(name, "/tool romon print")):
        add("INFO", "RoMON enabled.", "Disable if not used.")
    if re.search(r"allowed-interface-list:\s*all", _try(name, "/tool mac-server print")):
        add("MEDIUM", "MAC-Telnet allowed on all interfaces.", "/tool mac-server set allowed-interface-list=LAN")
    if re.search(r"allowed-interface-list:\s*all", _try(name, "/tool mac-server mac-winbox print")):
        add("MEDIUM", "MAC-Winbox allowed on all interfaces.", "/tool mac-server mac-winbox set allowed-interface-list=LAN")
    if re.search(r"discover-interface-list:\s*all", _try(name, "/ip neighbor discovery-settings print")):
        add("LOW", "Neighbor discovery on all interfaces (incl. WAN).",
            "/ip neighbor discovery-settings set discover-interface-list=LAN")
    if re.search(r"enabled:\s*yes", _try(name, "/snmp print")):
        if any(c.get("name") == "public" for c in _terse(name, "/snmp community print terse")):
            add("MEDIUM", "SNMP enabled with community 'public'.", "Change community or disable SNMP.")

    for s in _terse(name, "/system scheduler print terse"):
        if s.get("name", "").startswith("mcp-"):
            continue
        ev = s.get("on-event", "")
        sev = "HIGH" if re.search(r"fetch|http|socks|proxy|import", ev, re.I) else "INFO"
        add(sev, f"Scheduler '{s.get('name')}' runs: {ev[:120]}", "Confirm it is legitimate.")
    for s in _terse(name, "/system script print terse"):
        src = s.get("source", "")
        sev = "HIGH" if re.search(r"fetch|socks|proxy", src, re.I) else "INFO"
        add(sev, f"Script '{s.get('name')}' present.", "Review its contents.")

    if facts["wifi_driver"] == "wireless":
        profiles = {p.get("name"): p for p in _terse(name, "/interface wireless security-profiles print terse")}
        for w in _terse(name, "/interface wireless print terse"):
            if w["_disabled"]:
                continue
            p = profiles.get(w.get("security-profile", "default"), {})
            mode, auth = p.get("mode", ""), p.get("authentication-types", "").split(",")
            if mode == "none":
                add("HIGH", f"Wi-Fi {w.get('name')} ({w.get('ssid')}) is OPEN.", "Run configure_wifi.")
            elif mode.startswith("static-keys"):
                add("HIGH", f"Wi-Fi {w.get('name')} uses WEP.", "Run configure_wifi (WPA2).")
            elif "wpa-psk" in auth:
                add("MEDIUM", f"Wi-Fi {w.get('name')} allows WPA1.", "Use WPA2 only.")
            if w.get("wps-mode") not in (None, "", "disabled"):
                add("LOW", f"WPS enabled on {w.get('name')}.", "Disable WPS.")
    elif facts["wifi_driver"] in ("wifi", "wifiwave2"):
        menu = "/interface " + facts["wifi_driver"]
        for w in _terse(name, f"{menu} print terse"):
            if w["_disabled"]:
                continue
            auth = w.get("security.authentication-types", "")
            if "wpa3" not in auth and auth:
                add("INFO", f"Wi-Fi {w.get('name')} is WPA2-only; WPA3 is available.",
                    "configure_wifi security='wpa2-wpa3'.")

    v6addr = [a for a in _terse(name, "/ipv6 address print terse")
              if not a["_disabled"] and not a.get("address", "").lower().startswith("fe80")]
    if v6addr and not any(r.get("chain") == "input" for r in _terse(name, "/ipv6 firewall filter print terse")):
        add("HIGH", "IPv6 is active but has no IPv6 input firewall.", "Add an IPv6 firewall (defconf-style).")

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    F.sort(key=lambda x: order[x[0]])
    counts = {k: sum(1 for f in F if f[0] == k) for k in order}
    report = (f"Security audit: {_session(name)['host']} | {facts['board']} | RouterOS {facts['version']}\n"
              + " ".join(f"{k}:{v}" for k, v in counts.items()) + "\n\n"
              + "\n".join(f"[{s}] {f}\n    Fix: {x}" for s, f, x in F)
              + "\n\nNote: password strength cannot be checked remotely.")
    if site:
        folder = _site_folder(site, "audit")
        (folder / "security_audit.txt").write_text(report, encoding="utf-8")
        report += f"\nSaved to {folder}"
    return report


@mcp.tool()
def harden_services(name: str = "router",
                    disable_services: list[str] | None = None,
                    restrict_mgmt_to: str | None = None,
                    mac_access_lan_only: bool = True, neighbor_discovery_lan_only: bool = True,
                    disable_socks_proxy_bwtest: bool = True, disable_upnp: bool = False,
                    ssh_strong_crypto: bool = True,
                    dry_run: bool = True, rollback_minutes: int = 5) -> str:
    """Common hardening. disable_services default: telnet, ftp, www, api, api-ssl
    (SSH and Winbox stay on; SSH can never be disabled here).
    restrict_mgmt_to: subnets allowed to use SSH/Winbox (ask the user), comma-separated,
    '/prefix' or dotted mask. Refused if this computer's IP is not inside them."""
    services = disable_services if disable_services is not None else ["telnet", "ftp", "www", "api", "api-ssl"]
    if "ssh" in services:
        return "Refusing to disable SSH: this server needs it."
    C = [f'/ip service disable [find name={q(s)}]' for s in services]
    if restrict_mgmt_to:
        res, err = _check(restrict_mgmt_to, "network", "restrict_mgmt_to")
        if err:
            return err
        nets = [ipaddress.ip_network(r["cidr"]) for r in res]
        try:
            mine = ipaddress.ip_address(_session(name)["client"].get_transport().sock.getsockname()[0])
        except Exception:
            mine = None
        if mine and not any(mine in n for n in nets):
            return (f"Your computer ({mine}) is not inside {', '.join(map(str, nets))}. Applying this "
                    "would lock you out of SSH. Ask the user for the correct management subnet(s).")
        restrict_mgmt_to = ",".join(str(n) for n in nets)
        C.append(f'/ip service set [find name~"^(ssh|winbox)$"] address={q(restrict_mgmt_to)}')
    if mac_access_lan_only or neighbor_discovery_lan_only:
        C.append(_ensure_list("LAN"))
    if mac_access_lan_only:
        C += ['/tool mac-server set allowed-interface-list=LAN',
              '/tool mac-server mac-winbox set allowed-interface-list=LAN']
    if neighbor_discovery_lan_only:
        C.append('/ip neighbor discovery-settings set discover-interface-list=LAN')
    if disable_socks_proxy_bwtest:
        C += ['/ip socks set enabled=no', '/ip proxy set enabled=no',
              '/tool bandwidth-server set enabled=no']
    if disable_upnp:
        C.append('/ip upnp set enabled=no')
    if ssh_strong_crypto:
        C.append('/ip ssh set strong-crypto=yes')
    notes = "Make sure the LAN interface list contains your LAN bridge, or MAC-Winbox from LAN stops working."
    if restrict_mgmt_to:
        notes += f"\nSSH/Winbox will only accept {restrict_mgmt_to}; your laptop must be in that range."
    return _plan(name, C, "Harden router services", dry_run, rollback_minutes, notes=notes)


@mcp.tool()
def firewall_baseline(name: str = "router", wan_interface: str | None = None,
                      lan_interfaces: list[str] | None = None, replace_existing: bool = False,
                      add_nat: bool = True, dry_run: bool = True,
                      rollback_minutes: int = 5) -> str:
    """Apply a MikroTik-defconf-style IPv4 firewall:
    input: accept established/related/untracked, drop invalid, accept ICMP,
      accept WireGuard ports, drop everything not from LAN.
    forward: fasttrack, accept established/related, drop invalid,
      drop new WAN connections that aren't port-forwards.
    nat: masquerade out WAN (if none exists).
    If the router already has other filter rules, the tool stops and lists them;
    set replace_existing=True to replace them (rules tagged mcp-wifi/mcp-wg are kept)."""
    facts = _facts(name)
    wan = [wan_interface] if wan_interface else facts["interface_lists"].get("WAN", [])
    if not wan:
        return "Could not detect WAN. Pass wan_interface (e.g. 'ether1' or 'pppoe-out1')."
    lan = lan_interfaces or facts["interface_lists"].get("LAN", []) or \
        (["bridge"] if "bridge" in facts["bridges"] else [])
    if not lan:
        return "Could not detect LAN interfaces. Pass lan_interfaces (e.g. ['bridge'])."

    existing = [r for r in _terse(name, "/ip firewall filter print terse") if not r["_dynamic"]]
    others = [r for r in existing if not re.match(r"mcp-(baseline|wifi|wg)", r.get("comment", ""))]
    if others and not replace_existing:
        summary = "\n".join(f"  {r.get('chain')} {r.get('action')} {r.get('comment', '')}" for r in others[:25])
        return (f"Router already has {len(others)} non-MCP filter rule(s):\n{summary}\n\n"
                "Review them with the user. Call again with replace_existing=True to replace them "
                "with the baseline (collect_info first so the old rules are saved).")

    v7 = facts["major"] >= 7
    C = [_ensure_list("LAN"), _ensure_list("WAN")]
    C += [_ensure_member("WAN", w) for w in wan] + [_ensure_member("LAN", l) for l in lan]
    if replace_existing:
        C.append('/ip firewall filter remove [find where dynamic=no !(comment~"^mcp-(wifi|wg)")]')
    else:
        C.append('/ip firewall filter remove [find comment~"^mcp-baseline"]')

    t = "mcp-baseline: "
    rules = [
        f'chain=input action=accept connection-state=established,related,untracked comment="{t}in est/rel"',
        f'chain=input action=drop connection-state=invalid comment="{t}in drop invalid"',
        f'chain=input action=accept protocol=icmp comment="{t}in icmp"',
        f'chain=input action=accept dst-address=127.0.0.1 comment="{t}in loopback (capsman)"',
    ]
    if v7:
        for wg in _terse(name, "/interface wireguard print terse"):
            if wg.get("listen-port"):
                rules.append(f'chain=input action=accept protocol=udp dst-port={wg["listen-port"]} '
                             f'comment="{t}in wireguard {wg.get("name")}"')
    rules.append(f'chain=input action=drop in-interface-list=!LAN comment="{t}in drop all not from LAN"')
    rules.append(f'chain=forward action=fasttrack-connection connection-state=established,related'
                 f'{" hw-offload=yes" if v7 else ""} comment="{t}fwd fasttrack"')
    rules += [
        f'chain=forward action=accept connection-state=established,related,untracked comment="{t}fwd est/rel"',
        f'chain=forward action=drop connection-state=invalid comment="{t}fwd drop invalid"',
        f'chain=forward action=drop connection-state=new connection-nat-state=!dstnat '
        f'in-interface-list=WAN comment="{t}fwd drop WAN not dstnat"',
    ]
    C += [f"/ip firewall filter add {r}" for r in rules]

    nat = _terse(name, "/ip firewall nat print terse")
    if add_nat and not any(r.get("action") == "masquerade" for r in nat):
        C.append(f'/ip firewall nat add chain=srcnat action=masquerade out-interface-list=WAN comment="{t}masquerade"')

    notes = (f"WAN: {', '.join(wan)} | LAN: {', '.join(lan)}\n"
             "Router management (SSH/Winbox) will only be reachable from LAN-list interfaces. "
             "Your laptop must be on a LAN interface.\n"
             "Existing mcp-wifi / mcp-wg rules stay at the top.")
    return _plan(name, C, "IPv4 firewall baseline", dry_run, rollback_minutes, notes=notes)


# =====================================================================
# WireGuard (RouterOS v7). This server NEVER generates keys.
# =====================================================================

def _require_v7(name):
    if _version(name)[0] < 7:
        raise RuntimeError("WireGuard requires RouterOS v7. This router runs v6.")


def _wg_interfaces(name) -> dict:
    return {w.get("name"): w for w in _terse(name, "/interface wireguard print terse")}


def _wg_addrs(name, iface) -> list:
    return [a for a, i in _router_networks(name) if i == iface]


def _peer_find(interface: str, peer: str) -> str:
    field = "public-key" if _key_error(peer, "") is None else "comment"
    return f'[find interface={q(interface)} {field}={q(peer)}]'


def _peer_nets(p: dict) -> list:
    out = []
    for item in p.get("allowed-address", "").split(","):
        try:
            out.append(ipaddress.ip_network(item.strip(), strict=False))
        except ValueError:
            pass
    return out


@mcp.tool()
def wireguard_status(name: str = "router") -> str:
    """Show WireGuard interfaces (address with mask in both formats), peers
    (handshake, traffic, endpoints) and whether the firewall allows each port.
    Secrets are masked."""
    _require_v7(name)
    wgs = _wg_interfaces(name)
    if not wgs:
        return "No WireGuard interfaces configured."
    peers = _terse(name, "/interface wireguard peers print terse")
    rules = [r for r in _terse(name, "/ip firewall filter print terse") if not r["_disabled"]]
    lists = _facts(name)["interface_lists"]
    out = []
    for n, w in wgs.items():
        port = w.get("listen-port", "?")
        addrs = [f"{a} (mask {a.netmask})" for a in _wg_addrs(name, n)]
        allowed = any(r.get("chain") == "input" and r.get("action") == "accept" and
                      r.get("protocol") == "udp" and port in r.get("dst-port", "").split(",")
                      for r in rules)
        in_lists = [l for l, m in lists.items() if n in m]
        out.append(f"Interface {n}{' (DISABLED)' if w['_disabled'] else ''}: port {port}, "
                   f"address {', '.join(addrs) or 'NONE'}, public-key {w.get('public-key')}, "
                   f"interface lists {in_lists or 'none'}, "
                   f"firewall allows port: {'yes' if allowed else 'NO / not found'}")
        for p in [p for p in peers if p.get("interface") == n]:
            ep = p.get("current-endpoint-address") or p.get("endpoint-address") or "-"
            out.append(f"  peer '{p.get('comment', '')}'{' (DISABLED)' if p['_disabled'] else ''}: "
                       f"key {p.get('public-key', '')[:12]}..., allowed {p.get('allowed-address')}, "
                       f"endpoint {ep}, last handshake {p.get('last-handshake', 'never')}, "
                       f"rx {p.get('rx', '?')} tx {p.get('tx', '?')}, "
                       f"keepalive {p.get('persistent-keepalive', '-')}, "
                       f"preshared key {'yes' if p.get('preshared-key') else 'no'}")
    return "\n".join(out)


@mcp.tool()
def wireguard_create_interface(address: str, private_key_source: str, wg_name: str,
                               listen_port: int, name: str = "router",
                               private_key: str | None = None,
                               allow_in_firewall: bool = True, trust_as_lan: bool = False,
                               dry_run: bool = True, rollback_minutes: int = 5) -> str:
    """Create (or update) a WireGuard interface. All values come from the user.

    address (REQUIRED, ask the user, never invent): the router's tunnel IP with mask,
      as '10.10.10.1/24' or '10.10.10.1 255.255.255.0'. Validated and checked for
      overlap with the router's existing subnets.
    private_key_source (REQUIRED, ask the user):
      'router' = RouterOS creates the interface's own key (never leaves the router).
      'user'   = the user enters an existing private key (e.g. rebuilding a tunnel).
                 Leave private_key empty: it is entered in a local popup on apply.
    wg_name, listen_port (REQUIRED, ask the user; RouterOS commonly uses 13231)."""
    _require_v7(name)
    if private_key_source not in ("router", "user"):
        return "private_key_source must be 'router' or 'user'. Ask the user which they want."
    res, err = _check(address, "interface", "WireGuard interface address")
    if err:
        return err
    if len(res) != 1:
        return "Give exactly one address for the interface."
    r = res[0]
    if not 1 <= listen_port <= 65535:
        return f"Listen port {listen_port} is out of range (1-65535). Ask the user."
    problems = []
    ov = _overlaps(name, ipaddress.ip_network(r["network"]), exclude_interface=wg_name)
    if ov:
        problems.append(f"{r['network']} overlaps existing subnet(s): {', '.join(ov)}.")
    for n, w in _wg_interfaces(name).items():
        if n != wg_name and w.get("listen-port") == str(listen_port):
            problems.append(f"UDP {listen_port} is already used by WireGuard interface {n}.")
    if problems:
        return "Cannot continue:\n- " + "\n- ".join(problems) + "\nAsk the user for different values."

    pk = None
    if private_key_source == "user" and not dry_run:
        try:
            pk = _get_key(private_key, f"Private key for {wg_name}", secret=True)
        except (ValueError, RuntimeError) as e:
            return str(e)
    key_arg = ""
    if private_key_source == "user":
        key_arg = f" private-key={q(pk)}" if pk else ' private-key="<entered in popup on apply>"'

    cidr = r["cidr"]
    C = [f':if ([:len [/interface wireguard find name={q(wg_name)}]] = 0) '
         f'do={{/interface wireguard add name={q(wg_name)} listen-port={listen_port}{key_arg}}} '
         f'else={{/interface wireguard set [find name={q(wg_name)}] listen-port={listen_port}{key_arg}}}',
         f'/ip address remove [find interface={q(wg_name)} address!={q(cidr)}]',
         f':if ([:len [/ip address find interface={q(wg_name)} address={q(cidr)}]] = 0) '
         f'do={{/ip address add address={q(cidr)} interface={q(wg_name)}}}']
    if allow_in_firewall:
        C.append(f'/ip firewall filter remove [find comment="mcp-wg: allow {wg_name}"]')
        C.append(_top_filter_rule(f'chain=input action=accept protocol=udp dst-port={listen_port} '
                                  f'comment="mcp-wg: allow {wg_name}"'))
    if trust_as_lan:
        C += [_ensure_list("LAN"), _ensure_member("LAN", wg_name)]

    notes = (f"Validated address:\n{_fmt_addr(r)}\n"
             f"Key: {'generated by RouterOS' if private_key_source == 'router' else 'entered by the user in a local popup'}.\n"
             f"Remember port-forwarding UDP {listen_port} on any upstream modem/ISP router.\n"
             "With firewall_baseline, VPN peers reach the LAN but can't manage the router "
             "unless trust_as_lan=True.")
    result = _plan(name, C, f"WireGuard interface {wg_name} {cidr} port {listen_port}",
                   dry_run, rollback_minutes, hide=[pk] if pk else [], notes=notes)
    if not dry_run:
        rk = _wg_interfaces(name).get(wg_name, {}).get("public-key")
        if rk:
            result += f"\nRouter public key for {wg_name} (give this to the remote peers): {rk}"
            if pk and _pub_from_priv(pk) != rk:
                result += "\nWARNING: router's public key doesn't match the entered private key."
    return result


@mcp.tool()
def wireguard_add_peer(interface: str, allowed_address: str, name: str = "router",
                       public_key: str | None = None, use_preshared_key: bool = False,
                       preshared_key: str | None = None, comment: str = "",
                       endpoint: str | None = None, persistent_keepalive: int | None = None,
                       write_client_config: bool = False, client_allowed_ips: str | None = None,
                       client_dns: str | None = None, server_endpoint: str | None = None,
                       site: str | None = None, dry_run: bool = True,
                       rollback_minutes: int = 5) -> str:
    """Add a WireGuard peer. This server never generates keys; all values come from the user.

    allowed_address (REQUIRED, ask the user): addresses this peer uses/routes,
      comma-separated, '/prefix' or dotted mask. E.g. '10.10.10.2/32' (phone/laptop) or
      '10.10.10.2/32, 192.168.50.0 255.255.255.0' (remote site + its LAN). Validated:
      format, overlap with other peers, inside the tunnel subnet, not the router's own IP.
    public_key: the REMOTE peer's public key (shown in its WireGuard app / remote router).
      Leave empty to have the user type it in a local popup on apply. Checked: format,
      not this router's own key, not already used on this interface.
    use_preshared_key: on apply the preshared key is entered in a local popup (or via
      preshared_key). Never ask the user to paste it in chat.
    endpoint: 'host:port' of the remote side for site-to-site. Omit for roaming clients.
    write_client_config: also save a .conf for the remote device. Requires (ask the user):
      client_allowed_ips: '0.0.0.0/0' for full tunnel, or specific subnets (split tunnel);
      server_endpoint: public IP/hostname (and :port) the client connects to.
      On apply the user may enter the client's private key in a popup to get a complete
      config + QR; it is checked against public_key. If left empty, a template is saved.
    client_dns: optional DNS server IP(s) for the client config."""
    _require_v7(name)
    wgs = _wg_interfaces(name)
    if interface not in wgs:
        return f"WireGuard interface '{interface}' not found. Existing: {list(wgs) or 'none'}"
    listen_port = int(wgs[interface].get("listen-port", "0") or 0)

    res, err = _check(allowed_address, "network", "allowed_address")
    if err:
        return err
    nets = [ipaddress.ip_network(r["cidr"]) for r in res]
    errors, warnings = [], []

    for i, a in enumerate(nets):
        for b in nets[i + 1:]:
            if a.overlaps(b):
                errors.append(f"{a} and {b} overlap each other.")
    peers = [p for p in _terse(name, "/interface wireguard peers print terse")
             if p.get("interface") == interface]
    for p in peers:
        for pn in _peer_nets(p):
            for n in nets:
                if n.prefixlen and pn.prefixlen and n.version == pn.version and n.overlaps(pn):
                    errors.append(f"{n} overlaps {pn}, already used by peer "
                                  f"'{p.get('comment') or p.get('public-key', '')[:12]}'.")
    wg_addrs = _wg_addrs(name, interface)
    for a in wg_addrs:
        for n in nets:
            if n.version == a.version and a.ip in n and n.prefixlen == a.max_prefixlen:
                errors.append(f"{n} is the router's own tunnel IP on {interface}. Use another address.")
    if not wg_addrs:
        warnings.append(f"{interface} has no IP address yet.")
    elif not any(n.version == a.version and n.subnet_of(a.network) for n in nets for a in wg_addrs):
        warnings.append(f"None of the allowed addresses is inside {interface}'s tunnel subnet "
                        f"({', '.join(str(a.network) for a in wg_addrs)}). The peer's tunnel IP "
                        "(a /32 from that subnet) is normally included.")

    ep = None
    if endpoint:
        try:
            ep = _parse_endpoint(endpoint)
        except ValueError as e:
            errors.append(str(e))
    if persistent_keepalive is not None and not 0 <= persistent_keepalive <= 65535:
        errors.append("persistent_keepalive must be 0-65535 seconds (25 is typical).")

    client_nets, srv = [], None
    if write_client_config:
        if not client_allowed_ips:
            errors.append("client_allowed_ips is required for the client config. Ask the user: "
                          "'0.0.0.0/0' (all traffic through the VPN) or specific subnets (e.g. the office LAN).")
        else:
            cr, cerr = _check(client_allowed_ips, "network", "client_allowed_ips")
            if cerr:
                errors.append(cerr)
            else:
                client_nets = [r["cidr"] for r in cr]
        if not server_endpoint:
            cloud = _try(name, "/ip cloud print")
            m = re.search(r"dns-name:\s*(\S+)", cloud)
            hint = (f" This router's DDNS name is {m.group(1)}; confirm with the user."
                    if m and "ddns-enabled: yes" in cloud else "")
            errors.append("server_endpoint is required (the public IP or hostname clients connect to)."
                          + hint + " Ask the user.")
        else:
            try:
                srv = _parse_endpoint(server_endpoint, default_port=listen_port or None)
            except ValueError as e:
                errors.append(str(e))
        if client_dns:
            for d in re.split(r"[,;]", client_dns):
                try:
                    ipaddress.ip_address(d.strip())
                except ValueError:
                    errors.append(f"client_dns '{d.strip()}' is not a valid IP address.")
    if errors:
        return "Cannot continue:\n- " + "\n- ".join(errors) + "\nAsk the user to correct these values."

    allowed = ",".join(str(n) for n in nets)
    label = comment or allowed
    asks = []
    if not public_key:
        asks.append("the remote peer's public key")
    if use_preshared_key and not preshared_key:
        asks.append("the preshared key (hidden)")
    if write_client_config:
        asks.append("optionally the client's private key (hidden; empty = template)")
    notes = ("Validated allowed addresses:\n" + "\n".join(_fmt_addr(r) for r in res)
             + ("\nWarnings:\n- " + "\n- ".join(warnings) if warnings else "")
             + (f"\nOn apply, local popups will ask for: {', '.join(asks)}." if asks else ""))

    def build(pub, psk):
        c = (f'/interface wireguard peers add interface={q(interface)} public-key={q(pub)} '
             f'allowed-address={q(allowed)}')
        if comment:
            c += f" comment={q(comment)}"
        if ep:
            c += f" endpoint-address={q(ep[0])} endpoint-port={ep[1]}"
        if persistent_keepalive:
            c += f" persistent-keepalive={persistent_keepalive}s"
        if psk:
            c += f" preshared-key={q(psk)}"
        return c

    if dry_run:
        cmd = build(public_key or "<entered in popup>",
                    "<entered in popup>" if use_preshared_key else None)
        return _plan(name, [cmd], f"Add WireGuard peer '{label}' on {interface}", True,
                     rollback_minutes, notes=notes)

    try:
        pub = _get_key(public_key, f"Public key of remote peer '{label}'", secret=False)
        if pub == wgs[interface].get("public-key"):
            return (f"That is this router's OWN public key for {interface}. "
                    "Ask the user for the remote device's public key.")
        if any(p.get("public-key") == pub for p in peers):
            return f"A peer with this public key already exists on {interface}."
        psk = _get_key(preshared_key, "Preshared key", secret=True) if use_preshared_key else None
        client_priv = ""
        if write_client_config:
            client_priv = _popup("WireGuard", "Client private key (optional, leave empty for a template):",
                                 hidden=True, optional=True).strip()
            if client_priv:
                kerr = _key_error(client_priv, "Client private key")
                if kerr:
                    return kerr
                if _pub_from_priv(client_priv) != pub:
                    return ("The client private key does NOT match the public key entered. "
                            "Check both on the device; nothing was changed.")
    except (ValueError, RuntimeError) as e:
        return str(e)

    hide = [k for k in (psk, client_priv) if k]
    text, ok = _apply(name, [build(pub, psk)], f"Add WireGuard peer '{label}' on {interface}",
                      rollback_minutes, hide=hide)
    if ok and write_client_config:
        tunnel = next((n for n in nets for a in wg_addrs if n.version == a.version and n.subnet_of(a.network)), nets[0])
        conf = ("[Interface]\n"
                f"PrivateKey = {client_priv or '<PASTE_CLIENT_PRIVATE_KEY>'}\n"
                f"Address = {tunnel}\n"
                + (f"DNS = {client_dns}\n" if client_dns else "")
                + "\n[Peer]\n"
                f"PublicKey = {wgs[interface].get('public-key')}\n"
                + (f"PresharedKey = {psk}\n" if psk else "")
                + f"AllowedIPs = {', '.join(client_nets)}\n"
                f"Endpoint = {srv[0]}:{srv[1]}\n"
                "PersistentKeepalive = 25\n")
        folder = _site_folder(site or _session(name)["host"], "wireguard")
        fname = re.sub(r"[^\w.-]", "_", comment or "client")
        (folder / f"{fname}.conf").write_text(conf, encoding="utf-8")
        text += f"\nClient config saved: {folder / (fname + '.conf')}"
        if client_priv:
            try:
                import qrcode
                qrcode.make(conf).save(folder / f"{fname}.png")
                text += f"\nQR code saved: {folder / (fname + '.png')}"
            except Exception:
                text += "\n(Install 'qrcode[pil]' to also get a QR code.)"
        else:
            text += "\nTemplate only: the user must paste the client's private key into PrivateKey."
    return text + ("\nWarnings:\n- " + "\n- ".join(warnings) if warnings else "")


@mcp.tool()
def wireguard_update_peer(interface: str, peer: str, name: str = "router",
                          allowed_address: str | None = None, endpoint: str | None = None,
                          persistent_keepalive: int | None = None, disabled: bool | None = None,
                          new_comment: str | None = None,
                          replace_public_key: bool = False, new_public_key: str | None = None,
                          replace_preshared_key: bool = False,
                          dry_run: bool = True, rollback_minutes: int = 5) -> str:
    """Modify a WireGuard peer, found by its public key or comment.
    allowed_address: new value (validated, '/prefix' or dotted mask, comma-separated).
    endpoint: 'host:port', or '' to clear (roaming client).
    replace_public_key / replace_preshared_key: new key entered in a local popup on
      apply (public key may also be given as new_public_key). Keys are never generated."""
    _require_v7(name)
    wgs = _wg_interfaces(name)
    if interface not in wgs:
        return f"WireGuard interface '{interface}' not found."
    peers = [p for p in _terse(name, "/interface wireguard peers print terse") if p.get("interface") == interface]
    by_key = _key_error(peer, "") is None
    target = [p for p in peers if p.get("public-key" if by_key else "comment") == peer]
    if not target:
        return f"No peer '{peer}' on {interface}. Peers: " + \
            ", ".join(p.get("comment") or p.get("public-key", "")[:12] for p in peers)
    if len(target) > 1:
        return f"Several peers match '{peer}'. Use the public key instead."

    sets, notes, hide = [], [], []
    if allowed_address is not None:
        res, err = _check(allowed_address, "network", "allowed_address")
        if err:
            return err
        nets = [ipaddress.ip_network(r["cidr"]) for r in res]
        for p in peers:
            if p is target[0]:
                continue
            for pn in _peer_nets(p):
                for n in nets:
                    if n.prefixlen and pn.prefixlen and n.version == pn.version and n.overlaps(pn):
                        return f"{n} overlaps {pn} used by peer '{p.get('comment') or p.get('public-key', '')[:12]}'."
        sets.append(f"allowed-address={q(','.join(str(n) for n in nets))}")
        notes.append("Validated allowed addresses:\n" + "\n".join(_fmt_addr(r) for r in res))
    if endpoint is not None:
        if endpoint == "":
            sets.append('endpoint-address="" endpoint-port=0')
        else:
            try:
                h, p_ = _parse_endpoint(endpoint)
            except ValueError as e:
                return str(e)
            sets.append(f"endpoint-address={q(h)} endpoint-port={p_}")
    if persistent_keepalive is not None:
        sets.append(f"persistent-keepalive={persistent_keepalive}s")
    if disabled is not None:
        sets.append(f"disabled={'yes' if disabled else 'no'}")
    if new_comment is not None:
        sets.append(f"comment={q(new_comment)}")
    if replace_public_key:
        if dry_run:
            sets.append('public-key="<entered in popup>"' if not new_public_key else f"public-key={q(new_public_key)}")
        else:
            try:
                nk = _get_key(new_public_key, f"New public key for peer '{peer}'", secret=False)
            except (ValueError, RuntimeError) as e:
                return str(e)
            if nk == wgs[interface].get("public-key"):
                return "That is the router's own public key. Ask for the remote device's key."
            if any(p.get("public-key") == nk for p in peers if p is not target[0]):
                return "Another peer already uses that public key."
            sets.append(f"public-key={q(nk)}")
    if replace_preshared_key:
        if dry_run:
            sets.append('preshared-key="<entered in popup>"')
        else:
            try:
                psk = _get_key(None, "New preshared key", secret=True)
            except (ValueError, RuntimeError) as e:
                return str(e)
            sets.append(f"preshared-key={q(psk)}")
            hide.append(psk)
    if not sets:
        return "Nothing to change."
    C = [f"/interface wireguard peers set {_peer_find(interface, peer)} {' '.join(sets)}"]
    return _plan(name, C, f"Update WireGuard peer '{peer[:20]}' on {interface}", dry_run,
                 rollback_minutes, hide=hide, notes="\n".join(notes))


@mcp.tool()
def wireguard_remove_peer(interface: str, peer: str, name: str = "router",
                          dry_run: bool = True, rollback_minutes: int = 5) -> str:
    """Remove a WireGuard peer, identified by its public key or comment."""
    _require_v7(name)
    C = [f"/interface wireguard peers remove {_peer_find(interface, peer)}"]
    return _plan(name, C, f"Remove WireGuard peer '{peer[:20]}' from {interface}", dry_run, rollback_minutes)


# =====================================================================
# generic changes + commit/rollback
# =====================================================================

@mcp.tool()
def apply_changes(commands: list[str], description: str, name: str = "router",
                  rollback_minutes: int = 5, dry_run: bool = True) -> str:
    """Apply arbitrary RouterOS commands (one per list item) when no dedicated tool
    fits. Same safety net: backup + rollback timer + stop on first error."""
    return _plan(name, commands, description, dry_run, rollback_minutes)


@mcp.tool()
def confirm_changes(name: str = "router") -> str:
    """Disarm the rollback after verifying the change works; saves the new config locally."""
    s = _session(name)
    _run(name, f"/system scheduler remove [find name={ROLLBACK_SCHED}]")
    still = _run(name, f"/system scheduler print where name={ROLLBACK_SCHED}")
    folder = _site_folder("_changes", s["host"])
    (folder / "after_confirmed.rsc").write_text(_run(name, "/export show-sensitive terse", 90),
                                                encoding="utf-8")
    if ROLLBACK_SCHED in still:
        return "WARNING: rollback scheduler still present. Check /system scheduler."
    return f"Changes confirmed, rollback disarmed. Config saved to {folder}"


@mcp.tool()
def rollback_now(name: str = "router") -> str:
    """Immediately restore the pre-change backup. The router REBOOTS."""
    try:
        _run(name, f"/system scheduler remove [find name={ROLLBACK_SCHED}]")
        _run(name, f'/system backup load name={BACKUP_NAME} password=""', timeout=15)
    except Exception:
        pass
    return "Restore issued; router is rebooting. Reconnect in 1-2 minutes."


def main() -> None:
    """Entry point for the `sos-microtik-mcp` command."""
    mcp.run()


if __name__ == "__main__":
    main()

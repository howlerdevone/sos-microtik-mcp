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
  Tunnels    : tunnel_setup, tunnel_verify (WireGuard + iBGP/OSPF/static, hub & spokes)
  Changes    : apply_changes, confirm_changes, rollback_now
  Panel      : ui://sos-microtik/panel.html (MCP Apps, Claude Desktop)

Every write tool defaults to dry_run=True (returns the plan only). When applied,
changes run with a "commit confirmed" safety net: local export + on-router
backup + a rollback timer that restores the backup unless confirm_changes is
called.

Install: see README.md (uv tool install git+https://github.com/howlerdevone/sos-microtik-mcp)
"""
import base64
import datetime
import functools
import ipaddress
import pathlib
import re
import secrets
import socket
import struct
import threading
import time

import paramiko
from mcp.server.mcpserver import MCPServer as FastMCP
from mcp.types import CallToolResult, TextContent

from mikrotik_ui import PANEL_HTML

INSTRUCTIONS = """
You manage MikroTik RouterOS devices for an on-site IT technician.

WORKFLOW
1. discover_routers, then connect (omit `host` to use this PC's default gateway, or pass
   the IP of any reachable MikroTik). Never ask the user to type the router password in
   chat: leave `password` empty so a local popup appears on their computer.
   Right after connecting, read the "Technician PC" line that connect returns: it says
   whether the technician's PC is on the same network as the router (and gets its IP
   from the router's DHCP). Tell the user. If the customer asks to change that
   network's IP/subnet, warn BEFORE applying: the PC will lose the connection, and
   after applying it must release/renew its IP (Windows: ipconfig /release, then
   ipconfig /renew) to get an address in the new subnet, then reconnect(new_host=<new
   router IP>) and confirm_changes before the rollback timer runs out. Use
   rollback_minutes=10 for these changes, and make sure the LAN DHCP server/pool is
   moved to the new subnet too, or the renew will not get a valid address. In the
   panel, the same warning appears in the plan notes before 'Aplicar cambios'.
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

PANEL (Claude Desktop chat only)
- In Claude Desktop, the write tools, audit_security, wireguard_status, confirm_changes
  and rollback_now render an interactive panel in Spanish. A dry run shows an
  'Aplicar cambios' button; an applied change shows a rollback countdown with
  'Confirmar' / 'Revertir' buttons. The panel informs you (model context, prefixed
  '[Panel]') when the technician applies, confirms or reverts there: do NOT repeat
  that action. Keep replies short when the panel already shows the details.
- Claude Code has no panel: the same flow works in text.

ADDRESSES, SUBNETS AND KEYS: ALWAYS ASK THE USER
- Never invent or assume IP addresses, subnets, masks, DHCP ranges, VPN ports or
  endpoints. The tools have no default addresses: ask the user for each value.
- Users may give masks as /24 or 255.255.255.0 (e.g. '192.168.20.1 255.255.255.0').
  Call validate_network on what they gave (with the session name, to check overlaps)
  and explain the result (mask in both formats, usable range) before planning.
- This server never generates WireGuard keys. Ask the user for the remote peer's
  public key (in chat or the popup). Private and preshared keys are entered only in
  the local popup: leave those parameters empty and never ask for them in chat.

SITE-TO-SITE TUNNELS (docs/runbook-tunnels.md)
- Use tunnel_setup (one link at a time, one site at a time) and tunnel_verify. Hub = public IP;
  spokes initiate. iBGP with filters is the recommended routing; spokes must never reach
  each other (BGP filters + hub forward drop + allowed-address with only the hub's nets).
- If the other router is not reachable, leave remote_name empty: the tool returns and saves
  a CLI script for it. Later call tunnel_setup again with remote_public_key.
- Never confirm_changes until tunnel_verify passes (handshake, ping both ways, routing up,
  login to every router through the tunnel). Confirm on EVERY session touched.

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

# ---------------- MCP Apps panel ----------------
UI_URI = "ui://sos-microtik/panel.html"
UI_META = {"ui": {"resourceUri": UI_URI}, "ui/resourceUri": UI_URI}
_UI = threading.local()
_SECRET_ARGS = {"password", "private_key", "preshared_key"}


@mcp.resource(UI_URI, name="SOS MikroTik panel", mime_type="text/html;profile=mcp-app",
              description="Panel interactivo (español) para planes, cambios, auditoría y WireGuard",
              meta={"ui": {"prefersBorder": False}})
def panel_resource() -> str:
    return PANEL_HTML


def _ui_set(payload: dict) -> None:
    """Structured data for the panel (Claude Desktop); ignored by text-only clients."""
    _UI.payload = payload


def ui_tool(fn):
    """Register a tool that also renders the panel. The text result is unchanged
    for the model; structuredContent carries the data the panel draws."""
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        _UI.payload = None
        is_error = False
        try:
            text = str(fn(*args, **kwargs))
        except Exception as e:
            text, is_error = f"Error: {e}", True
        payload = dict(getattr(_UI, "payload", None) or {"view": "message"})
        payload.update({"text": text, "tool": fn.__name__, "session": kwargs.get("name", "router"),
                        "arguments": {k: v for k, v in kwargs.items() if k not in _SECRET_ARGS}})
        return CallToolResult(content=[TextContent(type="text", text=text)],
                              structuredContent=payload, isError=is_error)
    return mcp.tool(structured_output=False, meta=UI_META)(wrapper)

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


KEYRING_SERVICE = "sos-microtik-mcp"


def _cred_key(host: str, user: str) -> str:
    """Saved-password key: the gateway's MAC (so two customers that both use the same
    IP never share a password), falling back to the IP if the MAC is unknown."""
    import subprocess
    ident = host
    try:
        out = subprocess.run(["arp", "-a", host], capture_output=True, text=True, timeout=5).stdout
        m = re.search(rf"{re.escape(host)}\s+([0-9a-fA-F]{{2}}[-:][0-9a-fA-F]{{2}}[-:][0-9a-fA-F:-]{{11}})", out)
        if m:
            ident = m.group(1).upper().replace("-", ":")
    except Exception:
        pass
    return f"{user}@{ident}"


def _saved_password(key: str) -> str | None:
    try:
        import keyring
        return keyring.get_password(KEYRING_SERVICE, key)
    except Exception:
        return None


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


def _apply(name, commands, description, rollback_minutes=5, hide=(), fresh=True) -> tuple[str, bool]:
    """fresh=False: a follow-up step of the same change; keeps the backup and the
    rollback timer armed by the first step instead of re-taking them."""
    s = _session(name)
    folder = _site_folder("_changes", s["host"])
    (folder / "description.txt").write_text(description, encoding="utf-8")
    (folder / "commands.rsc").write_text("\n".join(commands), encoding="utf-8")
    if fresh:
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
    _ui_set({"view": "applied", "ok": ok, "description": description, "log": log,
             "rollback_minutes": rollback_minutes, "folder": str(folder),
             "deadline": (time.time() + rollback_minutes * 60) if rollback_minutes > 0 else None})
    return "\n".join(log) + tail + f"\nLog: {folder}", ok


def _plan(name, commands, description, dry_run, rollback_minutes, hide=(), notes="") -> str:
    if dry_run:
        _ui_set({"view": "plan", "description": description, "notes": notes,
                 "commands": [_redact(c, hide) for c in commands], "rollback_minutes": rollback_minutes})
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
    gw = _default_gateway()
    for info in found.values():
        info["is_default_gateway"] = info.get("ipv4") == gw
    return sorted(found.values(), key=lambda i: not i["is_default_gateway"])


def _default_gateway() -> str | None:
    """IPv4 default gateway of this PC's current network configuration (lowest-metric
    default route). The UDP connect() trick finds the active interface without sending."""
    import subprocess
    import sys
    try:
        if sys.platform == "win32":
            out = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | "
                 "Where-Object { $_.NextHop -ne '0.0.0.0' } | "
                 "Sort-Object { $_.RouteMetric + (Get-NetIPInterface -InterfaceIndex "
                 "$_.InterfaceIndex -AddressFamily IPv4).InterfaceMetric } | "
                 "Select-Object -First 1).NextHop"],
                capture_output=True, text=True, timeout=15).stdout.strip()
        elif sys.platform == "darwin":
            out = subprocess.run("route -n get default | awk '/gateway:/{print $2}'",
                                 shell=True, capture_output=True, text=True, timeout=10).stdout.strip()
        else:
            out = subprocess.run("ip -4 route show default | awk '{print $3; exit}'",
                                 shell=True, capture_output=True, text=True, timeout=10).stdout.strip()
        return str(ipaddress.IPv4Address(out.splitlines()[0].strip()))
    except Exception:
        return None


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
def connect(host: str | None = None, username: str = "admin", name: str = "router",
            port: int = 22, password: str | None = None,
            save_password: bool = False) -> str:
    """Open an SSH session to the router under `name`. `host` can be any reachable
    MikroTik (any IP/hostname); if empty, this PC's default gateway is used. Leave `password` empty so the
    user is prompted in a local popup (keeps it out of the conversation). A password
    saved earlier in the OS credential store is used automatically; set
    save_password=True (after the user agrees) to store the one typed in the popup.
    The default gateway is NOT always 192.168.88.1: never assume it, call
    discover_routers (lists devices, flags the gateway) or just omit `host`."""
    host = (host or "").strip() or _default_gateway()
    if not host:
        return "Could not determine this PC's default gateway. Pass `host` explicitly."
    key = _cred_key(host, username)
    from_store = False
    if password is None:
        password = _saved_password(key)
        from_store = password is not None
    if password is None:
        password = _popup_secret("MikroTik login", f"Password for {username}@{host}:")
    try:
        client = _open(host, username, port, password)
    except paramiko.AuthenticationException:
        if not from_store:
            raise
        forget_password(host, username)  # stale saved password: ask again
        password = _popup_secret("MikroTik login", f"Saved password rejected. Password for {username}@{host}:")
        client = _open(host, username, port, password)
        from_store = False
    saved = ""
    if save_password and not from_store:
        try:
            import keyring
            keyring.set_password(KEYRING_SERVICE, key, password)
            saved = "\nPassword saved in the OS credential store for this router."
        except Exception as e:
            saved = f"\nCould not save the password in the OS credential store: {e}"
    elif from_store:
        saved = "\nUsed the password saved in the OS credential store."
    if name in SESSIONS:
        SESSIONS[name]["client"].close()
    SESSIONS[name] = {"client": client, "host": host, "user": username,
                      "port": port, "password": password}
    return (f"Connected to {host} as '{name}'.{saved}\n" + _run(name, "/system identity print")
            + "\n\n" + _local_link(name)["text"])


@mcp.tool()
def forget_password(host: str | None = None, username: str = "admin") -> str:
    """Delete the router password saved in the OS credential store. `host` defaults
    to the current default gateway."""
    host = host or _default_gateway()
    if not host:
        return "Could not determine the router address."
    try:
        import keyring
        keyring.delete_password(KEYRING_SERVICE, _cred_key(host, username))
        return f"Saved password for {username}@{host} deleted."
    except Exception:
        return f"No saved password for {username}@{host}."


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

@ui_tool
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

    result = _plan(name, cmds, f"Configurar SSID '{ssid}' ({security}) en {', '.join(targets)}",
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

@ui_tool
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
    return _plan(name, C, f"Bridge ({mode}) con subred Wi-Fi {net}", dry_run,
                 rollback_minutes, notes="\n".join(notes))


# =====================================================================
# Security audit, hardening, firewall
# =====================================================================

SEV_ES = {"CRITICAL": "CRÍTICO", "HIGH": "ALTO", "MEDIUM": "MEDIO", "LOW": "BAJO", "INFO": "INFO"}


@ui_tool
def audit_security(name: str = "router", site: str | None = None) -> str:
    """Read-only security audit (report in Spanish): version, users, exposed services,
    firewall, DNS resolver, proxies, MAC access, SNMP, Wi-Fi encryption, IPv6 firewall,
    and compromise indicators (schedulers/scripts, socks/proxy, static DNS).
    Optionally saves the report to ~/mikrotik-sites/<site>/."""
    F: list[tuple[str, str, str]] = []

    def add(sev, finding, fix):
        F.append((sev, finding, fix))

    facts = _facts(name)
    ver = _version(name)
    wan = facts["interface_lists"].get("WAN", [])
    v = facts["version"]

    if ver < (6, 43):
        add("CRITICAL", f"RouterOS {v} es muy antiguo y tiene vulnerabilidades críticas conocidas "
                        "(p. ej. robo de credenciales vía Winbox).",
            "Actualizar de inmediato y luego cambiar todas las contraseñas.")
    elif ver[0] == 6:
        add("MEDIUM", f"RouterOS {v} (v6).", "Planificar la actualización a v7 estable.")
    else:
        add("INFO", f"RouterOS {v}.", "Revisar actualizaciones en System > Packages > Check For Updates.")

    users = _terse(name, "/user print terse")
    if any(u.get("name") == "admin" and not u["_disabled"] for u in users):
        add("MEDIUM", "El usuario por defecto 'admin' está activo.",
            "Crear un administrador con nombre propio y desactivar o eliminar 'admin'.")
    full = [u.get("name") for u in users if u.get("group") == "full" and not u["_disabled"]]
    add("INFO", f"Usuarios con permisos completos: {', '.join(full) or 'ninguno'}.",
        "Confirmar que todas las cuentas son conocidas.")

    for s in _terse(name, "/ip service print terse"):
        if s["_disabled"]:
            continue
        n, addr = s.get("name"), s.get("address", "")
        if n in ("telnet", "ftp"):
            add("HIGH", f"{n} habilitado (contraseñas sin cifrar).", f"/ip service disable {n}")
        elif n in ("www", "api"):
            add("MEDIUM", f"{n} habilitado (sin cifrar).", f"Deshabilitar {n} o usar la variante -ssl.")
        if not addr:
            add("LOW", f"El servicio {n} acepta conexiones desde cualquier dirección.",
                f"/ip service set {n} address=<subredes LAN/gestión>")

    if re.search(r"strong-crypto:\s*no", _try(name, "/ip ssh print")):
        add("LOW", "SSH strong-crypto deshabilitado.", "/ip ssh set strong-crypto=yes")

    rules = [r for r in _terse(name, "/ip firewall filter print terse") if not r["_dynamic"]]
    active = [r for r in rules if not r["_disabled"]]
    inp = [r for r in active if r.get("chain") == "input"]
    fwd = [r for r in active if r.get("chain") == "forward"]
    catchall_keys = {"chain", "action", "in-interface", "in-interface-list", "comment", "log", "log-prefix"}
    has_input_drop = any(r.get("action") == "drop" and set(k for k in r if not k.startswith("_")) <= catchall_keys
                         for r in inp)
    if not inp:
        add("CRITICAL", "No hay reglas de firewall en input: la administración del router podría "
                        "estar expuesta a Internet.", "Ejecutar firewall_baseline.")
    elif not has_input_drop:
        add("HIGH", "La cadena input no tiene una regla final de descarte (drop).",
            "Ejecutar firewall_baseline o agregar un drop final para lo que no venga de LAN.")
    if inp and not any("established" in r.get("connection-state", "") for r in inp):
        add("LOW", "La cadena input no acepta primero established/related.",
            "Agregar esa regla al inicio (mejora el rendimiento).")
    if wan and not any(r.get("action") == "drop" and (r.get("in-interface-list") == "WAN"
                                                      or r.get("in-interface") in wan) for r in fwd):
        add("HIGH", "La cadena forward no descarta conexiones nuevas desde WAN.", "Ejecutar firewall_baseline.")
    dis = [r for r in rules if r["_disabled"]]
    if dis:
        add("INFO", f"{len(dis)} regla(s) de firewall deshabilitada(s).", "Revisar y eliminar si no se usan.")
    if wan and not any(r.get("action") in ("masquerade", "src-nat")
                       for r in _terse(name, "/ip firewall nat print terse")):
        add("INFO", "No hay regla masquerade/src-nat.", "Los clientes LAN podrían no tener Internet; revisar NAT.")

    if re.search(r"allow-remote-requests:\s*yes", _try(name, "/ip dns print")) and not has_input_drop:
        add("HIGH", "DNS acepta consultas remotas sin firewall en input (resolver abierto).",
            "Agregar drop en input para WAN o deshabilitar allow-remote-requests.")
    static_dns = [d for d in _terse(name, "/ip dns static print terse") if not d["_dynamic"]]
    if static_dns:
        add("INFO", f"{len(static_dns)} entrada(s) DNS estática(s): "
                    + ", ".join(d.get("name", d.get("regexp", "?")) for d in static_dns[:10]),
            "Confirmar que ninguna redirige dominios populares (indicador de compromiso).")

    if re.search(r"enabled:\s*yes", _try(name, "/ip socks print")):
        add("HIGH", "Proxy SOCKS habilitado (común en routers comprometidos).", "/ip socks set enabled=no e investigar.")
    if re.search(r"enabled:\s*yes", _try(name, "/ip proxy print")):
        add("HIGH", "Web proxy habilitado (común en routers comprometidos).", "/ip proxy set enabled=no si no es intencional.")
    if re.search(r"enabled:\s*yes", _try(name, "/ip upnp print")):
        add("MEDIUM", "UPnP habilitado (los dispositivos LAN pueden abrir puertos).", "Deshabilitar salvo que se necesite.")
    if re.search(r"enabled:\s*yes", _try(name, "/tool bandwidth-server print")):
        add("LOW", "Servidor de bandwidth-test habilitado.", "/tool bandwidth-server set enabled=no")
    if re.search(r"enabled:\s*yes", _try(name, "/tool romon print")):
        add("INFO", "RoMON habilitado.", "Deshabilitar si no se usa.")
    if re.search(r"allowed-interface-list:\s*all", _try(name, "/tool mac-server print")):
        add("MEDIUM", "MAC-Telnet permitido en todas las interfaces.", "/tool mac-server set allowed-interface-list=LAN")
    if re.search(r"allowed-interface-list:\s*all", _try(name, "/tool mac-server mac-winbox print")):
        add("MEDIUM", "MAC-Winbox permitido en todas las interfaces.",
            "/tool mac-server mac-winbox set allowed-interface-list=LAN")
    if re.search(r"discover-interface-list:\s*all", _try(name, "/ip neighbor discovery-settings print")):
        add("LOW", "Descubrimiento de vecinos en todas las interfaces (incluida WAN).",
            "/ip neighbor discovery-settings set discover-interface-list=LAN")
    if re.search(r"enabled:\s*yes", _try(name, "/snmp print")):
        if any(c.get("name") == "public" for c in _terse(name, "/snmp community print terse")):
            add("MEDIUM", "SNMP habilitado con la comunidad 'public'.", "Cambiar la comunidad o deshabilitar SNMP.")

    for s in _terse(name, "/system scheduler print terse"):
        if s.get("name", "").startswith("mcp-"):
            continue
        ev = s.get("on-event", "")
        sev = "HIGH" if re.search(r"fetch|http|socks|proxy|import", ev, re.I) else "INFO"
        add(sev, f"La tarea programada '{s.get('name')}' ejecuta: {ev[:120]}", "Confirmar que es legítima.")
    for s in _terse(name, "/system script print terse"):
        sev = "HIGH" if re.search(r"fetch|socks|proxy", s.get("source", ""), re.I) else "INFO"
        add(sev, f"Existe el script '{s.get('name')}'.", "Revisar su contenido.")

    if facts["wifi_driver"] == "wireless":
        profiles = {p.get("name"): p for p in _terse(name, "/interface wireless security-profiles print terse")}
        for w in _terse(name, "/interface wireless print terse"):
            if w["_disabled"]:
                continue
            p = profiles.get(w.get("security-profile", "default"), {})
            mode, auth = p.get("mode", ""), p.get("authentication-types", "").split(",")
            if mode == "none":
                add("HIGH", f"La red Wi-Fi {w.get('name')} ({w.get('ssid')}) está ABIERTA.", "Ejecutar configure_wifi.")
            elif mode.startswith("static-keys"):
                add("HIGH", f"La red Wi-Fi {w.get('name')} usa WEP.", "Ejecutar configure_wifi (WPA2).")
            elif "wpa-psk" in auth:
                add("MEDIUM", f"La red Wi-Fi {w.get('name')} permite WPA1.", "Usar solo WPA2.")
            if w.get("wps-mode") not in (None, "", "disabled"):
                add("LOW", f"WPS habilitado en {w.get('name')}.", "Deshabilitar WPS.")
    elif facts["wifi_driver"] in ("wifi", "wifiwave2"):
        for w in _terse(name, f"/interface {facts['wifi_driver']} print terse"):
            if w["_disabled"]:
                continue
            auth = w.get("security.authentication-types", "")
            if auth and "wpa3" not in auth:
                add("INFO", f"La red Wi-Fi {w.get('name')} usa solo WPA2; WPA3 está disponible.",
                    "configure_wifi security='wpa2-wpa3'.")

    v6addr = [a for a in _terse(name, "/ipv6 address print terse")
              if not a["_disabled"] and not a.get("address", "").lower().startswith("fe80")]
    if v6addr and not any(r.get("chain") == "input" for r in _terse(name, "/ipv6 firewall filter print terse")):
        add("HIGH", "IPv6 está activo pero no hay firewall IPv6 en input.", "Agregar un firewall IPv6 (estilo defconf).")

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    F.sort(key=lambda x: order[x[0]])
    counts = {k: sum(1 for f in F if f[0] == k) for k in order}
    host = _session(name)["host"]
    report = (f"Auditoría de seguridad: {host} | {facts['board']} | RouterOS {v}\n"
              + " ".join(f"{SEV_ES[k]}:{c}" for k, c in counts.items()) + "\n\n"
              + "\n".join(f"[{SEV_ES[s]}] {f}\n    Corrección: {x}" for s, f, x in F)
              + "\n\nNota: la fortaleza de las contraseñas no se puede verificar remotamente.")
    saved = None
    if site:
        folder = _site_folder(site, "audit")
        (folder / "security_audit.txt").write_text(report, encoding="utf-8")
        saved = str(folder)
        report += f"\nGuardado en {folder}"
    _ui_set({"view": "audit", "host": host, "board": facts["board"], "version": v,
             "counts": counts, "saved": saved,
             "findings": [{"sev": s, "finding": f, "fix": x} for s, f, x in F]})
    return report


@ui_tool
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
    return _plan(name, C, "Endurecer servicios del router", dry_run, rollback_minutes, notes=notes)


@ui_tool
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
    return _plan(name, C, "Firewall base IPv4", dry_run, rollback_minutes, notes=notes)


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


@ui_tool
def wireguard_status(name: str = "router") -> str:
    """Show WireGuard interfaces (address with mask in both formats), peers
    (handshake, traffic, endpoints) and whether the firewall allows each port.
    Secrets are masked."""
    _require_v7(name)
    wgs = _wg_interfaces(name)
    host = _session(name)["host"]
    if not wgs:
        _ui_set({"view": "wireguard", "host": host, "interfaces": []})
        return "No WireGuard interfaces configured."
    peers = _terse(name, "/interface wireguard peers print terse")
    rules = [r for r in _terse(name, "/ip firewall filter print terse") if not r["_disabled"]]
    lists = _facts(name)["interface_lists"]
    data, out = [], []
    for n, w in wgs.items():
        port = w.get("listen-port", "?")
        addrs = _wg_addrs(name, n)
        fw_ok = any(r.get("chain") == "input" and r.get("action") == "accept" and
                    r.get("protocol") == "udp" and port in r.get("dst-port", "").split(",")
                    for r in rules)
        item = {"name": n, "disabled": w["_disabled"], "port": port,
                "addresses": [{"cidr": str(a), "mask": str(a.netmask)} for a in addrs],
                "public_key": w.get("public-key"), "firewall_ok": fw_ok,
                "lists": [l for l, m in lists.items() if n in m], "peers": []}
        for p in [p for p in peers if p.get("interface") == n]:
            item["peers"].append({
                "comment": p.get("comment", ""), "disabled": p["_disabled"],
                "public_key": p.get("public-key", ""), "allowed_address": p.get("allowed-address", ""),
                "endpoint": p.get("current-endpoint-address") or p.get("endpoint-address") or "",
                "last_handshake": p.get("last-handshake", ""), "rx": p.get("rx", ""), "tx": p.get("tx", ""),
                "keepalive": p.get("persistent-keepalive", ""), "psk": bool(p.get("preshared-key"))})
        data.append(item)
        out.append(f"Interface {n}{' (DISABLED)' if item['disabled'] else ''}: port {port}, address "
                   f"{', '.join(a['cidr'] + ' (mask ' + a['mask'] + ')' for a in item['addresses']) or 'NONE'}, "
                   f"public-key {item['public_key']}, interface lists {item['lists'] or 'none'}, "
                   f"firewall allows port: {'yes' if fw_ok else 'NO / not found'}")
        for p in item["peers"]:
            out.append(f"  peer '{p['comment']}'{' (DISABLED)' if p['disabled'] else ''}: "
                       f"key {p['public_key'][:12]}..., allowed {p['allowed_address']}, "
                       f"endpoint {p['endpoint'] or '-'}, last handshake {p['last_handshake'] or 'never'}, "
                       f"rx {p['rx'] or '?'} tx {p['tx'] or '?'}, keepalive {p['keepalive'] or '-'}, "
                       f"preshared key {'yes' if p['psk'] else 'no'}")
    _ui_set({"view": "wireguard", "host": host, "interfaces": data})
    return "\n".join(out)


@ui_tool
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
    result = _plan(name, C, f"Interfaz WireGuard {wg_name} {cidr}, puerto {listen_port}",
                   dry_run, rollback_minutes, hide=[pk] if pk else [], notes=notes)
    if not dry_run:
        rk = _wg_interfaces(name).get(wg_name, {}).get("public-key")
        if rk:
            result += f"\nRouter public key for {wg_name} (give this to the remote peers): {rk}"
            if pk and _pub_from_priv(pk) != rk:
                result += "\nWARNING: router's public key doesn't match the entered private key."
    return result


@ui_tool
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
        return _plan(name, [cmd], f"Agregar peer WireGuard '{label}' en {interface}", True,
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
    text, ok = _apply(name, [build(pub, psk)], f"Agregar peer WireGuard '{label}' en {interface}",
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


@ui_tool
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
    return _plan(name, C, f"Modificar peer WireGuard '{peer[:20]}' en {interface}", dry_run,
                 rollback_minutes, hide=hide, notes="\n".join(notes))


@ui_tool
def wireguard_remove_peer(interface: str, peer: str, name: str = "router",
                          dry_run: bool = True, rollback_minutes: int = 5) -> str:
    """Remove a WireGuard peer, identified by its public key or comment."""
    _require_v7(name)
    C = [f"/interface wireguard peers remove {_peer_find(interface, peer)}"]
    return _plan(name, C, f"Eliminar peer WireGuard '{peer[:20]}' de {interface}", dry_run, rollback_minutes)


# =====================================================================
# Site-to-site tunnels: WireGuard + iBGP / OSPF / static (hub and spokes).
# Design: docs/runbook-tunnels.md. One WireGuard interface per spoke on the hub.
# =====================================================================

def _bgp_filter(chain: str, nets: list) -> list[str]:
    C = [f'/routing filter rule remove [find chain={q(chain)}]']
    for n in nets:
        C.append(f'/routing filter rule add chain={q(chain)} '
                 f'rule="if (dst in {n} && dst-len == {n.prefixlen}) {{ accept }}"')
    C.append(f'/routing filter rule add chain={q(chain)} rule="reject"')
    return C


def _tunnel_tag(wg: str) -> str:
    return f"mcp-tunnel: {wg}"


def _tunnel_side(s: dict) -> list[str]:
    """Commands for ONE router of a link (interface, lists, firewall, routing).
    The WireGuard peer is separate (_tunnel_peer) because it needs the other side's key."""
    wg, role, tag = s["wg"], s["role"], _tunnel_tag(s["wg"])
    lst = "SPOKES" if role == "hub" else "HUB"
    ip, peer_ip = s["cidr"].split("/")[0], s["peer_ip"]
    C = [f':if ([:len [/interface wireguard find name={q(wg)}]] = 0) '
         f'do={{/interface wireguard add name={q(wg)} listen-port={s["port"]}}} '
         f'else={{/interface wireguard set [find name={q(wg)}] listen-port={s["port"]}}}',
         f'/ip address remove [find interface={q(wg)} address!={q(s["cidr"])}]',
         f':if ([:len [/ip address find interface={q(wg)} address={q(s["cidr"])}]] = 0) '
         f'do={{/ip address add address={q(s["cidr"])} interface={q(wg)}}}',
         _ensure_list(lst), _ensure_member(lst, wg)]

    rules = []  # (suffix, rule args)
    if role == "hub":
        rules.append(("udp", f'chain=input action=accept protocol=udp dst-port={s["port"]}'))
        if s["isolate"]:
            rules.append(("isolate", 'chain=forward action=drop in-interface-list=SPOKES '
                                     'out-interface-list=SPOKES'))
        if s["block_initiated"]:
            rules.append(("no-initiate", 'chain=forward action=drop connection-state=new '
                                         'in-interface-list=SPOKES'))
    rules.append(("icmp", f'chain=input action=accept protocol=icmp in-interface-list={lst}'))
    if s["routing"] == "ibgp":
        rules.append(("bgp", f'chain=input action=accept protocol=tcp dst-port=179 in-interface-list={lst}'))
    elif s["routing"] == "ospf":
        rules.append(("ospf", f'chain=input action=accept protocol=ospf in-interface-list={lst}'))
    if s["mgmt"]:
        al = f"mcp-mgmt-{wg}"
        C.append(f'/ip firewall address-list remove [find list={q(al)}]')
        for n in [ipaddress.ip_network(peer_ip + "/32")] + s["peer_lans"]:
            C.append(f'/ip firewall address-list add list={q(al)} address={n}')
        rules.append(("mgmt", f'chain=input action=accept protocol=tcp dst-port=22,8291 '
                              f'in-interface-list={lst} src-address-list={al}'))
    for suffix, args in rules:
        comment = f"{tag} {suffix}"
        C.append(f'/ip firewall filter remove [find comment={q(comment)}]')
        C.append(_top_filter_rule(f'{args} comment={q(comment)}'))

    if s["routing"] == "ibgp":
        in_c, out_c, conn = f"mcp-bgp-in-{wg}", f"mcp-bgp-out-{wg}", f"bgp-{wg}"
        C += _bgp_filter(out_c, s["lans"]) + _bgp_filter(in_c, s["peer_lans"])
        if s["ver"] >= (7, 20):
            C.append(f':if ([:len [/routing bgp instance find name=bgp-main]] = 0) do={{'
                     f'/routing bgp instance add name=bgp-main as={s["asn"]} router-id={ip}}}')
            base = " instance=bgp-main"
        else:
            base = f" as={s['asn']} router-id={ip}"
        C.append(f'/routing bgp connection remove [find name={q(conn)}]')
        C.append(f'/routing bgp connection add name={q(conn)}{base} local.role=ibgp '
                 f'local.address={ip} remote.address={peer_ip} remote.as={s["asn"]} '
                 f'input.filter={q(in_c)} output.filter-chain={q(out_c)} output.redistribute=connected')
    elif s["routing"] == "ospf":
        c = f"{tag} ospf"
        C += [f':if ([:len [/routing ospf instance find name=mcp-ospf]] = 0) '
              f'do={{/routing ospf instance add name=mcp-ospf version=2 router-id={ip}}}',
              f':if ([:len [/routing ospf area find name=mcp-backbone]] = 0) '
              f'do={{/routing ospf area add name=mcp-backbone area-id=0.0.0.0 instance=mcp-ospf}}',
              f'/routing ospf interface-template remove [find comment={q(c)}]',
              f'/routing ospf interface-template add area=mcp-backbone interfaces={q(wg)} '
              f'type=ptp comment={q(c)}']
        C += [f'/routing ospf interface-template add area=mcp-backbone networks={n} passive '
              f'comment={q(c)}' for n in s["lans"]]
    else:  # static
        c = f"{tag} route"
        C.append(f'/ip route remove [find comment={q(c)}]')
        C += [f'/ip route add dst-address={n} gateway={peer_ip} comment={q(c)}' for n in s["peer_lans"]]
    return C


def _tunnel_peer(s: dict, pub: str) -> list[str]:
    """The peer allows ONLY the other side's tunnel IP and LANs (never 0.0.0.0/0)."""
    wg, tag = s["wg"], _tunnel_tag(s["wg"])
    allowed = ",".join([f'{s["peer_ip"]}/32'] + [str(n) for n in s["peer_lans"]])
    c = (f'/interface wireguard peers add interface={q(wg)} public-key={q(pub)} '
         f'allowed-address={q(allowed)} comment={q(tag)}')
    if s["endpoint"]:
        c += f' endpoint-address={q(s["endpoint"][0])} endpoint-port={s["endpoint"][1]}'
    if s["keepalive"]:
        c += f' persistent-keepalive={s["keepalive"]}s'
    return [f'/interface wireguard peers remove [find interface={q(wg)} comment={q(tag)}]', c]


@ui_tool
def tunnel_setup(
        name: str, role: str, wg_name: str, local_tunnel_ip: str, remote_tunnel_ip: str,
        listen_port: int, local_lans: str, remote_lans: str, routing: str,
        hub_endpoint: str | None = None, remote_name: str | None = None,
        remote_public_key: str | None = None, remote_wg_name: str | None = None,
        as_number: int = 65000, remote_routeros_version: str | None = None,
        allow_management: bool = True, isolate_spokes: bool = True,
        block_spoke_initiated: bool = False, site: str | None = None,
        dry_run: bool = True, rollback_minutes: int = 10) -> str:
    """Configure ONE site-to-site link (WireGuard + dynamic routing) between the connected
    router `name` and a second router. For 2 sites one acts as hub; for more sites call it
    once per spoke on the hub (one wg interface + UDP port + /30 per spoke).
    Design and the isolation layers: docs/runbook-tunnels.md. ALL values come from the user.

    role: role of THIS router: 'hub' (public IP, listens) or 'spoke' (initiates, keepalive 25).
    wg_name: WireGuard interface on this router (e.g. wg-of01 on the hub, wg-hub on a spoke).
    local_tunnel_ip: this router's tunnel IP with mask ('10.255.0.5/30'); remote_tunnel_ip:
      the other side's IP (no mask), in the same subnet.
    listen_port: UDP port (the hub's, unique per spoke). hub_endpoint: the hub's public
      'host:port' (required if role='spoke'; also needed to build the spoke's script).
    local_lans / remote_lans: comma-separated LAN subnets of each side. Only these are
      advertised/allowed. They must not overlap each other or the tunnel net.
    routing: 'ibgp' (recommended: filters isolate spokes, AS=as_number, no route-reflector),
      'ospf' (no route filtering: spokes isolation then relies on firewall + allowed-address)
      or 'static'.
    remote_name: session name of the other router if it is reachable (both are configured
      and keys exchanged automatically). If it is NOT reachable, leave empty: a CLI script
      for the other router is generated and saved; run it there, read its public key and call
      this tool again with remote_public_key to add the peer here.
    remote_public_key: the other router's PUBLIC key (never private keys). remote_wg_name /
      remote_routeros_version: only for the generated script (default same name / >= 7.20).
    allow_management: accept SSH/Winbox from the other side's tunnel IP and LANs only
      (needed by tunnel_verify to log in to every router through the tunnel).
    isolate_spokes (hub): drop forward between spokes. block_spoke_initiated (hub): spokes
      cannot start connections towards the hub side. Ask the user about the latter.
    Verify afterwards with tunnel_verify, then confirm_changes on EVERY session touched."""
    _require_v7(name)
    if role not in ("hub", "spoke"):
        return "role must be 'hub' or 'spoke'. Ask the user which role this router has."
    if routing not in ("ibgp", "ospf", "static"):
        return "routing must be 'ibgp', 'ospf' or 'static'. Ask the user."
    errors, warnings = [], []
    res, err = _check(local_tunnel_ip, "interface", "local_tunnel_ip")
    if err or len(res) != 1:
        return err or "Give exactly one local_tunnel_ip."
    lt = res[0]
    tnet = ipaddress.ip_network(lt["network"])
    try:
        rip = ipaddress.ip_address(remote_tunnel_ip.strip().split("/")[0])
    except ValueError:
        return f"remote_tunnel_ip '{remote_tunnel_ip}' is not a valid IP."
    if rip not in tnet or str(rip) == lt["ip"]:
        errors.append(f"remote_tunnel_ip {rip} must be a different address inside {tnet}.")
    lr, e1 = _check(local_lans, "network", "local_lans")
    rr, e2 = _check(remote_lans, "network", "remote_lans")
    if e1 or e2:
        return e1 or e2
    lans = [ipaddress.ip_network(r["cidr"]) for r in lr]
    rlans = [ipaddress.ip_network(r["cidr"]) for r in rr]
    for a in lans:
        for b in rlans + [tnet]:
            if a.overlaps(b):
                errors.append(f"{a} overlaps {b}. Never connect overlapping networks: renumber one.")
    if not 1 <= listen_port <= 65535:
        errors.append("listen_port must be 1-65535.")
    ov = _overlaps(name, tnet, exclude_interface=wg_name)
    if ov:
        errors.append(f"Tunnel network {tnet} overlaps existing subnet(s): {', '.join(ov)}.")
    for n, w in _wg_interfaces(name).items():
        if n != wg_name and w.get("listen-port") == str(listen_port):
            errors.append(f"UDP {listen_port} is already used by WireGuard interface {n}.")
    connected = [a.network for a, _ in _router_networks(name)]
    for n in lans:
        if n not in connected:
            warnings.append(f"{n} is not a directly connected network of this router: "
                            "it won't be advertised (output.redistribute=connected).")
    ep = None
    if hub_endpoint:
        try:
            ep = _parse_endpoint(hub_endpoint, default_port=listen_port)
        except ValueError as e:
            errors.append(str(e))
    elif role == "spoke":
        errors.append("hub_endpoint (the hub's public IP/hostname) is required for a spoke. Ask the user.")
    if remote_public_key and _key_error(remote_public_key, "remote_public_key"):
        errors.append(_key_error(remote_public_key, "remote_public_key") or "")
    if remote_name:
        try:
            _require_v7(remote_name)
        except RuntimeError as e:
            errors.append(f"{remote_name}: {e}")
    if errors:
        return "Cannot continue:\n- " + "\n- ".join(errors) + "\nAsk the user to correct these values."

    ver_l = _version(name)
    if remote_name:
        ver_r = _version(remote_name)
    elif remote_routeros_version and re.fullmatch(r"\d+(\.\d+)+", remote_routeros_version):
        ver_r = tuple(int(x) for x in remote_routeros_version.split("."))
    else:
        ver_r = (7, 20)
        if routing == "ibgp":
            warnings.append("Remote RouterOS version unknown: script uses the 7.20+ BGP syntax "
                            "('/routing bgp instance'). Pass remote_routeros_version if older.")
    other = "spoke" if role == "hub" else "hub"
    common = dict(routing=routing, asn=as_number, isolate=isolate_spokes,
                  block_initiated=block_spoke_initiated, mgmt=allow_management)
    local = dict(common, role=role, wg=wg_name, cidr=lt["cidr"], peer_ip=str(rip), port=listen_port,
                 lans=lans, peer_lans=rlans, endpoint=ep if role == "spoke" else None,
                 keepalive=25 if role == "spoke" else None, ver=ver_l)
    remote = dict(common, role=other, wg=remote_wg_name or wg_name,
                  cidr=f"{rip}/{tnet.prefixlen}", peer_ip=lt["ip"], port=listen_port,
                  lans=rlans, peer_lans=lans,
                  endpoint=ep if other == "spoke" else None,
                  keepalive=25 if other == "spoke" else None, ver=ver_r)
    if other == "spoke" and not ep:
        remote["endpoint"] = ("<HUB_PUBLIC_IP>", listen_port)
        warnings.append("hub_endpoint missing: the spoke script has a <HUB_PUBLIC_IP> placeholder. Ask the user.")
    if allow_management:
        for r in [name] + ([remote_name] if remote_name else []):
            svc = [x for x in _terse(r, "/ip service print terse")
                   if x.get("name") in ("ssh", "winbox") and x.get("address")]
            if svc:
                warnings.append(f"{r}: SSH/Winbox have available-from restrictions "
                                f"({', '.join(x['name'] + '=' + x['address'] for x in svc)}). Add the "
                                "other side's LANs there too (keep the local LAN) or logins through the tunnel fail.")

    l_cmds, r_cmds = _tunnel_side(local), _tunnel_side(remote)
    desc = f"Tunel {routing} {wg_name}: {lt['cidr']} <-> {rip} ({role})"
    notes = ("Layers: " + ("iBGP filters (own LANs out, peer LANs in), " if routing == "ibgp" else "")
             + ("hub drops spoke<->spoke forward, " if role == "hub" and isolate_spokes else "")
             + "peer allowed-address = peer tunnel IP + peer LANs only.\n"
             + (f"Remote router '{remote_name}' is connected: both sides will be configured and keys exchanged.\n"
                if remote_name else
                "Remote router is NOT connected: a CLI script for it will be generated.\n")
             + ("Warnings:\n- " + "\n- ".join(warnings) if warnings else ""))

    if dry_run:
        def peer_preview(side, pub):
            return _tunnel_peer(side, pub)[1]
        rp = peer_preview(local, remote_public_key or "<remote public key>")
        lp = peer_preview(remote, "<this router's public key>")
        all_cmds = [f"# {name}"] + l_cmds + [rp] + \
                   ([f"# {remote_name}"] if remote_name else ["# SCRIPT for the remote router"]) + r_cmds + [lp]
        _ui_set({"view": "plan", "description": desc, "notes": notes, "commands": all_cmds,
                 "rollback_minutes": rollback_minutes})
        return (f"DRY RUN: nothing was changed.\n\nPlan: {desc}\n\nNotes:\n{notes}\n\n"
                f"THIS router ({name}):\n" + "\n".join(f"  {c}" for c in l_cmds + [rp])
                + f"\n\n{'REMOTE router ' + remote_name if remote_name else 'REMOTE router (script, not reachable)'}:\n"
                + "\n".join(f"  {c}" for c in r_cmds + [lp])
                + "\n\nExplain to the user. After approval call again with dry_run=False.")

    out = []
    text, ok = _apply(name, l_cmds, desc, rollback_minutes)
    out.append(f"== {name} ==\n{text}")
    if not ok:
        return "\n".join(out)
    local_pub = _wg_interfaces(name).get(wg_name, {}).get("public-key", "")
    remote_pub = remote_public_key
    sessions = [name]
    if remote_name:
        text, ok = _apply(remote_name, r_cmds, desc, rollback_minutes)
        out.append(f"== {remote_name} ==\n{text}")
        if not ok:
            return "\n".join(out) + f"\n{name} was already changed: rollback_now on it if you stop here."
        remote_pub = _wg_interfaces(remote_name).get(remote["wg"], {}).get("public-key", "")
        sessions.append(remote_name)
        text, ok = _apply(remote_name, _tunnel_peer(remote, local_pub)[0:2], desc + " (peer)",
                          rollback_minutes, fresh=False)
        out.append(f"== {remote_name} peer ==\n{text}")
    if remote_pub:
        text, ok2 = _apply(name, _tunnel_peer(local, remote_pub), desc + " (peer)",
                           rollback_minutes, fresh=False)
        out.append(f"== {name} peer ==\n{text}")
    else:
        out.append(f"Peer on {name} NOT added yet: the remote public key is unknown.")
    if not remote_name:
        script = "\n".join(r_cmds + _tunnel_peer(remote, local_pub))
        folder = _site_folder(site or _session(name)["host"], "tunnels")
        safe = re.sub(r"[^\w.-]", "_", remote["wg"])
        f = folder / f"remote-{safe}.rsc"
        f.write_text(script, encoding="utf-8")
        out.append(f"\nCLI SCRIPT for the remote router ({f}). Paste it in its terminal "
                   f"(or /import), then read its key with `/interface wireguard print "
                   f"where name={remote['wg']}` and call tunnel_setup again with "
                   f"remote_public_key=<that key>:\n\n{script}")
    out.append(f"\nPublic key of {name}/{wg_name}: {local_pub}\n"
               f"Next: tunnel_verify, then confirm_changes on: {', '.join(sessions)}.")
    return "\n".join(out)


def _ping(name: str, dst: str, src: str | None = None, count: int = 4) -> int:
    out = _run(name, f"/ping {dst} count={count}" + (f" src-address={src}" if src else ""), 40)
    m = re.findall(r"received=(\d+)", out)
    return int(m[-1]) if m else 0


def _handshake_age(text: str) -> int | None:
    m = re.fullmatch(r"(?:(\d+)w)?(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?", (text or "").strip())
    if not m or not any(m.groups()):
        return None
    w, d, h, mi, sec = (int(x or 0) for x in m.groups())
    return ((w * 7 + d) * 24 + h) * 3600 + mi * 60 + sec


def _link_checks(name: str, wg: str, peer_ip: str, my_ip: str, routing: str,
                 peer_lans: list[str]) -> list[tuple[str, bool, str]]:
    """Checks run on one router of the link, against the other one."""
    R = []
    peers = [p for p in _terse(name, "/interface wireguard peers print terse") if p.get("interface") == wg]
    age = _handshake_age(peers[0].get("last-handshake", "")) if peers else None
    R.append((f"[{name}] WireGuard handshake on {wg}", age is not None and age <= 180,
              "no peer" if not peers else (f"{age}s ago" if age is not None else "never")))
    got = _ping(name, peer_ip, src=my_ip)
    R.append((f"[{name}] ping {peer_ip} through the tunnel", got > 0, f"{got}/4 replies"))
    if routing == "ibgp":
        rows = _terse(name, "/routing bgp session print terse")
        ok = any(r.get("remote.address") == peer_ip and
                 (r.get("established") in ("true", "yes") or "E" in r["_flags"]) for r in rows)
        R.append((f"[{name}] BGP session with {peer_ip} established", ok, "ok" if ok else "not established"))
    elif routing == "ospf":
        rows = _terse(name, "/routing ospf neighbor print terse")
        ok = any(r.get("address") == peer_ip and r.get("state") == "Full" for r in rows)
        R.append((f"[{name}] OSPF neighbor {peer_ip} Full", ok, "ok" if ok else "not Full"))
    for lan in peer_lans:
        rows = _terse(name, f"/ip route print terse where dst-address={lan}")
        ok = any(not r["_disabled"] and "A" in r["_flags"] for r in rows)
        R.append((f"[{name}] active route to {lan}", ok, "ok" if ok else "missing"))
    return R


@ui_tool
def tunnel_verify(name: str, wg_name: str, remote_tunnel_ip: str, routing: str,
                  local_lans: str, remote_lans: str, remote_name: str | None = None,
                  remote_user: str = "admin", remote_password: str | None = None,
                  isolation_test_ip: str | None = None, isolation_from: str = "remote") -> str:
    """Verify a tunnel BEFORE confirm_changes. Checks on this router and on the remote one:
    WireGuard handshake, ping both ways across the tunnel (=> both firewalls accept the
    traffic), BGP established / OSPF Full, active routes to the other side's LANs, and a
    real SSH LOGIN to the remote router through its tunnel IP from this PC.
    If remote_name (a session) is empty, the login through the tunnel is also used to run
    the remote-side checks. Leave remote_password empty (saved or local popup).
    isolation_test_ip: an IP of ANOTHER spoke's LAN; pinged from the spoke
    (isolation_from='remote' or 'local'): it must NOT answer.
    Returns PASS/FAIL per check and whether it is safe to confirm_changes."""
    my = _wg_addrs(name, wg_name)
    if not my:
        return f"{wg_name} has no IP on {name}."
    my_ip = str(my[0].ip)
    lres, _ = _check(local_lans, "network", "local_lans")
    rres, _ = _check(remote_lans, "network", "remote_lans")
    llans, rlans = [r["cidr"] for r in lres], [r["cidr"] for r in rres]
    R = _link_checks(name, wg_name, remote_tunnel_ip, my_ip, routing, rlans)

    tmp, client = None, None
    key = f"{remote_user}@{remote_tunnel_ip}"
    try:
        socket.create_connection((remote_tunnel_ip, 22), timeout=6).close()
        reach = True
    except OSError as e:
        reach = False
        R.append((f"SSH port 22 of {remote_tunnel_ip} reachable from this PC", False,
                  f"{e}. Check the route from this PC, allow_management and the remote firewall input"))
    if reach:
        pw = remote_password or _saved_password(key) or \
            _popup_secret("MikroTik login", f"Password for {remote_user}@{remote_tunnel_ip} (via tunnel):")
        try:
            client = _open(remote_tunnel_ip, remote_user, 22, pw)
            R.append((f"Login to {remote_tunnel_ip} through the tunnel", True, "ok"))
        except Exception as e:
            R.append((f"Login to {remote_tunnel_ip} through the tunnel", False, str(e)))
    rname = remote_name
    if not rname and client:
        tmp = rname = f"_verify-{wg_name}"
        SESSIONS[tmp] = {"client": client, "host": remote_tunnel_ip, "user": remote_user,
                         "port": 22, "password": pw}
    try:
        if rname:
            rwg = next((i for a, i in _router_networks(rname) if str(a.ip) == remote_tunnel_ip), None)
            if rwg is None:
                R.append((f"[{rname}] interface holding {remote_tunnel_ip}", False, "not found"))
            else:
                R += _link_checks(rname, rwg, my_ip, remote_tunnel_ip, routing, llans)
        else:
            R.append(("Checks on the remote router", False, "no session and no login: cannot check its side"))
        if isolation_test_ip:
            who = rname if isolation_from == "remote" else name
            if who:
                got = _ping(who, isolation_test_ip)
                R.append((f"[{who}] ISOLATION: {isolation_test_ip} must NOT answer", got == 0,
                          "isolated" if got == 0 else f"{got}/4 replies: SECURITY INCIDENT, do not confirm"))
    finally:
        if tmp:
            SESSIONS.pop(tmp, None)
        if client:
            client.close()
    lines = [f"{'PASS' if ok else 'FAIL'}  {label}: {detail}" for label, ok, detail in R]
    bad = [label for label, ok, _ in R if not ok]
    _ui_set({"view": "message"})
    verdict = ("ALL CHECKS PASSED. Ask the user to confirm their access, then confirm_changes on every "
               "session of this tunnel." if not bad else
               "NOT SAFE TO CONFIRM. Failed: " + "; ".join(bad) + ". Do not confirm; fix or rollback_now. "
               "See docs/runbook-tunnels.md (section 'Problemas comunes').")
    return "\n".join(lines) + "\n\n" + verdict


# =====================================================================
# generic changes + commit/rollback
# =====================================================================

@ui_tool
def apply_changes(commands: list[str], description: str, name: str = "router",
                  rollback_minutes: int = 5, dry_run: bool = True) -> str:
    """Apply arbitrary RouterOS commands (one per list item) when no dedicated tool
    fits. Same safety net: backup + rollback timer + stop on first error."""
    return _plan(name, commands, description, dry_run, rollback_minutes)


@ui_tool
def confirm_changes(name: str = "router") -> str:
    """Disarm the rollback after verifying the change works; saves the new config locally."""
    s = _session(name)
    _run(name, f"/system scheduler remove [find name={ROLLBACK_SCHED}]")
    still = _run(name, f"/system scheduler print where name={ROLLBACK_SCHED}")
    folder = _site_folder("_changes", s["host"])
    (folder / "after_confirmed.rsc").write_text(_run(name, "/export show-sensitive terse", 90),
                                                encoding="utf-8")
    _ui_set({"view": "confirmed"})
    if ROLLBACK_SCHED in still:
        return "WARNING: rollback scheduler still present. Check /system scheduler."
    return f"Changes confirmed, rollback disarmed. Config saved to {folder}"


@ui_tool
def rollback_now(name: str = "router") -> str:
    """Immediately restore the pre-change backup. The router REBOOTS."""
    try:
        _run(name, f"/system scheduler remove [find name={ROLLBACK_SCHED}]")
        _run(name, f'/system backup load name={BACKUP_NAME} password=""', timeout=15)
    except Exception:
        pass
    _ui_set({"view": "rolledback"})
    return "Restore issued; router is rebooting. Reconnect in 1-2 minutes."


def main() -> None:
    """Entry point for the `sos-microtik-mcp` command."""
    mcp.run()


if __name__ == "__main__":
    main()

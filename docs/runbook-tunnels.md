# Runbook: túneles entre sitios con `tunnel_setup` y `tunnel_verify`

Basado en el runbook hub-and-spoke WireGuard + iBGP. Este documento describe cómo lo ejecutan las herramientas `tunnel_setup` y `tunnel_verify` del conector, y qué hacer cuando el otro router **no está disponible**.

## 1. Diseño

- El **hub** tiene IP pública y escucha. Cada **spoke** (oficina) inicia el túnel hacia el hub con `persistent-keepalive` de 25 s.
- **Un túnel WireGuard por spoke** en el hub (`wg-ofNN`), con una red /30 propia y un puerto UDP propio. Con solo dos sitios, uno hace de hub.
- El hub aprende las LANs de todos los spokes. Cada spoke solo aprende las LANs del hub. **Un spoke nunca llega a otro.**
- Solo se anuncian las LANs indicadas (`local_lans`): nunca el WAN, los túneles ni la ruta por defecto.

Aislamiento entre spokes, tres capas (con `routing="ibgp"` están las tres):

1. **Rutas:** iBGP sin route-reflector; filtros `mcp-bgp-out-<wg>` (solo la LAN propia) y `mcp-bgp-in-<wg>` (solo las LANs exactas del otro lado).
2. **Firewall del hub:** `forward` descartado entre interfaces de la lista `SPOKES`.
3. **WireGuard:** el `allowed-address` del peer contiene solo la IP de túnel del otro lado y sus LANs. Nunca `0.0.0.0/0`.

> OSPF (`routing="ospf"`) anuncia por interfaz, sin filtros de ruta: el aislamiento queda solo en las capas 2 y 3. Para redes con spokes se recomienda iBGP. `routing="static"` crea rutas estáticas hacia las LANs del otro lado.

## 2. Reglas para el agente

1. Todos los valores (IPs de túnel, puertos, LANs, endpoint del hub, AS) vienen del usuario o de su CSV. Si falta alguno, se detiene y lo pide.
2. Nunca contraseñas ni claves privadas en el chat. `connect` abre una ventana local y la contraseña puede guardarse en el almacén de credenciales del sistema (`save_password=true`). Las claves privadas de WireGuard las crea el router y no salen de él; solo se intercambian claves **públicas**.
3. Todo empieza en dry run. Se explica el plan y se espera aprobación.
4. **No se ejecuta `confirm_changes` hasta que `tunnel_verify` pasa** y el usuario confirma su acceso. Se confirma en **todas** las sesiones tocadas.
5. Un sitio a la vez; no se pasa al siguiente hasta confirmar el anterior.
6. Antes de nada: RouterOS 7 en ambos extremos, redes sin solapamiento (`validate_network`) y firewall con estructura conocida.

## 3. Procedimiento

### 3.1 Conectarse

`discover_routers`, luego `connect` (sin `host`: usa la puerta de enlace predeterminada de esta PC). Para el segundo router, otra sesión con otro `name` (`connect` solo acepta la puerta de enlace actual; si el segundo router está en otra red, no se conecta: ver 3.3).

### 3.2 Ambos routers accesibles

`tunnel_setup` en dry run, con la sesión del hub:

```
name=hub, role=hub, wg_name=wg-of01,
local_tunnel_ip=10.255.0.5/30, remote_tunnel_ip=10.255.0.6,
listen_port=13231, local_lans=<LAN hub>, remote_lans=<LAN oficina>,
routing=ibgp, hub_endpoint=<ip o dominio publico>:13231,
remote_name=of01, remote_wg_name=wg-hub
```

Con `dry_run=false` el conector:

1. Aplica la base en el hub (interfaz, IP, lista `SPOKES`, firewall, filtros y sesión BGP) y lee su clave pública.
2. Aplica lo mismo en la oficina (lista `HUB`, endpoint = `hub_endpoint`, keepalive 25) y lee su clave pública.
3. Agrega el peer en cada lado con la clave pública del otro (con `allowed-address` restringido).
4. Deja armado el rollback en ambos routers (10 min por defecto).

### 3.3 El otro router NO está disponible

Se omite `remote_name`. Con `dry_run=false`:

1. Se configura solo este router (con su rollback).
2. Se **genera y guarda un script CLI** (`~/mikrotik-sites/<sitio>/tunnels/remote-<wg>.rsc`) para pegar en la terminal del otro router, o importar con `/import`. Ya incluye la clave pública de este router.
3. En el otro router se lee su clave: `/interface wireguard print where name=<wg>`.
4. Se vuelve a llamar a `tunnel_setup` (mismos valores) con `remote_public_key=<esa clave>`: agrega el peer aquí. Es idempotente.

Si no se indica `remote_routeros_version`, el script usa la sintaxis BGP de 7.20+ (`/routing bgp instance`); con una versión anterior se usa la variante con `as` y `router-id` en la conexión.

### 3.4 Verificar y confirmar

`tunnel_verify` (con `remote_name` si hay sesión; si no, entra por el túnel):

| # | Dónde | Prueba | Esperado |
| --- | --- | --- | --- |
| 1 | Ambos | Handshake de WireGuard | menos de 3 min |
| 2 | Ambos | Ping a la IP de túnel del otro | respuestas (el firewall de **ambos** deja pasar el tráfico) |
| 3 | Ambos | BGP *established* / OSPF *Full* | arriba |
| 4 | Ambos | Ruta activa a cada LAN del otro lado | presente |
| 5 | Esta PC | Puerto 22 y **login SSH a la IP de túnel de cada router** | acceso correcto |
| 6 | Spoke | Ping a la LAN de otro spoke (`isolation_test_ip`) | **sin respuesta** |

Si todo pasa y el usuario confirma su acceso: `confirm_changes` en cada sesión. Si falla la prueba 6, es un incidente de seguridad: no se confirma y se revisan las tres capas.

El login por el túnel exige `allow_management=true` (por defecto): acepta SSH y Winbox solo desde la IP de túnel y las LANs del otro lado. Si el router restringe los servicios con `available-from`, `tunnel_setup` lo avisa: hay que agregar las LANs del otro lado (sin quitar la local). Además esta PC debe tener ruta hacia la IP de túnel (normalmente por la puerta de enlace, que es el hub o el spoke local).

## 4. Varios sitios (más de 2)

Una llamada a `tunnel_setup` por spoke, siempre en el hub, con una interfaz, puerto UDP y /30 distintos (`wg-of01`/13231/10.255.0.4/30, `wg-of02`/13232/10.255.0.8/30…). `tunnel_verify` por enlace. Todos los routers comparten el mismo AS (iBGP); el router-id es la IP de túnel del primer enlace creado.

## 5. Objetos que crea el conector (todos con `mcp-tunnel: <wg>` o prefijo `mcp-`)

| Objeto | Nombre |
| --- | --- |
| Listas de interfaces | `SPOKES` (hub), `HUB` (spoke) |
| Reglas de firewall | comentario `mcp-tunnel: <wg> <udp\|icmp\|bgp\|ospf\|mgmt\|isolate\|no-initiate>`, al inicio de la cadena |
| Address-list de administración | `mcp-mgmt-<wg>` |
| Filtros BGP | cadenas `mcp-bgp-in-<wg>`, `mcp-bgp-out-<wg>`; conexión `bgp-<wg>`; instancia `bgp-main` |
| OSPF | instancia `mcp-ospf`, área `mcp-backbone` |
| Peer | comentario `mcp-tunnel: <wg>` |

Reejecutar `tunnel_setup` reemplaza estos objetos sin duplicarlos.

## 6. Problemas comunes

| Síntoma | Causa probable | Acción |
| --- | --- | --- |
| Sin handshake | endpoint o puerto mal, UDP cerrado en el hub o en su proveedor | Revisar `hub_endpoint`, la regla `udp` y el reenvío de puertos |
| Handshake OK, BGP no levanta | falta TCP 179 en input, IPs de túnel mal, versión BGP distinta | Revisar reglas `mcp-tunnel` y la sintaxis según la versión |
| BGP arriba, sin rutas | filtro `in`/`out` no coincide con el prefijo real | Comparar `/ip address print` con `local_lans`/`remote_lans`; la LAN debe estar conectada directamente |
| Ruta presente, sin ping a equipos | `allowed-address` sin la LAN, firewall de los equipos | Revisar peers de ambos lados |
| No hay login por el túnel | `available-from`, sin ruta desde la PC, `allow_management=false` | Ver 3.4 |
| Páginas lentas o cortadas | MTU (1420 por defecto, menos con PPPoE) | Bajar el MTU de `wg-*` a 1400 o `change-mss` |
| LANs solapadas | ambas usan 192.168.88.0/24 | Renumerar una; nunca conectar redes solapadas |

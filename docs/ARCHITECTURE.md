# wireguard-windows — Architecture

This document describes how `wireguard.exe` (WireGuard WS) is structured at runtime and build time,
including the userspace path that carries WebSocket peers. Security rationale lives in [`attacksurface.md`](attacksurface.md);
routing and kill-switch details in [`netquirk.md`](netquirk.md); project facts and decisions in
[`PROJECT.md`](PROJECT.md).

## 1. Processes & privilege boundaries

One executable runs in three roles. Only the services are privileged; the UI runs with its privileges
dropped and talks exclusively to the manager.

```mermaid
flowchart LR
    subgraph Session["Interactive session (admin or operator)"]
        UI["wireguard.exe /ui<br/>privileges dropped"]
    end
    subgraph System["LocalSystem services"]
        MGR["WireGuardWSManager<br/>wireguard.exe /managerservice"]
        TS["WireGuardWSTunnel$name<br/>wireguard.exe /tunnelservice"]
    end
    SCM["Service Control Manager"]
    STORE[("Data\Configurations name.conf.dpapi<br/>Data\WebSocketTLS name\file.dpapi")]
    RLOG[("Data\log.bin<br/>shared ring log")]
    REG[("HKLM Software WireGuard WS<br/>admin knobs")]
    WGNT["WireGuardNT driver<br/>wireguard.dll embedded"]
    WGGO["wireguard-go fork on Wintun<br/>wintun.dll embedded; UAPI named pipe"]
    WFP["WFP kill switch<br/>dynamic session"]
    IPH["IP Helper<br/>routes, addresses, DNS"]

    UI -- "gob RPC over inherited pipes" --> MGR
    MGR -- "launches with pipe and log handles" --> UI
    MGR -- "install, start, uninstall; status notifications" --> SCM
    SCM -- "runs" --> TS
    MGR -- "save, load, delete" --> STORE
    TS -- "load config at start" --> STORE
    MGR -- "open adapter, read runtime config" --> WGNT
    TS -- "create adapter, set config, up" --> WGNT
    MGR -- "UAPI get over the pipe" --> WGGO
    TS -- "runs the device in-process" --> WGGO
    TS --> WFP
    TS --> IPH
    UI -. "reads" .-> RLOG
    MGR --> RLOG
    TS --> RLOG
    MGR -. "LimitedOperatorUI" .-> REG
    TS -. "DangerousScriptExecution" .-> REG
```

- **Manager** (`manager/`): installs itself as `WireGuardWSManager`; for every admin session (and operator
  session when `LimitedOperatorUI` is set) it creates the IPC pipes and launches the UI. It owns the
  config store, starts/stops tunnels, tracks tunnel services through SCM notifications, and serves
  runtime statistics. Operator sessions receive redacted configs and cannot mutate state.
- **Tunnel service** (`tunnel/`): one per running tunnel (`WireGuardWSTunnel$<name>`, LocalSystem,
  unrestricted service SID, depends on `Nsi` and `TcpIp`). It configures WireGuardNT, or runs the
  userspace device for a config with a WebSocket peer (section 7), sets up networking and the firewall,
  then drops all privileges except `SeLoadDriverPrivilege`.
- **Identity**: the service names above, the data directory `%ProgramFiles%\WireGuard WS\Data`, the
  admin key `HKLM\Software\WireGuard WS` and the management window class differ from the official
  client's, so both can be installed side by side.
- **UI** (`ui/`): walk-based tray + management window; never talks to tunnel services or the driver.
- **Start/stop semantics**: *Start* stops any running tunnel whose routes intersect the new one, then
  installs and starts its tunnel service; *Stop* uninstalls the tunnel service.

## 2. Tunnel bring-up (WireGuardNT)

```mermaid
sequenceDiagram
    autonumber
    participant UI as UI
    participant MGR as Manager service
    participant SCM as SCM
    participant TS as Tunnel service
    participant DRV as WireGuardNT
    participant NET as WFP and IP Helper

    UI->>MGR: Start(name)
    MGR->>MGR: stop intersecting tunnels (async)
    MGR->>SCM: install and start WireGuardWSTunnel$name
    SCM->>TS: /tunnelservice config path
    TS->>TS: LoadFromPath, deduplicate entries
    TS->>TS: register interface watcher
    TS->>TS: ResolveEndpoints (DNS, retries)
    TS->>DRV: CreateAdapter(name, "WireGuard", deterministic GUID)
    TS->>TS: PreUp script (only if allowed)
    TS->>NET: enable firewall (WFP)
    TS->>TS: drop privileges
    TS->>DRV: SetConfiguration(ToDriverConfiguration)
    TS->>DRV: SetAdapterState(Up)
    TS->>NET: per family: routes, addresses, MTU, metric, DNS
    TS->>TS: PostUp script (only if allowed)
    TS-->>SCM: SERVICE_RUNNING
    SCM-->>MGR: status notification
    MGR-->>UI: tunnel state changed
```

Tear-down runs the PreDown script, flushes routes, addresses, and DNS, removes the firewall filters,
closes the adapter, and runs PostDown.

## 3. Runtime statistics

```mermaid
sequenceDiagram
    participant UI as UI config view
    participant MGR as Manager service
    participant DRV as WireGuardNT
    participant DEV as Userspace device

    Note over UI: every second while a tunnel is shown
    UI->>MGR: RuntimeConfig(name)
    alt stored config has a WebSocket peer
        MGR->>DEV: dial the UAPI pipe (owner must be SYSTEM), get=1
        DEV-->>MGR: UAPI text (peers, counters, handshakes)
        MGR->>MGR: FromUAPI(runtime, stored)
    else UDP only
        MGR->>DRV: OpenAdapter(name) (cached) and GetConfiguration
        DRV-->>MGR: binary runtime config (peers, counters, handshakes)
        MGR->>MGR: FromDriverConfiguration(runtime, stored)
    end
    MGR->>MGR: Redact() for operator sessions
    MGR-->>UI: conf.Config (gob)
```

Interface fields the backend does not hold (addresses, DNS, MTU, scripts, table) come from the stored
config. Peers are rebuilt from runtime data; a userspace peer's WebSocket settings are copied from the
stored config, because the device reports the decrypted TLS file paths it was given.

## 4. Config data model & serialization surfaces

```mermaid
classDiagram
    class Config {
        +Name string
        +Interface Interface
        +Peers Peer[]
        +WSTLSFiles map
    }
    class Interface {
        +PrivateKey Key
        +Addresses Prefix[]
        +ListenPort uint16
        +MTU uint16
        +DNS Addr[]
        +DNSSearch string[]
        +PreUp PostUp PreDown PostDown string
        +TableOff bool
    }
    class Peer {
        +PublicKey Key
        +PresharedKey Key
        +AllowedIPs Prefix[]
        +Endpoint Endpoint
        +PersistentKeepalive uint16
        +WSMode WSURL WSTunnelTarget WSBearer
        +WSMask WSTLSInsecure bool
        +WSTLSCA WSTLSCert WSTLSKey string
        +WSPingInterval WSBackoffMin WSBackoffMax uint32
        +RxBytes TxBytes Bytes
        +LastHandshakeTime HandshakeTime
    }
    class Endpoint {
        +Host string
        +Port uint16
    }
    Config *-- Interface
    Config *-- Peer
    Peer *-- Endpoint
```

```mermaid
flowchart LR
    EDIT["UI raw-text editor<br/>ui/syntax highlighter"] --> TXT["wg-quick text"]
    TXT -- "FromWgQuick" --> CFG["conf.Config"]
    CFG -- "ToWgQuick" --> TXT
    CFG -- "Save: DPAPI encrypt" --> STORE[("name.conf.dpapi")]
    STORE -- "LoadFromPath: DPAPI decrypt" --> CFG
    DISK[("on-disk name.conf<br/>/installtunnelservice")] -- "LoadFromPath" --> CFG
    CFG -- "ResolveEndpoints then ToDriverConfiguration" --> BIN["WireGuardNT binary layout"]
    BIN -- "FromDriverConfiguration plus stored config" --> CFG
    CFG -- "ResolveEndpoints, PrepareWSTLSFiles, ToUAPI" --> UAPI["UAPI text for wireguard-go"]
    UAPI -- "FromUAPI plus stored config" --> CFG
    CFG -- "WSTLSFiles: SaveWSTLSFiles, DPAPI encrypt" --> TLS[("WebSocketTLS name\file.dpapi")]
```

The parser rejects unknown keys, so every new key must be added to the model, the parser, the writer,
the highlighter, and the config view together. The WebSocket keys and their validation mirror the
Android and Apple clients (see [`PROJECT.md`](PROJECT.md)).

**TLS files.** In a stored tunnel, `WSTLSCA`, `WSTLSCert` and `WSTLSKey` are bare file names. When the
editor saves or the importer imports a config, the unprivileged UI reads each referenced file (an
absolute path, a path next to the imported `.conf`, or an entry of the imported zip), tells the user
which files it copied, and sends the contents with the config (`Config.WSTLSFiles`). The manager
validates them and stores each DPAPI-encrypted in `Data\WebSocketTLS\<tunnel>\`; `StoredConfig`
returns them to administrators only, so edits, renames and zip exports keep them. At start the tunnel
service decrypts them into `Data\WebSocketTLS\$runtime\<tunnel>\`, readable by SYSTEM only, and
removes them at stop; they are deleted with the tunnel. A config started from disk with
`/installtunnelservice` must use absolute local paths, which are read in place; relative, UNC and
device paths are rejected.

## 5. Firewall, kill switch & routing

```mermaid
flowchart TD
    START["Tunnel service: enable firewall"] --> ALWAYS["Always: permit all traffic of this tunnel service<br/>(app ID of wireguard.exe AND the tunnel's service SID)"]
    START --> Q{"Exactly one peer with a /0 AllowedIP<br/>and Table not off?"}
    Q -- "no" --> DONE["No further filters"]
    Q -- "yes: kill switch" --> KS["Permit: tunnel interface, loopback, DHCP, NDP<br/>Block: DNS except to the tunnel's DNS servers<br/>Block: everything else"]
```

- The permit rule is scoped by application and service SID, not by endpoint, so any connection the
  tunnel service makes, including the WebSocket connection, passes the kill switch.
- Routing-loop avoidance for UDP is done **inside WireGuardNT**: it tracks the routing table, picks the
  route that does not loop back into itself, and sends with `IP_PKTINFO`/`IPV6_PKTINFO`
  ([`netquirk.md`](netquirk.md)).
- For the userspace path the tunnel service does it itself (section 7): it pins the UDP sockets to the
  interface of the lowest-metric default route that is not the tunnel (`IP_UNICAST_IF`), and keeps a
  host route (`/32` or `/128`) to each WebSocket server through that route's gateway, so the TCP
  WebSocket connection never enters the tunnel. Other processes' traffic to those servers is not
  tunnelled either; with the kill switch on, WFP still blocks it.

## 6. Build pipeline

```mermaid
flowchart LR
    DL["Pinned downloads, SHA-256 verified<br/>Go, llvm-mingw, ImageMagick, make,<br/>wireguard-tools fork, Wintun, WireGuardNT"] --> ICONS["SVG to ICO icons"]
    DL --> RC["windres resources.rc<br/>manifest, icons, version info,<br/>wintun.dll and wireguard.dll as RCDATA"]
    ICONS --> RC
    RC --> SYSO["resources_arch.syso"]
    SYSO --> GOB["go build<br/>-tags load_wintun_from_rsrc,load_wgnt_from_rsrc"]
    GOB --> EXE["arch\wireguard.exe<br/>x86, amd64, arm64"]
    DL --> WG["make wireguard-tools"]
    WG --> WGEXE["arch\wg.exe"]
    EXE --> SIGN["signtool (only with sign.bat)"]
    WGEXE --> SIGN
    SIGN --> MSI["installer build: WiX MSIs"]
```

`build.bat` (Windows) runs the whole pipeline; the Linux `Makefile` runs the `wireguard.exe` part only.
Upstream's `.overlay` stubs of the standard library crypto are removed: they cannot build
`crypto/tls` (needed for `wss://`). `wintun/` holds a copy of the `golang.zx2c4.com/wintun`
bindings, replaced in `go.mod`, that loads `wintun.dll` from `RCDATA` through `driver/memmod`, like
`driver/` loads `wireguard.dll`.

## 7. Userspace path (WebSocket peers)

A config with at least one WebSocket peer runs in the tunnel service on the `danielealbano/wireguard-go`
fork over Wintun; a UDP-only config keeps the WireGuardNT path of sections 2 to 5.

```mermaid
sequenceDiagram
    autonumber
    participant TS as Tunnel service
    participant WT as Wintun
    participant DEV as wireguard-go device
    participant MON as Default-route monitor
    participant NET as WFP and IP Helper

    TS->>TS: LoadFromPath, PrepareWSTLSFiles, ResolveEndpoints
    TS->>WT: CreateTUNWithRequestedGUID(name, deterministic GUID, MTU)
    TS->>NET: enable firewall (WFP), drop privileges
    TS->>DEV: NewDevice(multiplex bind: UDP and WebSocket)
    TS->>TS: UAPIListen on the tunnel's named pipe
    TS->>DEV: IpcSet(ToUAPI)
    TS->>MON: add host routes to the WebSocket servers via the default gateway
    TS->>DEV: Up (WebSocket connections start outside the tunnel)
    TS->>MON: pin UDP sockets, follow route changes
    TS->>NET: per family: routes, addresses, MTU, metric, DNS
    Note over MON,DEV: on a default route change: move the host routes, BindUpdate (re-dial), re-pin UDP
```

Tear-down closes the pipe and the device (which removes the Wintun adapter), removes the host routes and
the decrypted TLS files, besides the common steps of section 2.

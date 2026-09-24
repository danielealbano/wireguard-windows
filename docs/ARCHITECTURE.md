# wireguard-windows — Architecture

This document describes how `wireguard.exe` is structured at runtime and build time, and where the
fork's WireGuard WS work lands. Security rationale lives in [`attacksurface.md`](attacksurface.md);
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
        MGR["WireGuardManager<br/>wireguard.exe /managerservice"]
        TS["WireGuardTunnel$name<br/>wireguard.exe /tunnelservice"]
    end
    SCM["Service Control Manager"]
    STORE[("Data\Configurations<br/>name.conf.dpapi")]
    RLOG[("Data\log.bin<br/>shared ring log")]
    REG[("HKLM Software WireGuard<br/>admin knobs")]
    WGNT["WireGuardNT driver<br/>wireguard.dll embedded"]
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
    TS --> WFP
    TS --> IPH
    UI -. "reads" .-> RLOG
    MGR --> RLOG
    TS --> RLOG
    MGR -. "LimitedOperatorUI" .-> REG
    TS -. "DangerousScriptExecution" .-> REG
```

- **Manager** (`manager/`): installs itself as `WireGuardManager`; for every admin session (and operator
  session when `LimitedOperatorUI` is set) it creates the IPC pipes and launches the UI. It owns the
  config store, starts/stops tunnels, tracks tunnel services through SCM notifications, and serves
  runtime statistics. Operator sessions receive redacted configs and cannot mutate state.
- **Tunnel service** (`tunnel/`): one per running tunnel (`WireGuardTunnel$<name>`, LocalSystem,
  unrestricted service SID, depends on `Nsi` and `TcpIp`). It configures the driver, networking, and
  firewall, then drops all privileges except `SeLoadDriverPrivilege`.
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
    MGR->>SCM: install and start WireGuardTunnel$name
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

    Note over UI: every second while a tunnel is shown
    UI->>MGR: RuntimeConfig(name)
    MGR->>DRV: OpenAdapter(name) (cached) and GetConfiguration
    DRV-->>MGR: binary runtime config (peers, counters, handshakes)
    MGR->>MGR: FromDriverConfiguration(runtime, stored)
    MGR->>MGR: Redact() for operator sessions
    MGR-->>UI: conf.Config (gob)
```

Interface fields the driver does not hold (addresses, DNS, MTU, scripts, table) come from the stored
config; peers are rebuilt from driver data only.

## 4. Config data model & serialization surfaces

```mermaid
classDiagram
    class Config {
        +Name string
        +Interface Interface
        +Peers Peer[]
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
```

The parser rejects unknown keys, so every new key must be added to the model, the parser, the writer,
the highlighter, and the config view together.

## 5. Firewall, kill switch & routing

```mermaid
flowchart TD
    START["Tunnel service: enable firewall"] --> ALWAYS["Always: permit all traffic of this tunnel service<br/>(app ID of wireguard.exe AND the tunnel's service SID)"]
    START --> Q{"Exactly one peer with a /0 AllowedIP<br/>and Table not off?"}
    Q -- "no" --> DONE["No further filters"]
    Q -- "yes: kill switch" --> KS["Permit: tunnel interface, loopback, DHCP, NDP<br/>Block: DNS except to the tunnel's DNS servers<br/>Block: everything else"]
```

- The permit rule is scoped by application and service SID, not by endpoint, so any connection the
  tunnel service makes (including a future WebSocket carrier) passes the kill switch.
- Routing-loop avoidance for UDP is done **inside WireGuardNT**: it tracks the routing table, picks the
  route that does not loop back into itself, and sends with `IP_PKTINFO`/`IPV6_PKTINFO`
  ([`netquirk.md`](netquirk.md)). The Go code adds no host routes and binds no sockets today.

## 6. Build pipeline

```mermaid
flowchart LR
    DL["Pinned downloads, SHA-256 verified<br/>Go, llvm-mingw, ImageMagick, make,<br/>wireguard-tools snapshot, WireGuardNT"] --> ICONS["SVG to ICO icons"]
    DL --> RC["windres resources.rc<br/>manifest, icons, version info,<br/>wireguard.dll as RCDATA"]
    ICONS --> RC
    RC --> SYSO["resources_arch.syso"]
    SYSO --> GOB["go build -overlay<br/>-tags load_wgnt_from_rsrc"]
    GOB --> EXE["arch\wireguard.exe<br/>x86, amd64, arm64"]
    DL --> WG["make wireguard-tools"]
    WG --> WGEXE["arch\wg.exe"]
    EXE --> SIGN["signtool (only with sign.bat)"]
    WGEXE --> SIGN
    SIGN --> MSI["installer build: WiX MSIs"]
```

`build.bat` (Windows) runs the whole pipeline; the Linux `Makefile` runs the `wireguard.exe` part only.

## 7. Where WireGuard WS lands (ROADMAP)

The agreed design (see [`PROJECT.md`](PROJECT.md) → Roadmap) selects the backend per tunnel inside the
tunnel service:

```mermaid
flowchart TD
    TSVC["Tunnel service starts"] --> Q{"Config has any<br/>WebSocket peer?"}
    Q -- "no" --> NT["WireGuardNT path<br/>(sections 2 to 5, unchanged)"]
    Q -- "yes" --> US["Userspace path"]
    US --> WTUN["Wintun adapter<br/>wintun.dll embedded"]
    US --> DEVICE["wireguard-go fork device<br/>multiplex bind: UDP and WebSocket"]
    US --> MON["Default-route monitor<br/>host route to each WebSocket endpoint,<br/>re-dial on change"]
    US --> STATS["Runtime stats for the manager<br/>(mechanism settled in the plan)"]
    DEVICE -- "TLS WebSocket carrier via the physical NIC" --> SRV["websocket or wstunnel server"]
    MON -. "keeps the carrier route off the tunnel" .-> DEVICE
```

Supporting changes: the config model, parser, writer, highlighter, and config view gain the WebSocket
keys; certificate files are copied into the store DPAPI-encrypted for UI-managed tunnels; the product
gets its own "WireGuard WS" identity so it installs alongside the official client.

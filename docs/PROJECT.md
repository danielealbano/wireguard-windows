# wireguard-windows — Project

## What this is

**wireguard-windows** is the official [WireGuard](https://www.wireguard.com/) client for Windows,
MIT-licensed; this fork builds it as **WireGuard WS**, which adds per-peer WebSocket/wstunnel transport. A single Go program, `wireguard.exe`, runs in several roles: a **manager service** that
owns the configuration store and serves the UI, one **tunnel service** per active tunnel that drives
the **WireGuardNT** kernel driver, and an unprivileged **UI** (tray icon + management window). The
driver ships prebuilt and Microsoft-signed inside `wireguard.dll`, which is embedded in the executable
as a resource. For the security design see [`attacksurface.md`](attacksurface.md); for routing and
kill-switch behaviour see [`netquirk.md`](netquirk.md).

> **Fork status:** this repository is a fork of `WireGuard/wireguard-windows`
> (`origin` = `github.com/danielealbano/wireguard-windows`, default branch `main`;
> `upstream` = `github.com/WireGuard/wireguard-windows`, branch `master`), based on upstream **1.1.1**
> (`6ece77bc`). It changes only what **WireGuard WS** needs — see [WireGuard WS](#wireguard-ws).

## Tech stack

| Concern | Choice |
|---|---|
| Language | Go (pure Go — no cgo in the main module); module `golang.zx2c4.com/wireguard/windows`, `go 1.26.0`; build scripts pin Go 1.27.1 |
| Kernel driver | WireGuardNT 1.1 (`wireguard.dll`, embedded as `RCDATA`, loaded in-memory by `driver/memmod` with build tag `load_wgnt_from_rsrc`) for UDP-only tunnels |
| Userspace backend | `danielealbano/wireguard-go` fork **v1.3.1** (`replace golang.zx2c4.com/wireguard` in `go.mod`) over **Wintun 0.14.1** (`wintun.dll`, embedded as `RCDATA`, loaded in-memory with build tag `load_wintun_from_rsrc` through the `wintun/` copy of the bindings) for tunnels with a WebSocket peer |
| UI | lxn/walk + lxn/win (Win32), via upstream-maintained forks replaced in `go.mod` |
| Windows APIs | `golang.org/x/sys/windows`; WFP (`tunnel/firewall`); IP Helper (`tunnel/winipcfg`); SCM; DPAPI (`conf/dpapi`); mkwinsyscall-generated bindings |
| Config storage | DPAPI-encrypted `.conf.dpapi` files in `%ProgramFiles%\WireGuard WS\Data\Configurations`, TLS files DPAPI-encrypted in `Data\WebSocketTLS` (SYSTEM + Administrators only) |
| Logging | Memory-mapped ring log `%ProgramFiles%\WireGuard WS\Data\log.bin` (`ringlogger`), shared by all roles |
| Localization | `golang.org/x/text/message`; `locales/*/messages.gotext.json` (Crowdin) → generated `zgotext.go` |
| Admin policy | `HKLM\Software\WireGuard WS` knobs (`LimitedOperatorUI`, `DangerousScriptExecution`) — see [`adminregistry.md`](adminregistry.md) |
| CLI tool | `wg.exe`, built by `build.bat` from the `danielealbano/wireguard-tools` fork pinned at `68b49a93` |
| Packaging | WiX 3.14.1 MSI (`installer/`), per-architecture MSIs + the `wireguard-installer.exe` fetcher |
| Build | `build.bat` on Windows (canonical: x86, amd64, arm64 + `wg.exe`; llvm-mingw) · `Makefile` on Linux (`wireguard.exe` only; mingw-w64) |
| Tests / CI | Windows-only Go tests; GitHub Actions on `windows-latest` (see [Testing](#testing)) |

## Repository layout

| Path | Contents |
|---|---|
| `main.go` | Command-line verb dispatch (see [Process roles](#process-roles)); DLL search-path hardening |
| `manager/` | Manager service, service install/uninstall, gob IPC server/client for the UI, tunnel tracking via SCM notifications, driver adapter cache for stats, update state |
| `tunnel/` | Tunnel service (bring-up/tear-down), address/route/DNS configuration, interface watcher, MTU monitor, pitfall checks, script runner |
| `tunnel/firewall/` | WFP kill switch (dynamic session, permit/block rules) |
| `tunnel/winipcfg/` | IP Helper wrappers (LUID-based addresses, routes, DNS, change callbacks) |
| `driver/` | WireGuardNT bindings (`wireguard.dll`), binary configuration layout, in-memory DLL loader (`memmod/`) |
| `conf/` | Config model, wg-quick parser/writer, driver-format conversion, DPAPI store, store watcher, migration, admin knobs, endpoint DNS resolution |
| `ui/` | walk UI: tray, manage window, tunnels page, config view, edit dialog, log page, update page; `ui/syntax/` (raw-text editor + highlighter) |
| `services/` | Service error codes, boot detection |
| `elevate/` | Token/privilege helpers, UAC `ShellExecute`, run-as-SYSTEM helpers |
| `ringlogger/` | Shared memory-mapped ring log |
| `updater/`, `version/` | Signify-verified MSI updater (active only for official signed builds), version constants, signature checks |
| `l18n/`, `locales/`, `gotext.go`, `zgotext.go` | Localization |
| `installer/` | WiX MSI sources, C custom actions, `fetcher/` bootstrapper |
| `embeddable-dll-service/` | `tunnel.dll` for embedding + C# demo — **out of scope for this fork** |
| `.overlay/` | Upstream's Go stdlib crypto overlays; **not applied** by this fork's builds (they cannot build `crypto/tls`) |
| `wintun/` | Copy of the `golang.zx2c4.com/wintun` bindings (`wintun-go` `0fa3db229ce2`, MIT), replaced in `go.mod`, whose loader with `load_wintun_from_rsrc` reads `wintun.dll` from `RCDATA` |
| `.github/workflows/` | CI (`ci.yml`) |
| `resources.rc`, `manifest.xml` | Windows resources (icons, version info, embedded `wireguard.dll`, manifest) |
| `build.bat`, `Makefile`, `go.mod.master` | Builds (Windows / Linux) and the `remaster` dependency-refresh template |
| `docs/` | This file, [`ARCHITECTURE.md`](ARCHITECTURE.md), upstream reference docs, `plans/` |

## Process roles

`wireguard.exe` selects its role from its first argument (`main.go`):

| Verb | Role |
|---|---|
| *(none)* | Elevate and install the manager service |
| `/installmanagerservice`, `/uninstallmanagerservice` | Install/remove `WireGuardWSManager` |
| `/managerservice` | Run as the manager service (LocalSystem) |
| `/installtunnelservice CONFIG_PATH`, `/uninstalltunnelservice NAME` | Install/remove `WireGuardWSTunnel$<name>` for a config file (read in place at every start) |
| `/tunnelservice CONFIG_PATH` | Run as a tunnel service (LocalSystem, unrestricted service SID) |
| `/ui …` | Run the UI (launched by the manager into each admin/operator session with inherited pipe handles) |
| `/dumplog [/tail]`, `/update`, `/removedriver` | Log dump, updater, driver removal |

## Config model & storage

- **Model** (`conf/config.go`): `Config{Name, Interface, Peers}`; `Interface{PrivateKey, Addresses,
  ListenPort, MTU, DNS, DNSSearch, PreUp, PostUp, PreDown, PostDown, TableOff}`;
  `Peer{PublicKey, PresharedKey, AllowedIPs, Endpoint{Host, Port}, PersistentKeepalive, WSMode, WSURL,
  WSTunnelTarget, WSBearer, WSMask, WSTLSCA, WSTLSCert, WSTLSKey, WSTLSInsecure, WSPingInterval,
  WSBackoffMin, WSBackoffMax, RxBytes, TxBytes, LastHandshakeTime}`; comments are preserved per
  section; `Config.WSTLSFiles` carries TLS file contents between the UI and the manager.
- **wg-quick text** (`conf/parser.go`, `conf/writer.go`): `[Interface]` keys `PrivateKey`,
  `ListenPort`, `MTU`, `Address`, `DNS` (IPs → servers, other values → search domains), `PreUp`,
  `PostUp`, `PreDown`, `PostDown`, `Table`; `[Peer]` keys `PublicKey`, `PresharedKey`, `AllowedIPs`,
  `PersistentKeepalive`, `Endpoint` (`host:port`, or a `ws://`/`wss://` URL for a WebSocket peer) and
  the WebSocket keys listed under [WireGuard WS](#wireguard-ws). **Unknown keys are parse errors**
  (so the server-side `WSListen`, `WSServer*` and `WSTrustedProxies` are rejected); `#` starts a
  comment (except in script values); empty values are errors; a repeated scalar key keeps the last
  value.
- **Driver format** (`conf/writer.go` `ToDriverConfiguration`, `conf/parser.go`
  `FromDriverConfiguration`, `driver/configuration_windows.go`): the flat binary layout WireGuardNT
  consumes and reports (keys, endpoint sockaddr, keepalive, allowed IPs, counters). Endpoint hostnames
  are resolved by the tunnel service before conversion (`conf/dnsresolver_windows.go`).
- **UAPI format** (`conf/uapi.go` `ToUAPI`, `FromUAPI`): the text the userspace device is configured
  with (`transport=` on every peer, the `ws_*` keys) and reports on its named pipe
  `\\.\pipe\ProtectedPrefix\Administrators\WireGuard\<name>`.
- **Storage** (`conf/store.go`, `conf/path_windows.go`): UI-managed tunnels are saved by the manager as
  DPAPI-encrypted `<name>.conf.dpapi` files; unencrypted `.conf` files dropped into the directory are
  migrated. Admins can also run a tunnel from an on-disk `.conf` via `/installtunnelservice`
  (see [`enterprise.md`](enterprise.md)); that file is read in place at every start.
- **TLS files** (`conf/wstls.go`, `conf/wstls_store.go`): see [`ARCHITECTURE.md`](ARCHITECTURE.md) §4 —
  bare file names in stored tunnels (DPAPI-encrypted copies in `Data\WebSocketTLS\<tunnel>\`,
  decrypted for SYSTEM only while the tunnel runs), absolute local paths read in place for on-disk
  configs.

## Build, packaging & release

- **Windows (canonical)**: `build.bat` downloads and hash-verifies Go, llvm-mingw, ImageMagick, make,
  the wireguard-tools fork, Wintun and WireGuardNT, renders icons, compiles resources, builds
  `wireguard.exe` for x86/amd64/arm64 and `wg.exe`, and signs them when a `sign.bat` provides a signing
  identity. `installer\build.bat` builds the MSIs with WiX.
- **Distribution**: CI publishes each architecture's `wireguard.exe` and `wg.exe` as a zip artifact
  (running `wireguard.exe` installs the manager service) and the `wireguard-ws-<arch>-<version>.msi`
  installers. The MSI is the product "WireGuard WS" (publisher Daniele Salvatore Albano, its own
  upgrade and component codes, installed in `%ProgramFiles%\WireGuard WS`), so it installs, upgrades
  and uninstalls next to the official client without touching it.
- **Linux (development)**: `make` cross-builds `wireguard.exe` (x86/amd64; arm64 needs an aarch64
  mingw not packaged by Ubuntu) and `make deploy` copies it to a Windows host over SSH. Ubuntu's GNU
  `windres` cannot compile `resources.rc` (it rejects `LANG_PERSIAN`, in upstream too), so the Windows
  build is the one that works.
- **Unofficial builds** (anything not signed by WireGuard LLC) show "(unsigned build, no updates)" and
  never run the updater.

## Development environment

- **Host**: Linux, with Go, `mingw-w64`, `libarchive-tools`, ImageMagick, and libvirt/KVM.
- **Windows test VM** (developer-local): Windows 11 Enterprise Evaluation 25H2 under libvirt as
  `wgws-win11` — UEFI Secure Boot + TPM 2.0, 16 GB RAM, 8 vCPU, 80 GB disk; NIC1 on the libvirt
  `default` NAT (192.168.122.50, metric 10), NIC2 on the `wgws-alt` NAT (192.168.123.50, metric 50);
  reached as `ssh wgws-win11` (elevated administrator, PowerShell). Toggling NIC1's link
  (`virsh domif-setlink wgws-win11 52:54:00:77:67:01 down|up`) simulates a network switch. The
  evaluation expires after 90 days, so the VM is rebuilt from its unattended-install scripts.
- The spike artifacts (probe source, VM provisioning, VM test scripts, logs) live outside the repo in
  `/home/daalbano/dev/wireguard-windows-spike/` and on the VM in `C:\wgws\`; they are the reference for
  the WireGuard WS plan and MUST be kept.

## Testing

- **Automated**: Windows-only Go tests in `conf/`, `conf/dpapi/`, `ringlogger/`, `tunnel/`,
  `tunnel/firewall/`, `tunnel/winipcfg/`, `ui/syntax/`, `updater/`, `updater/winhttp/`, `version/`.
  Some need elevation, a live network, or the official signature. No package compiles its tests on a
  non-Windows host. Tests that use the real configuration store carry the `integration` build tag
  (`conf/wstls_store_test.go`). The fork's tests run with `-race` (cgo with the llvm-mingw of
  `build.bat`): `go test -race -tags integration ./conf ./ui/syntax ./tunnel`.
- **CI** (`.github/workflows/ci.yml`, `windows-latest`): `build.bat`, `gofmt`, `go mod tidy`, `go vet`
  on amd64 and arm64 failing only on lines the fork added or changed since `6ece77bc` (the vendored
  `wintun/` excluded), the race tests above, `govulncheck`, `installer\build.bat`, and the
  per-architecture and MSI artifacts.
- **Scope of the gates**: the fork changes only what WireGuard WS strictly needs. `gofmt`, `go vet` and
  tests gate the code and tests the fork adds or changes; upstream's existing `go vet` findings (113 at
  1.1.1) and its broken or environment-dependent tests are left as they are. golangci-lint is not used.
- **End-to-end**: on `wgws-win11` against the user's wstunnel server, with scratch scripts kept outside
  the repo: split and full tunnel, network switch, the UI flows (import, activate, stats, edit, export,
  delete) and the TLS file cases.

## WireGuard WS

**Goal:** per-peer **WebSocket/wstunnel transport** with parity with the user's `wireguard-android`
and `wireguard-apple` forks, consuming the `danielealbano/wireguard-go` fork (WebSocket transport +
UDP/WebSocket multiplex bind), with a config surface byte-compatible with the `wireguard-tools` fork.

**Status:** implemented as described in [`ARCHITECTURE.md`](ARCHITECTURE.md) and validated on
`wgws-win11`, including the MSI installed next to the official client. Code signing is still to do
(decision 9).

### Agreed decisions

| # | Topic | Decision |
|---|---|---|
| 1 | Backend | **Per-tunnel dual backend.** A config with at least one WebSocket peer runs in the tunnel service on the wireguard-go fork in userspace over **Wintun**; pure-UDP configs stay on WireGuardNT, unchanged. This resurrects the pre-v0.5 userspace path (last present at `94949cd7`, removed in `548405e2`), which upstream once shipped side by side with WireGuardNT. |
| 2 | Keeping the carrier off the tunnel | A **host route** (`/32` or `/128`) to each WebSocket peer's resolved endpoint via the current non-tunnel default gateway (lowest-metric default route excluding the tunnel), moved on default-route changes followed by a carrier re-dial (`BindUpdate`). Lives in this repo, like wg-quick on macOS. `IP_UNICAST_IF` does **not** work for the TCP carrier (spike T3/T4). Traffic from other processes to that IP is not tunnelled; with the kill switch active, WFP still blocks it. |
| 3 | Config surface | Mimic the Android/Apple forks: the 11 client-only `[Peer]` keys (`WSMode`, `WSTunnelTarget`, `WSBearer`, `WSMask`, `WSTLSCA`, `WSTLSCert`, `WSTLSKey`, `WSTLSInsecure`, `WSPingInterval`, `WSBackoffMin`, `WSBackoffMax`) plus `ws://`/`wss://` URLs in `Endpoint`; device-level server keys (`WSListen`, `WSServer*`, `WSTrustedProxies`) are rejected. |
| 4 | Where Android and Apple differ | The **wireguard-tools fork** is the tie-breaker: user/password in the URL **rejected** (the transport never sends it — authentication is `WSBearer`: `Bearer` for websocket, `Basic` base64 `user:pass` for wstunnel); query without a path rejected; a repeated key keeps the last value; timings are uint32 milliseconds (0 = default); `transport=` is emitted for every peer in the UAPI. |
| 5 | TLS files, UI-managed tunnels | On import, zip import (certificates inside the zip are resolved), and editor save, referenced certificate/key files are read by the UI, sent to the manager, and stored **DPAPI-encrypted** in the protected data directory with the paths rewritten to bare file names; the user is told the files were copied. The tunnel service decrypts them into a SYSTEM-only location at start and removes them at stop. They are deleted with the tunnel, carried over on rename, and included in zip export. |
| 6 | TLS files, on-disk tunnels | For `/installtunnelservice C:\path\x.conf`, certificate paths are used **in place** (like wg-quick); **UNC/network and relative paths are rejected**. |
| 7 | Identity | Branded **"WireGuard WS"** and installable **alongside** the official client: services `WireGuardWSManager` and `WireGuardWSTunnel$<name>`, data directory `%ProgramFiles%\WireGuard WS\Data`, registry key `HKLM\Software\WireGuard WS`, window title and management window class; MSI product "WireGuard WS" with its own codes, folder and publisher (Daniele Salvatore Albano), also in the executable's version information. The updater stays inactive. |
| 8 | Packaging | `wintun.dll` embedded like `wireguard.dll`; `wg.exe` built from the wireguard-tools fork; zip distribution first, the WiX MSI as the very last step. `tunnel.dll` is out of scope. |
| 9 | CI / signing | GitHub Actions on `windows-latest` for the entire flow; code signing added later. |
| 10 | Prerequisite | wireguard-go fork **v1.3.1** (released): asynchronous WebSocket dial, so a dial in flight no longer blocks `BindUpdate`/`Close` for up to 15 s (found by spike T5; affects every platform using the fork). |
| 11 | End-to-end | Driven over SSH on `wgws-win11` against the user's live wstunnel server, with the user's test configs kept out of the repo. |

### Spike results (2026-09-24)

A throwaway probe (wireguard-go fork v1.3.0 + Wintun 0.14.1 + this repo's `winipcfg`) was run as a
SYSTEM scheduled task on `wgws-win11` against the live wstunnel server.

| Test | Result |
|---|---|
| T1 — SSH admin session is elevated and can manage services | Pass (High integrity, SCM create/delete) |
| T2 — Split tunnel (`192.168.178.0/24`) over wstunnel | Pass on re-run (LAN gateway reached through the tunnel; the first run lost data after the handshake, cause not determined) |
| T3 — Full tunnel, carrier pinned with `IP_UNICAST_IF` | Fail: after the routes went live the carrier connected from the tunnel address and looped |
| T3b — Full tunnel, host route to the server | Pass: carrier on the physical NIC, 5 MB through the tunnel |
| T4 — Full tunnel, no protection (control) | Fail as expected (same loop as T3) |
| T5 — Network switch (NIC1 down, then up) with the host route | Pass both ways; `BindUpdate` blocked ~15 s on link loss (→ decision 10) |
| T6 — Official 1.1.1 MSI + `/installtunnelservice` headless over SSH | Pass |

Also learned: `winipcfg` routes must be set before addresses (the route flush races the automatic
routes of a new address); the UDP `BindSocketToInterface` pin only works after `Device.Up`; Wintun
0.14.1 and WireGuardNT 1.1 install under Secure Boot (both drivers are Microsoft-signed).

### Settled during implementation

- Runtime stats for userspace tunnels come from the device's UAPI over its named pipe (`manager/ipc_uapi.go`,
  `conf.FromUAPI`), chosen by whether the stored config has a WebSocket peer.
- The UDP sockets of a userspace tunnel are pinned to the default-route interface with `IP_UNICAST_IF`,
  re-pinned after every re-dial, and blackholed when the tunnel carries a default route and there is no
  other one.
- Stored TLS file references are bare file names (see decision 5).

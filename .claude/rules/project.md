# wireguard-windows — Project Rules

This repo is **wireguard-windows**, built as **WireGuard WS**: the [WireGuard](https://www.wireguard.com/)
client for Windows — a single Go program, `wireguard.exe`, that runs in several roles (a manager
service, one service per tunnel, and an unprivileged UI) and drives the **WireGuardNT** kernel driver
(shipped prebuilt and Microsoft-signed inside `wireguard.dll`, embedded as a resource) or, for tunnels
with a WebSocket peer, the **wireguard-go fork** over **Wintun** (`wintun.dll`, embedded). Tunnel
configurations are stored DPAPI-encrypted under `%ProgramFiles%\WireGuard WS\Data`. It is built with the Go toolchain +
mingw resources via `build.bat` (Windows) or the `Makefile` (Linux cross-build) and packaged as an MSI
with WiX.

> **STATUS: this is a FORK of upstream `WireGuard/wireguard-windows`** (`origin` =
> `github.com/danielealbano/wireguard-windows`, default branch `main`; `upstream` =
> `github.com/WireGuard/wireguard-windows`, branch `master`), based on upstream 1.1.1 (`6ece77bc`).
> **"WireGuard WS"** — per-peer **WebSocket/wstunnel transport** with parity with the user's
> `wireguard-android` / `wireguard-apple` forks — is implemented: WebSocket configs run on the sibling
> **`danielealbano/wireguard-go` fork v1.3.1** in userspace over **Wintun**, pure-UDP configs stay on
> WireGuardNT. Decisions, status and what remains (code signing) are in `docs/PROJECT.md` →
> WireGuard WS. The canonical docs MUST be kept current as decisions land.

## MANDATORY: Read These First

You MUST ALWAYS read these before ANY work, in this order:

1. **`docs/PROJECT.md`** — what the app is, fork status and roadmap decisions, tech stack, repository
   layout, process roles, config model and storage, build/packaging, development environment, testing.
2. **`docs/ARCHITECTURE.md`** — processes and privilege boundaries, tunnel bring-up, runtime stats
   path, config data model, firewall/routing, build pipeline, and where WireGuard WS lands (Mermaid).
3. The upstream reference docs it points to: `docs/attacksurface.md`, `docs/netquirk.md`,
   `docs/adminregistry.md`, `docs/enterprise.md`, `docs/buildrun.md`.

You MUST ALSO follow, per the Rule Map below: `agent.md`, `development_pipeline.md`, `go.md` (all Go
code), `windows.md` (Windows platform), `ui.md` (the desktop UI), and `github.md`. It is ABSOLUTELY
MANDATORY to pass ALL quality gates before any work is considered done.

This rule file MUST stay accurate but CONCISE — it references the canonical docs, it does NOT
duplicate them.

---

## Tech Stack (current)

Versions are authoritative in `go.mod`, `Makefile`, `build.bat`, `installer/build.bat`, and
`version/version.go`. Re-verify before bumping.

| Concern | Choice | Notes |
|---|---|---|
| Language | **Go** (pure Go, NO cgo in the main module) | Module `golang.zx2c4.com/wireguard/windows`, `go 1.26.5` directive (required by the wireguard-go fork); the build scripts download and pin **Go 1.27.1** (SHA-256 verified). |
| Kernel driver | **WireGuardNT 1.1** (`wireguard-nt-1.1.zip`) | Prebuilt `wireguard.dll` (WireGuard LLC EV-signed; embedded `.sys` Microsoft-signed) embedded as `RCDATA` and loaded in-memory (`driver/memmod`, build tag `load_wgnt_from_rsrc`). UDP-only tunnels. |
| Userspace backend | **`danielealbano/wireguard-go` v1.3.1** over **Wintun 0.14.1** | `replace golang.zx2c4.com/wireguard` in `go.mod`; `wintun.dll` embedded as `RCDATA`, loaded in-memory by the `wintun/` copy of the bindings (`replace golang.zx2c4.com/wintun => ./wintun`, build tag `load_wintun_from_rsrc`). Tunnels with a WebSocket peer. |
| UI | **lxn/walk** + **lxn/win** (Win32) | Replaced by upstream-maintained forks (`golang.zx2c4.com/wireguard/windows` `pkg/walk` / `pkg/walk-win`) in `go.mod`. Raw-text config editor with a Go syntax highlighter (`ui/syntax`). |
| Windows APIs | `golang.org/x/sys/windows`, mkwinsyscall-generated bindings (`zsyscall_windows.go`, `zwinipcfg_windows.go`) | WFP firewall (`tunnel/firewall`), IP Helper (`tunnel/winipcfg`), SCM services, DPAPI (`conf/dpapi`). |
| Stdlib overlay | none | Upstream's `.overlay/` (stubs of the standard library crypto applied with `go build -overlay`) was removed: it cannot build `crypto/tls`, which `wss://` needs. |
| Localization | `golang.org/x/text/message` catalogs | `locales/*/messages.gotext.json` (Crowdin-managed) → generated `zgotext.go` via `go generate`; `l18n.Sprintf`. |
| CLI tool | `wg.exe` from the **`danielealbano/wireguard-tools` fork** | `build.bat` builds it from the fork pinned at `68b49a93` (GitHub archive, SHA-256 verified) with llvm-mingw. |
| Installer | **WiX 3.14.1** MSI (`installer/`) | Windows-only build; C custom actions (`customactions.c`); per-arch `UpgradeCode`s; `installer/fetcher` bootstrapper (upstream's, not built). Product "WireGuard WS", publisher Daniele Salvatore Albano, own `UpgradeCode`s; output `installer\dist\wireguard-ws-<arch>-<version>.msi`. |
| Build | `build.bat` (Windows, canonical: x86/amd64/arm64 + `wg.exe`) / `Makefile` (Linux cross-build of `wireguard.exe`) | llvm-mingw 20260311 on Windows; Ubuntu `mingw-w64` on Linux (no aarch64 → arm64 not buildable on the Linux host). |
| Tests / CI | Windows-only Go tests; **GitHub Actions on `windows-latest`** (`.github/workflows/ci.yml`) | See Testing. |

---

## Hard Project Invariants — ABSOLUTE RULES

- **THE PRIVILEGE MODEL IS SACRED** (`docs/attacksurface.md`): the manager service
  (`WireGuardWSManager`, LocalSystem) and the per-tunnel services (`WireGuardWSTunnel$<name>`, LocalSystem,
  unrestricted service SID, privileges dropped after the firewall is up) do all privileged work; the UI
  runs with dropped privileges and talks ONLY to the manager over the inherited-pipe gob IPC; operator
  (non-admin) sessions get redacted configs and no mutating operations. You MUST NOT weaken any of it.
- **THE KILL-SWITCH AND ROUTING SEMANTICS ARE SACRED** (`docs/netquirk.md`): the WFP dynamic session,
  the permit rule scoped to the tunnel service's app ID + service SID, and the block-all/permit rules
  MUST keep their documented behaviour.
- **CONFIG STORAGE**: tunnel configs are `.conf.dpapi` files in the SYSTEM/Administrators-only
  `%ProgramFiles%\WireGuard WS\Data\Configurations` (`conf/store.go`, `conf/path_windows.go`), their
  WebSocket TLS files DPAPI-encrypted in `Data\WebSocketTLS\<tunnel>` and decrypted for SYSTEM only
  while the tunnel runs (`conf/wstls_store.go`); an admin may also run a tunnel from an on-disk `.conf`
  with `/installtunnelservice` (read in place at every start; TLS files by absolute local path only).
  Key material, bearers and TLS keys MUST NEVER be logged, shown to operator sessions, or written
  elsewhere.
- **IDENTITY**: WireGuard WS installs alongside the official client — its service names, data directory,
  `HKLM\Software\WireGuard WS` key, window class and MSI codes MUST stay distinct from upstream's.
- **THE CONFIG MODEL IS A CONTRACT**: `conf` parses/serializes wg-quick text (`FromWgQuick`/`ToWgQuick`,
  unknown keys REJECTED, WebSocket keys validated exactly like the Android/Apple forks), converts to the
  WireGuardNT binary IOCTL layout (`ToDriverConfiguration`/`FromDriverConfiguration`), which MUST match
  `wireguard.h` of the pinned WireGuardNT release, and to the wireguard-go UAPI (`ToUAPI`/`FromUAPI`),
  which MUST match the pinned fork.
- **DRIVER PACKAGES**: ONLY the unmodified, WireGuard LLC-signed prebuilt DLLs are used (WireGuardNT
  `wireguard.dll`; Wintun `wintun.dll`), through their published headers only.
  Their "Prebuilt Binaries License" forbids modifying/extracting them and allows redistribution only
  alongside software using the published API. This project NEVER builds or signs drivers.
- **THE BUILD MUST NOT BREAK** for x86, amd64, and arm64 via `build.bat`; generated files
  (`zgotext.go`, `zsyscall_windows.go`, `zwinipcfg_windows.go`) MUST be regenerated, never hand-edited.
- **THE UPDATER MUST STAY INACTIVE FOR THIS FORK**: it only runs when the executable is signed with the
  official WireGuard LLC certificate (`version.IsRunningOfficialVersion`); it MUST NEVER be pointed at
  or enabled for this fork's builds.
- **NO SECRETS IN LOGS OR COMMITS**: private/preshared keys, bearer tokens, and the live-server test
  configs (kept by the user outside the repo) MUST NEVER be logged or committed.
- Keep it SIMPLE and consistent with the existing upstream code style.

---

## Documented exceptions (referenced by `go.md` / `windows.md`)

- **Upstream code is the style reference.** `go.md` §1 constructor DI / functional options and
  `context.Context`-first apply to NEW packages and types; changes inside existing upstream packages
  MUST follow the surrounding code's idioms. You MUST NOT refactor upstream code to these patterns
  unless a plan explicitly calls for it.
- **Configuration is NOT environment variables**: `wireguard.exe` is a Windows service/desktop program
  configured through its command-line verbs, the DPAPI config store, and the `HKLM\Software\WireGuard WS`
  policy knobs (`conf.AdminBool`, `docs/adminregistry.md`). The `go.md` env-var configuration rule does
  NOT apply.
- **No cgo in the main module** → the `go.md` cross-compiled cgo exemption does not apply. Only the
  `-race` tests use cgo, with the llvm-mingw toolchain `build.bat` downloads.
  `embeddable-dll-service/` (`tunnel.dll`, c-shared `//export`) is OUT OF SCOPE; if ever touched, its
  exports are a fixed foreign ABI consumed by embedding applications.
- **Tests run on Windows only**: every package imports `golang.org/x/sys/windows`, so no test compiles
  for a non-Windows host; "host-testable" means runnable on the Windows test machine (see Testing).
- **Testcontainers do NOT apply**: there is no external-service infrastructure; end-to-end behaviour is
  validated on a Windows VM against the user's live WireGuard/wstunnel server (see Testing).
- **Upstream code stays as is (decided 2026-09-24).** This fork makes ONLY the changes the WireGuard WS
  flow strictly needs. The gates (`gofmt`, `go vet`, tests) apply to the code and tests this fork ADDS or
  CHANGES; upstream's pre-existing `go vet` findings (113 at 1.1.1) and its broken, manual or
  environment-dependent tests (`ringlogger`, `updater`, `updater/winhttp`, `version`, `tunnel/winipcfg`)
  are left untouched and are NOT gates. You MUST NOT fix, refactor or "clean up" upstream code that the
  change does not require. **golangci-lint is NOT used** (no committed config), so the `go.md`
  golangci-lint requirement does NOT apply. 32-bit (x86) is built by `build.bat` but not checked.
  `wintun/` is a copy of the upstream `wintun-go` bindings: only its DLL loader is the fork's code, and
  CI's `go vet` gate excludes it.

---

## Non-goals (MUST NOT build unless the user EXPLICITLY asks)

- Do NOT re-architect the process/privilege model, replace the UI toolkit (no new UI framework, no C#
  UI), or change config storage. Do NOT implement the WebSocket **transport** here — it belongs to the
  `wireguard-go` fork; this repo consumes it and adds config/UI/platform support. Do NOT touch
  `embeddable-dll-service/` (out of scope). Do NOT build or sign drivers. Do NOT enable the updater.
  Do NOT add lint/format tooling, CI, or test harnesses beyond what was agreed — tooling decisions
  require the user.

---

## Commit Scopes

All commits MUST use one of the scopes below. A commit spanning multiple scopes uses `app`.

| Scope | Applies to |
|---|---|
| `app` | Cross-cutting changes and anything without its own scope (incl. `main.go`) |
| `ui` | `ui/` (windows, editor, syntax highlighter, tray) |
| `manager` | `manager/` (manager service, IPC server/client, tunnel tracking) |
| `tunnel` | `tunnel/` (tunnel service, address/route config, firewall, winipcfg) |
| `conf` | `conf/` (config model, parser/writer, store, DPAPI, admin knobs) |
| `driver` | `driver/` (WireGuardNT bindings, memmod), `wintun/` (Wintun bindings) |
| `updater` | `updater/`, `version/` |
| `l18n` | `l18n/`, `locales/`, `zgotext.go`, `gotext.go` |
| `build` | `Makefile`, `build.bat`, `resources.rc`, `manifest.xml`, `quickinstall.bat` |
| `installer` | `installer/` |
| `docs` | `docs/` (PROJECT, ARCHITECTURE, upstream docs, plans) |
| `deps` | Dependency-only updates (`go.mod`/`go.sum`, pinned downloads) |
| `ci` | CI and release workflows (`.github/workflows/`) |

```
feat(conf): parse the WSMode and WSTunnelTarget peer keys
```

---

## Standard Commands

There is NO wrapper beyond the existing scripts; invoke them directly. `build.bat` is the CANONICAL
build (and the one CI uses); the `Makefile` is the Linux development build, whose `windres` step fails
with Ubuntu's GNU `windres` (it rejects `LANG_PERSIAN` in `resources.rc`, upstream too).

| Task | Command |
|---|---|
| Build (Windows, canonical — x86/amd64/arm64 + `wg.exe`) | `build.bat` (from the repo root on Windows) |
| Build (Linux dev, amd64) | `make amd64/wireguard.exe` (also `x86/wireguard.exe`; needs `mingw-w64`, `libarchive-tools`, ImageMagick) |
| Deploy to the test VM | `make deploy DEPLOYMENT_HOST=wgws-win11` (copies `amd64/wireguard.exe` to the VM Desktop) |
| Format | `make fmt` (Linux) / `gofmt -l .` must print nothing |
| Vet | `GOOS=windows GOARCH=<amd64\|arm64> go vet <changed packages>` — no findings on lines changed since `6ece77bc` (CI's `go vet` step checks exactly that) |
| Regenerate catalogs/bindings | `make generate` (Linux) / `set GoGenerate=yes` + `build.bat` (Windows) |
| Tidy | `go mod tidy` (MUST produce NO `go.mod`/`go.sum` diff) |
| Vulncheck | `go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...` (with `GOOS=windows`; the version CI pins) |
| Tests | on Windows, elevated, with `.deps\go\bin` and `.deps\bin` on `PATH`: `set CGO_ENABLED=1` + `set CC=x86_64-w64-mingw32-gcc` + `go test -race -count=1 -tags integration ./conf ./ui/syntax ./tunnel` (add any other changed package) |
| Installer (Windows only) | `installer\build.bat` |
| Release | bump `Number` in `version/version.go` (follows the embedded wireguard-go fork), merge, push tag `v<Number>` → `release.yml` drafts the GitHub release |
| Mermaid check | validate all Mermaid blocks under `docs/` per `development_pipeline.md` §9 |

**Quality gates** (per `development_pipeline.md` §2, `go.md`, `windows.md`, `ui.md`, scoped by the
"Upstream code stays as is" exception): a clean canonical build, `gofmt` clean and no NEW `go vet`
findings in the code this fork changes, `go mod tidy` with NO diff, `govulncheck` clean, the fork's
new/changed tests passing ON Windows, and Mermaid validation (when charts were touched). Changes to
the tunnel, manager or UI flows are also validated end to end on the Windows VM (see Testing).

---

## Testing — ABSOLUTE (project-specific)

- Go tests (Windows-only): `conf/parser_test.go`, `conf/websocket_test.go`, `conf/wstls_test.go`,
  `conf/store_test.go` (upstream, untagged) and `conf/wstls_store_test.go` (`integration` tag), which write to the real Program
  Files store), `conf/dpapi/dpapi_windows_test.go`, `ringlogger/cli_test.go`,
  `tunnel/defaultroutemonitor_test.go`, `tunnel/firewall/types_windows_test.go`,
  `tunnel/winipcfg/{types_test,winipcfg_test}.go` (`winipcfg_test` needs elevation and a specially named
  adapter), `ui/syntax/highlighter_test.go`, `updater/{updater_test, winhttp/winhttp_test}.go` (need
  the official signature/network), `version/certificate_test.go`. There are NO tests for `manager/`,
  `driver/`, or the walk UI.
- **Test machine**: the developer-local Windows 11 VM `wgws-win11` (libvirt `qemu:///system`, SSH alias
  `wgws-win11`, elevated admin session; NIC1 MAC `52:54:00:77:67:01` on `default`, NIC2 MAC
  `52:54:00:77:67:02` on `wgws-alt`; NIC1's link is toggled with `virsh domif-setlink` to simulate a
  network switch). Its provisioning, the WireGuard WS spike probe, the VM test scripts, and all spike
  logs live OUTSIDE the repo in `/home/daalbano/dev/wireguard-windows-spike/` and on the VM in
  `C:\wgws\` — both MUST be kept intact.
- **End-to-end**: run on the VM over SSH against the user's live wstunnel server (split and full tunnel,
  handshake + traffic through the tunnel, network switch, teardown, and the UI flows driven in the
  console session). The user decided (2026-09-24) that NO e2e script is committed: scratch scripts stay
  outside the repo. The live test configs are provided by the user outside the repo and MUST NEVER be
  committed.
- **CI**: GitHub Actions on `windows-latest` (`.github/workflows/ci.yml`): `build.bat`, `gofmt`,
  `go mod tidy`, `go vet` on changed lines, the race tests, `govulncheck`, `installer\build.bat`,
  per-architecture and MSI artifacts; signing later.

---

## Key Conventions

- **All tunnel control flows UI → manager IPC → SCM → tunnel service**; the UI never talks to tunnel
  services or the driver. Runtime stats: manager → driver (`ipc_driver.go`) → `FromDriverConfiguration`,
  or for a tunnel with a WebSocket peer manager → UAPI pipe (`ipc_uapi.go`) → `FromUAPI`.
- **User-facing strings** via `l18n.Sprintf` + regenerated catalogs; **admin knobs** via
  `conf.AdminBool` (documented in `docs/adminregistry.md`); **logging** via `log.Printf` into the
  shared ring log (`ringlogger`), NEVER key material.
- **Service errors** use the typed codes in `services/errors.go`.
- **Configuration-rendering UI surfaces** (all MUST change together when keys are added):
  `ui/syntax/highlighter.go` (keyword enum + value validators), `ui/editdialog.go` (raw editor + the
  kill-switch toggle, which re-serializes via `ToWgQuick`), `ui/confview.go` (peer detail rows).
- **Windows bindings** are declared in `mksyscall.go` files (`tunnel/firewall`, `tunnel/winipcfg`,
  `updater/winhttp`) and generated into `zsyscall_windows.go` / `zwinipcfg_windows.go`.

---

## Rule Map

| Concern | Rule file |
|---|---|
| Agnostic agent behavior, git, plans, reviews, subagents | `agent.md` |
| Plan-driven development pipeline (write → review → implement → PR) + Mermaid validation | `development_pipeline.md` |
| Go — idioms, concurrency, errors, testing, gates (agnostic) | `go.md` |
| Windows — build, services/privileges, IPC security, networking, drivers, packaging, signing (agnostic) | `windows.md` |
| Desktop UI — privilege, threading, localization, secrets, editors (agnostic) | `ui.md` |
| GitHub (`gh` CLI, branches, PRs) (tooling) | `github.md` |
| Project context (this file) | `project.md` |

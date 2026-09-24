# Windows Platform Rules — ABSOLUTE RULES

These rules govern the **Windows-platform build, services and privilege model, IPC, local security,
networking, kernel components, configuration, packaging, signing, and release** in ANY Windows
project where this file is present. They are **VERY STRICT and ABSOLUTELY NON-NEGOTIABLE**. They are
AGNOSTIC: project-specific details (processes, service names, paths, registry keys, driver packages,
architectures, command surface, documented exceptions) live in `project.md` and the canonical docs it
references. When a rule below allows a "documented exception", that exception MUST be documented in
`project.md` — otherwise it does not exist. Language specifics live in `go.md`; desktop UI specifics
in `ui.md`.

## 1) Build System & Toolchain — ABSOLUTE RULES

- The project's build scripts (see `project.md`) are authoritative. You MUST build through them; you
  MUST NOT invent parallel build paths, scripts, or competing build files.
- Every toolchain or third-party artifact a build script downloads MUST be pinned to an exact version
  AND verified by a cryptographic hash (or a verified signature). You MUST NEVER add an unpinned or
  unverified download. A bump MUST update the version and the hash together.
- Where the project supports more than one build host (e.g. a native Windows build and a
  cross-compiled build from another OS), `project.md` MUST state which one is canonical. A change MUST
  keep EVERY supported architecture building via the canonical build.
- Windows resources (application manifest, icons, version information, embedded binaries) MUST be
  produced by the project's resource pipeline; version information MUST come from the project's
  single documented version source — never hardcoded per artifact.
- The application manifest (requested execution level, DPI awareness, supported-OS entries) is a
  contract: you MUST NOT change it without the user's explicit approval.
- Generated code (e.g. system-call bindings, message catalogs) MUST be regenerated with the project's
  generator commands and MUST NEVER be hand-edited; the committed generated files MUST match their
  generators.

## 2) Services, Processes & Privilege Separation — ABSOLUTE RULES

- Privileged work MUST run in Windows services under the account `project.md` documents; interactive
  UI processes MUST run with the least privilege the documented model allows. You MUST NEVER move a
  privileged operation into a UI process, and you MUST NEVER widen a process's privileges beyond the
  documented model.
- Services MUST handle Service Control Manager requests (stop, shutdown, and any control they
  register) promptly, report accurate status, and clean up EVERYTHING they created (adapters,
  routes, addresses, DNS settings, firewall filters, temporary files, decrypted material) on EVERY
  exit path, including failures and crashes they can observe.
- Where the documented model drops privileges after start-up, that drop MUST stay in place and MUST
  happen as early as possible; you MUST NOT re-add privileges.
- Service identity (service names, display names, service SIDs, dependencies, start types, recovery
  settings) is an install/upgrade contract: changes MUST be deliberate, approved, and handled by the
  install, upgrade, and uninstall paths.
- Elevation MUST happen only through the documented mechanism (UAC or a privileged service). You MUST
  NEVER bypass UAC or add an auto-elevation path.
- Every IPC boundary between privilege levels MUST authenticate and authorize the caller (token
  membership, session, pipe/object security) and MUST treat all input from the less-privileged side
  as untrusted: validate it at the boundary, in the privileged process.

## 3) IPC & Local Security — ABSOLUTE RULES

- Named pipes, shared memory, files, and other IPC objects MUST carry an explicit security descriptor
  granting ONLY the required principals. A client MUST verify the server's identity (e.g. the expected
  object owner) before sending it secrets.
- Directories holding secrets MUST have explicit, restrictive ACLs (e.g. SYSTEM + Administrators only),
  applied at creation and re-verified; code creating or opening them MUST defend against reparse
  points/junctions and path swaps (TOCTOU).
- A privileged process MUST NEVER open a path supplied by a less-privileged principal without
  validation. Network/UNC paths (`\\host\share\…`, `\\?\UNC\…`) MUST be rejected — opening them makes
  the machine account authenticate to a remote host — and relative paths MUST be rejected. Prefer
  having the less-privileged side read the file and pass its CONTENTS over the authenticated IPC.
- DLL loading MUST be restricted to trusted locations (restricted default DLL directories and
  `LOAD_LIBRARY_SEARCH_*`-style flags). You MUST NEVER rely on the default search order or the current
  directory.
- Secrets at rest MUST be encrypted with the platform data-protection API (DPAPI or the project's
  documented equivalent) AND stored in an ACL-restricted location. Decrypted secrets MUST only ever be
  written where solely the consuming privileged principal can read them, and MUST be removed as soon
  as they are no longer needed.
- Secrets (private/preshared keys, bearer tokens, passwords, certificate private keys) MUST NEVER be
  logged, displayed to less-privileged principals, or included in error messages.

## 4) Networking & Kernel Components — ABSOLUTE RULES

- Runtime network configuration (addresses, routes, DNS, interface metrics, MTU) MUST use the
  platform's supported APIs (IP Helper) with deterministic cleanup on every exit path. You MUST NOT
  shell out to `netsh`, `route`, or similar tools for runtime configuration.
- Firewall state (WFP filters) MUST be scoped so it cannot outlive its owner unexpectedly (e.g.
  dynamic sessions) or MUST be removed explicitly. Permit rules MUST be as narrow as possible (app ID,
  service SID, protocol, address) and MUST NOT weaken the project's documented kill-switch semantics.
- ANY route or firewall change that lets traffic bypass a tunnel (e.g. a host route to a relay
  server) is a security decision: it MUST be agreed with the user and documented in the canonical
  docs.
- Socket-option and routing semantics are EXTERNAL CLAIMS (see `agent.md` §1bis): they MUST be
  verified per protocol and per platform before being relied on (behaviour valid for UDP is NOT
  automatically valid for TCP).
- Kernel drivers: the project MUST NOT build, sign, or ship its own kernel drivers unless the user
  EXPLICITLY decides so. Only the vendor's prebuilt, Microsoft-signed driver packages MAY be used,
  UNMODIFIED, through their published API/headers, within their license terms (which MUST be recorded
  in `project.md`). Driver and adapter installation/removal MUST be clean and idempotent.

## 5) Configuration & Policy — ABSOLUTE RULES

- Administrator policy knobs MUST live in the project's documented registry location, MUST be
  read-only for the application, and MUST be documented in the canonical docs. Adding a knob REQUIRES
  the user's approval; the uninstaller MUST remove only what the project documents.
- Per-machine state and per-user state MUST NOT be mixed: machine-wide configuration belongs to the
  privileged side; per-user preferences MUST NOT alter machine-wide behaviour.

## 6) Packaging, Installer & Upgrade — ABSOLUTE RULES

- The installer (e.g. an MSI) is a contract: product/upgrade codes, component identities, install
  paths, service registration, and custom actions MUST stay stable unless the user approves a change.
  Upgrade AND uninstall MUST remain correct (services, adapters/drivers, and data removed exactly per
  the documented policy).
- Custom actions MUST be minimal, MUST follow the same signing rules as the main binaries, and MUST
  NOT perform network access.
- Every distribution artifact (installer, archive) MUST be produced from the standard build commands
  with NO manual steps.

## 7) Code Signing & Release — ABSOLUTE RULES

- When signing is configured, every shippable executable, library, installer, and custom action MUST
  be Authenticode-signed AND timestamped. Unsigned builds MUST behave per the project's documented
  unofficial-build behaviour (e.g. update mechanisms disabled).
- Signing material (certificates, private keys, tokens, HSM/cloud-signing credentials) MUST NEVER be
  committed or logged; it MUST come from CI secrets or the signing service.
- Third-party prebuilt signed binaries MUST be redistributed UNMODIFIED and verified (hash and/or
  signature) at build time.
- CI/release automation MUST use the project's standard commands, MUST NOT print secrets, and MUST be
  extended deliberately — you MUST NOT add parallel/competing workflows or signing paths.

## 8) Testing (platform level) — ABSOLUTE RULES

- Windows-specific code MUST be tested ON Windows (a VM or a Windows CI runner). Cross-compiling is a
  build check, NOT a test.
- Tests that need elevation, drivers, adapters, routes, firewall changes, or services are integration
  or end-to-end tests: they MUST be separated from unit tests as `go.md`/`project.md` define, MUST
  restore the machine's state (remove adapters, routes, filters, services) even on failure, and MUST
  NEVER modify the developer's host network configuration.
- End-to-end tests against live infrastructure run ONLY as `project.md` documents; their credentials
  and configs MUST NEVER be committed or printed.
- Remote test machines MUST be driven only through the mechanism `project.md` documents, and any state
  a test changes on them (links, adapters, services) MUST be restored.

## 9) Quality Gates — ABSOLUTE RULES

A change touching a Windows project is DONE **ONLY** if ALL are true:

- The canonical build succeeds for EVERY supported architecture via the standard commands in
  `project.md`, with NO new compiler/linker/resource warnings.
- Static analysis passes per `go.md` and the gates in `project.md`.
- The tests defined in `project.md` pass ON Windows.
- Installer/archive builds succeed when packaging was touched.
- No new privileges, services, IPC endpoints, firewall permits, routes that bypass a tunnel, registry
  knobs, drivers, dependencies, or signing paths beyond what was agreed with the user.
- Mermaid charts (if any docs were touched) validate per `development_pipeline.md` §9.

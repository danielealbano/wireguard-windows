# WireGuard WS — WireGuard for Windows with WebSocket/wstunnel support

> **Unofficial fork — not the official WireGuard client.** This is based on the official
> [WireGuard for Windows](https://www.wireguard.com/) client and adds support for tunnelling
> WireGuard over **WebSocket / wstunnel**, so you can reach a server on networks that block plain UDP.
>
> It installs as its own product, "WireGuard WS" (its own services, data directory, registry key and
> MSI), and can be installed alongside the official WireGuard client.

## WebSocket / wstunnel support

A peer uses the WebSocket path when its `Endpoint` is a `ws://` or `wss://` URL and it sets `WSMode`
(`websocket` or `wstunnel`); the other WebSocket keys are `WSTunnelTarget`, `WSBearer`, `WSMask`,
`WSTLSCA`, `WSTLSCert`, `WSTLSKey`, `WSTLSInsecure`, `WSPingInterval`, `WSBackoffMin` and
`WSBackoffMax`. A tunnel with a WebSocket peer runs on the userspace implementation over
[Wintun](https://www.wintun.net/); UDP-only tunnels keep using
[WireGuardNT](https://git.zx2c4.com/wireguard-nt/about/) unchanged. TLS files referenced by a tunnel
are copied, encrypted, into the tunnel store when the configuration is imported or saved.

The client only *consumes* the transport — running it **requires the matching forks**:

- **wireguard-go fork** — <https://github.com/danielealbano/wireguard-go> — the userspace core that
  implements the WebSocket/wstunnel transport, built into `wireguard.exe`.
- **wireguard-tools fork** — <https://github.com/danielealbano/wireguard-tools> — the byte-compatible
  `wg`/`wg-quick` config surface, used for the bundled `wg.exe` and for the server side.

## Download &amp; Install

The installers (`wireguard-ws-<arch>-<version>.msi`) and zips of `wireguard.exe` and `wg.exe` for
x86, amd64 and arm64 are attached to the
[GitHub releases](https://github.com/danielealbano/wireguard-windows/releases). The releases are not
code-signed yet, so Windows SmartScreen warns before running them.

## Building

On Windows, `build.bat` downloads a pinned toolchain and builds `wireguard.exe` and `wg.exe` for every
architecture; `installer\build.bat` then builds the MSIs. See [`docs/PROJECT.md`](docs/PROJECT.md) for
details.

## Documentation

In addition to this [`README.md`](README.md), the following documents are also available:

- [`PROJECT.md`](docs/PROJECT.md) &ndash; What WireGuard WS is, its decisions, build, packaging and testing.
- [`ARCHITECTURE.md`](docs/ARCHITECTURE.md) &ndash; How the processes, the WireGuardNT and userspace paths, the configuration and the build fit together.
- [`adminregistry.md`](docs/adminregistry.md) &ndash; A list of registry keys settable by the system administrator for changing the behavior of the application.
- [`attacksurface.md`](docs/attacksurface.md) &ndash; A discussion of the various components from a security perspective, so that future auditors of this code have a head start in assessing its security design.
- [`buildrun.md`](docs/buildrun.md) &ndash; Instructions on building, localizing, running, and developing for this repository.
- [`enterprise.md`](docs/enterprise.md) &ndash; A summary of various features and tips for making the application usable in enterprise settings.
- [`netquirk.md`](docs/netquirk.md) &ndash; A description of various networking quirks and "kill-switch" semantics.

## License

This repository is MIT-licensed.

```text
Copyright (C) 2018-2026 WireGuard LLC. All Rights Reserved.

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
```

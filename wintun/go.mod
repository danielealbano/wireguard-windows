// The golang.zx2c4.com/wintun bindings (git.zx2c4.com/wintun-go at 0fa3db229ce2), extended to
// load wintun.dll from RCDATA with the load_wintun_from_rsrc tag. See docs/PROJECT.md.

module golang.zx2c4.com/wintun

go 1.26.0

require (
	golang.org/x/sys v0.48.0
	golang.zx2c4.com/wireguard/windows v0.0.0-00010101000000-000000000000
)

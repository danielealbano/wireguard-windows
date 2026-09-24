module golang.zx2c4.com/wireguard/windows

go 1.26.5

require (
	github.com/lxn/walk v0.0.0-20210112085537-c389da54e794
	github.com/lxn/win v0.0.0-20210218163916-a377121e959e
	golang.org/x/crypto v0.57.0
	golang.org/x/sys v0.48.0
	golang.org/x/text v0.42.1-0.20260918223412-6dcc5b674302
	golang.zx2c4.com/wireguard v0.0.0-20250521234502-f333402bd9cb
)

require (
	github.com/gobwas/httphead v0.1.0 // indirect
	github.com/gobwas/pool v0.2.1 // indirect
	github.com/gobwas/ws v1.4.0 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	golang.org/x/net v0.59.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
)

require (
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/tools v0.49.0 // indirect
)

replace (
	github.com/lxn/walk => golang.zx2c4.com/wireguard/windows v0.0.0-20260420103851-857e549307fe
	github.com/lxn/win => golang.zx2c4.com/wireguard/windows v0.0.0-20210224134948-620c54ef6199
	golang.zx2c4.com/wintun => ./wintun
	golang.zx2c4.com/wireguard => github.com/danielealbano/wireguard-go v1.3.1
)

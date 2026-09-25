/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package tunnel

import (
	"net/netip"
	"reflect"
	"testing"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

const routeTestInterface = `[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
`

func routeTestConfig(t *testing.T, peers string) *conf.Config {
	t.Helper()
	c, err := conf.FromWgQuick(routeTestInterface+peers, "routes")
	if err != nil {
		t.Fatalf("FromWgQuick: %v", err)
	}
	return c
}

func TestWebSocketServerHosts(t *testing.T) {
	c := routeTestConfig(t, `
[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = wss://203.0.113.7:443/ws
WSMode = websocket

[Peer]
PublicKey = TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0=
Endpoint = ws://203.0.113.7:80
WSMode = websocket

[Peer]
PublicKey = gN65BkIKy1eCE9pP1wdc8ROUtkHLF2PfAqYdyYBz6EA=
Endpoint = wss://[2001:db8::7]:443
WSMode = wstunnel
WSTunnelTarget = 127.0.0.1:51820

[Peer]
PublicKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Endpoint = 198.51.100.1:51820

[Peer]
PublicKey = HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=
WSMode = websocket

[Peer]
PublicKey = UQuEZs0reI5GWgg2fKLhpvsGVErYChJc8RAL6PQUk/k=
Endpoint = wss://[::ffff:198.51.100.9]:443/ws
WSMode = websocket
`)
	tests := []struct {
		name   string
		family winipcfg.AddressFamily
		want   []netip.Prefix
	}{
		{name: "IPv4 servers deduplicated and unmapped, UDP and inbound peers ignored", family: windows.AF_INET, want: []netip.Prefix{netip.MustParsePrefix("203.0.113.7/32"), netip.MustParsePrefix("198.51.100.9/32")}},
		{name: "IPv6 server", family: windows.AF_INET6, want: []netip.Prefix{netip.MustParsePrefix("2001:db8::7/128")}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := webSocketServerHosts(c, tc.family)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("webSocketServerHosts() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestWebSocketServerHosts_UnresolvedHostIgnored(t *testing.T) {
	c := routeTestConfig(t, `
[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = wss://vpn.example.com:443/ws
WSMode = websocket
`)
	if got := webSocketServerHosts(c, windows.AF_INET); len(got) != 0 {
		t.Errorf("webSocketServerHosts() = %v, want none", got)
	}
}

func TestDefaultRouteMonitor_HostRouteDeleted(t *testing.T) {
	tests := []struct {
		name           string
		deleted        string
		want           bool
		wantIncomplete [2]bool
	}{
		{name: "IPv4 host route", deleted: "203.0.113.7/32", want: true, wantIncomplete: [2]bool{true, false}},
		{name: "IPv6 host route", deleted: "2001:db8::7/128", want: true, wantIncomplete: [2]bool{false, true}},
		{name: "other route", deleted: "203.0.113.0/24", want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := &defaultRouteMonitor{families: [2]defaultRouteFamily{
				{family: windows.AF_INET, hosts: []netip.Prefix{netip.MustParsePrefix("203.0.113.7/32")}},
				{family: windows.AF_INET6, hosts: []netip.Prefix{netip.MustParsePrefix("2001:db8::7/128")}},
			}}
			var route winipcfg.MibIPforwardRow2
			if err := route.DestinationPrefix.SetPrefix(netip.MustParsePrefix(tc.deleted)); err != nil {
				t.Fatalf("SetPrefix: %v", err)
			}

			got := m.hostRouteDeleted(&route)

			if got != tc.want {
				t.Errorf("hostRouteDeleted(%s) = %v, want %v", tc.deleted, got, tc.want)
			}
			for i, want := range tc.wantIncomplete {
				if m.families[i].incomplete != want {
					t.Errorf("families[%d].incomplete = %v, want %v", i, m.families[i].incomplete, want)
				}
			}
		})
	}
}

func TestHasDefaultRoute(t *testing.T) {
	tests := []struct {
		name       string
		allowedIPs string
		want4      bool
		want6      bool
	}{
		{name: "full tunnel", allowedIPs: "0.0.0.0/0, ::/0", want4: true, want6: true},
		{name: "split halves", allowedIPs: "0.0.0.0/1, 128.0.0.0/1, ::/1, 8000::/1", want4: true, want6: true},
		{name: "one half only", allowedIPs: "0.0.0.0/1, ::/1", want4: false, want6: false},
		{name: "IPv4 only", allowedIPs: "0.0.0.0/0", want4: true, want6: false},
		{name: "split tunnel", allowedIPs: "192.168.178.0/24", want4: false, want6: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := routeTestConfig(t, "\n[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nAllowedIPs = "+tc.allowedIPs+"\n")
			if got := hasDefaultRoute(windows.AF_INET, c); got != tc.want4 {
				t.Errorf("hasDefaultRoute(v4) = %v, want %v", got, tc.want4)
			}
			if got := hasDefaultRoute(windows.AF_INET6, c); got != tc.want6 {
				t.Errorf("hasDefaultRoute(v6) = %v, want %v", got, tc.want6)
			}
		})
	}
}

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"strings"
	"testing"
)

const wsTestInterface = `[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.0.0.2/32
`

const wsTestPeerKey = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="

func wsTestConfig(peerLines string) string {
	return wsTestInterface + "\n[Peer]\nPublicKey = " + wsTestPeerKey + "\nAllowedIPs = 0.0.0.0/0\n" + peerLines
}

func TestFromWgQuick_WebSocketPeer_Valid(t *testing.T) {
	tests := []struct {
		name  string
		peer  string
		check func(t *testing.T, p *Peer)
	}{
		{
			name: "websocket with all settings",
			peer: "Endpoint = wss://vpn.example.com:443/ws\nWSMode = websocket\nWSBearer = s3cret\nWSMask = true\n" +
				"WSTLSCA = C:\\certs\\ca.pem\nWSTLSCert = C:\\certs\\c.pem\nWSTLSKey = C:\\certs\\c.key\nWSTLSInsecure = false\n" +
				"WSPingInterval = 15000\nWSBackoffMin = 500\nWSBackoffMax = 30000\n",
			check: func(t *testing.T, p *Peer) {
				equal(t, WSModeWebSocket, p.WSMode)
				equal(t, "wss://vpn.example.com:443/ws", p.WSURL)
				equal(t, Endpoint{Host: "vpn.example.com", Port: 443}, p.Endpoint)
				equal(t, "s3cret", p.WSBearer)
				equal(t, true, p.WSMask)
				equal(t, `C:\certs\ca.pem`, p.WSTLSCA)
				equal(t, `C:\certs\c.pem`, p.WSTLSCert)
				equal(t, `C:\certs\c.key`, p.WSTLSKey)
				equal(t, false, p.WSTLSInsecure)
				equal(t, uint32(15000), p.WSPingInterval)
				equal(t, uint32(500), p.WSBackoffMin)
				equal(t, uint32(30000), p.WSBackoffMax)
			},
		},
		{
			name: "wstunnel with target and case-insensitive scheme and mode",
			peer: "Endpoint = WS://203.0.113.7:8080\nWSMode = WSTunnel\nWSTunnelTarget = 127.0.0.1:51820\n",
			check: func(t *testing.T, p *Peer) {
				equal(t, WSModeWSTunnel, p.WSMode)
				equal(t, "WS://203.0.113.7:8080", p.WSURL)
				equal(t, Endpoint{Host: "203.0.113.7", Port: 8080}, p.Endpoint)
				equal(t, "127.0.0.1:51820", p.WSTunnelTarget)
			},
		},
		{
			name: "IPv6 literal host",
			peer: "Endpoint = ws://[2001:db8::1]:443/x?y=1\nWSMode = websocket\n",
			check: func(t *testing.T, p *Peer) {
				equal(t, Endpoint{Host: "2001:db8::1", Port: 443}, p.Endpoint)
			},
		},
		{
			name: "inbound websocket peer without endpoint",
			peer: "WSMode = websocket\n",
			check: func(t *testing.T, p *Peer) {
				equal(t, WSModeWebSocket, p.WSMode)
				equal(t, "", p.WSURL)
				equal(t, true, p.Endpoint.IsEmpty())
			},
		},
		{
			name: "later UDP endpoint replaces a WebSocket one",
			peer: "Endpoint = ws://a.example.com:80\nEndpoint = 192.0.2.1:51820\n",
			check: func(t *testing.T, p *Peer) {
				equal(t, "", p.WSURL)
				equal(t, Endpoint{Host: "192.0.2.1", Port: 51820}, p.Endpoint)
			},
		},
		{
			name: "zero timing means default",
			peer: "Endpoint = ws://a.example.com:80\nWSMode = websocket\nWSPingInterval = 0\n",
			check: func(t *testing.T, p *Peer) {
				equal(t, uint32(0), p.WSPingInterval)
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := FromWgQuick(wsTestConfig(tc.peer), "ws")
			if err != nil {
				t.Fatalf("FromWgQuick: %v", err)
			}
			if len(c.Peers) != 1 {
				t.Fatalf("got %d peers, want 1", len(c.Peers))
			}
			tc.check(t, &c.Peers[0])
		})
	}
}

func TestFromWgQuick_WebSocketPeer_Invalid(t *testing.T) {
	tests := []struct {
		name string
		peer string
	}{
		{name: "ws URL without WSMode", peer: "Endpoint = ws://a.example.com:80\n"},
		{name: "WSMode with a host:port endpoint", peer: "Endpoint = 192.0.2.1:51820\nWSMode = websocket\n"},
		{name: "inbound wstunnel", peer: "WSMode = wstunnel\nWSTunnelTarget = 127.0.0.1:51820\n"},
		{name: "wstunnel without target", peer: "Endpoint = ws://a.example.com:80\nWSMode = wstunnel\n"},
		{name: "target with websocket mode", peer: "Endpoint = ws://a.example.com:80\nWSMode = websocket\nWSTunnelTarget = 127.0.0.1:51820\n"},
		{name: "WS key on a UDP peer", peer: "Endpoint = 192.0.2.1:51820\nWSMask = false\n"},
		{name: "bearer on a UDP peer", peer: "WSBearer = token\n"},
		{name: "unknown mode", peer: "Endpoint = ws://a.example.com:80\nWSMode = http\n"},
		{name: "bad boolean", peer: "Endpoint = ws://a.example.com:80\nWSMode = websocket\nWSMask = yes\n"},
		{name: "timing overflows uint32", peer: "Endpoint = ws://a.example.com:80\nWSMode = websocket\nWSBackoffMax = 4294967296\n"},
		{name: "negative timing", peer: "Endpoint = ws://a.example.com:80\nWSMode = websocket\nWSBackoffMin = -1\n"},
		{name: "URL without port", peer: "Endpoint = ws://a.example.com/x\nWSMode = websocket\n"},
		{name: "URL with userinfo", peer: "Endpoint = ws://user:pass@a.example.com:80/x\nWSMode = websocket\n"},
		{name: "URL query without path", peer: "Endpoint = ws://a.example.com:80?x=1\nWSMode = websocket\n"},
		{name: "URL without host", peer: "Endpoint = ws://:80/x\nWSMode = websocket\n"},
		{name: "target without port", peer: "Endpoint = ws://a.example.com:80\nWSMode = wstunnel\nWSTunnelTarget = 127.0.0.1\n"},
		{name: "server key in peer section", peer: "WSListen = ws://0.0.0.0:80\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := FromWgQuick(wsTestConfig(tc.peer), "ws"); err == nil {
				t.Fatalf("FromWgQuick accepted %q", tc.peer)
			}
		})
	}
}

func TestFromWgQuick_WebSocketServerKeys_Rejected(t *testing.T) {
	for _, key := range []string{"WSListen", "WSServerTLSCert", "WSServerTLSKey", "WSServerBearer", "WSTrustedProxies"} {
		t.Run(key, func(t *testing.T) {
			input := strings.Replace(wsTestConfig(""), "[Interface]\n", "[Interface]\n"+key+" = x\n", 1)
			if _, err := FromWgQuick(input, "ws"); err == nil {
				t.Fatalf("FromWgQuick accepted interface key %s", key)
			}
		})
	}
}

func TestFromWgQuick_WebSocketBearer_NotInErrors(t *testing.T) {
	_, err := FromWgQuick(wsTestConfig("Endpoint = 192.0.2.1:51820\nWSBearer = topsecret\n"), "ws")
	if err == nil {
		t.Fatal("FromWgQuick accepted a bearer on a UDP peer")
	}
	if strings.Contains(err.Error(), "topsecret") {
		t.Fatalf("error leaks the bearer: %v", err)
	}
}

func TestToWgQuick_WebSocketPeer_RoundTrip(t *testing.T) {
	input := wsTestConfig("Endpoint = wss://vpn.example.com:443/ws\nWSMode = wstunnel\nWSTunnelTarget = 127.0.0.1:51820\n" +
		"WSMask = true\nWSTLSCA = ca.pem\nWSTLSInsecure = true\nWSPingInterval = 1000\nWSBackoffMin = 2\nWSBackoffMax = 3\nWSBearer = s3cret\n")
	c, err := FromWgQuick(input, "ws")
	if err != nil {
		t.Fatalf("FromWgQuick: %v", err)
	}
	out := c.ToWgQuick()
	for _, line := range []string{
		"Endpoint = wss://vpn.example.com:443/ws", "WSMode = wstunnel", "WSTunnelTarget = 127.0.0.1:51820",
		"WSMask = true", "WSTLSCA = ca.pem", "WSTLSInsecure = true", "WSPingInterval = 1000",
		"WSBackoffMin = 2", "WSBackoffMax = 3", "WSBearer = s3cret",
	} {
		if !strings.Contains(out, line+"\n") {
			t.Errorf("ToWgQuick output lacks %q:\n%s", line, out)
		}
	}
	c2, err := FromWgQuick(out, "ws")
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	equal(t, c.Peers, c2.Peers)
}

func TestToWgQuick_UDPPeer_NoWebSocketKeys(t *testing.T) {
	c, err := FromWgQuick(wsTestConfig("Endpoint = 192.0.2.1:51820\n"), "udp")
	if err != nil {
		t.Fatalf("FromWgQuick: %v", err)
	}
	if out := c.ToWgQuick(); strings.Contains(out, "WS") {
		t.Fatalf("UDP peer serialized WebSocket keys:\n%s", out)
	}
}

func TestToUAPI_TransportAndWebSocketKeys(t *testing.T) {
	input := wsTestInterface + `
[Peer]
PublicKey = ` + wsTestPeerKey + `
AllowedIPs = 10.0.0.0/24
Endpoint = 192.0.2.1:51820

[Peer]
PublicKey = TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0=
AllowedIPs = 0.0.0.0/0
Endpoint = wss://203.0.113.7:443/p
WSMode = websocket
WSBearer = tok
WSTLSInsecure = true
WSPingInterval = 5000
`
	c, err := FromWgQuick(input, "ws")
	if err != nil {
		t.Fatalf("FromWgQuick: %v", err)
	}
	uapi := c.ToUAPI()
	peers := strings.Split(uapi, "public_key=")
	if len(peers) != 3 {
		t.Fatalf("got %d peer blocks, want 2:\n%s", len(peers)-1, uapi)
	}
	udp, ws := peers[1], peers[2]
	if !strings.Contains(udp, "transport=udp\n") || strings.Contains(udp, "ws_") {
		t.Errorf("UDP peer block wrong:\n%s", udp)
	}
	for _, line := range []string{"transport=websocket", "endpoint=203.0.113.7:443", "ws_url=wss://203.0.113.7:443/p",
		"ws_bearer=tok", "ws_tls_insecure=true", "ws_ping_interval=5000", "allowed_ip=0.0.0.0/0"} {
		if !strings.Contains(ws, line+"\n") {
			t.Errorf("WebSocket peer block lacks %q:\n%s", line, ws)
		}
	}
	if strings.Contains(ws, "ws_mask") || strings.Contains(ws, "ws_backoff") {
		t.Errorf("WebSocket peer block has unset keys:\n%s", ws)
	}
}

func TestFromUAPI_WebSocketSettingsFromStoredConfig(t *testing.T) {
	stored, err := FromWgQuick(wsTestConfig("Endpoint = wss://vpn.example.com:443/ws\nWSMode = websocket\nWSTLSCA = ca.pem\n"), "ws")
	if err != nil {
		t.Fatalf("FromWgQuick: %v", err)
	}
	response := "private_key=" + strings.Repeat("11", 32) + "\nlisten_port=51000\n" +
		"public_key=c53201039adba14be71f886da1d8dbe9eebded08cb111b75340078999aa9f038\n" +
		"preshared_key=" + strings.Repeat("00", 32) + "\nprotocol_version=1\ntransport=websocket\n" +
		"endpoint=198.51.100.9:443\nws_url=wss://vpn.example.com:443/ws\nws_tls_ca=C:\\tmp\\x\\ca.pem\n" +
		"last_handshake_time_sec=10\nlast_handshake_time_nsec=5\ntx_bytes=100\nrx_bytes=200\n" +
		"persistent_keepalive_interval=25\nallowed_ip=0.0.0.0/0\nerrno=0\n\n"
	c, err := FromUAPI(strings.NewReader(response), stored)
	if err != nil {
		t.Fatalf("FromUAPI: %v", err)
	}
	if len(c.Peers) != 1 {
		t.Fatalf("got %d peers, want 1", len(c.Peers))
	}
	p := c.Peers[0]
	equal(t, wsTestPeerKey, p.PublicKey.String())
	equal(t, uint16(51000), c.Interface.ListenPort)
	equal(t, Endpoint{Host: "198.51.100.9", Port: 443}, p.Endpoint)
	equal(t, WSModeWebSocket, p.WSMode)
	equal(t, "wss://vpn.example.com:443/ws", p.WSURL)
	equal(t, "ca.pem", p.WSTLSCA)
	equal(t, Bytes(100), p.TxBytes)
	equal(t, Bytes(200), p.RxBytes)
	equal(t, uint16(25), p.PersistentKeepalive)
	equal(t, HandshakeTime(10_000_000_005), p.LastHandshakeTime)
}

func TestFromUAPI_ErrnoFails(t *testing.T) {
	if _, err := FromUAPI(strings.NewReader("errno=5\n\n"), &Config{Name: "ws"}); err == nil {
		t.Fatal("FromUAPI accepted a non-zero errno")
	}
}

func TestRedact_ClearsWebSocketBearer(t *testing.T) {
	c, err := FromWgQuick(wsTestConfig("Endpoint = ws://a.example.com:80\nWSMode = websocket\nWSBearer = s3cret\n"), "ws")
	if err != nil {
		t.Fatalf("FromWgQuick: %v", err)
	}
	c.Redact()
	equal(t, "", c.Peers[0].WSBearer)
}

func TestHasWebSocketPeers(t *testing.T) {
	tests := []struct {
		name string
		peer string
		want bool
	}{
		{name: "UDP only", peer: "Endpoint = 192.0.2.1:51820\n", want: false},
		{name: "WebSocket peer", peer: "Endpoint = ws://a.example.com:80\nWSMode = websocket\n", want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := FromWgQuick(wsTestConfig(tc.peer), "ws")
			if err != nil {
				t.Fatalf("FromWgQuick: %v", err)
			}
			equal(t, tc.want, c.HasWebSocketPeers())
		})
	}
}

func TestFromWgQuick_WebSocketURLPassword_NotInErrors(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
	}{
		{name: "userinfo", endpoint: "wss://user:S3cretPw@vpn.example.com:443/ws"},
		{name: "userinfo and query without path", endpoint: "wss://user:S3cretPw@vpn.example.com:443?x=1"},
		{name: "userinfo and missing port", endpoint: "wss://user:S3cretPw@vpn.example.com/ws"},
		{name: "userinfo and unparsable URL", endpoint: "wss://user:S3cretPw@vpn example.com:443/%zz"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := FromWgQuick(wsTestConfig("Endpoint = "+tc.endpoint+"\nWSMode = websocket\n"), "ws")
			if err == nil {
				t.Fatal("FromWgQuick accepted the URL")
			}
			if strings.Contains(err.Error(), "S3cretPw") {
				t.Fatalf("error leaks the URL password: %v", err)
			}
		})
	}
}

func TestRedactWSURL(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{in: "wss://user:pw@host:443/p?q#f", want: "wss://xxxxx@host:443/p?q#f"},
		{in: "ws://host:80/a@b", want: "ws://host:80/a@b"},
		{in: "ws://host:80", want: "ws://host:80"},
		{in: "not a url", want: "not a url"},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			equal(t, tc.want, redactWSURL(tc.in))
		})
	}
}

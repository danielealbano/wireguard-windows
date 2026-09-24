/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package syntax

import (
	"strings"
	"testing"
)

// highlightsOf returns the highlight types of the spans covering the key and the value of
// the only "key = value" line of the peer section in config.
func highlightsOf(t *testing.T, line string) (key, value highlight) {
	t.Helper()
	config := "[Peer]\n" + line + "\n"
	keyStart := strings.Index(config, line)
	valueStart := keyStart + strings.Index(line, "=") + 1
	for valueStart < len(config) && config[valueStart] == ' ' {
		valueStart++
	}
	key, value = -1, -1
	for _, span := range highlightConfig(config) {
		if span.s == keyStart {
			key = span.t
		}
		if span.s == valueStart {
			value = span.t
		}
	}
	if key == -1 || value == -1 {
		t.Fatalf("no key/value spans for %q", line)
	}
	return key, value
}

func TestHighlightConfig_WebSocketKeys(t *testing.T) {
	tests := []struct {
		name  string
		line  string
		value highlight
	}{
		{name: "ws URL endpoint", line: "Endpoint = wss://vpn.example.com:443/ws", value: highlightHost},
		{name: "ws URL endpoint with IPv6", line: "Endpoint = ws://[2001:db8::1]:80/x", value: highlightHost},
		{name: "ws URL without port", line: "Endpoint = ws://vpn.example.com/ws", value: highlightError},
		{name: "ws URL with userinfo", line: "Endpoint = ws://u:p@vpn.example.com:80/ws", value: highlightError},
		{name: "ws URL query without path", line: "Endpoint = ws://vpn.example.com:80?x", value: highlightError},
		{name: "mode websocket", line: "WSMode = websocket", value: highlightHost},
		{name: "mode wstunnel caseless", line: "WSMode = WSTunnel", value: highlightHost},
		{name: "mode invalid", line: "WSMode = http", value: highlightError},
		{name: "tunnel target", line: "WSTunnelTarget = 127.0.0.1:51820", value: highlightHost},
		{name: "tunnel target without port", line: "WSTunnelTarget = 127.0.0.1", value: highlightError},
		{name: "bearer", line: "WSBearer = token", value: highlightHost},
		{name: "tls ca", line: "WSTLSCA = C:\\certs\\ca.pem", value: highlightHost},
		{name: "tls cert", line: "WSTLSCert = cert.pem", value: highlightHost},
		{name: "tls key", line: "WSTLSKey = key.pem", value: highlightHost},
		{name: "mask true", line: "WSMask = true", value: highlightHost},
		{name: "insecure false", line: "WSTLSInsecure = false", value: highlightHost},
		{name: "mask invalid", line: "WSMask = yes", value: highlightError},
		{name: "ping interval", line: "WSPingInterval = 15000", value: highlightKeepalive},
		{name: "backoff min max uint32", line: "WSBackoffMin = 4294967295", value: highlightKeepalive},
		{name: "backoff max overflow", line: "WSBackoffMax = 4294967296", value: highlightError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key, value := highlightsOf(t, tc.line)
			if key != highlightField {
				t.Errorf("key highlighted as %d, want field", key)
			}
			if value != tc.value {
				t.Errorf("value highlighted as %d, want %d", value, tc.value)
			}
		})
	}
}

func TestHighlightConfig_WebSocketKeyInInterface_IsError(t *testing.T) {
	config := "[Interface]\nWSMode = websocket\n"
	for _, span := range highlightConfig(config) {
		if span.s == strings.Index(config, "WSMode") && span.t != highlightError {
			t.Fatalf("WSMode in [Interface] highlighted as %d, want error", span.t)
		}
	}
}

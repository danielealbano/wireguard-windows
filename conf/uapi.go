/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/windows/l18n"
)

// ToUAPI serializes the configuration for the userspace (wireguard-go) backend. Endpoint
// hosts must already be resolved to IP addresses.
func (conf *Config) ToUAPI() string {
	var output strings.Builder
	fmt.Fprintf(&output, "private_key=%s\n", hex.EncodeToString(conf.Interface.PrivateKey[:]))
	if conf.Interface.ListenPort > 0 {
		fmt.Fprintf(&output, "listen_port=%d\n", conf.Interface.ListenPort)
	}
	output.WriteString("replace_peers=true\n")

	for i := range conf.Peers {
		peer := &conf.Peers[i]
		fmt.Fprintf(&output, "public_key=%s\n", hex.EncodeToString(peer.PublicKey[:]))
		transport := "udp"
		if peer.WSMode != WSModeNone {
			transport = string(peer.WSMode)
		}
		fmt.Fprintf(&output, "transport=%s\n", transport)
		if !peer.PresharedKey.IsZero() {
			fmt.Fprintf(&output, "preshared_key=%s\n", hex.EncodeToString(peer.PresharedKey[:]))
		}
		if !peer.Endpoint.IsEmpty() {
			fmt.Fprintf(&output, "endpoint=%s\n", peer.Endpoint.String())
		}
		if peer.WSMode != WSModeNone {
			writeWSUAPI(&output, peer)
		}
		fmt.Fprintf(&output, "persistent_keepalive_interval=%d\n", peer.PersistentKeepalive)
		output.WriteString("replace_allowed_ips=true\n")
		for _, address := range peer.AllowedIPs {
			fmt.Fprintf(&output, "allowed_ip=%s\n", address.String())
		}
	}
	return output.String()
}

func writeWSUAPI(output *strings.Builder, peer *Peer) {
	if peer.WSURL != "" {
		fmt.Fprintf(output, "ws_url=%s\n", peer.WSURL)
	}
	if peer.WSTunnelTarget != "" {
		fmt.Fprintf(output, "wstunnel_target=%s\n", peer.WSTunnelTarget)
	}
	if peer.WSBearer != "" {
		fmt.Fprintf(output, "ws_bearer=%s\n", peer.WSBearer)
	}
	if peer.WSMask {
		output.WriteString("ws_mask=true\n")
	}
	if peer.WSTLSCA != "" {
		fmt.Fprintf(output, "ws_tls_ca=%s\n", peer.WSTLSCA)
	}
	if peer.WSTLSCert != "" {
		fmt.Fprintf(output, "ws_tls_cert=%s\n", peer.WSTLSCert)
	}
	if peer.WSTLSKey != "" {
		fmt.Fprintf(output, "ws_tls_key=%s\n", peer.WSTLSKey)
	}
	if peer.WSTLSInsecure {
		output.WriteString("ws_tls_insecure=true\n")
	}
	if peer.WSPingInterval > 0 {
		fmt.Fprintf(output, "ws_ping_interval=%d\n", peer.WSPingInterval)
	}
	if peer.WSBackoffMin > 0 {
		fmt.Fprintf(output, "ws_backoff_min=%d\n", peer.WSBackoffMin)
	}
	if peer.WSBackoffMax > 0 {
		fmt.Fprintf(output, "ws_backoff_max=%d\n", peer.WSBackoffMax)
	}
}

func parseKeyHex(s string) (*Key, error) {
	k, err := hex.DecodeString(s)
	if err != nil {
		return nil, &ParseError{l18n.Sprintf("Invalid key: %v", err), s}
	}
	if len(k) != KeyLength {
		return nil, &ParseError{l18n.Sprintf("Keys must decode to exactly 32 bytes"), s}
	}
	var key Key
	copy(key[:], k)
	return &key, nil
}

func parseBytesOrStamp(s string) (uint64, error) {
	b, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, &ParseError{l18n.Sprintf("Number must be a number between 0 and 2^64-1: %v", err), s}
	}
	return b, nil
}

// FromUAPI builds the runtime view of a userspace tunnel from a UAPI get response, the
// counterpart of FromDriverConfiguration. The WebSocket settings of each peer are taken
// from existingConfig, because the device reports the paths of the TLS files it was
// given at start rather than the configured ones.
func FromUAPI(reader io.Reader, existingConfig *Config) (*Config, error) {
	parserState := inInterfaceSection
	conf := Config{
		Name: existingConfig.Name,
		Interface: Interface{
			Addresses: existingConfig.Interface.Addresses,
			DNS:       existingConfig.Interface.DNS,
			DNSSearch: existingConfig.Interface.DNSSearch,
			MTU:       existingConfig.Interface.MTU,
			PreUp:     existingConfig.Interface.PreUp,
			PostUp:    existingConfig.Interface.PostUp,
			PreDown:   existingConfig.Interface.PreDown,
			PostDown:  existingConfig.Interface.PostDown,
			TableOff:  existingConfig.Interface.TableOff,
		},
	}
	var peer *Peer
	addPeer := func() {
		if peer == nil {
			return
		}
		for i := range existingConfig.Peers {
			existing := &existingConfig.Peers[i]
			if existing.PublicKey != peer.PublicKey {
				continue
			}
			peer.WSMode = existing.WSMode
			peer.WSURL = existing.WSURL
			peer.WSTunnelTarget = existing.WSTunnelTarget
			peer.WSBearer = existing.WSBearer
			peer.WSMask = existing.WSMask
			peer.WSTLSCA = existing.WSTLSCA
			peer.WSTLSCert = existing.WSTLSCert
			peer.WSTLSKey = existing.WSTLSKey
			peer.WSTLSInsecure = existing.WSTLSInsecure
			peer.WSPingInterval = existing.WSPingInterval
			peer.WSBackoffMin = existing.WSBackoffMin
			peer.WSBackoffMax = existing.WSBackoffMax
			break
		}
		conf.Peers = append(conf.Peers, *peer)
		peer = nil
	}
	lineReader := bufio.NewReader(reader)
	for {
		line, err := lineReader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimSuffix(line, "\n")
		if len(line) == 0 {
			break
		}
		key, val, hasValue := strings.Cut(line, "=")
		if !hasValue {
			return nil, &ParseError{l18n.Sprintf("Config key is missing an equals separator"), line}
		}
		switch key {
		case "errno":
			if val != "0" {
				return nil, &ParseError{l18n.Sprintf("Error in getting configuration"), val}
			}
			continue
		case "public_key":
			addPeer()
			peer = &Peer{}
			parserState = inPeerSection
		}
		if parserState == inInterfaceSection {
			switch key {
			case "private_key":
				k, err := parseKeyHex(val)
				if err != nil {
					return nil, err
				}
				conf.Interface.PrivateKey = *k
			case "listen_port":
				p, err := parsePort(val)
				if err != nil {
					return nil, err
				}
				conf.Interface.ListenPort = p
			case "fwmark", "ws_listen", "ws_server_tls_cert", "ws_server_tls_key", "ws_server_bearer", "ws_trusted_proxies":
			default:
				return nil, &ParseError{l18n.Sprintf("Invalid key for interface section"), key}
			}
			continue
		}
		switch key {
		case "public_key":
			k, err := parseKeyHex(val)
			if err != nil {
				return nil, err
			}
			peer.PublicKey = *k
		case "preshared_key":
			k, err := parseKeyHex(val)
			if err != nil {
				return nil, err
			}
			peer.PresharedKey = *k
		case "protocol_version":
			if val != "1" {
				return nil, &ParseError{l18n.Sprintf("Protocol version must be 1"), val}
			}
		case "allowed_ip":
			a, err := parseIPCidr(val)
			if err != nil {
				return nil, err
			}
			peer.AllowedIPs = append(peer.AllowedIPs, a)
		case "persistent_keepalive_interval":
			p, err := parsePersistentKeepalive(val)
			if err != nil {
				return nil, err
			}
			peer.PersistentKeepalive = p
		case "endpoint":
			e, err := parseEndpoint(val)
			if err != nil {
				return nil, err
			}
			peer.Endpoint = *e
		case "tx_bytes":
			b, err := parseBytesOrStamp(val)
			if err != nil {
				return nil, err
			}
			peer.TxBytes = Bytes(b)
		case "rx_bytes":
			b, err := parseBytesOrStamp(val)
			if err != nil {
				return nil, err
			}
			peer.RxBytes = Bytes(b)
		case "last_handshake_time_sec":
			t, err := parseBytesOrStamp(val)
			if err != nil {
				return nil, err
			}
			peer.LastHandshakeTime += HandshakeTime(time.Duration(t) * time.Second)
		case "last_handshake_time_nsec":
			t, err := parseBytesOrStamp(val)
			if err != nil {
				return nil, err
			}
			peer.LastHandshakeTime += HandshakeTime(time.Duration(t) * time.Nanosecond)
		case "transport", "ws_url", "wstunnel_target", "ws_bearer", "ws_mask", "ws_tls_ca", "ws_tls_cert",
			"ws_tls_key", "ws_tls_insecure", "ws_ping_interval", "ws_backoff_min", "ws_backoff_max":
		default:
			return nil, &ParseError{l18n.Sprintf("Invalid key for peer section"), key}
		}
	}
	addPeer()
	return &conf, nil
}

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func wsTLSTestConfig(t *testing.T, peerLines ...string) *Config {
	t.Helper()
	input := wsTestInterface
	for i, lines := range peerLines {
		keys := []string{wsTestPeerKey, "TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0="}
		input += "\n[Peer]\nPublicKey = " + keys[i] + "\nAllowedIPs = 10.0.0." + string(rune('1'+i)) + "/32\n" +
			"Endpoint = wss://vpn.example.com:443/ws\nWSMode = websocket\n" + lines
	}
	c, err := FromWgQuick(input, "wstls")
	if err != nil {
		t.Fatalf("FromWgQuick: %v", err)
	}
	return c
}

func TestWSTLSFileNameIsValid(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{name: "ca.pem", want: true},
		{name: "client-cert_2.crt", want: true},
		{name: "", want: false},
		{name: ".hidden", want: false},
		{name: "trailing.", want: false},
		{name: `C:\certs\ca.pem`, want: false},
		{name: "dir/ca.pem", want: false},
		{name: "con.pem", want: false},
		{name: strings.Repeat("a", 65), want: false},
		{name: "spa ce.pem", want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			equal(t, tc.want, WSTLSFileNameIsValid(tc.name))
		})
	}
}

func TestIsWSTLSLocalPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{path: `C:\certs\ca.pem`, want: true},
		{path: `d:/certs/ca.pem`, want: true},
		{path: `\\server\share\ca.pem`, want: false},
		{path: `\\?\UNC\server\share\ca.pem`, want: false},
		{path: `\\?\C:\ca.pem`, want: false},
		{path: `\\.\pipe\x`, want: false},
		{path: `C:ca.pem`, want: false},
		{path: `certs\ca.pem`, want: false},
		{path: `ca.pem`, want: false},
		{path: `\certs\ca.pem`, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			equal(t, tc.want, IsWSTLSLocalPath(tc.path))
		})
	}
}

func TestSanitizeWSTLSFileName(t *testing.T) {
	tests := []struct {
		base string
		want string
	}{
		{base: "ca.pem", want: "ca.pem"},
		{base: "my cert (1).pem", want: "my_cert__1_.pem"},
		{base: "..", want: wsTLSFileNameFallback},
		{base: "", want: wsTLSFileNameFallback},
		{base: ".ca.pem.", want: "ca.pem"},
		{base: "aux.key", want: "_aux.key"},
		{base: "clé.pem", want: "cl_.pem"},
		{base: strings.Repeat("a", 70) + ".pem", want: strings.Repeat("a", 60) + ".pem"},
	}
	for _, tc := range tests {
		t.Run(tc.base, func(t *testing.T) {
			got := sanitizeWSTLSFileName(tc.base)
			equal(t, tc.want, got)
			if !WSTLSFileNameIsValid(got) {
				t.Errorf("sanitized name %q is not valid", got)
			}
		})
	}
}

func TestCollectWSTLSFiles_CopiesAndRewrites(t *testing.T) {
	c := wsTLSTestConfig(t,
		"WSTLSCA = C:\\a\\ca.pem\nWSTLSCert = C:\\a\\client.pem\nWSTLSKey = kept.key\n",
		"WSTLSCA = C:\\b\\ca.pem\nWSTLSCert = C:\\a\\client.pem\n",
	)
	contents := map[string][]byte{
		`C:\a\ca.pem`:     []byte("ca-a"),
		`C:\b\ca.pem`:     []byte("ca-b"),
		`C:\a\client.pem`: []byte("client"),
		"kept.key":        []byte("key"),
	}
	reads := 0
	copied, err := c.CollectWSTLSFiles(func(ref string) ([]byte, error) {
		reads++
		data, ok := contents[ref]
		if !ok {
			return nil, errors.New("unexpected read")
		}
		return data, nil
	})
	if err != nil {
		t.Fatalf("CollectWSTLSFiles: %v", err)
	}
	equal(t, 4, reads)
	equal(t, "ca.pem", c.Peers[0].WSTLSCA)
	equal(t, "client.pem", c.Peers[0].WSTLSCert)
	equal(t, "kept.key", c.Peers[0].WSTLSKey)
	equal(t, "ca-2.pem", c.Peers[1].WSTLSCA)
	equal(t, "client.pem", c.Peers[1].WSTLSCert)
	equal(t, map[string]string{`C:\a\ca.pem`: "ca.pem", `C:\b\ca.pem`: "ca-2.pem", `C:\a\client.pem`: "client.pem"}, copied)
	equal(t, map[string][]byte{"ca.pem": []byte("ca-a"), "ca-2.pem": []byte("ca-b"), "client.pem": []byte("client"), "kept.key": []byte("key")}, c.WSTLSFiles)
	if err := c.ValidateWSTLSFiles(); err != nil {
		t.Fatalf("ValidateWSTLSFiles after collecting: %v", err)
	}
}

func TestCollectWSTLSFiles_StoredNameKeepsItsName(t *testing.T) {
	c := wsTLSTestConfig(t, "WSTLSCA = ca.pem\nWSTLSCert = C:\\x\\ca.pem\n")
	copied, err := c.CollectWSTLSFiles(func(ref string) ([]byte, error) { return []byte(ref), nil })
	if err != nil {
		t.Fatalf("CollectWSTLSFiles: %v", err)
	}
	equal(t, "ca.pem", c.Peers[0].WSTLSCA)
	equal(t, "ca-2.pem", c.Peers[0].WSTLSCert)
	equal(t, map[string]string{`C:\x\ca.pem`: "ca-2.pem"}, copied)
}

func TestCollectWSTLSFiles_Errors(t *testing.T) {
	tests := []struct {
		name string
		read func(string) ([]byte, error)
	}{
		{name: "read fails", read: func(string) ([]byte, error) { return nil, os.ErrNotExist }},
		{name: "file too large", read: func(string) ([]byte, error) { return make([]byte, MaxWSTLSFileSize+1), nil }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := wsTLSTestConfig(t, "WSTLSCA = C:\\a\\ca.pem\n")
			if _, err := c.CollectWSTLSFiles(tc.read); err == nil {
				t.Fatal("CollectWSTLSFiles succeeded")
			}
		})
	}
}

func TestValidateWSTLSFiles(t *testing.T) {
	tests := []struct {
		name    string
		peer    string
		files   map[string][]byte
		wantErr bool
	}{
		{name: "no TLS files", peer: "", files: nil, wantErr: false},
		{name: "stored name with contents", peer: "WSTLSCA = ca.pem\n", files: map[string][]byte{"ca.pem": {1}}, wantErr: false},
		{name: "absolute local path", peer: "WSTLSCA = C:\\certs\\ca.pem\n", files: nil, wantErr: false},
		{name: "stored name without contents", peer: "WSTLSCA = ca.pem\n", files: nil, wantErr: true},
		{name: "UNC path", peer: "WSTLSCA = \\\\srv\\share\\ca.pem\n", files: nil, wantErr: true},
		{name: "relative path", peer: "WSTLSCA = certs\\ca.pem\n", files: nil, wantErr: true},
		{name: "unreferenced file", peer: "", files: map[string][]byte{"ca.pem": {1}}, wantErr: true},
		{name: "invalid file name", peer: "WSTLSCA = ca.pem\n", files: map[string][]byte{"ca.pem": {1}, "../x": {1}}, wantErr: true},
		{name: "file too large", peer: "WSTLSCA = ca.pem\n", files: map[string][]byte{"ca.pem": make([]byte, MaxWSTLSFileSize+1)}, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := wsTLSTestConfig(t, tc.peer)
			c.WSTLSFiles = tc.files
			err := c.ValidateWSTLSFiles()
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateWSTLSFiles() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestWSTLSFileReader(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ca.pem"), []byte("disk"), 0o600); err != nil {
		t.Fatal(err)
	}
	known := map[string][]byte{"stored.pem": []byte("known"), "sub/x.pem": []byte("zip")}
	tests := []struct {
		name    string
		baseDir string
		ref     string
		want    string
		wantErr bool
	}{
		{name: "known name", ref: "stored.pem", want: "known"},
		{name: "known relative path", ref: `sub\x.pem`, want: "zip"},
		{name: "absolute path", ref: filepath.Join(dir, "ca.pem"), want: "disk"},
		{name: "relative to base", baseDir: dir, ref: "ca.pem", want: "disk"},
		{name: "relative without base", ref: "ca.pem", wantErr: true},
		{name: "missing file", ref: filepath.Join(dir, "missing.pem"), wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := WSTLSFileReader(known, tc.baseDir)(tc.ref)
			if (err != nil) != tc.wantErr {
				t.Fatalf("read(%q) error = %v, wantErr %v", tc.ref, err, tc.wantErr)
			}
			equal(t, tc.want, string(got))
		})
	}
}

func TestPrepareWSTLSFiles_RejectsNonLocalPaths(t *testing.T) {
	tests := []struct {
		name      string
		peer      string
		fromStore bool
	}{
		{name: "stored name outside the store", peer: "WSTLSCA = ca.pem\n", fromStore: false},
		{name: "UNC path", peer: "WSTLSCA = \\\\srv\\share\\ca.pem\n", fromStore: true},
		{name: "relative path", peer: "WSTLSCA = certs\\ca.pem\n", fromStore: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := wsTLSTestConfig(t, tc.peer)
			if _, err := c.PrepareWSTLSFiles(tc.fromStore); err == nil {
				t.Fatal("PrepareWSTLSFiles succeeded")
			}
		})
	}
}

func TestPrepareWSTLSFiles_LocalPathsInPlace(t *testing.T) {
	c := wsTLSTestConfig(t, "WSTLSCA = C:\\certs\\ca.pem\nWSTLSKey = D:/k.pem\n")
	cleanup, err := c.PrepareWSTLSFiles(false)
	if err != nil {
		t.Fatalf("PrepareWSTLSFiles: %v", err)
	}
	cleanup()
	equal(t, `C:\certs\ca.pem`, c.Peers[0].WSTLSCA)
	equal(t, "D:/k.pem", c.Peers[0].WSTLSKey)
}

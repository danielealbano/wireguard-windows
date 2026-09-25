/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"archive/zip"
	"bytes"
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
		{base: "aux." + strings.Repeat("a", 56) + ".pem", want: "_aux." + strings.Repeat("a", 55) + ".pem"},
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
	stored, err := c.CollectWSTLSFiles(func(ref string) ([]byte, error) {
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
	equal(t, map[string]string{`C:\a\ca.pem`: "ca.pem", `C:\b\ca.pem`: "ca-2.pem", `C:\a\client.pem`: "client.pem", "kept.key": "kept.key"}, stored)
	equal(t, map[string][]byte{"ca.pem": []byte("ca-a"), "ca-2.pem": []byte("ca-b"), "client.pem": []byte("client"), "kept.key": []byte("key")}, c.WSTLSFiles)
	if err := c.ValidateWSTLSFiles(); err != nil {
		t.Fatalf("ValidateWSTLSFiles after collecting: %v", err)
	}
}

func TestCollectWSTLSFiles_StoredNameKeepsItsName(t *testing.T) {
	c := wsTLSTestConfig(t, "WSTLSCA = ca.pem\nWSTLSCert = C:\\x\\ca.pem\n")
	stored, err := c.CollectWSTLSFiles(func(ref string) ([]byte, error) { return []byte(ref), nil })
	if err != nil {
		t.Fatalf("CollectWSTLSFiles: %v", err)
	}
	equal(t, "ca.pem", c.Peers[0].WSTLSCA)
	equal(t, "ca-2.pem", c.Peers[0].WSTLSCert)
	equal(t, map[string]string{"ca.pem": "ca.pem", `C:\x\ca.pem`: "ca-2.pem"}, stored)
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
		{name: "UNC path", ref: `\\203.0.113.9\share\ca.pem`, wantErr: true},
		{name: "device path", ref: `\\?\C:\ca.pem`, wantErr: true},
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

func TestCollectWSTLSFiles_CaseVariantsShareOneFile(t *testing.T) {
	c := wsTLSTestConfig(t, "WSTLSCA = ca.pem\nWSTLSCert = CA.pem\n")
	reads := 0
	_, err := c.CollectWSTLSFiles(func(string) ([]byte, error) {
		reads++
		return []byte("ca"), nil
	})
	if err != nil {
		t.Fatalf("CollectWSTLSFiles: %v", err)
	}
	equal(t, 1, reads)
	equal(t, "ca.pem", c.Peers[0].WSTLSCA)
	equal(t, "ca.pem", c.Peers[0].WSTLSCert)
	equal(t, map[string][]byte{"ca.pem": []byte("ca")}, c.WSTLSFiles)
}

func TestValidateWSTLSFiles_CaseOnlyDuplicates(t *testing.T) {
	c := wsTLSTestConfig(t, "WSTLSCA = ca.pem\nWSTLSCert = CA.pem\n")
	c.WSTLSFiles = map[string][]byte{"ca.pem": {1}, "CA.pem": {2}}
	if err := c.ValidateWSTLSFiles(); err == nil {
		t.Fatal("ValidateWSTLSFiles accepted names that differ only in case")
	}
}

// wsTLSTestZip builds an in-memory archive from name/content pairs.
func wsTLSTestZip(t *testing.T, entries map[string][]byte) map[string]*zip.File {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, data := range entries {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	files := make(map[string]*zip.File, len(r.File))
	for _, f := range r.File {
		files[f.Name] = f
	}
	return files
}

func TestWSTLSZipFileReader(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "disk.pem"), []byte("disk"), 0o600); err != nil {
		t.Fatal(err)
	}
	files := wsTLSTestZip(t, map[string][]byte{
		"set/tun.conf":         []byte("[Interface]"),
		"set/tun/ca.pem":       []byte("folder"),
		"set/ca.pem":           []byte("sibling"),
		"set/only-sibling.pem": []byte("sibling only"),
		"set/tun/certs/c.pem":  []byte("nested"),
		"set/tun/big.pem":      make([]byte, MaxWSTLSFileSize+1),
	})
	read := WSTLSZipFileReader(files, "set/tun.conf")
	tests := []struct {
		name    string
		ref     string
		want    string
		wantErr bool
	}{
		{name: "folder named after the configuration first", ref: "ca.pem", want: "folder"},
		{name: "next to the configuration", ref: "only-sibling.pem", want: "sibling only"},
		{name: "nested with backslashes", ref: `certs\c.pem`, want: "nested"},
		{name: "absolute local path", ref: filepath.Join(dir, "disk.pem"), want: "disk"},
		{name: "UNC path", ref: `\\203.0.113.9\share\ca.pem`, wantErr: true},
		{name: "too large", ref: "big.pem", wantErr: true},
		{name: "missing", ref: "missing.pem", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := read(tc.ref)
			if (err != nil) != tc.wantErr {
				t.Fatalf("read(%q) error = %v, wantErr %v", tc.ref, err, tc.wantErr)
			}
			equal(t, tc.want, string(got))
		})
	}
}

func TestUniqueWSTLSFileName(t *testing.T) {
	long := "k." + strings.Repeat("a", 62)
	tests := []struct {
		name  string
		taken []string
		want  string
	}{
		{name: "ca.pem", taken: nil, want: "ca.pem"},
		{name: "ca.pem", taken: []string{"ca.pem"}, want: "ca-2.pem"},
		{name: "ca.pem", taken: []string{"CA.PEM", "ca-2.pem"}, want: "ca-3.pem"},
		{name: strings.Repeat("a", 64), taken: []string{strings.Repeat("a", 64)}, want: strings.Repeat("a", 62) + "-2"},
		{name: long, taken: []string{long}, want: long[:62] + "-2"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			taken := make(map[string]bool)
			for _, n := range tc.taken {
				taken[strings.ToLower(n)] = true
			}
			got := uniqueWSTLSFileName(tc.name, taken)
			equal(t, tc.want, got)
			if !WSTLSFileNameIsValid(got) {
				t.Errorf("unique name %q is not valid", got)
			}
		})
	}
}

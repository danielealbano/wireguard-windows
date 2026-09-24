//go:build integration

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"os"
	"testing"
)

// These tests use the real configuration store, so they need an elevated session.

func TestWSTLSStore_SaveLoadPrepareDelete(t *testing.T) {
	const name = "golangWSTLSTest"
	t.Cleanup(func() { DeleteWSTLSFiles(name) })
	c := wsTLSTestConfig(t, "WSTLSCA = ca.pem\nWSTLSCert = C:\\certs\\c.pem\n")
	c.Name = name
	files := map[string][]byte{"ca.pem": []byte("ca contents"), "stale.pem": []byte("x")}
	if err := SaveWSTLSFiles(name, files); err != nil {
		t.Fatalf("SaveWSTLSFiles: %v", err)
	}
	delete(files, "stale.pem")
	if err := SaveWSTLSFiles(name, files); err != nil {
		t.Fatalf("SaveWSTLSFiles again: %v", err)
	}
	if _, err := loadWSTLSFile(name, "stale.pem"); err == nil {
		t.Error("a file left out of the new set was not removed")
	}

	if err := c.LoadWSTLSFiles(); err != nil {
		t.Fatalf("LoadWSTLSFiles: %v", err)
	}
	equal(t, map[string][]byte{"ca.pem": []byte("ca contents")}, c.WSTLSFiles)

	cleanup, err := c.PrepareWSTLSFiles(true)
	if err != nil {
		t.Fatalf("PrepareWSTLSFiles: %v", err)
	}
	runtimePath := c.Peers[0].WSTLSCA
	if !IsWSTLSLocalPath(runtimePath) {
		t.Fatalf("reference not rewritten to a local path: %q", runtimePath)
	}
	data, err := os.ReadFile(runtimePath)
	if err != nil {
		t.Fatalf("reading decrypted file: %v", err)
	}
	equal(t, "ca contents", string(data))
	equal(t, `C:\certs\c.pem`, c.Peers[0].WSTLSCert)
	cleanup()
	if _, err := os.Stat(runtimePath); !os.IsNotExist(err) {
		t.Errorf("decrypted file not removed: %v", err)
	}

	if err := DeleteWSTLSFiles(name); err != nil {
		t.Fatalf("DeleteWSTLSFiles: %v", err)
	}
	if _, err := loadWSTLSFile(name, "ca.pem"); err == nil {
		t.Error("stored file not deleted")
	}
}

func TestWSTLSStore_FileBoundToTunnelName(t *testing.T) {
	t.Cleanup(func() {
		DeleteWSTLSFiles("golangWSTLSA")
		DeleteWSTLSFiles("golangWSTLSB")
	})
	if err := SaveWSTLSFiles("golangWSTLSA", map[string][]byte{"ca.pem": []byte("a")}); err != nil {
		t.Fatalf("SaveWSTLSFiles: %v", err)
	}
	dirA, err := wsTLSDirectory(false, "golangWSTLSA")
	if err != nil {
		t.Fatal(err)
	}
	dirB, err := wsTLSDirectory(true, "golangWSTLSB")
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := os.ReadFile(dirA + `\ca.pem` + wsTLSEncryptedSuffix)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dirB+`\ca.pem`+wsTLSEncryptedSuffix, encrypted, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadWSTLSFile("golangWSTLSB", "ca.pem"); err == nil {
		t.Error("a file copied from another tunnel was decrypted")
	}
}

func TestWSTLSStore_StaleDecryptedFilesRemoved(t *testing.T) {
	const name = "golangWSTLSStale"
	t.Cleanup(func() { DeleteWSTLSFiles(name) })
	writeStale := func() string {
		t.Helper()
		dir, err := wsTLSDirectory(true, wsTLSRuntimeDirectoryName, name)
		if err != nil {
			t.Fatal(err)
		}
		stale := dir + `\key.pem`
		if err := os.WriteFile(stale, []byte("plaintext key"), 0o600); err != nil {
			t.Fatal(err)
		}
		return stale
	}

	stale := writeStale()
	c := wsTLSTestConfig(t, "")
	c.Name = name
	cleanup, err := c.PrepareWSTLSFiles(true)
	if err != nil {
		t.Fatalf("PrepareWSTLSFiles: %v", err)
	}
	cleanup()
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("PrepareWSTLSFiles left a stale decrypted file: %v", err)
	}

	stale = writeStale()
	if err := DeleteWSTLSFiles(name); err != nil {
		t.Fatalf("DeleteWSTLSFiles: %v", err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("DeleteWSTLSFiles left a decrypted file: %v", err)
	}
}

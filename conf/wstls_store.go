/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"golang.zx2c4.com/wireguard/windows/conf/dpapi"
	"golang.zx2c4.com/wireguard/windows/l18n"
)

const (
	wsTLSDirectoryName        = "WebSocketTLS"
	wsTLSRuntimeDirectoryName = "$runtime" // '$' cannot appear in tunnel names
	wsTLSEncryptedSuffix      = ".dpapi"
)

// wsTLSDirectory returns Data\WebSocketTLS\<elem...>, creating it when create is set.
// The directories inherit the SYSTEM and Administrators only ACL of the data directory.
func wsTLSDirectory(create bool, elem ...string) (string, error) {
	root, err := RootDirectory(true)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(append([]string{root, wsTLSDirectoryName}, elem...)...)
	if create {
		err = os.MkdirAll(dir, os.ModeDir|0o700)
		if err != nil {
			return "", err
		}
	}
	return dir, nil
}

func wsTLSDescription(tunnelName, fileName string) string {
	return tunnelName + "/" + fileName
}

// SaveWSTLSFiles replaces the stored TLS files of a tunnel with files, encrypting each
// with DPAPI.
func SaveWSTLSFiles(tunnelName string, files map[string][]byte) error {
	if !TunnelNameIsValid(tunnelName) {
		return errors.New("Tunnel name is not valid")
	}
	if len(files) == 0 {
		return DeleteWSTLSFiles(tunnelName)
	}
	dir, err := wsTLSDirectory(true, tunnelName)
	if err != nil {
		return err
	}
	for name, data := range files {
		if !WSTLSFileNameIsValid(name) {
			return &ParseError{l18n.Sprintf("Unexpected stored TLS file"), name}
		}
		encrypted, err := dpapi.Encrypt(data, wsTLSDescription(tunnelName, name))
		if err != nil {
			return err
		}
		err = writeLockedDownFile(filepath.Join(dir, name+wsTLSEncryptedSuffix), true, encrypted)
		if err != nil {
			return err
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name, isEncrypted := strings.CutSuffix(entry.Name(), wsTLSEncryptedSuffix)
		if _, ok := files[name]; isEncrypted && ok {
			continue
		}
		err = os.Remove(filepath.Join(dir, entry.Name()))
		if err != nil {
			return err
		}
	}
	return nil
}

func loadWSTLSFile(tunnelName, fileName string) ([]byte, error) {
	if !TunnelNameIsValid(tunnelName) || !WSTLSFileNameIsValid(fileName) {
		return nil, errors.New("TLS file name is not valid")
	}
	dir, err := wsTLSDirectory(false, tunnelName)
	if err != nil {
		return nil, err
	}
	encrypted, err := os.ReadFile(filepath.Join(dir, fileName+wsTLSEncryptedSuffix))
	if err != nil {
		return nil, err
	}
	return dpapi.Decrypt(encrypted, wsTLSDescription(tunnelName, fileName))
}

// LoadWSTLSFiles fills WSTLSFiles with the stored TLS files the config refers to.
func (config *Config) LoadWSTLSFiles() error {
	names := config.WSTLSStoredFileNames()
	if len(names) == 0 {
		config.WSTLSFiles = nil
		return nil
	}
	files := make(map[string][]byte, len(names))
	for _, name := range names {
		data, err := loadWSTLSFile(config.Name, name)
		if err != nil {
			return fmt.Errorf("%s: %w", l18n.Sprintf("Unable to load stored TLS file %q", name), err)
		}
		files[name] = data
	}
	config.WSTLSFiles = files
	return nil
}

// DeleteWSTLSFiles removes the stored TLS files of a tunnel and any decrypted copies.
func DeleteWSTLSFiles(tunnelName string) error {
	if !TunnelNameIsValid(tunnelName) {
		return errors.New("Tunnel name is not valid")
	}
	dir, err := wsTLSDirectory(false, tunnelName)
	if err != nil {
		return err
	}
	err = os.RemoveAll(dir)
	if err != nil {
		return err
	}
	return removeWSTLSRuntimeFiles(tunnelName)
}

// removeWSTLSRuntimeFiles removes the decrypted TLS files of a tunnel, including those
// left behind by a tunnel service that did not stop cleanly.
func removeWSTLSRuntimeFiles(tunnelName string) error {
	dir, err := wsTLSDirectory(false, wsTLSRuntimeDirectoryName, tunnelName)
	if err != nil {
		return err
	}
	return os.RemoveAll(dir)
}

// PrepareWSTLSFiles makes the TLS files the config refers to available to the tunnel
// service. For a tunnel from the configuration store, stored file names are decrypted
// into files that only SYSTEM can read, and the references are rewritten to their paths.
// Absolute local paths are used in place; any other reference is rejected, as are
// stored file names in a configuration that is not in the store. The returned function
// removes the decrypted files.
func (config *Config) PrepareWSTLSFiles(fromStore bool) (func(), error) {
	refs := config.wsTLSReferences()
	for _, ref := range refs {
		if !IsWSTLSLocalPath(*ref) && (!fromStore || !WSTLSFileNameIsValid(*ref)) {
			return nil, &ParseError{l18n.Sprintf("TLS file must be an absolute local path"), *ref}
		}
	}
	cleanup := func() {}
	if !fromStore {
		return cleanup, nil
	}
	if err := removeWSTLSRuntimeFiles(config.Name); err != nil {
		return nil, err
	}
	var runtimeDir string
	paths := make(map[string]string)
	for _, ref := range refs {
		if IsWSTLSLocalPath(*ref) {
			continue
		}
		path, ok := paths[*ref]
		if !ok {
			if runtimeDir == "" {
				var err error
				runtimeDir, err = wsTLSDirectory(true, wsTLSRuntimeDirectoryName, config.Name)
				if err != nil {
					return nil, err
				}
				cleanup = func() {
					if err := os.RemoveAll(runtimeDir); err != nil {
						log.Printf("Unable to remove the decrypted TLS files: %v", err)
					}
				}
			}
			data, err := loadWSTLSFile(config.Name, *ref)
			if err != nil {
				cleanup()
				return nil, fmt.Errorf("%s: %w", l18n.Sprintf("Unable to load stored TLS file %q", *ref), err)
			}
			path = filepath.Join(runtimeDir, *ref)
			err = writeLockedDownFile(path, true, data)
			if err != nil {
				cleanup()
				return nil, err
			}
			paths[*ref] = path
		}
		*ref = path
	}
	return cleanup, nil
}

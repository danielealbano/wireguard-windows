/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"golang.zx2c4.com/wireguard/windows/l18n"
)

// The WSTLSCA, WSTLSCert and WSTLSKey values of a tunnel in the configuration store are
// bare file names, which refer to copies of the files kept DPAPI-encrypted in the store
// (see docs/PROJECT.md). Any other value must be an absolute local path, which is used in
// place.

const (
	// MaxWSTLSFileSize bounds each stored TLS file; certificates and keys are far smaller.
	MaxWSTLSFileSize = 1 << 20
	// MaxWSTLSFiles bounds the number of stored TLS files of one tunnel.
	MaxWSTLSFiles = 64

	wsTLSFileNameFallback = "ws-tls"
	wsTLSFileNameMaxLen   = 64
)

var allowedWSTLSFileNameFormat = regexp.MustCompile("^[a-zA-Z0-9_-][a-zA-Z0-9_.-]{0,63}$")

// WSTLSFileNameIsValid reports whether name is a valid stored TLS file name.
func WSTLSFileNameIsValid(name string) bool {
	return allowedWSTLSFileNameFormat.MatchString(name) && !strings.HasSuffix(name, ".") && !isReserved(name)
}

// IsWSTLSLocalPath reports whether path is an absolute path on a local drive, rather
// than a relative, UNC or device path.
func IsWSTLSLocalPath(path string) bool {
	return len(path) >= 3 && isAlphabetic(path[0]) && path[1] == ':' && (path[2] == '\\' || path[2] == '/')
}

func isAlphabetic(c byte) bool {
	return (c|32) >= 'a' && (c|32) <= 'z'
}

// sanitizeWSTLSFileName derives a valid stored file name from a file's base name.
func sanitizeWSTLSFileName(base string) string {
	var b strings.Builder
	for _, r := range base {
		if r < 0x80 && (isAlphabetic(byte(r)) || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	name := strings.Trim(b.String(), ".")
	if len(name) > wsTLSFileNameMaxLen {
		ext := filepath.Ext(name)
		if len(ext) > wsTLSFileNameMaxLen/2 {
			ext = ""
		}
		name = strings.TrimRight(name[:wsTLSFileNameMaxLen-len(ext)], ".") + ext
	}
	if name == "" {
		return wsTLSFileNameFallback
	}
	if isReserved(name) {
		name = "_" + name
	}
	return name
}

// uniqueWSTLSFileName returns name, or name with a numeric suffix before its extension,
// that is not in taken.
func uniqueWSTLSFileName(name string, taken map[string]bool) string {
	if !taken[strings.ToLower(name)] {
		return name
	}
	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	for i := 2; ; i++ {
		suffix := fmt.Sprintf("-%d", i)
		candidate := stem
		if len(candidate)+len(suffix)+len(ext) > wsTLSFileNameMaxLen {
			candidate = candidate[:wsTLSFileNameMaxLen-len(suffix)-len(ext)]
		}
		candidate += suffix + ext
		if !taken[strings.ToLower(candidate)] {
			return candidate
		}
	}
}

// wsTLSReferences returns pointers to every non-empty TLS file reference of the config.
func (config *Config) wsTLSReferences() []*string {
	var refs []*string
	for i := range config.Peers {
		peer := &config.Peers[i]
		for _, ref := range []*string{&peer.WSTLSCA, &peer.WSTLSCert, &peer.WSTLSKey} {
			if *ref != "" {
				refs = append(refs, ref)
			}
		}
	}
	return refs
}

// WSTLSStoredFileNames returns the distinct stored TLS file names the config refers to.
func (config *Config) WSTLSStoredFileNames() []string {
	seen := make(map[string]bool)
	var names []string
	for _, ref := range config.wsTLSReferences() {
		if WSTLSFileNameIsValid(*ref) && !seen[*ref] {
			seen[*ref] = true
			names = append(names, *ref)
		}
	}
	sort.Strings(names)
	return names
}

// CollectWSTLSFiles reads every TLS file the config refers to with read, stores the
// contents in WSTLSFiles under a stored file name and rewrites each reference to that
// name. It returns every reference mapped to the name it was stored under, so that the
// caller can disclose the copies to the user.
func (config *Config) CollectWSTLSFiles(read func(ref string) ([]byte, error)) (map[string]string, error) {
	files := make(map[string][]byte)
	taken := make(map[string]bool)
	names := make(map[string]string)
	refs := config.wsTLSReferences()
	// Stored file names keep their name, so claim them before naming copied files. Names
	// that differ only in case are the same file on Windows, so they share one spelling.
	spellings := make(map[string]string)
	for _, ref := range refs {
		if WSTLSFileNameIsValid(*ref) {
			lower := strings.ToLower(*ref)
			if _, ok := spellings[lower]; !ok {
				spellings[lower] = *ref
			}
			names[*ref] = spellings[lower]
			taken[lower] = true
		}
	}
	stored := make(map[string]string)
	for _, ref := range refs {
		name, ok := names[*ref]
		if !ok {
			name = uniqueWSTLSFileName(sanitizeWSTLSFileName(filepath.Base(*ref)), taken)
			names[*ref] = name
			taken[strings.ToLower(name)] = true
		}
		stored[*ref] = name
		if _, ok := files[name]; !ok {
			data, err := read(*ref)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", l18n.Sprintf("Unable to read TLS file %q", *ref), err)
			}
			if len(data) > MaxWSTLSFileSize {
				return nil, &ParseError{l18n.Sprintf("TLS file is too large"), *ref}
			}
			files[name] = data
		}
		*ref = name
	}
	if len(files) > MaxWSTLSFiles {
		return nil, &ParseError{l18n.Sprintf("Too many TLS files"), fmt.Sprint(len(files))}
	}
	config.WSTLSFiles = files
	return stored, nil
}

// ValidateWSTLSFiles checks that WSTLSFiles holds exactly the stored TLS files the
// config refers to, each with a valid name and size, and that every other TLS file
// reference is an absolute local path.
func (config *Config) ValidateWSTLSFiles() error {
	referenced := make(map[string]bool)
	for _, ref := range config.wsTLSReferences() {
		if WSTLSFileNameIsValid(*ref) {
			referenced[*ref] = true
			if _, ok := config.WSTLSFiles[*ref]; !ok {
				return &ParseError{l18n.Sprintf("Missing contents of stored TLS file"), *ref}
			}
		} else if !IsWSTLSLocalPath(*ref) {
			return &ParseError{l18n.Sprintf("TLS file must be a stored file name or an absolute local path"), *ref}
		}
	}
	if len(config.WSTLSFiles) > MaxWSTLSFiles {
		return &ParseError{l18n.Sprintf("Too many TLS files"), fmt.Sprint(len(config.WSTLSFiles))}
	}
	lowerNames := make(map[string]bool, len(config.WSTLSFiles))
	for name, data := range config.WSTLSFiles {
		if lowerNames[strings.ToLower(name)] {
			return &ParseError{l18n.Sprintf("Stored TLS file names must differ in more than letter case"), name}
		}
		lowerNames[strings.ToLower(name)] = true
		if !WSTLSFileNameIsValid(name) || !referenced[name] {
			return &ParseError{l18n.Sprintf("Unexpected stored TLS file"), name}
		}
		if len(data) > MaxWSTLSFileSize {
			return &ParseError{l18n.Sprintf("TLS file is too large"), name}
		}
	}
	return nil
}

// WSTLSFileReader returns a read function for CollectWSTLSFiles. A reference found in
// known, keyed by its slash-separated form, comes from there; an absolute path on a
// local drive is read from disk, while UNC and device paths are rejected so that an
// imported configuration cannot make Windows connect to a remote host; any other path is
// read relative to baseDir, or rejected when baseDir is empty.
func WSTLSFileReader(known map[string][]byte, baseDir string) func(ref string) ([]byte, error) {
	return func(ref string) ([]byte, error) {
		if data, ok := known[filepath.ToSlash(ref)]; ok {
			return data, nil
		}
		path := ref
		if filepath.IsAbs(path) && !IsWSTLSLocalPath(path) {
			return nil, errors.New(l18n.Sprintf("the path must be on a local drive"))
		}
		if !filepath.IsAbs(path) {
			if baseDir == "" {
				return nil, errors.New(l18n.Sprintf("the path must be absolute or the name of a file stored with the tunnel"))
			}
			path = filepath.Join(baseDir, path)
		}
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if info.Size() > MaxWSTLSFileSize {
			return nil, errors.New(l18n.Sprintf("the file is too large"))
		}
		return os.ReadFile(path)
	}
}

// WSTLSZipFileReader returns a read function for CollectWSTLSFiles that resolves the TLS
// file references of the configuration at confPath in an archive: a relative reference
// is looked up in the folder named after the configuration, as the UI's zip export
// writes it, then next to the configuration; an absolute path is read like
// WSTLSFileReader does.
func WSTLSZipFileReader(files map[string]*zip.File, confPath string) func(ref string) ([]byte, error) {
	dir := path.Dir(confPath)
	name := strings.TrimSuffix(path.Base(confPath), path.Ext(confPath))
	readFromDisk := WSTLSFileReader(nil, "")
	return func(ref string) ([]byte, error) {
		if filepath.IsAbs(ref) {
			return readFromDisk(ref)
		}
		rel := filepath.ToSlash(ref)
		for _, candidate := range []string{path.Join(dir, name, rel), path.Join(dir, rel)} {
			f, ok := files[candidate]
			if !ok {
				continue
			}
			if f.UncompressedSize64 > MaxWSTLSFileSize {
				return nil, errors.New(l18n.Sprintf("the file is too large"))
			}
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			defer rc.Close()
			data, err := io.ReadAll(io.LimitReader(rc, MaxWSTLSFileSize+1))
			if err != nil {
				return nil, err
			}
			if len(data) > MaxWSTLSFileSize {
				return nil, errors.New(l18n.Sprintf("the file is too large"))
			}
			return data, nil
		}
		return nil, errors.New(l18n.Sprintf("the file is not in the archive"))
	}
}

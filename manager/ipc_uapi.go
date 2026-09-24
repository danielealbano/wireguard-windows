/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package manager

import (
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/ipc/namedpipe"

	"golang.zx2c4.com/wireguard/windows/conf"
)

// uapiRuntimeConfig reads the runtime configuration of a tunnel running on the userspace
// backend from its UAPI named pipe, which must be owned by SYSTEM.
func uapiRuntimeConfig(storedConfig *conf.Config) (*conf.Config, error) {
	localSystem, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, err
	}
	pipe, err := (&namedpipe.DialConfig{ExpectedOwner: localSystem}).DialTimeout(`\\.\pipe\ProtectedPrefix\Administrators\WireGuard\`+storedConfig.Name, time.Second)
	if err != nil {
		return nil, err
	}
	defer pipe.Close()
	err = pipe.SetDeadline(time.Now().Add(time.Second * 5))
	if err != nil {
		return nil, err
	}
	_, err = pipe.Write([]byte("get=1\n\n"))
	if err != nil {
		return nil, err
	}
	return conf.FromUAPI(pipe, storedConfig)
}

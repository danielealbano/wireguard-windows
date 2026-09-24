/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package tunnel

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/driver"
	"golang.zx2c4.com/wireguard/windows/elevate"
	"golang.zx2c4.com/wireguard/windows/ringlogger"
	"golang.zx2c4.com/wireguard/windows/services"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

type tunnelService struct {
	Path string
}

func (service *tunnelService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (svcSpecificEC bool, exitCode uint32) {
	serviceState := svc.StartPending
	changes <- svc.Status{State: serviceState}

	var watcher *interfaceWatcher
	var adapter *driver.Adapter
	var nativeTun *tun.NativeTun
	var dev *device.Device
	var uapi net.Listener
	var routeMonitor *defaultRouteMonitor
	var removeWSTLSFiles func()
	var luid winipcfg.LUID
	var config *conf.Config
	var err error
	serviceError := services.ErrorSuccess

	defer func() {
		svcSpecificEC, exitCode = services.DetermineErrorCode(err, serviceError)
		logErr := services.CombineErrors(err, serviceError)
		if logErr != nil {
			log.Println(logErr)
		}
		serviceState = svc.StopPending
		changes <- svc.Status{State: serviceState}

		stopIt := make(chan bool, 1)
		go func() {
			t := time.NewTicker(time.Second * 30)
			for {
				select {
				case <-t.C:
					t.Stop()
					buf := make([]byte, 1024)
					for {
						n := runtime.Stack(buf, true)
						if n < len(buf) {
							buf = buf[:n]
							break
						}
						buf = make([]byte, 2*len(buf))
					}
					lines := bytes.Split(buf, []byte{'\n'})
					log.Println("Failed to shutdown after 30 seconds. Probably dead locked. Printing stack and killing.")
					for _, line := range lines {
						if len(bytes.TrimSpace(line)) > 0 {
							log.Println(string(line))
						}
					}
					os.Exit(777)
					return
				case <-stopIt:
					t.Stop()
					return
				}
			}
		}()

		if logErr == nil && (adapter != nil || nativeTun != nil) && config != nil {
			logErr = runScriptCommand(config.Interface.PreDown, config.Name)
		}
		if watcher != nil {
			watcher.Destroy()
		}
		if routeMonitor != nil {
			routeMonitor.Destroy()
		}
		if uapi != nil {
			uapi.Close()
		}
		if dev != nil {
			dev.Close()
		} else if nativeTun != nil {
			nativeTun.Close()
		}
		if adapter != nil {
			adapter.Close()
		}
		if removeWSTLSFiles != nil {
			removeWSTLSFiles()
		}
		if logErr == nil && (adapter != nil || nativeTun != nil) && config != nil {
			_ = runScriptCommand(config.Interface.PostDown, config.Name)
		}
		stopIt <- true
		log.Println("Shutting down")
	}()

	var logFile string
	logFile, err = conf.LogFile(true)
	if err != nil {
		serviceError = services.ErrorRingloggerOpen
		return
	}
	err = ringlogger.InitGlobalLogger(logFile, "TUN")
	if err != nil {
		serviceError = services.ErrorRingloggerOpen
		return
	}

	config, err = conf.LoadFromPath(service.Path)
	if err != nil {
		serviceError = services.ErrorLoadConfiguration
		return
	}
	config.DeduplicateNetworkEntries()
	removeWSTLSFiles, err = config.PrepareWSTLSFiles(conf.PathIsEncrypted(service.Path))
	if err != nil {
		serviceError = services.ErrorLoadConfiguration
		return
	}

	log.SetPrefix(fmt.Sprintf("[%s] ", config.Name))

	services.PrintStarting()

	if services.StartedAtBoot() {
		if m, err := mgr.Connect(); err == nil {
			if lockStatus, err := m.LockStatus(); err == nil && lockStatus.IsLocked {
				/* If we don't do this, then the driver installation will block forever, because
				 * installing a network adapter starts the driver service too. Apparently at boot time,
				 * Windows 8.1 locks the SCM for each service start, creating a deadlock if we don't
				 * announce that we're running before starting additional services.
				 */
				log.Printf("SCM locked for %v by %s, marking service as started", lockStatus.Age, lockStatus.Owner)
				serviceState = svc.Running
				changes <- svc.Status{State: serviceState}
			}
			m.Disconnect()
		}
	}

	evaluateStaticPitfalls()

	log.Println("Watching network interfaces")
	watcher, err = watchInterface()
	if err != nil {
		serviceError = services.ErrorSetNetConfig
		return
	}

	log.Println("Resolving DNS names")
	err = config.ResolveEndpoints()
	if err != nil {
		serviceError = services.ErrorDNSLookup
		return
	}

	log.Println("Creating network adapter")
	if config.HasWebSocketPeers() {
		// WebSocket peers need the userspace implementation, running over Wintun.
		var wintun tun.Device
		for i := range 15 {
			if i > 0 {
				time.Sleep(time.Second)
				log.Printf("Retrying adapter creation after failure because system just booted (T+%v): %v", windows.DurationSinceBoot(), err)
			}
			wintun, err = tun.CreateTUNWithRequestedGUID(config.Name, deterministicGUID(config), int(config.Interface.MTU))
			if err == nil || !services.StartedAtBoot() {
				break
			}
		}
		if err != nil {
			err = fmt.Errorf("Error creating adapter: %w", err)
			serviceError = services.ErrorCreateNetworkAdapter
			return
		}
		nativeTun = wintun.(*tun.NativeTun)
		luid = winipcfg.LUID(nativeTun.LUID())
		wintunVersion, versionErr := nativeTun.RunningVersion()
		if versionErr != nil {
			log.Printf("Warning: unable to determine Wintun version: %v", versionErr)
		} else {
			log.Printf("Using Wintun/%d.%d", (wintunVersion>>16)&0xffff, wintunVersion&0xffff)
		}
	} else {
		for i := range 15 {
			if i > 0 {
				time.Sleep(time.Second)
				log.Printf("Retrying adapter creation after failure because system just booted (T+%v): %v", windows.DurationSinceBoot(), err)
			}
			adapter, err = driver.CreateAdapter(config.Name, "WireGuard", deterministicGUID(config))
			if err == nil || !services.StartedAtBoot() {
				break
			}
		}
		if err != nil {
			err = fmt.Errorf("Error creating adapter: %w", err)
			serviceError = services.ErrorCreateNetworkAdapter
			return
		}
		luid = adapter.LUID()
		driverVersion, versionErr := driver.RunningVersion()
		if versionErr != nil {
			log.Printf("Warning: unable to determine driver version: %v", versionErr)
		} else {
			log.Printf("Using WireGuardNT/%d.%d", (driverVersion>>16)&0xffff, driverVersion&0xffff)
		}
		err = adapter.SetLogging(driver.AdapterLogOn)
		if err != nil {
			err = fmt.Errorf("Error enabling adapter logging: %w", err)
			serviceError = services.ErrorCreateNetworkAdapter
			return
		}
	}

	err = runScriptCommand(config.Interface.PreUp, config.Name)
	if err != nil {
		serviceError = services.ErrorRunScript
		return
	}

	err = enableFirewall(config, luid)
	if err != nil {
		serviceError = services.ErrorFirewall
		return
	}

	log.Println("Dropping privileges")
	err = elevate.DropAllPrivileges(true)
	if err != nil {
		serviceError = services.ErrorDropPrivileges
		return
	}

	if nativeTun != nil {
		log.Println("Creating interface instance")
		var bind conn.Bind
		bind, err = conn.NewMultiplexBind(conn.WithWSLogger(conn.Logger{Verbosef: log.Printf, Errorf: log.Printf}))
		if err != nil {
			serviceError = services.ErrorDeviceSetConfig
			return
		}
		dev = device.NewDevice(nativeTun, bind, &device.Logger{Verbosef: log.Printf, Errorf: log.Printf})

		log.Println("Setting interface configuration")
		uapi, err = ipc.UAPIListen(config.Name)
		if err != nil {
			serviceError = services.ErrorUAPIListen
			return
		}
		err = dev.IpcSet(config.ToUAPI())
		if err != nil {
			serviceError = services.ErrorDeviceSetConfig
			return
		}

		routeMonitor, err = newDefaultRouteMonitor(config, bind.(conn.BindSocketToInterface), dev.BindUpdate, luid)
		if err != nil {
			serviceError = services.ErrorBindSocketsToDefaultRoutes
			return
		}

		log.Println("Bringing peers up")
		err = dev.Up()
		if err != nil {
			serviceError = services.ErrorDeviceBringUp
			return
		}
		err = routeMonitor.start()
		if err != nil {
			serviceError = services.ErrorBindSocketsToDefaultRoutes
			return
		}
		watcher.Configure(nil, nativeTun, config, luid)

		log.Println("Listening for UAPI requests")
		go func() {
			for {
				uapiConn, err := uapi.Accept()
				if err != nil {
					return
				}
				go dev.IpcHandle(uapiConn)
			}
		}()
	} else {
		log.Println("Setting interface configuration")
		err = adapter.SetConfiguration(config.ToDriverConfiguration())
		if err != nil {
			serviceError = services.ErrorDeviceSetConfig
			return
		}
		err = adapter.SetAdapterState(driver.AdapterStateUp)
		if err != nil {
			serviceError = services.ErrorDeviceBringUp
			return
		}
		watcher.Configure(adapter, nil, config, luid)
	}

	err = runScriptCommand(config.Interface.PostUp, config.Name)
	if err != nil {
		serviceError = services.ErrorRunScript
		return
	}

	changes <- svc.Status{State: serviceState, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	var devWaitChan chan struct{}
	if dev != nil {
		devWaitChan = dev.Wait()
	}
	var started bool
	for {
		select {
		case <-devWaitChan:
			return
		case c := <-r:
			switch c.Cmd {
			case svc.Stop, svc.Shutdown:
				return
			case svc.Interrogate:
				changes <- c.CurrentStatus
			default:
				log.Printf("Unexpected service control request #%d\n", c)
			}
		case <-watcher.started:
			if !started {
				serviceState = svc.Running
				changes <- svc.Status{State: serviceState, Accepts: svc.AcceptStop | svc.AcceptShutdown}
				log.Println("Startup complete")
				started = true
			}
		case e := <-watcher.errors:
			serviceError, err = e.serviceError, e.err
			return
		}
	}
}

func Run(confPath string) error {
	name, err := conf.NameFromPath(confPath)
	if err != nil {
		return err
	}
	serviceName, err := conf.ServiceNameOfTunnel(name)
	if err != nil {
		return err
	}
	return svc.Run(serviceName, &tunnelService{confPath})
}

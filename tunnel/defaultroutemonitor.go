/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package tunnel

import (
	"fmt"
	"log"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// defaultRouteMonitor follows the lowest-metric default route that is not the tunnel
// for the userspace backend: it pins the UDP sockets to that interface, like WireGuardNT
// does internally, and keeps a host route to each WebSocket server through its gateway,
// so the WebSocket connection never enters the tunnel (see docs/ARCHITECTURE.md). When
// the gateway changes, it moves the host routes and re-dials the WebSocket connections.
type defaultRouteMonitor struct {
	mu        sync.Mutex
	binder    conn.BindSocketToInterface
	rebind    func() error
	ourLUID   winipcfg.LUID
	families  [2]defaultRouteFamily
	callbacks []winipcfg.ChangeCallback

	burstMutex sync.Mutex
	burstTimer *time.Timer
	firstBurst time.Time
}

type defaultRouteFamily struct {
	family    winipcfg.AddressFamily
	blackhole bool
	hosts     []netip.Prefix
	gateway   defaultGateway
	// owned holds the host routes through gateway that this monitor added, the only ones
	// it removes; a route that already existed belongs to someone else.
	owned map[netip.Prefix]bool
	// incomplete is set while not every host route is known to go through gateway, so
	// that a failed AddRoute, or a host route deleted by someone else, is retried.
	incomplete bool
}

type defaultGateway struct {
	luid    winipcfg.LUID
	index   uint32
	nextHop netip.Addr
}

func findDefaultGateway(family winipcfg.AddressFamily, ourLUID winipcfg.LUID) (defaultGateway, error) {
	r, err := winipcfg.GetIPForwardTable2(family)
	if err != nil {
		return defaultGateway{}, err
	}
	lowestMetric := ^uint64(0)
	var gateway defaultGateway
	for i := range r {
		if r[i].DestinationPrefix.PrefixLength != 0 || r[i].InterfaceLUID == ourLUID {
			continue
		}
		ifrow, err := r[i].InterfaceLUID.Interface()
		if err != nil || ifrow.OperStatus != winipcfg.IfOperStatusUp {
			continue
		}
		iface, err := r[i].InterfaceLUID.IPInterface(family)
		if err != nil {
			continue
		}
		combinedMetric := uint64(r[i].Metric) + uint64(iface.Metric)
		if combinedMetric < lowestMetric {
			lowestMetric = combinedMetric
			gateway = defaultGateway{r[i].InterfaceLUID, r[i].InterfaceIndex, r[i].NextHop.Addr()}
		}
	}
	return gateway, nil
}

// webSocketServerHosts returns the host prefixes of the resolved endpoints of the peers
// that dial a WebSocket server.
func webSocketServerHosts(config *conf.Config, family winipcfg.AddressFamily) []netip.Prefix {
	var hosts []netip.Prefix
	for i := range config.Peers {
		peer := &config.Peers[i]
		if peer.WSURL == "" {
			continue
		}
		addr, err := netip.ParseAddr(peer.Endpoint.Host)
		if err != nil || addr.Is4() != (family == windows.AF_INET) {
			continue
		}
		prefix := netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen())
		duplicate := false
		for _, host := range hosts {
			duplicate = duplicate || host == prefix
		}
		if !duplicate {
			hosts = append(hosts, prefix)
		}
	}
	return hosts
}

// newDefaultRouteMonitor installs the WebSocket server host routes. It must run before
// the device is brought up, so that the first WebSocket connection is already routed
// outside the tunnel; start then pins the UDP sockets and follows route changes.
func newDefaultRouteMonitor(config *conf.Config, binder conn.BindSocketToInterface, rebind func() error, ourLUID winipcfg.LUID) (*defaultRouteMonitor, error) {
	m := &defaultRouteMonitor{binder: binder, rebind: rebind, ourLUID: ourLUID}
	for i, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		m.families[i] = defaultRouteFamily{
			family:    family,
			blackhole: hasDefaultRoute(family, config),
			hosts:     webSocketServerHosts(config, family),
			owned:     make(map[netip.Prefix]bool),
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, err := m.updateLocked(); err != nil {
		m.removeHostRoutesLocked()
		return nil, err
	}
	return m, nil
}

func (m *defaultRouteMonitor) start() error {
	m.mu.Lock()
	err := m.pinSocketsLocked()
	m.mu.Unlock()
	if err != nil {
		return err
	}

	m.burstTimer = time.AfterFunc(time.Hour*200, func() {
		m.burstMutex.Lock()
		m.firstBurst = time.Time{}
		m.burstMutex.Unlock()
		m.update()
	})
	m.burstTimer.Stop()
	cbr, err := winipcfg.RegisterRouteChangeCallback(func(notificationType winipcfg.MibNotificationType, route *winipcfg.MibIPforwardRow2) {
		if route == nil {
			return
		}
		if route.DestinationPrefix.PrefixLength == 0 ||
			(notificationType == winipcfg.MibDeleteInstance && m.hostRouteDeleted(route)) {
			m.bump()
		}
	})
	if err != nil {
		return err
	}
	cbi, err := winipcfg.RegisterInterfaceChangeCallback(func(notificationType winipcfg.MibNotificationType, iface *winipcfg.MibIPInterfaceRow) {
		if notificationType == winipcfg.MibParameterNotification {
			m.bump()
		}
	})
	if err != nil {
		cbr.Unregister()
		return err
	}
	m.mu.Lock()
	m.callbacks = []winipcfg.ChangeCallback{cbr, cbi}
	m.mu.Unlock()
	return nil
}

// hostRouteDeleted marks a family incomplete when a route to one of its WebSocket servers
// was deleted, for example by another tunnel to the same server, so that the next update
// adds the host route again if it is gone.
func (m *defaultRouteMonitor) hostRouteDeleted(route *winipcfg.MibIPforwardRow2) bool {
	prefix := route.DestinationPrefix.Prefix()
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.families {
		f := &m.families[i]
		for _, host := range f.hosts {
			if host == prefix {
				f.incomplete = true
				return true
			}
		}
	}
	return false
}

func (m *defaultRouteMonitor) bump() {
	m.burstMutex.Lock()
	defer m.burstMutex.Unlock()
	m.burstTimer.Reset(time.Millisecond * 150)
	if m.firstBurst.IsZero() {
		m.firstBurst = time.Now()
	} else if time.Since(m.firstBurst) > time.Second*2 {
		m.firstBurst = time.Time{}
		m.burstTimer.Stop()
		go m.update()
	}
}

func (m *defaultRouteMonitor) update() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.callbacks == nil {
		return
	}
	movedHostRoutes, err := m.updateLocked()
	if err != nil {
		log.Printf("Unable to follow the default route: %v", err)
	}
	if movedHostRoutes {
		log.Println("Reconnecting WebSocket peers after a default route change")
		if err := m.rebind(); err != nil {
			log.Printf("Unable to rebind sockets: %v", err)
		}
	}
	if err := m.pinSocketsLocked(); err != nil {
		log.Printf("Unable to bind sockets to the default route: %v", err)
	}
}

// updateLocked reads the default gateways and moves the host routes of the families
// whose gateway changed or whose routes are incomplete, reporting whether any host
// route moved and the first error.
func (m *defaultRouteMonitor) updateLocked() (bool, error) {
	moved := false
	var firstErr error
	for i := range m.families {
		f := &m.families[i]
		gateway, err := findDefaultGateway(f.family, m.ourLUID)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if gateway == f.gateway && !f.incomplete {
			continue
		}
		previous := f.gateway
		f.gateway, f.incomplete = gateway, true
		if previous != gateway {
			if len(f.hosts) != 0 {
				log.Printf("Routing WebSocket servers %v through interface %d", f.hosts, gateway.index)
			}
			for host := range f.owned {
				previous.luid.DeleteRoute(host, previous.nextHop)
			}
			clear(f.owned)
			moved = moved || len(f.hosts) != 0
		}
		for _, host := range f.hosts {
			if gateway.luid == 0 {
				continue
			}
			err = gateway.luid.AddRoute(host, gateway.nextHop, 0)
			if err == nil {
				f.owned[host] = true
				moved = true
			} else if err != windows.ERROR_OBJECT_ALREADY_EXISTS {
				err = fmt.Errorf("unable to add host route %v: %w", host, err)
				break
			}
			err = nil
		}
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		f.incomplete = false
	}
	return moved, firstErr
}

func (m *defaultRouteMonitor) pinSocketsLocked() error {
	for i := range m.families {
		f := &m.families[i]
		blackhole := f.blackhole && f.gateway.index == 0
		var err error
		if f.family == windows.AF_INET {
			log.Printf("Binding v4 socket to interface %d (blackhole=%v)", f.gateway.index, blackhole)
			err = m.binder.BindSocketToInterface4(f.gateway.index, blackhole)
		} else {
			log.Printf("Binding v6 socket to interface %d (blackhole=%v)", f.gateway.index, blackhole)
			err = m.binder.BindSocketToInterface6(f.gateway.index, blackhole)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *defaultRouteMonitor) removeHostRoutesLocked() {
	for i := range m.families {
		f := &m.families[i]
		for host := range f.owned {
			f.gateway.luid.DeleteRoute(host, f.gateway.nextHop)
		}
		clear(f.owned)
		f.gateway = defaultGateway{}
	}
}

func (m *defaultRouteMonitor) Destroy() {
	m.mu.Lock()
	callbacks := m.callbacks
	m.callbacks = nil
	m.mu.Unlock()
	for _, cb := range callbacks {
		cb.Unregister()
	}
	if m.burstTimer != nil {
		m.burstTimer.Stop()
	}
	m.mu.Lock()
	m.removeHostRoutesLocked()
	m.mu.Unlock()
}

// hasDefaultRoute reports whether the tunnel routes all traffic of family, in which case
// UDP packets are dropped rather than sent into the tunnel while there is no other
// default route.
func hasDefaultRoute(family winipcfg.AddressFamily, config *conf.Config) bool {
	var (
		foundHalf0, foundHalf1, foundFull bool
		zero                              netip.Addr
		half                              netip.Addr
	)
	if family == windows.AF_INET {
		zero, half = netip.IPv4Unspecified(), netip.AddrFrom4([4]byte{0x80})
	} else {
		zero, half = netip.IPv6Unspecified(), netip.AddrFrom16([16]byte{0x80})
	}
	for i := range config.Peers {
		for _, allowedip := range config.Peers[i].AllowedIPs {
			switch allowedip {
			case netip.PrefixFrom(zero, 0):
				foundFull = true
			case netip.PrefixFrom(zero, 1):
				foundHalf0 = true
			case netip.PrefixFrom(half, 1):
				foundHalf1 = true
			}
		}
	}
	return foundFull || (foundHalf0 && foundHalf1)
}

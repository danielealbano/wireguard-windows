/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package tunnel

import (
	"reflect"
	"sync"
	"testing"
)

type recordingMTUClamper struct {
	mu     sync.Mutex
	forced []int
}

func (r *recordingMTUClamper) ForceMTU(mtu int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.forced = append(r.forced, mtu)
}

func TestFamilyMTUClamper_ForcesTheSmallerMTU(t *testing.T) {
	tun := &recordingMTUClamper{}
	shared := &sharedMTUClamper{tun: tun}
	v4, v6 := familyMTUClamper{shared, 0}, familyMTUClamper{shared, 1}
	v4.ForceMTU(1420)
	v6.ForceMTU(1280)
	v4.ForceMTU(1400)
	v6.ForceMTU(1500)
	want := []int{1420, 1280, 1280, 1400}
	if !reflect.DeepEqual(tun.forced, want) {
		t.Errorf("forced MTUs = %v, want %v", tun.forced, want)
	}
}

func TestFamilyMTUClamper_ConcurrentFamilies(t *testing.T) {
	tun := &recordingMTUClamper{}
	shared := &sharedMTUClamper{tun: tun}
	var wg sync.WaitGroup
	for index, mtu := range []int{1420, 1280} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				familyMTUClamper{shared, index}.ForceMTU(mtu)
			}
		}()
	}
	wg.Wait()
	if last := tun.forced[len(tun.forced)-1]; last != 1280 {
		t.Errorf("last forced MTU = %d, want 1280", last)
	}
}

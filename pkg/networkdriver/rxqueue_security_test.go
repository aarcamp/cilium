// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/networkdriver/rxqueue"
)

func TestRXQueueSafetyWithoutNetworkDriver(t *testing.T) {
	oldReset := resetLeasedRXQueueFlows
	t.Cleanup(func() { resetLeasedRXQueueFlows = oldReset })
	errCleanup := errors.New("unknown active lease")
	resetLeasedRXQueueFlows = func(context.Context, func(netlink.Link) (bool, error)) error { return errCleanup }
	primaryIPAM := &ipam.IPAM{}
	require.Nil(t, registerNetworkDriver(networkDriverParams{PrimaryIPAM: primaryIPAM}))
	require.ErrorIs(t, primaryIPAM.ConfigureAllocator(t.Context()), errCleanup,
		"startup cleanup must precede IPAM even when Network Driver is disabled")
}

func TestRXQueueAddressRelease(t *testing.T) {
	f := newRXQueueControllerFixture(t)
	f.allocate(nil)
	guard := &rxQueueAddressGuard{driver: f.driver}
	oldRevoke := rxQueueRevokeForIP
	t.Cleanup(func() { rxQueueRevokeForIP = oldRevoke })
	errCleanup := errors.New("rule withdrawal failed")
	var calls []netip.Addr
	rxQueueRevokeForIP = func(device *rxqueue.RXQueueDevice, address netip.Addr) (*rxqueue.RXQueueDevice, error) {
		calls = append(calls, address)
		return &rxqueue.RXQueueDevice{PhysicalIfName: device.PhysicalIfName, Prepared: true}, errCleanup
	}
	v4, v6 := netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("2001:db8::10")
	require.ErrorIs(t, guard.BeforeRelease(v4, ipam.PoolDefault()), errCleanup)
	for row := range f.driver.allocationTable.All(f.db.ReadTxn()) {
		require.Nil(t, row.PreparedDevice.(*rxqueue.RXQueueDevice).Binding)
	}
	require.ErrorIs(t, guard.BeforeRelease(v4, ipam.PoolDefault()), errCleanup)
	require.ErrorIs(t, guard.BeforeRelease(v6, ipam.PoolDefault()), errCleanup)
	errCleanup = nil
	require.NoError(t, guard.BeforeRelease(v6, ipam.PoolDefault()))
	require.Equal(t, []netip.Addr{v4, v4, v6, v6}, calls)
}

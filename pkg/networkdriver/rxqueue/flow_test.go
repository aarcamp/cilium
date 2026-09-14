// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package rxqueue

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"

	"github.com/cilium/cilium/pkg/networkdriver/types"
)

func testRXFlows() []types.RXQueueFlow {
	return []types.RXQueueFlow{
		{
			DestinationIP:   netip.MustParseAddr("2001:db8::10"),
			DestinationPort: 5353,
			Protocol:        corev1.ProtocolUDP,
		},
		{
			DestinationIP:   netip.MustParseAddr("192.0.2.10"),
			DestinationPort: 9000,
			Protocol:        corev1.ProtocolTCP,
		},
	}
}

func prepareTestRXQueue(t *testing.T, fake *fakeNetlink) *RXQueueDevice {
	t.Helper()
	device, err := testDevice(8).Setup(testAllocation(testShareID))
	require.NoError(t, err)
	return device.(*RXQueueDevice)
}

func TestSetRXQueueFlows(t *testing.T) {
	fake := newFakeNetlink(8, 8, testShareID)
	fake.install(t)
	prepared := prepareTestRXQueue(t, fake)

	flows := testRXFlows()
	flows = append(flows, flows[1])
	device, err := prepared.SetRXQueueFlows(flows)
	require.NoError(t, err)

	programmed := device.(*RXQueueDevice)
	require.Len(t, programmed.rxFlows, 2)
	require.Len(t, fake.flowInsertCalls, 2)
	require.Equal(t, uint32(7), fake.flowInsertCalls[0].Queue)
	require.Equal(t, uint32(7), fake.flowInsertCalls[1].Queue)

	tcp4, ok := fake.flowInsertCalls[0].Match.(netlink.TCP4Flow)
	require.True(t, ok)
	require.True(t, tcp4.DstIP.Equal(net.ParseIP("192.0.2.10")))
	require.Equal(t, net.IP(net.CIDRMask(32, 32)), tcp4.DstIPMask)
	require.Equal(t, uint16(9000), tcp4.DstPort)
	require.Equal(t, ^uint16(0), tcp4.DstPortMask)

	udp6, ok := fake.flowInsertCalls[1].Match.(netlink.UDP6Flow)
	require.True(t, ok)
	require.True(t, udp6.DstIP.Equal(net.ParseIP("2001:db8::10")))
	require.Equal(t, net.IP(net.CIDRMask(128, 128)), udp6.DstIPMask)
	require.Equal(t, uint16(5353), udp6.DstPort)
	require.Equal(t, ^uint16(0), udp6.DstPortMask)

	host := fake.links[fake.hostIfName]
	ownership, err := ownedRXFlows(host, fake.hostIfName)
	require.NoError(t, err)
	require.Equal(t, []uint32{100, 101}, ownership.locations)
	require.Equal(t, rxFlowDigest([]types.RXQueueFlow{
		flows[1],
		flows[0],
	}), ownership.digest)
	data, err := programmed.MarshalBinary()
	require.NoError(t, err)
	restoredDevice, err := (&RXQueueManager{}).RestoreDevice(data)
	require.NoError(t, err)
	require.Equal(t, programmed.rxFlows, restoredDevice.(*RXQueueDevice).rxFlows)

	_, err = programmed.SetRXQueueFlows([]types.RXQueueFlow{flows[0], flows[1]})
	require.NoError(t, err)
	require.Len(t, fake.flowInsertCalls, 2)

	delete(fake.flows, 100)
	device, err = programmed.SetRXQueueFlows([]types.RXQueueFlow{flows[0], flows[1]})
	require.NoError(t, err)
	programmed = device.(*RXQueueDevice)
	require.Equal(t, uint32(100), fake.flowInsertCalls[2].Location)

	clearedDevice, err := programmed.SetRXQueueFlows(nil)
	require.NoError(t, err)
	require.Empty(t, clearedDevice.(*RXQueueDevice).rxFlows)
	require.Empty(t, fake.flows)
	require.Equal(t, []uint32{100, 101}, fake.flowDeleteCalls)
	require.Equal(t, ownershipAlias(fake.hostIfName), host.Attrs().Alias)
}

func TestSetRXQueueFlowsRollsBack(t *testing.T) {
	fake := newFakeNetlink(8, 8, testShareID)
	fake.install(t)
	prepared := prepareTestRXQueue(t, fake)
	boom := errors.New("insert failed")
	fake.flowInsertErrors[2] = boom

	_, err := prepared.SetRXQueueFlows(testRXFlows())
	require.ErrorIs(t, err, boom)
	require.Empty(t, fake.flows)
	require.Equal(t, []uint32{100}, fake.flowDeleteCalls)
	require.Equal(t, ownershipAlias(fake.hostIfName), fake.links[fake.hostIfName].Attrs().Alias)
}

func TestRecoverRXQueueFlows(t *testing.T) {
	fake := newFakeNetlink(8, 8, testShareID)
	fake.install(t)
	prepared := prepareTestRXQueue(t, fake)
	flows := testRXFlows()[:1]

	device, err := prepared.SetRXQueueFlows(flows)
	require.NoError(t, err)
	data, err := device.MarshalBinary()
	require.NoError(t, err)
	restoredDevice, err := (&RXQueueManager{}).RestoreDevice(data)
	require.NoError(t, err)

	delete(fake.links, fake.hostIfName)
	delete(fake.links, fake.peerIfName)
	clear(fake.leases)
	clear(fake.flows)

	recoveredDevice, err := restoredDevice.Recover(testAllocation(testShareID))
	require.NoError(t, err)
	recovered := recoveredDevice.(*RXQueueDevice)
	require.Equal(t, flows[0], recovered.rxFlows[0].Flow)
	require.Equal(t, uint32(101), recovered.rxFlows[0].Location)
	require.Contains(t, fake.flows, uint32(101))
	require.Equal(t, uint32(7), fake.flows[101].Queue)

	require.NoError(t, recovered.Free(testAllocation(testShareID)))
	require.Empty(t, fake.flows)
	require.NotContains(t, fake.links, fake.hostIfName)
}

func TestInsertRXFlowExplicitLocationFallback(t *testing.T) {
	for _, driverErr := range []error{unix.EINVAL, unix.ENOSPC} {
		t.Run(driverErr.Error(), func(t *testing.T) {
			fake := newFakeNetlink(8, 8, testShareID)
			fake.flowAnyLocationError = driverErr
			fake.flows[0] = netlink.NetDevRxFlow{Location: 0}
			fake.flows[2] = netlink.NetDevRxFlow{Location: 2}
			fake.install(t)

			location, err := insertRXFlow(testPhysicalIfName, netlink.NetDevRxFlow{
				Match:    netlink.TCP4Flow{},
				Queue:    7,
				Location: netlink.RX_CLS_LOC_ANY,
			})
			require.NoError(t, err)
			require.Equal(t, uint32(1), location)
			require.Len(t, fake.flowInsertCalls, 2)
			require.Equal(t, uint32(netlink.RX_CLS_LOC_ANY), fake.flowInsertCalls[0].Location)
			require.Equal(t, uint32(1), fake.flowInsertCalls[1].Location)
			require.Contains(t, fake.flows, uint32(0))
			require.Contains(t, fake.flows, uint32(1))
			require.Contains(t, fake.flows, uint32(2))
		})
	}
}

func TestInsertRXFlowExplicitLocationListFailure(t *testing.T) {
	fake := newFakeNetlink(8, 8, testShareID)
	fake.flowAnyLocationError = unix.ENOSPC
	fake.flowListError = unix.EIO
	fake.install(t)

	_, err := insertRXFlow(testPhysicalIfName, netlink.NetDevRxFlow{
		Match:    netlink.TCP4Flow{},
		Queue:    7,
		Location: netlink.RX_CLS_LOC_ANY,
	})
	require.ErrorIs(t, err, unix.ENOSPC)
	require.ErrorIs(t, err, unix.EIO)
	require.Len(t, fake.flowInsertCalls, 1)
	require.Empty(t, fake.flows)
}

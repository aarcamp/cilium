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

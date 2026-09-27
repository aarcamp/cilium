// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package rxqueue

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	kube_types "k8s.io/apimachinery/pkg/types"

	ciliumnetns "github.com/cilium/cilium/pkg/netns"
)

const fakePodNetNSID = 24

type fakeQueueNetlinkHandle struct {
	peer       netlink.Link
	netlink    *fakeNetlink
	creates    []netlink.NetDevQueueCreateRequest
	netNSID    int
	setNSCalls int
}

func (h *fakeQueueNetlinkHandle) LinkByName(name string) (netlink.Link, error) {
	if h.peer != nil && h.peer.Attrs().Name == name {
		return h.peer, nil
	}
	return nil, netlink.LinkNotFoundError{}
}

func (h *fakeQueueNetlinkHandle) NetDevQueueCreate(req netlink.NetDevQueueCreateRequest) (uint32, error) {
	h.creates = append(h.creates, req)
	h.netlink.leases[req.Lease.Queue.ID] = &netlink.NetDevQueueLease{
		IfIndex: uint32(req.IfIndex),
		Queue: netlink.NetDevQueueID{
			ID:   firstLeasedRXQueueID,
			Type: netlink.NetDevQueueTypeRx,
		},
		NetNSID:    fakePodNetNSID,
		NetNSIDSet: true,
	}
	return firstLeasedRXQueueID, nil
}

func (h *fakeQueueNetlinkHandle) GetNetNsIdByFd(int) (int, error) {
	return h.netNSID, nil
}

func (h *fakeQueueNetlinkHandle) SetNetNsIdByFd(int, int) error {
	h.setNSCalls++
	h.netNSID = 42
	return nil
}

func (*fakeQueueNetlinkHandle) Close() error { return nil }

func installQueueBindingFakes(
	t *testing.T,
	fake *fakeNetlink,
	peer netlink.Link,
) *fakeQueueNetlinkHandle {
	t.Helper()

	handle := &fakeQueueNetlinkHandle{
		peer:    peer,
		netlink: fake,
		netNSID: -1,
	}
	originalNewHandle := newQueueNetlinkHandle
	originalCurrentNS := currentNetNS
	originalIsPrimary := netkitIsPrimary
	originalHostGetNSID := hostGetNetNSIDByFD
	originalHostSetNSID := hostSetNetNSIDByFD
	hostNSID := -1
	t.Cleanup(func() {
		newQueueNetlinkHandle = originalNewHandle
		currentNetNS = originalCurrentNS
		netkitIsPrimary = originalIsPrimary
		hostGetNetNSIDByFD = originalHostGetNSID
		hostSetNetNSIDByFD = originalHostSetNSID
	})
	newQueueNetlinkHandle = func(*ciliumnetns.NetNS) (queueNetlinkHandle, error) {
		return handle, nil
	}
	currentNetNS = func() (*ciliumnetns.NetNS, error) {
		return &ciliumnetns.NetNS{}, nil
	}
	hostGetNetNSIDByFD = func(int) (int, error) { return hostNSID, nil }
	hostSetNetNSIDByFD = func(int, int) error {
		hostNSID = fakePodNetNSID
		return nil
	}
	netkitIsPrimary = func(link *netlink.Netkit) bool {
		return link.Attrs().Name == fake.hostIfName
	}
	return handle
}

func TestBindRXQueueToPodNetkit(t *testing.T) {
	fake := newFakeNetlink(8, 8, testShareID)
	fake.install(t)
	const originalAlias = "cilium-primary"
	fake.links[fake.hostIfName] = &netlink.Netkit{LinkAttrs: netlink.LinkAttrs{
		Name:  fake.hostIfName,
		Index: testHostIndex,
		Alias: originalAlias,
	}}
	peer := &netlink.Netkit{LinkAttrs: netlink.LinkAttrs{
		Name:        "eth0",
		Index:       testPeerIndex,
		NumRxQueues: 2,
	}}
	handle := installQueueBindingFakes(t, fake, peer)

	advertised := testDevice(8)
	device, err := advertised.Setup(testAllocation(testShareID))
	require.NoError(t, err)
	prepared := device.(*RXQueueDevice)

	device, err = prepared.BindRXQueue(fake.hostIfName, &ciliumnetns.NetNS{})
	require.NoError(t, err)
	bound := device.(*RXQueueDevice)
	require.True(t, bound.Bound)
	require.Equal(t, fake.hostIfName, bound.HostIfName)
	require.Equal(t, originalAlias, bound.OriginalHostAlias)
	require.Equal(t, uint32(7), bound.PhysicalQueueID)
	require.Equal(t, uint32(1), bound.VirtualQueueID)
	require.Len(t, handle.creates, 1)
	require.Equal(t, testPeerIndex, handle.creates[0].IfIndex)
	require.Equal(t, uint32(testPhysicalIndex), handle.creates[0].Lease.IfIndex)
	require.Equal(t, uint32(7), handle.creates[0].Lease.Queue.ID)
	require.True(t, handle.creates[0].Lease.NetNSIDSet)
	require.Equal(t, int32(42), handle.creates[0].Lease.NetNSID)
	require.Equal(t, 1, handle.setNSCalls)

	retried, err := bound.BindRXQueue(fake.hostIfName, &ciliumnetns.NetNS{})
	require.NoError(t, err)
	require.True(t, retried.(*RXQueueDevice).Bound)
	require.Len(t, handle.creates, 1)

	require.ErrorIs(t, bound.Free(testAllocation(testShareID)), errActiveLease)
	delete(fake.leases, uint32(7))
	require.NoError(t, bound.Free(testAllocation(testShareID)))

	nextShare := kube_types.UID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
	next, err := advertised.Setup(testAllocation(nextShare))
	require.NoError(t, err)
	require.Equal(t, uint32(7), next.(*RXQueueDevice).PhysicalQueueID)
}

func TestBindRXQueueAfterPodNetkitRecreation(t *testing.T) {
	fake := newFakeNetlink(8, 8, testShareID)
	fake.install(t)
	const originalAlias = "cilium-primary"
	fake.links[fake.hostIfName] = &netlink.Netkit{LinkAttrs: netlink.LinkAttrs{
		Name: fake.hostIfName, Index: testHostIndex, Alias: originalAlias,
	}}
	peer := &netlink.Netkit{LinkAttrs: netlink.LinkAttrs{
		Name: "eth0", Index: testPeerIndex, NumRxQueues: 2,
	}}
	handle := installQueueBindingFakes(t, fake, peer)

	device, err := testDevice(8).Setup(testAllocation(testShareID))
	require.NoError(t, err)
	device, err = device.(*RXQueueDevice).BindRXQueue(fake.hostIfName, &ciliumnetns.NetNS{})
	require.NoError(t, err)
	device, err = device.(*RXQueueDevice).SetRXQueueFlows(testRXFlows()[:1])
	require.NoError(t, err)
	programmed := device.(*RXQueueDevice)
	require.NotEmpty(t, programmed.rxFlows)
	require.NotEmpty(t, fake.flows)

	// Removing the Pod netkit releases its queue lease and loses the alias
	// journal, while the physical ntuple rule remains until Cilium removes it.
	delete(fake.leases, programmed.PhysicalQueueID)
	fake.links[fake.hostIfName] = &netlink.Netkit{LinkAttrs: netlink.LinkAttrs{
		Name: fake.hostIfName, Index: testHostIndex, Alias: originalAlias,
	}}

	device, err = programmed.BindRXQueue(fake.hostIfName, &ciliumnetns.NetNS{})
	require.NoError(t, err)
	rebound := device.(*RXQueueDevice)
	require.True(t, rebound.Bound)
	require.Empty(t, rebound.rxFlows)
	require.Empty(t, fake.flows)
	require.Equal(t, []uint32{100}, fake.flowDeleteCalls)
	require.Len(t, handle.creates, 2)
}
func TestBindRXQueueValidatesPodNetkit(t *testing.T) {
	t.Run("requires queue capacity", func(t *testing.T) {
		fake := newFakeNetlink(8, 8, testShareID)
		fake.install(t)
		fake.links[fake.hostIfName] = &netlink.Netkit{LinkAttrs: netlink.LinkAttrs{
			Name: fake.hostIfName, Index: testHostIndex,
		}}
		peer := &netlink.Netkit{LinkAttrs: netlink.LinkAttrs{
			Name: "eth0", Index: testPeerIndex, NumRxQueues: 1,
		}}
		installQueueBindingFakes(t, fake, peer)

		device, err := testDevice(8).Setup(testAllocation(testShareID))
		require.NoError(t, err)
		_, err = device.(*RXQueueDevice).BindRXQueue(fake.hostIfName, &ciliumnetns.NetNS{})
		require.ErrorContains(t, err, "does not have capacity")
	})

	t.Run("rejects a competing lease", func(t *testing.T) {
		fake := newFakeNetlink(8, 8, testShareID)
		fake.install(t)
		fake.links[fake.hostIfName] = &netlink.Netkit{LinkAttrs: netlink.LinkAttrs{
			Name: fake.hostIfName, Index: testHostIndex,
		}}
		peer := &netlink.Netkit{LinkAttrs: netlink.LinkAttrs{
			Name: "eth0", Index: testPeerIndex, NumRxQueues: 2,
		}}
		installQueueBindingFakes(t, fake, peer)

		device, err := testDevice(8).Setup(testAllocation(testShareID))
		require.NoError(t, err)
		fake.leases[7] = &netlink.NetDevQueueLease{
			IfIndex:    testPeerIndex,
			NetNSID:    fakePodNetNSID + 1,
			NetNSIDSet: true,
			Queue: netlink.NetDevQueueID{
				ID:   firstLeasedRXQueueID,
				Type: netlink.NetDevQueueTypeRx,
			},
		}
		_, err = device.(*RXQueueDevice).BindRXQueue(fake.hostIfName, &ciliumnetns.NetNS{})
		require.ErrorIs(t, err, errNoAvailableRXQueue)
	})
}

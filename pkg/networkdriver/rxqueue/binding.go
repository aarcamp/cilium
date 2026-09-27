// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package rxqueue

import (
	"errors"
	"fmt"

	"github.com/vishvananda/netlink"
	netlinkns "github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	ciliumnetns "github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/networkdriver/types"
)

type queueNetlinkHandle interface {
	LinkByName(string) (netlink.Link, error)
	NetDevQueueCreate(netlink.NetDevQueueCreateRequest) (uint32, error)
	GetNetNsIdByFd(int) (int, error)
	SetNetNsIdByFd(int, int) error
	Close() error
}

var (
	newQueueNetlinkHandle = func(ns *ciliumnetns.NetNS) (queueNetlinkHandle, error) {
		return netlink.NewHandleAt(netlinkns.NsHandle(ns.FD()), unix.NETLINK_ROUTE, unix.NETLINK_GENERIC)
	}
	currentNetNS       = ciliumnetns.Current
	netkitIsPrimary    = func(n *netlink.Netkit) bool { return n.IsPrimary() }
	hostGetNetNSIDByFD = netlink.GetNetNsIdByFd
	hostSetNetNSIDByFD = netlink.SetNetNsIdByFd
)

func netNSID(handle queueNetlinkHandle, fd int) (int, error) {
	return ensureNetNSID(handle.GetNetNsIdByFd, handle.SetNetNsIdByFd, fd)
}

func ensureNetNSID(
	get func(int) (int, error),
	set func(int, int) error,
	fd int,
) (int, error) {
	id, err := get(fd)
	if err != nil {
		return 0, err
	}
	if id >= 0 {
		return id, nil
	}
	if err := set(fd, -1); err != nil && !errors.Is(err, unix.EEXIST) {
		return 0, err
	}
	id, err = get(fd)
	if err != nil {
		return 0, err
	}
	if id < 0 {
		return 0, errors.New("kernel did not assign a network namespace ID")
	}
	return id, nil
}

// BindRXQueue leases the reserved physical queue to the existing Pod-side
// netkit interface. DRA preparation happens before CNI creates that interface,
// so the endpoint lifecycle calls this method after CNI has completed.
func (d *RXQueueDevice) BindRXQueue(hostIfName string, podNS *ciliumnetns.NetNS) (types.Device, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.Prepared || d.ShareID == "" || d.PodIfName == "" {
		return nil, fmt.Errorf("%w: RX queue must be reserved before it can be bound", errInvalidAllocation)
	}

	host, err := netlinkLinkByName(hostIfName)
	if err != nil {
		return nil, fmt.Errorf("failed to find Pod netkit host %s: %w", hostIfName, err)
	}
	hostNetkit, ok := host.(*netlink.Netkit)
	if !ok || !netkitIsPrimary(hostNetkit) {
		return nil, fmt.Errorf("%w: host interface %s is not a primary netkit", errInvalidAllocation, hostIfName)
	}

	handle, err := newQueueNetlinkHandle(podNS)
	if err != nil {
		return nil, fmt.Errorf("failed to open netlink sockets in Pod network namespace: %w", err)
	}
	defer handle.Close()

	peer, err := handle.LinkByName(d.PodIfName)
	if err != nil {
		return nil, fmt.Errorf("failed to find Pod interface %s: %w", d.PodIfName, err)
	}
	peerNetkit, ok := peer.(*netlink.Netkit)
	if !ok || netkitIsPrimary(peerNetkit) {
		return nil, fmt.Errorf("%w: Pod interface %s is not a netkit peer", errInvalidAllocation, d.PodIfName)
	}
	if peer.Attrs().NumRxQueues < int(firstLeasedRXQueueID+1) {
		return nil, fmt.Errorf("Pod interface %s does not have capacity for a leased RX queue", d.PodIfName)
	}

	podNSID, err := ensureNetNSID(hostGetNetNSIDByFD, hostSetNetNSIDByFD, podNS.FD())
	if err != nil {
		return nil, fmt.Errorf("failed to resolve Pod network namespace ID from host: %w", err)
	}

	physical, err := netlinkLinkByName(d.PhysicalIfName)
	if err != nil {
		return nil, fmt.Errorf("failed to find physical interface %s: %w", d.PhysicalIfName, err)
	}
	queue, err := netlinkNetDevQueueGet(physical.Attrs().Index, d.PhysicalQueueID, netlink.NetDevQueueTypeRx)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect reserved RX queue %s/%d: %w", d.PhysicalIfName, d.PhysicalQueueID, err)
	}

	if queue.Lease == nil {
		rootNS, err := currentNetNS()
		if err != nil {
			return nil, fmt.Errorf("failed to open host network namespace: %w", err)
		}
		defer rootNS.Close()

		rootNSID, err := netNSID(handle, rootNS.FD())
		if err != nil {
			return nil, fmt.Errorf("failed to resolve host network namespace ID from Pod: %w", err)
		}
		virtualQueueID, err := handle.NetDevQueueCreate(netlink.NetDevQueueCreateRequest{
			IfIndex: peer.Attrs().Index,
			Type:    netlink.NetDevQueueTypeRx,
			Lease: netlink.NetDevQueueLease{
				IfIndex: uint32(physical.Attrs().Index),
				Queue: netlink.NetDevQueueID{
					ID:   d.PhysicalQueueID,
					Type: netlink.NetDevQueueTypeRx,
				},
				NetNSID:    int32(rootNSID),
				NetNSIDSet: true,
			},
		})
		if err != nil {
			return nil, fmt.Errorf("failed to lease RX queue %s/%d to %s: %w", d.PhysicalIfName, d.PhysicalQueueID, d.PodIfName, err)
		}
		if virtualQueueID != firstLeasedRXQueueID {
			return nil, fmt.Errorf("kernel created virtual RX queue %d on %s, expected %d", virtualQueueID, d.PodIfName, firstLeasedRXQueueID)
		}

		queue, err = netlinkNetDevQueueGet(physical.Attrs().Index, d.PhysicalQueueID, netlink.NetDevQueueTypeRx)
		if err != nil {
			return nil, fmt.Errorf("failed to verify RX queue lease %s/%d: %w", d.PhysicalIfName, d.PhysicalQueueID, err)
		}
	}
	if !leaseMatches(queue.Lease, peer.Attrs().Index, int32(podNSID)) || queue.Lease.Queue.ID != firstLeasedRXQueueID {
		return nil, fmt.Errorf("%w: RX queue %s/%d is leased by another interface", errNoAvailableRXQueue, d.PhysicalIfName, d.PhysicalQueueID)
	}

	bound := d.clone()
	bound.Bound = true
	bound.HostIfName = hostIfName
	bound.VirtualQueueID = firstLeasedRXQueueID
	if !d.Bound || d.HostIfName != hostIfName {
		bound.OriginalHostAlias = host.Attrs().Alias
	}
	return bound, nil
}

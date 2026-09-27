// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package rxqueue

import (
	"fmt"
	"slices"
	"sync"

	kube_types "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/networkdriver/types"
)

type queueReservations struct {
	mu     sync.Mutex
	owners map[uint32]kube_types.UID
}

func (m *RXQueueManager) reservationsFor(ifName string) *queueReservations {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.reservations == nil {
		m.reservations = make(map[string]*queueReservations)
	}
	reservations := m.reservations[ifName]
	if reservations == nil {
		reservations = &queueReservations{owners: make(map[uint32]kube_types.UID)}
		m.reservations[ifName] = reservations
	}
	return reservations
}

func (d *RXQueueDevice) reserve(allocation types.DeviceAllocation, candidates []uint32) (*RXQueueDevice, error) {
	if err := validateAllocation(allocation); err != nil {
		return nil, err
	}

	podIfName := allocation.Config.PodIfName
	if podIfName == "" {
		podIfName = types.DefaultRXQueuePodIfName
	}
	if err := types.ValidateInterfaceName(podIfName); err != nil {
		return nil, fmt.Errorf("%w: invalid pod interface name %q: %v", errInvalidAllocation, podIfName, err)
	}
	if d.Prepared && (d.ShareID != allocation.ShareID || d.PodIfName != podIfName) {
		return nil, fmt.Errorf("%w: stored RX queue state does not match allocation", errInvalidAllocation)
	}
	if d.reservations == nil {
		return nil, fmt.Errorf("%w: RX queue reservation state is unavailable", errInvalidAllocation)
	}

	d.reservations.mu.Lock()
	defer d.reservations.mu.Unlock()
	if d.reservations.owners == nil {
		d.reservations.owners = make(map[uint32]kube_types.UID)
	}

	for _, queueID := range candidates {
		owner, reserved := d.reservations.owners[queueID]
		if reserved {
			if owner == allocation.ShareID {
				return d.preparedForAllocation(allocation.ShareID, podIfName, queueID), nil
			}
			continue
		}

		queue, err := netlinkNetDevQueueGetByName(d.PhysicalIfName, queueID)
		if err != nil {
			return nil, err
		}
		if queue.Lease != nil {
			continue
		}

		d.reservations.owners[queueID] = allocation.ShareID
		return d.preparedForAllocation(allocation.ShareID, podIfName, queueID), nil
	}

	return nil, fmt.Errorf("%w on %s", errNoAvailableRXQueue, d.PhysicalIfName)
}

func (d *RXQueueDevice) restoreReservation() error {
	if !d.Prepared {
		return nil
	}
	if d.ShareID == "" || d.PodIfName == "" || !slices.Contains(d.ReservedQueueIDs, d.PhysicalQueueID) {
		return fmt.Errorf("%w: stored RX queue reservation is incomplete", errInvalidAllocation)
	}
	if d.reservations == nil {
		return fmt.Errorf("%w: RX queue reservation state is unavailable", errInvalidAllocation)
	}

	d.reservations.mu.Lock()
	defer d.reservations.mu.Unlock()
	if d.reservations.owners == nil {
		d.reservations.owners = make(map[uint32]kube_types.UID)
	}
	if owner, exists := d.reservations.owners[d.PhysicalQueueID]; exists && owner != d.ShareID {
		return fmt.Errorf("%w: RX queue %s/%d is already reserved", errInvalidAllocation, d.PhysicalIfName, d.PhysicalQueueID)
	}
	d.reservations.owners[d.PhysicalQueueID] = d.ShareID
	return nil
}

func (d *RXQueueDevice) releaseReservation() {
	if d.reservations == nil {
		return
	}
	d.reservations.mu.Lock()
	defer d.reservations.mu.Unlock()
	if d.reservations.owners[d.PhysicalQueueID] == d.ShareID {
		delete(d.reservations.owners, d.PhysicalQueueID)
	}
}

func (d *RXQueueDevice) preparedForAllocation(shareID kube_types.UID, podIfName string, physicalQueueID uint32) *RXQueueDevice {
	prepared := d.clone()
	prepared.Prepared = true
	prepared.Bound = false
	prepared.ShareID = shareID
	prepared.PodIfName = podIfName
	prepared.HostIfName = ""
	prepared.OriginalHostAlias = ""
	prepared.PhysicalQueueID = physicalQueueID
	prepared.VirtualQueueID = firstLeasedRXQueueID
	prepared.rxFlows = nil
	return prepared
}

func (d *RXQueueDevice) clone() *RXQueueDevice {
	return &RXQueueDevice{
		PhysicalIfName:    d.PhysicalIfName,
		HardwareAddress:   d.HardwareAddress,
		MTU:               d.MTU,
		TotalRXQueues:     d.TotalRXQueues,
		ReservedQueueIDs:  slices.Clone(d.ReservedQueueIDs),
		Prepared:          d.Prepared,
		Bound:             d.Bound,
		ShareID:           d.ShareID,
		PodIfName:         d.PodIfName,
		HostIfName:        d.HostIfName,
		OriginalHostAlias: d.OriginalHostAlias,
		PhysicalQueueID:   d.PhysicalQueueID,
		VirtualQueueID:    d.VirtualQueueID,
		rxFlows:           slices.Clone(d.rxFlows),
		reservations:      d.reservations,
	}
}

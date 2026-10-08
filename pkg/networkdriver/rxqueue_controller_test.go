// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	kube_types "k8s.io/apimachinery/pkg/types"

	k8sTables "github.com/cilium/cilium/pkg/k8s/tables"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/networkdriver/rxqueue"
	"github.com/cilium/cilium/pkg/networkdriver/types"
)

const rxQueueTestPodUID = kube_types.UID("rx-queue-pod")

type rxQueueControllerFixture struct {
	rxQueueServiceFixture
	driver *Driver
	pods   statedb.RWTable[k8sTables.LocalPod]
}

func newRXQueueControllerFixture(t *testing.T) rxQueueControllerFixture {
	f := rxQueueControllerFixture{rxQueueServiceFixture: newRXQueueServiceFixture(t)}
	allocations, err := newAllocationTable(f.db)
	require.NoError(t, err)
	flows, err := newRXQueueFlowsTable(f.db)
	require.NoError(t, err)
	f.pods, err = k8sTables.NewPodTable(f.db)
	require.NoError(t, err)

	f.driver = &Driver{
		logger:          hivetest.Logger(t),
		db:              f.db,
		allocationTable: allocations,
		rxQueueFlows:    flows,
		localPods:       f.pods,
		services:        f.services,
		backends:        f.backends,
	}
	return f
}

func (f rxQueueControllerFixture) allocate(config *types.RXQueueConfig) *DRAAllocation {
	allocation := &DRAAllocation{
		DeviceName: "ens1",
		Pool:       "node",
		ShareID:    "share",
		Manager:    types.DeviceManagerTypeRXQueue,
		PodUID:     rxQueueTestPodUID,
		Config:     types.DeviceConfig{RXQueue: config},
		PreparedDevice: &rxqueue.RXQueueDevice{
			PhysicalIfName:  "ens1",
			Prepared:        true,
			PhysicalQueueID: 7,
		},
	}
	wtxn := f.db.WriteTxn(f.driver.allocationTable)
	f.driver.allocationTable.Insert(wtxn, allocation)
	wtxn.Commit()
	return allocation
}

func (f rxQueueControllerFixture) upsertPod() {
	pod := rxQueueTestPod()
	pod.UID = rxQueueTestPodUID
	wtxn := f.db.WriteTxn(f.pods)
	f.pods.Insert(wtxn, k8sTables.LocalPod{Pod: pod})
	wtxn.Commit()
}

func (f rxQueueControllerFixture) update(t *testing.T) []*RXQueueFlows {
	wtxn := f.db.WriteTxn(f.driver.rxQueueFlows)
	f.driver.updateRXQueueFlows(t.Context(), wtxn, statedb.NewWatchSet())
	wtxn.Commit()
	return statedb.Collect(f.driver.rxQueueFlows.All(f.db.ReadTxn()))
}

func TestUpdateRXQueueFlows(t *testing.T) {
	f := newRXQueueControllerFixture(t)
	allocation := f.allocate(&types.RXQueueConfig{
		ServiceEndpoint: &types.RXQueueServiceEndpoint{ServiceName: "storage", Port: "rpc"},
	})

	rows := f.update(t)
	require.Len(t, rows, 1)
	require.Equal(t, "Pod is not running on this node", rows[0].Unresolved)
	require.Empty(t, rows[0].Flows)
	require.Equal(t, "ens1", rows[0].PhysicalIfName)
	require.Equal(t, allocation.ShareID, rows[0].ShareID)
	require.Equal(t, uint32(7), rows[0].QueueID)

	f.upsertPod()
	require.Contains(t, f.update(t)[0].Unresolved, "was not found")

	f.upsert(&loadbalancer.Service{
		Name:      loadbalancer.NewServiceName("default", "storage"),
		PortNames: map[string]uint16{"rpc": 9000},
	}, rxQueueTestBackend(loadbalancer.TCP, "192.0.2.10", 8080, "rpc"))
	rows = f.update(t)
	require.Empty(t, rows[0].Unresolved)
	require.Equal(t, []types.RXQueueFlow{{
		DestinationIP:   netip.MustParseAddr("192.0.2.10"),
		DestinationPort: 8080,
		Protocol:        corev1.ProtocolTCP,
	}}, rows[0].Flows)

	revision := f.driver.rxQueueFlows.Revision(f.db.ReadTxn())
	f.update(t)
	require.Equal(t, revision, f.driver.rxQueueFlows.Revision(f.db.ReadTxn()), "unchanged rows are not rewritten")

	wtxn := f.db.WriteTxn(f.driver.allocationTable)
	f.driver.allocationTable.Delete(wtxn, allocation)
	wtxn.Commit()
	require.Empty(t, f.update(t))
}

func TestRXQueueFlowController(t *testing.T) {
	f := newRXQueueControllerFixture(t)
	f.upsertPod()
	f.allocate(&types.RXQueueConfig{
		PodEndpoint: &types.RXQueuePodEndpoint{Port: "rpc", Protocol: corev1.ProtocolTCP},
	})

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error)
	health, _ := cell.NewSimpleHealth()
	go func() { done <- f.driver.runRXQueueFlowController(ctx, health) }()
	t.Cleanup(func() {
		cancel()
		require.NoError(t, <-done)
	})

	require.Eventually(t, func() bool {
		return f.driver.rxQueueFlows.NumObjects(f.db.ReadTxn()) == 1
	}, 5*time.Second, 10*time.Millisecond)
	rows := statedb.Collect(f.driver.rxQueueFlows.All(f.db.ReadTxn()))
	require.Len(t, rows[0].Flows, 2)
	require.Equal(t, uint16(8080), rows[0].Flows[0].DestinationPort)
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"context"
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	kube_types "k8s.io/apimachinery/pkg/types"

	k8sTables "github.com/cilium/cilium/pkg/k8s/tables"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/networkdriver/rxqueue"
	"github.com/cilium/cilium/pkg/time"
)

// rxQueueFlowSettleTime coalesces bursts of Pod, Service, and allocation
// changes into one update of the desired flows.
const rxQueueFlowSettleTime = 100 * time.Millisecond

// runRXQueueFlowController keeps the desired RX queue flows in sync with the
// RX queue allocations, the Pods holding them, and the Services they select.
// It only writes StateDB; the flow reconciler programs the NIC.
func (driver *Driver) runRXQueueFlowController(ctx context.Context, health cell.Health) error {
	for _, table := range []statedb.TableMeta{driver.localPods, driver.services, driver.backends} {
		for {
			initialized, watch := table.Initialized(driver.db.ReadTxn())
			if initialized {
				break
			}
			select {
			case <-ctx.Done():
				return nil
			case <-watch:
			}
		}
	}

	for {
		ws := statedb.NewWatchSet()
		wtxn := driver.db.WriteTxn(driver.rxQueueFlows)
		driver.updateRXQueueFlows(ctx, wtxn, ws)
		wtxn.Commit()
		health.OK("RX queue flows up to date")

		if _, err := ws.Wait(ctx, rxQueueFlowSettleTime); err != nil {
			return nil
		}
	}
}

func (driver *Driver) updateRXQueueFlows(ctx context.Context, wtxn statedb.WriteTxn, ws *statedb.WatchSet) {
	pods, watch := driver.localPods.AllWatch(wtxn)
	ws.Add(watch)
	podsByUID := make(map[kube_types.UID]k8sTables.LocalPod)
	for pod := range pods {
		podsByUID[kube_types.UID(pod.UID)] = pod
	}

	allocations, watch := driver.allocationTable.AllWatch(wtxn)
	ws.Add(watch)
	desired := make(map[string]*RXQueueFlows)
	for row := range allocations {
		device, ok := row.PreparedDevice.(*rxqueue.RXQueueDevice)
		if !ok || !device.Prepared {
			continue
		}
		flows := &RXQueueFlows{
			Allocation:     AllocationKey(row.Pool, row.DeviceName, row.ShareID),
			ShareID:        row.ShareID,
			PhysicalIfName: device.PhysicalIfName,
			QueueID:        device.PhysicalQueueID,
		}
		// Without resolvable flows the row still exists, so the reconciler
		// removes any rule that targets the allocation's queue.
		pod, found := podsByUID[row.PodUID]
		switch {
		case row.Config.RXQueue == nil:
		case !found:
			flows.Unresolved = "Pod is not running on this node"
		case pod.Spec.HostNetwork:
			flows.Unresolved = "Pod uses the host network"
		default:
			resolved, err := resolveRXQueueFlows(wtxn, driver.services, driver.backends, ws, pod.Pod, row.Config.RXQueue)
			if err != nil {
				flows.Unresolved = err.Error()
			} else {
				flows.Flows = resolved
			}
		}
		desired[flows.Allocation] = flows
	}

	var stale []*RXQueueFlows
	for existing := range driver.rxQueueFlows.All(wtxn) {
		if _, found := desired[existing.Allocation]; !found {
			stale = append(stale, existing)
		}
	}
	for _, existing := range stale {
		driver.rxQueueFlows.Delete(wtxn, existing)
	}

	for _, flows := range desired {
		existing, _, found := driver.rxQueueFlows.Get(wtxn, rxQueueFlowsByAllocation.Query(flows.Allocation))
		if found && existing.ShareID == flows.ShareID &&
			existing.PhysicalIfName == flows.PhysicalIfName && existing.QueueID == flows.QueueID &&
			slices.Equal(existing.Flows, flows.Flows) && existing.Unresolved == flows.Unresolved {
			continue
		}
		if flows.Unresolved != "" && (!found || existing.Unresolved != flows.Unresolved) {
			driver.logger.InfoContext(ctx, "RX queue flow selector is not resolved; no traffic is steered to the queue",
				logfields.Device, flows.PhysicalIfName,
				logfields.Reason, flows.Unresolved,
			)
		}
		flows.Status = reconciler.StatusPending()
		driver.rxQueueFlows.Insert(wtxn, flows)
	}
}

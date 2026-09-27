// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"context"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

const rxQueueReconcileRetryInterval = time.Second

func (driver *Driver) triggerRXQueueReconciliation() {
	select {
	case driver.rxQueueReconcile <- struct{}{}:
	default:
	}
}

func (driver *Driver) EndpointCreated(ep *endpoint.Endpoint) {
	if ep.K8sNamespaceAndPodNameIsSet() {
		driver.triggerRXQueueReconciliation()
	}
}

func (driver *Driver) EndpointDeleted(ep *endpoint.Endpoint, _ endpoint.DeleteConfig) {
	if ep.K8sNamespaceAndPodNameIsSet() {
		driver.triggerRXQueueReconciliation()
	}
}

func (driver *Driver) EndpointRestored(ep *endpoint.Endpoint) {
	if ep.K8sNamespaceAndPodNameIsSet() {
		driver.triggerRXQueueReconciliation()
	}
}

func (driver *Driver) runRXQueueResourceEvents(ctx context.Context, _ cell.Health) error {
	podEvents := driver.pods.Events(ctx)
	serviceEvents := driver.services.Events(ctx)

	for podEvents != nil || serviceEvents != nil {
		select {
		case <-ctx.Done():
			return nil
		case event, open := <-podEvents:
			if !open {
				podEvents = nil
				continue
			}
			event.Done(nil)
			driver.triggerRXQueueReconciliation()
		case event, open := <-serviceEvents:
			if !open {
				serviceEvents = nil
				continue
			}
			event.Done(nil)
			driver.triggerRXQueueReconciliation()
		}
	}
	return nil
}

func (driver *Driver) runRXQueueFlowReconciliation(ctx context.Context, _ cell.Health) error {
	pods, err := driver.pods.Store(ctx)
	if err != nil {
		return err
	}
	services, err := driver.services.Store(ctx)
	if err != nil {
		return err
	}
	claims, err := driver.resourceClaims.Store(ctx)
	if err != nil {
		return err
	}

	for {
		txn := driver.db.ReadTxn()
		_, allocationsWatch := driver.allocationTable.AllWatch(txn)

		err := driver.withLock(func() error {
			return driver.reconcileRXQueueFlows(ctx, pods, services, claims)
		})
		var retry <-chan time.Time
		if err != nil {
			driver.logger.ErrorContext(ctx, "failed to reconcile RX queue flow steering",
				logfields.Error, err)
			retry = time.After(rxQueueReconcileRetryInterval)
		}

		select {
		case <-ctx.Done():
			return nil
		case <-allocationsWatch:
		case <-driver.rxQueueReconcile:
		case <-retry:
		}
	}
}

var _ endpointmanager.Subscriber = (*Driver)(nil)

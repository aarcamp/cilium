// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"

	corev1 "k8s.io/api/core/v1"
	resourceapi "k8s.io/api/resource/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kube_types "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/networkdriver/types"
)

type rxQueueEndpointManager interface {
	GetEndpointsByPodName(string) []*endpoint.Endpoint
}

type rxQueuePodStore interface {
	List() []*corev1.Pod
}

type rxQueueServiceStore interface {
	GetByKey(resource.Key) (*corev1.Service, bool, error)
}

type rxQueueClaimStore interface {
	List() []*resourceapi.ResourceClaim
}

func (driver *Driver) reconcileRXQueueFlows(
	ctx context.Context,
	pods rxQueuePodStore,
	services rxQueueServiceStore,
	claims rxQueueClaimStore,
) error {
	podsByUID := make(map[kube_types.UID]*corev1.Pod)
	for _, pod := range pods.List() {
		podsByUID[pod.UID] = pod
	}

	claimKeys := make(map[kube_types.UID]resource.Key)
	for _, claim := range claims.List() {
		claimKeys[claim.UID] = resource.Key{
			Namespace: claim.Namespace,
			Name:      claim.Name,
		}
	}

	txn := driver.db.ReadTxn()
	var allocations []*DRAAllocation
	for row := range driver.allocationTable.All(txn) {
		if row.Manager != types.DeviceManagerTypeRXQueue ||
			row.PreparedDevice == nil ||
			row.Config.RXQueue == nil {
			continue
		}
		allocations = append(allocations, row.Clone())
	}

	var errs []error
	for _, row := range allocations {
		claimKey, found := claimKeys[row.ClaimUID]
		if !found {
			errs = append(errs, fmt.Errorf("ResourceClaim with UID %s was not found", row.ClaimUID))
			continue
		}

		flows, apply, resolveErr := driver.resolveAllocationRXQueueFlows(
			podsByUID[row.PodUID],
			services,
			row.Config.RXQueue,
		)
		if !apply {
			errs = append(errs, fmt.Errorf("resolve flows for claim %s: %w", row.ClaimUID, resolveErr))
			continue
		}

		if resolveErr != nil {
			driver.logger.WarnContext(ctx, "RX queue flow selector is not currently resolvable; removing flow steering",
				logfields.UID, row.ClaimUID,
				logfields.Error, resolveErr)
		}

		programmer, ok := row.PreparedDevice.(types.RXQueueFlowProgrammer)
		if !ok {
			errs = append(errs, fmt.Errorf(
				"prepared RX queue device %s does not support flow programming",
				row.DeviceName,
			))
			continue
		}
		updatedDevice, err := programmer.SetRXQueueFlows(flows)
		if err != nil {
			errs = append(errs, fmt.Errorf(
				"program flows for RX queue allocation %s: %w",
				AllocationKey(row.Pool, row.DeviceName, row.ShareID),
				err,
			))
			continue
		}
		if updatedDevice == nil {
			errs = append(errs, fmt.Errorf(
				"RX queue device %s returned no programmed device",
				row.DeviceName,
			))
			continue
		}

		if err := driver.persistRXQueueFlowDevice(
			ctx,
			row,
			updatedDevice,
			claimKey,
		); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// resolveAllocationRXQueueFlows returns apply=false only when a transient
// store lookup failed. Missing Pods, endpoints, or Services produce an empty
// desired set so stale steering is removed.
func (driver *Driver) resolveAllocationRXQueueFlows(
	pod *corev1.Pod,
	services rxQueueServiceStore,
	config *types.RXQueueConfig,
) (flows []types.RXQueueFlow, apply bool, err error) {
	if pod == nil {
		return nil, true, nil
	}

	endpoints := driver.endpointManager.GetEndpointsByPodName(
		pod.Namespace + "/" + pod.Name,
	)
	ips := make([]netip.Addr, 0, len(endpoints)*2)
	for _, ep := range endpoints {
		if kube_types.UID(ep.GetK8sPodUID()) != pod.UID {
			continue
		}
		if ip := ep.IPv4Address(); ip.IsValid() {
			ips = append(ips, ip)
		}
		if ip := ep.IPv6Address(); ip.IsValid() {
			ips = append(ips, ip)
		}
	}
	if len(ips) == 0 {
		return nil, true, nil
	}

	var service *corev1.Service
	if config.ServiceEndpoint != nil {
		var found bool
		service, found, err = services.GetByKey(resource.Key{
			Namespace: pod.Namespace,
			Name:      config.ServiceEndpoint.ServiceName,
		})
		if err != nil {
			return nil, false, err
		}
		if !found {
			return nil, true, fmt.Errorf(
				"Service %s/%s was not found",
				pod.Namespace,
				config.ServiceEndpoint.ServiceName,
			)
		}
	}

	targets, err := resolveRXQueueFlowTargets(pod, service, ips, config)
	if err != nil {
		return nil, true, err
	}
	flows = make([]types.RXQueueFlow, 0, len(targets))
	for _, target := range targets {
		flows = append(flows, types.RXQueueFlow{
			DestinationIP:   target.IP,
			DestinationPort: target.Port,
			Protocol:        target.Protocol,
		})
	}
	return flows, true, nil
}

func (driver *Driver) persistRXQueueFlowDevice(
	ctx context.Context,
	row *DRAAllocation,
	device types.Device,
	claimKey resource.Key,
) error {
	before := allocationFromRow(row)
	after := before
	after.Device = device

	beforeData, err := serializeDevice(before)
	if err != nil {
		return fmt.Errorf("serialize prior RX queue device %s: %w", row.DeviceName, err)
	}
	afterData, err := serializeDevice(after)
	if err != nil {
		return fmt.Errorf("serialize programmed RX queue device %s: %w", row.DeviceName, err)
	}
	if bytes.Equal(beforeData, afterData) {
		return nil
	}
	if claimKey.Name == "" {
		return fmt.Errorf("ResourceClaim with UID %s was not found", row.ClaimUID)
	}

	if err := driver.updateClaimDeviceData(ctx, claimKey, after.id(), afterData); err != nil {
		return err
	}
	driver.updateAllocationDevice(after)
	return nil
}

func (driver *Driver) updateClaimDeviceData(
	ctx context.Context,
	key resource.Key,
	id allocationID,
	data []byte,
) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		claim, err := driver.kubeClient.ResourceV1().
			ResourceClaims(key.Namespace).
			Get(ctx, key.Name, metav1.GetOptions{})
		if err != nil {
			if k8sErrors.IsNotFound(err) {
				return fmt.Errorf("ResourceClaim %s/%s was deleted", key.Namespace, key.Name)
			}
			return err
		}

		index := -1
		for i := range claim.Status.Devices {
			status := &claim.Status.Devices[i]
			if status.Driver == driver.config.DriverName &&
				allocationIDFromStatus(*status) == id {
				if index != -1 {
					return fmt.Errorf(
						"ResourceClaim %s/%s has duplicate status for device %s",
						key.Namespace,
						key.Name,
						id.Device,
					)
				}
				index = i
			}
		}
		if index == -1 {
			return fmt.Errorf(
				"ResourceClaim %s/%s has no status for device %s",
				key.Namespace,
				key.Name,
				id.Device,
			)
		}
		if claim.Status.Devices[index].Data != nil &&
			bytes.Equal(claim.Status.Devices[index].Data.Raw, data) {
			return nil
		}

		updated := claim.DeepCopy()
		updated.Status.Devices[index].Data = &runtime.RawExtension{
			Raw: slices.Clone(data),
		}
		_, err = driver.kubeClient.ResourceV1().
			ResourceClaims(key.Namespace).
			UpdateStatus(ctx, updated, metav1.UpdateOptions{})
		return err
	})
}

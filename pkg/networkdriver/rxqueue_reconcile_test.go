// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	resourceapi "k8s.io/api/resource/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/networkdriver/types"
)

type staticRXQueuePods []*corev1.Pod

func (pods staticRXQueuePods) List() []*corev1.Pod { return pods }

type staticRXQueueClaims []*resourceapi.ResourceClaim

func (claims staticRXQueueClaims) List() []*resourceapi.ResourceClaim { return claims }

type staticRXQueueServices struct {
	objects map[resource.Key]*corev1.Service
	lookups []resource.Key
	err     error
}

func (services *staticRXQueueServices) GetByKey(key resource.Key) (*corev1.Service, bool, error) {
	services.lookups = append(services.lookups, key)
	if services.err != nil {
		return nil, false, services.err
	}
	service, found := services.objects[key]
	return service, found, nil
}

type fakeRXQueueEndpointManager struct {
	endpoints  map[string][]*endpoint.Endpoint
	lookups    []string
	subscriber endpointmanager.Subscriber
}

func (manager *fakeRXQueueEndpointManager) GetEndpointsByPodName(name string) []*endpoint.Endpoint {
	manager.lookups = append(manager.lookups, name)
	return manager.endpoints[name]
}

func (manager *fakeRXQueueEndpointManager) Subscribe(subscriber endpointmanager.Subscriber) {
	manager.subscriber = subscriber
}

func (manager *fakeRXQueueEndpointManager) Unsubscribe(subscriber endpointmanager.Subscriber) {
	if manager.subscriber == subscriber {
		manager.subscriber = nil
	}
}

type reconcileFlowDevice struct {
	*trackedDevice
	flows    []types.RXQueueFlow
	setCalls *atomic.Int32
}

type reconcileFlowDeviceState struct {
	Name  string              `json:"name"`
	Flows []types.RXQueueFlow `json:"flows,omitempty"`
}

func (device *reconcileFlowDevice) SetRXQueueFlows(flows []types.RXQueueFlow) (types.Device, error) {
	device.setCalls.Add(1)
	updated := *device
	updated.flows = slices.Clone(flows)
	if len(updated.flows) == 0 {
		updated.flows = nil
	}
	return &updated, nil
}

func (device *reconcileFlowDevice) MarshalBinary() ([]byte, error) {
	return json.Marshal(reconcileFlowDeviceState{
		Name:  device.name,
		Flows: device.flows,
	})
}

func (device *reconcileFlowDevice) UnmarshalBinary(data []byte) error {
	var state reconcileFlowDeviceState
	if err := json.Unmarshal(data, &state); err != nil {
		return err
	}
	if device.trackedDevice == nil {
		device.trackedDevice = &trackedDevice{}
	}
	if device.setCalls == nil {
		device.setCalls = &atomic.Int32{}
	}
	device.name = state.Name
	device.flows = slices.Clone(state.Flows)
	return nil
}

type rxQueueReconcileFixture struct {
	driver          *Driver
	client          *k8sClient.FakeClientset
	pods            staticRXQueuePods
	claims          staticRXQueueClaims
	services        *staticRXQueueServices
	endpointManager *fakeRXQueueEndpointManager
	setCalls        *atomic.Int32
}

func newRXQueueReconcileFixture(t *testing.T, config *types.RXQueueConfig) *rxQueueReconcileFixture {
	t.Helper()

	client, _ := k8sClient.NewFakeClientset(hivetest.Logger(t))
	db := statedb.New()
	allocationTable, err := newAllocationTable(db)
	require.NoError(t, err)

	setCalls := &atomic.Int32{}
	device := &reconcileFlowDevice{
		trackedDevice: &trackedDevice{name: "zcrx0"},
		setCalls:      setCalls,
	}
	row := &DRAAllocation{
		DeviceName:     prepTestDev0,
		Manager:        types.DeviceManagerTypeRXQueue,
		PreparedDevice: device,
		Pool:           prepTestPool,
		PodUID:         prepTestPodUID,
		ClaimUID:       prepTestClaimUID,
		Config: types.DeviceConfig{
			PodIfName: "zcrx0",
			RXQueue:   config,
		},
		ShareID: prepTestShareID0,
	}
	wtxn := db.WriteTxn(allocationTable)
	allocationTable.Insert(wtxn, row)
	wtxn.Commit()

	data, err := serializeDevice(allocationFromRow(row))
	require.NoError(t, err)
	shareID := string(prepTestShareID0)
	claim := &resourceapi.ResourceClaim{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: prepTestClaimNS,
			Name:      prepTestClaimName,
			UID:       prepTestClaimUID,
		},
		Status: resourceapi.ResourceClaimStatus{
			Devices: []resourceapi.AllocatedDeviceStatus{{
				Driver:  prepTestDriverName,
				Pool:    prepTestPool,
				Device:  prepTestDev0,
				ShareID: &shareID,
				Conditions: []metav1.Condition{{
					Type:   "Ready",
					Status: metav1.ConditionTrue,
				}},
				Data: &runtime.RawExtension{Raw: data},
				NetworkData: &resourceapi.NetworkDeviceData{
					InterfaceName: "zcrx0",
				},
			}},
		},
	}
	createPrepClaim(t, client, claim)

	pod := rxQueueTestPod()
	pod.UID = prepTestPodUID
	endpointManager := &fakeRXQueueEndpointManager{
		endpoints: map[string][]*endpoint.Endpoint{
			pod.Namespace + "/" + pod.Name: {
				{
					K8sNamespace: pod.Namespace,
					K8sPodName:   pod.Name,
					K8sUID:       string(pod.UID),
					IPv4:         netip.MustParseAddr("192.0.2.10"),
					IPv6:         netip.MustParseAddr("2001:db8::10"),
				},
			},
		},
	}
	services := &staticRXQueueServices{objects: map[resource.Key]*corev1.Service{}}
	driver := &Driver{
		logger:          hivetest.Logger(t),
		kubeClient:      client,
		endpointManager: endpointManager,
		config: &v2alpha1.CiliumNetworkDriverNodeConfigSpec{
			DriverName: prepTestDriverName,
		},
		db:              db,
		allocationTable: allocationTable,
	}

	return &rxQueueReconcileFixture{
		driver:          driver,
		client:          client,
		pods:            staticRXQueuePods{pod},
		claims:          staticRXQueueClaims{claim},
		services:        services,
		endpointManager: endpointManager,
		setCalls:        setCalls,
	}
}

func (fixture *rxQueueReconcileFixture) reconcile(t *testing.T) error {
	t.Helper()
	return fixture.driver.reconcileRXQueueFlows(
		t.Context(),
		fixture.pods,
		fixture.services,
		fixture.claims,
	)
}

func (fixture *rxQueueReconcileFixture) device(t *testing.T) *reconcileFlowDevice {
	t.Helper()
	txn := fixture.driver.db.ReadTxn()
	row, _, found := fixture.driver.allocationTable.Get(txn, allocationByKey.Query(
		AllocationKey(prepTestPool, prepTestDev0, prepTestShareID0),
	))
	require.True(t, found)
	device, ok := row.PreparedDevice.(*reconcileFlowDevice)
	require.True(t, ok)
	return device
}

func (fixture *rxQueueReconcileFixture) claimDeviceState(t *testing.T) reconcileFlowDeviceState {
	t.Helper()
	claim, err := fixture.client.KubernetesFakeClientset.ResourceV1().
		ResourceClaims(prepTestClaimNS).
		Get(t.Context(), prepTestClaimName, metav1.GetOptions{})
	require.NoError(t, err)
	require.Len(t, claim.Status.Devices, 1)
	require.Equal(t, "Ready", claim.Status.Devices[0].Conditions[0].Type)
	require.Equal(t, "zcrx0", claim.Status.Devices[0].NetworkData.InterfaceName)

	serialized, err := deserializeDevice(claim.Status.Devices[0].Data.Raw)
	require.NoError(t, err)
	var state reconcileFlowDeviceState
	require.NoError(t, json.Unmarshal(serialized.Dev, &state))
	return state
}

func resourceClaimStatusUpdateCount(client *k8sClient.FakeClientset) int {
	count := 0
	for _, action := range client.KubernetesFakeClientset.Actions() {
		if action.Matches("update", "resourceclaims") && action.GetSubresource() == "status" {
			count++
		}
	}
	return count
}

func TestReconcileRXQueuePodEndpointFlows(t *testing.T) {
	fixture := newRXQueueReconcileFixture(t, &types.RXQueueConfig{
		PodEndpoint: &types.RXQueuePodEndpoint{
			Port:     "9000",
			Protocol: corev1.ProtocolTCP,
		},
	})
	want := []types.RXQueueFlow{
		{DestinationIP: netip.MustParseAddr("192.0.2.10"), DestinationPort: 9000, Protocol: corev1.ProtocolTCP},
		{DestinationIP: netip.MustParseAddr("2001:db8::10"), DestinationPort: 9000, Protocol: corev1.ProtocolTCP},
	}

	require.NoError(t, fixture.reconcile(t))
	require.Equal(t, []string{"default/storage-0"}, fixture.endpointManager.lookups)
	require.Equal(t, want, fixture.device(t).flows)
	require.Equal(t, want, fixture.claimDeviceState(t).Flows)
	require.EqualValues(t, 1, fixture.setCalls.Load())

	updates := resourceClaimStatusUpdateCount(fixture.client)
	require.NoError(t, fixture.reconcile(t))
	require.Equal(t, updates, resourceClaimStatusUpdateCount(fixture.client),
		"unchanged serialized state must not rewrite ResourceClaim status")

	fixture.endpointManager.endpoints["default/storage-0"] = []*endpoint.Endpoint{{
		K8sNamespace: "default",
		K8sPodName:   "storage-0",
		K8sUID:       "replacement-pod",
		IPv4:         netip.MustParseAddr("192.0.2.20"),
	}}
	require.NoError(t, fixture.reconcile(t))
	require.Empty(t, fixture.device(t).flows)
	require.Empty(t, fixture.claimDeviceState(t).Flows)
}

func TestReconcileRXQueueServiceEndpointFlow(t *testing.T) {
	fixture := newRXQueueReconcileFixture(t, &types.RXQueueConfig{
		ServiceEndpoint: &types.RXQueueServiceEndpoint{
			ServiceName: "storage",
			Port:        "rpc",
		},
	})
	key := resource.Key{Namespace: "default", Name: "storage"}
	fixture.services.objects[key] = rxQueueTestService()

	require.NoError(t, fixture.reconcile(t))
	require.Equal(t, []resource.Key{key}, fixture.services.lookups)
	require.Equal(t, []types.RXQueueFlow{
		{DestinationIP: netip.MustParseAddr("192.0.2.10"), DestinationPort: 8080, Protocol: corev1.ProtocolTCP},
		{DestinationIP: netip.MustParseAddr("2001:db8::10"), DestinationPort: 8080, Protocol: corev1.ProtocolTCP},
	}, fixture.device(t).flows)
}

func TestReconcileRXQueueFlowsPersistsStatusBeforeStateDB(t *testing.T) {
	fixture := newRXQueueReconcileFixture(t, &types.RXQueueConfig{
		PodEndpoint: &types.RXQueuePodEndpoint{Port: "9000", Protocol: corev1.ProtocolTCP},
	})
	fixture.client.KubernetesFakeClientset.PrependReactor(
		"update",
		"resourceclaims",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("status update failed")
		},
	)

	err := fixture.reconcile(t)
	require.ErrorContains(t, err, "status update failed")
	require.Empty(t, fixture.device(t).flows,
		"StateDB must retain the last device state when ResourceClaim status was not updated")
}

var _ types.RXQueueFlowProgrammer = (*reconcileFlowDevice)(nil)

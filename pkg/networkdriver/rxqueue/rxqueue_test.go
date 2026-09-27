// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package rxqueue

import (
	"context"
	"errors"
	"net"
	"slices"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	resourceapi "k8s.io/api/resource/v1"
	apiresource "k8s.io/apimachinery/pkg/api/resource"
	kube_types "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/networkdriver/types"
)

const (
	testPhysicalIfName = "eth0"
	testPhysicalIndex  = 10
	testHostIndex      = 20
	testPeerIndex      = 21
	testShareID        = kube_types.UID("11111111-2222-3333-4444-555555555555")
)

func publishedDevices(t *testing.T, mgr *RXQueueManager) []types.Device {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	var devices []types.Device
	require.NoError(t, mgr.Run(ctx, func(current []types.Device) {
		devices = current
	}))
	return devices
}

type fakeNetlink struct {
	links                   map[string]netlink.Link
	leases                  map[uint32]*netlink.NetDevQueueLease
	realRXQueues            int
	rss                     netlink.NetDevRSS
	rings                   netlink.NetDevRings
	features                map[string]netlink.NetDevFeature
	rssSetCalls             []netlink.NetDevRSSConfig
	ringsSetCalls           []netlink.NetDevRingsConfig
	featureSetCalls         []map[string]bool
	rssSetError             error
	ringsSetError           error
	featuresGetError        error
	featuresSetError        error
	ignoreRSSSet            bool
	ignoreRingsSet          bool
	ignoreFeaturesSet       bool
	ringsRequireHardwareGRO bool
	hostIfName              string
	flows                   map[uint32]netlink.NetDevRxFlow
	flowInsertCalls         []netlink.NetDevRxFlow
	flowDeleteCalls         []uint32
	flowInsertErrors        map[int]error
	flowAnyLocationError    error
	flowListError           error
	nextFlowLocation        uint32
}

func newFakeNetlink(maxRXQueues, realRXQueues int, _ kube_types.UID) *fakeNetlink {
	hwAddr, _ := net.ParseMAC("02:00:00:00:00:01")
	physical := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{
		Name:         testPhysicalIfName,
		Index:        testPhysicalIndex,
		MTU:          9000,
		HardwareAddr: hwAddr,
		Flags:        net.FlagUp,
		NumRxQueues:  maxRXQueues,
	}}
	indirectionTable := make([]uint32, realRXQueues*2)
	for i := range indirectionTable {
		indirectionTable[i] = uint32(i % realRXQueues)
	}
	return &fakeNetlink{
		links: map[string]netlink.Link{
			testPhysicalIfName: physical,
		},
		leases:           make(map[uint32]*netlink.NetDevQueueLease),
		features:         make(map[string]netlink.NetDevFeature),
		flows:            make(map[uint32]netlink.NetDevRxFlow),
		flowInsertErrors: make(map[int]error),
		nextFlowLocation: 100,
		realRXQueues:     realRXQueues,
		rss: netlink.NetDevRSS{
			HashFunction:        netlink.NetDevRSSHashFunctionToeplitz,
			IndirectionTable:    indirectionTable,
			HashKey:             []byte{1, 2, 3, 4},
			InputTransformation: netlink.NetDevRSSInputTransformationNone,
		},
		rings: netlink.NetDevRings{
			RxMax:           4096,
			TxMax:           4096,
			Rx:              512,
			Tx:              512,
			TCPDataSplit:    netlink.NetDevTCPDataSplitDisabled,
			HDSThresholdMax: 4096,
		},
		hostIfName: "lxc123",
	}
}

func (f *fakeNetlink) install(t *testing.T) {
	t.Helper()

	originalLinkByName := netlinkLinkByName
	originalLinkSetAlias := netlinkLinkSetAlias
	originalQueueGet := netlinkNetDevQueueGet
	originalRSSGet := netlinkNetDevRSSGet
	originalRSSSet := netlinkNetDevRSSSet
	originalRingsGet := netlinkNetDevRingsGet
	originalRingsSet := netlinkNetDevRingsSet
	originalFeaturesGet := netlinkNetDevFeaturesGet
	originalFeaturesSet := netlinkNetDevFeaturesSet
	originalFlowInsert := netlinkNetDevRxFlowInsert
	originalFlowDelete := netlinkNetDevRxFlowDelete
	originalFlowList := netlinkNetDevRxFlowList
	t.Cleanup(func() {
		netlinkLinkByName = originalLinkByName
		netlinkLinkSetAlias = originalLinkSetAlias
		netlinkNetDevQueueGet = originalQueueGet
		netlinkNetDevRSSGet = originalRSSGet
		netlinkNetDevRSSSet = originalRSSSet
		netlinkNetDevRingsGet = originalRingsGet
		netlinkNetDevRingsSet = originalRingsSet
		netlinkNetDevRxFlowInsert = originalFlowInsert
		netlinkNetDevFeaturesGet = originalFeaturesGet
		netlinkNetDevFeaturesSet = originalFeaturesSet
		netlinkNetDevRxFlowDelete = originalFlowDelete
		netlinkNetDevRxFlowList = originalFlowList
	})

	netlinkLinkByName = func(name string) (netlink.Link, error) {
		link, exists := f.links[name]
		if !exists {
			return nil, netlink.LinkNotFoundError{}
		}
		return link, nil
	}
	netlinkLinkSetAlias = func(link netlink.Link, alias string) error {
		link.Attrs().Alias = alias
		return nil
	}
	netlinkNetDevQueueGet = func(ifIndex int, queueID uint32, queueType netlink.NetDevQueueType) (*netlink.NetDevQueue, error) {
		if ifIndex != testPhysicalIndex {
			return nil, unix.ENODEV
		}
		if queueType != netlink.NetDevQueueTypeRx {
			return nil, unix.EINVAL
		}
		if int(queueID) >= f.realRXQueues {
			return nil, unix.EINVAL
		}
		return &netlink.NetDevQueue{
			IfIndex: uint32(ifIndex),
			ID:      queueID,
			Type:    queueType,
			Lease:   f.leases[queueID],
		}, nil
	}
	netlinkNetDevRSSGet = func(ifIndex int, context uint32) (*netlink.NetDevRSS, error) {
		if ifIndex != testPhysicalIndex {
			return nil, unix.ENODEV
		}
		if context != 0 {
			return nil, unix.EINVAL
		}
		return cloneNetDevRSS(&f.rss), nil
	}
	netlinkNetDevRSSSet = func(ifIndex int, context uint32, config netlink.NetDevRSSConfig) error {
		if ifIndex != testPhysicalIndex {
			return unix.ENODEV
		}
		if context != 0 {
			return unix.EINVAL
		}
		config.IndirectionTable = slices.Clone(config.IndirectionTable)
		config.HashKey = slices.Clone(config.HashKey)
		f.rssSetCalls = append(f.rssSetCalls, config)
		if f.rssSetError != nil {
			return f.rssSetError
		}
		if !f.ignoreRSSSet && config.IndirectionTable != nil {
			f.rss.IndirectionTable = slices.Clone(config.IndirectionTable)
		}
		return nil
	}
	netlinkNetDevRingsGet = func(ifIndex int) (*netlink.NetDevRings, error) {
		if ifIndex != testPhysicalIndex {
			return nil, unix.ENODEV
		}
		rings := f.rings
		return &rings, nil
	}
	netlinkNetDevRingsSet = func(ifIndex int, config netlink.NetDevRingsConfig) error {
		if ifIndex != testPhysicalIndex {
			return unix.ENODEV
		}
		f.ringsSetCalls = append(f.ringsSetCalls, config)
		if f.ringsSetError != nil {
			return f.ringsSetError
		}
		if f.ringsRequireHardwareGRO && config.TCPDataSplit != nil &&
			*config.TCPDataSplit == netlink.NetDevTCPDataSplitEnabled &&
			!f.features[hardwareGROFeature].Active {
			return unix.EINVAL
		}
		if !f.ignoreRingsSet && config.TCPDataSplit != nil {
			f.rings.TCPDataSplit = *config.TCPDataSplit
		}
		if !f.ignoreRingsSet && config.HDSThreshold != nil {
			f.rings.HDSThreshold = *config.HDSThreshold
		}
		return nil
	}
	netlinkNetDevFeaturesGet = func(ifIndex int) (map[string]netlink.NetDevFeature, error) {
		if ifIndex != testPhysicalIndex {
			return nil, unix.ENODEV
		}
		if f.featuresGetError != nil {
			return nil, f.featuresGetError
		}
		features := make(map[string]netlink.NetDevFeature, len(f.features))
		for name, feature := range f.features {
			features[name] = feature
		}
		return features, nil
	}
	netlinkNetDevFeaturesSet = func(ifIndex int, config map[string]bool) error {
		if ifIndex != testPhysicalIndex {
			return unix.ENODEV
		}
		request := make(map[string]bool, len(config))
		for name, wanted := range config {
			request[name] = wanted
		}
		f.featureSetCalls = append(f.featureSetCalls, request)
		if f.featuresSetError != nil {
			return f.featuresSetError
		}
		if f.ignoreFeaturesSet {
			return nil
		}
		for name, wanted := range config {
			feature, ok := f.features[name]
			if !ok {
				return unix.EINVAL
			}
			feature.Wanted = wanted
			feature.Active = wanted
			f.features[name] = feature
		}
		return nil
	}
	netlinkNetDevRxFlowInsert = func(ifName string, flow netlink.NetDevRxFlow) (uint32, error) {
		if ifName != testPhysicalIfName {
			return 0, unix.ENODEV
		}
		f.flowInsertCalls = append(f.flowInsertCalls, flow)
		if err := f.flowInsertErrors[len(f.flowInsertCalls)]; err != nil {
			return 0, err
		}
		if flow.Location == netlink.RX_CLS_LOC_ANY && f.flowAnyLocationError != nil {
			return 0, f.flowAnyLocationError
		}
		location := flow.Location
		if location == netlink.RX_CLS_LOC_ANY {
			location = f.nextFlowLocation
			f.nextFlowLocation++
		}
		flow.Location = location
		f.flows[location] = flow
		return location, nil
	}
	netlinkNetDevRxFlowDelete = func(ifName string, location uint32) error {
		if ifName != testPhysicalIfName {
			return unix.ENODEV
		}
		f.flowDeleteCalls = append(f.flowDeleteCalls, location)
		delete(f.flows, location)
		return nil
	}
	netlinkNetDevRxFlowList = func(ifName string) ([]uint32, error) {
		if ifName != testPhysicalIfName {
			return nil, unix.ENODEV
		}
		if f.flowListError != nil {
			return nil, f.flowListError
		}
		locations := make([]uint32, 0, len(f.flows))
		for location := range f.flows {
			locations = append(locations, location)
		}
		slices.Sort(locations)
		return locations, nil
	}
}

func testDevice(total int) *RXQueueDevice {
	return testDeviceWithCount(total, defaultReservedRXQueues)
}

func testDeviceWithCount(total, count int) *RXQueueDevice {
	return &RXQueueDevice{
		PhysicalIfName:   testPhysicalIfName,
		HardwareAddress:  "02:00:00:00:00:01",
		MTU:              9000,
		TotalRXQueues:    total,
		ReservedQueueIDs: reservedRXQueueIDs(total, count),
		reservations: &queueReservations{
			owners: make(map[uint32]kube_types.UID),
		},
	}
}

func testAllocation(shareID kube_types.UID) types.DeviceAllocation {
	return types.DeviceAllocation{
		ShareID: shareID,
		ConsumedCapacity: map[resourceapi.QualifiedName]apiresource.Quantity{
			types.RXQueuesCapacity: apiresource.MustParse("1"),
		},
	}
}

func TestReservedRXQueueIDs(t *testing.T) {
	tests := []struct {
		total int
		count int
		want  []uint32
	}{
		{total: 0, count: 1},
		{total: 1, count: 1},
		{total: 8, count: 0},
		{total: 8, count: 8},
		{total: 2, count: 1, want: []uint32{1}},
		{total: 4, count: 3, want: []uint32{3, 2, 1}},
		{total: 8, count: 2, want: []uint32{7, 6}},
		{total: 64, count: 8, want: []uint32{63, 62, 61, 60, 59, 58, 57, 56}},
	}

	for _, tt := range tests {
		require.Equal(t, tt.want, reservedRXQueueIDs(tt.total, tt.count),
			"total RX queues: %d, reserved: %d", tt.total, tt.count)
	}
}

func TestValidateConfig(t *testing.T) {
	require.ErrorIs(t, validateConfig(nil), errNoInterfaces)
	require.ErrorIs(t, validateConfig(&v2alpha1.RXQueueDeviceManagerConfig{}), errNoInterfaces)

	err := validateConfig(&v2alpha1.RXQueueDeviceManagerConfig{
		Ifaces: []v2alpha1.RXQueueDeviceConfig{{IfName: ""}},
	})
	require.Error(t, err)

	err = validateConfig(&v2alpha1.RXQueueDeviceManagerConfig{
		Ifaces: []v2alpha1.RXQueueDeviceConfig{{IfName: "lo"}},
	})
	require.Error(t, err)

	err = validateConfig(&v2alpha1.RXQueueDeviceManagerConfig{
		Ifaces: []v2alpha1.RXQueueDeviceConfig{{IfName: "eth0", Count: -1}},
	})
	require.Error(t, err)

	err = validateConfig(&v2alpha1.RXQueueDeviceManagerConfig{
		Ifaces: []v2alpha1.RXQueueDeviceConfig{{IfName: "eth0"}, {IfName: "eth0"}},
	})
	require.ErrorIs(t, err, errDuplicateInterface)

	require.NoError(t, validateConfig(&v2alpha1.RXQueueDeviceManagerConfig{
		Ifaces: []v2alpha1.RXQueueDeviceConfig{{IfName: "eth0"}, {IfName: "eth1"}},
	}))
}

func TestActiveRXQueueCount(t *testing.T) {
	t.Run("uses real queue count", func(t *testing.T) {
		fake := newFakeNetlink(16, 12, testShareID)
		fake.install(t)

		count, err := activeRXQueueCount(fake.links[testPhysicalIfName])
		require.NoError(t, err)
		require.Equal(t, 12, count)
	})

	t.Run("interface must be up", func(t *testing.T) {
		fake := newFakeNetlink(8, 8, testShareID)
		fake.install(t)
		fake.links[testPhysicalIfName].Attrs().Flags = 0

		_, err := activeRXQueueCount(fake.links[testPhysicalIfName])
		require.Error(t, err)
		require.Contains(t, err.Error(), "down")
	})

	t.Run("queue error is returned", func(t *testing.T) {
		fake := newFakeNetlink(8, 8, testShareID)
		fake.install(t)
		boom := errors.New("queue query failed")
		netlinkNetDevQueueGet = func(int, uint32, netlink.NetDevQueueType) (*netlink.NetDevQueue, error) {
			return nil, boom
		}

		_, err := activeRXQueueCount(fake.links[testPhysicalIfName])
		require.ErrorIs(t, err, boom)
	})
}

func TestRSSTableWithoutReservedQueues(t *testing.T) {
	t.Run("reassigns only reserved queues", func(t *testing.T) {
		table := []uint32{0, 0, 3, 3, 1, 2, 3, 3}

		got, err := rssTableWithoutReservedQueues(table, 4, []uint32{3})
		require.NoError(t, err)
		require.Equal(t, []uint32{0, 0, 1, 2, 1, 2, 0, 1}, got)
		require.Equal(t, []uint32{0, 0, 3, 3, 1, 2, 3, 3}, table)
	})

	t.Run("does not introduce an unused queue", func(t *testing.T) {
		table := []uint32{0, 3, 0, 3}

		got, err := rssTableWithoutReservedQueues(table, 4, []uint32{3})
		require.NoError(t, err)
		require.Equal(t, []uint32{0, 0, 0, 0}, got)
	})

	t.Run("leaves an isolated table unchanged", func(t *testing.T) {
		table := []uint32{0, 1, 2, 0}

		got, err := rssTableWithoutReservedQueues(table, 4, []uint32{3})
		require.NoError(t, err)
		require.Equal(t, table, got)
		got[0] = 2
		require.Equal(t, uint32(0), table[0])
	})

	t.Run("rejects an empty table", func(t *testing.T) {
		_, err := rssTableWithoutReservedQueues(nil, 4, []uint32{3})
		require.Error(t, err)
	})

	t.Run("rejects an out-of-range table entry", func(t *testing.T) {
		_, err := rssTableWithoutReservedQueues([]uint32{0, 4}, 4, []uint32{3})
		require.Error(t, err)
	})

	t.Run("requires a normal receive queue", func(t *testing.T) {
		_, err := rssTableWithoutReservedQueues([]uint32{0, 1}, 2, []uint32{0, 1})
		require.Error(t, err)
	})

	t.Run("rejects duplicate reserved queues", func(t *testing.T) {
		_, err := rssTableWithoutReservedQueues([]uint32{0, 1}, 2, []uint32{1, 1})
		require.Error(t, err)
	})
}

func TestNewManager(t *testing.T) {
	t.Run("leaves one queue for normal receive processing", func(t *testing.T) {
		fake := newFakeNetlink(8, 1, testShareID)
		fake.install(t)

		_, err := NewManager(hivetest.Logger(t), &v2alpha1.RXQueueDeviceManagerConfig{
			Ifaces: []v2alpha1.RXQueueDeviceConfig{{IfName: testPhysicalIfName}},
		})
		require.ErrorIs(t, err, errInsufficientRXQueues)
	})

	t.Run("defaults to one reserved queue", func(t *testing.T) {
		fake := newFakeNetlink(16, 2, testShareID)
		fake.install(t)

		mgr, err := NewManager(hivetest.Logger(t), &v2alpha1.RXQueueDeviceManagerConfig{
			Ifaces: []v2alpha1.RXQueueDeviceConfig{{IfName: testPhysicalIfName}},
		})
		require.NoError(t, err)
		require.Equal(t, types.DeviceManagerTypeRXQueue, mgr.Type())

		devices := publishedDevices(t, mgr)
		require.Len(t, devices, 1)

		dev := devices[0].(*RXQueueDevice)
		require.Equal(t, []uint32{1}, dev.ReservedQueueIDs)
		require.Equal(t, testPhysicalIfName, dev.IfName())
		require.True(t, dev.AllowMultipleAllocations())

		capacity := dev.GetCapacity()[types.RXQueuesCapacity]
		require.Zero(t, capacity.Value.Cmp(apiresource.MustParse("1")))
		require.NotNil(t, capacity.RequestPolicy)
		require.Equal(t, []apiresource.Quantity{apiresource.MustParse("1")}, capacity.RequestPolicy.ValidValues)
	})

	t.Run("advertises configured reserved capacity", func(t *testing.T) {
		fake := newFakeNetlink(16, 8, testShareID)
		fake.install(t)

		mgr, err := NewManager(hivetest.Logger(t), &v2alpha1.RXQueueDeviceManagerConfig{
			Ifaces: []v2alpha1.RXQueueDeviceConfig{{IfName: testPhysicalIfName, Count: 3}},
		})
		require.NoError(t, err)

		devices := publishedDevices(t, mgr)
		dev := devices[0].(*RXQueueDevice)
		require.Equal(t, []uint32{7, 6, 5}, dev.ReservedQueueIDs)

		capacity := dev.GetCapacity()[types.RXQueuesCapacity]
		require.Zero(t, capacity.Value.Cmp(apiresource.MustParse("3")))
	})

	t.Run("programs and verifies NIC receive configuration", func(t *testing.T) {
		fake := newFakeNetlink(8, 4, testShareID)
		fake.rss.IndirectionTable = []uint32{0, 3, 1, 3, 2, 3}
		originalHashKey := slices.Clone(fake.rss.HashKey)
		fake.featuresGetError = errors.New("unexpected feature query")
		fake.install(t)

		_, err := NewManager(hivetest.Logger(t), &v2alpha1.RXQueueDeviceManagerConfig{
			Ifaces: []v2alpha1.RXQueueDeviceConfig{{IfName: testPhysicalIfName}},
		})
		require.NoError(t, err)
		require.Equal(t, []uint32{0, 0, 1, 1, 2, 2}, fake.rss.IndirectionTable)
		require.Equal(t, originalHashKey, fake.rss.HashKey)
		require.Equal(t, netlink.NetDevTCPDataSplitEnabled, fake.rings.TCPDataSplit)
		require.Len(t, fake.rssSetCalls, 1)
		require.Len(t, fake.ringsSetCalls, 1)
	})

	t.Run("enables hardware GRO when mlx5 rejects TCP data splitting", func(t *testing.T) {
		fake := newFakeNetlink(8, 4, testShareID)
		fake.rss.IndirectionTable = []uint32{0, 3, 1, 3, 2, 3}
		fake.features[hardwareGROFeature] = netlink.NetDevFeature{Hardware: true}
		fake.ringsRequireHardwareGRO = true
		fake.install(t)

		_, err := NewManager(hivetest.Logger(t), &v2alpha1.RXQueueDeviceManagerConfig{
			Ifaces: []v2alpha1.RXQueueDeviceConfig{{IfName: testPhysicalIfName}},
		})
		require.NoError(t, err)
		require.Equal(t, netlink.NetDevTCPDataSplitEnabled, fake.rings.TCPDataSplit)
		require.True(t, fake.features[hardwareGROFeature].Active)
		require.Len(t, fake.ringsSetCalls, 2)
		require.Equal(t, []map[string]bool{{hardwareGROFeature: true}}, fake.featureSetCalls)
	})

	t.Run("accepts an already prepared NIC without writing", func(t *testing.T) {
		fake := newFakeNetlink(8, 4, testShareID)
		fake.rss.IndirectionTable = []uint32{0, 1, 2, 0}
		fake.rings.TCPDataSplit = netlink.NetDevTCPDataSplitEnabled
		fake.install(t)

		_, err := NewManager(hivetest.Logger(t), &v2alpha1.RXQueueDeviceManagerConfig{
			Ifaces: []v2alpha1.RXQueueDeviceConfig{{IfName: testPhysicalIfName}},
		})
		require.NoError(t, err)
		require.Empty(t, fake.rssSetCalls)
		require.Empty(t, fake.ringsSetCalls)
	})

	t.Run("sets a zero HDS threshold when TCP data splitting is already enabled", func(t *testing.T) {
		fake := newFakeNetlink(8, 4, testShareID)
		fake.rss.IndirectionTable = []uint32{0, 1, 2, 0}
		fake.rings.TCPDataSplit = netlink.NetDevTCPDataSplitEnabled
		fake.rings.HDSThreshold = 128
		fake.install(t)

		_, err := NewManager(hivetest.Logger(t), &v2alpha1.RXQueueDeviceManagerConfig{
			Ifaces: []v2alpha1.RXQueueDeviceConfig{{IfName: testPhysicalIfName}},
		})
		require.NoError(t, err)
		require.Zero(t, fake.rings.HDSThreshold)
		require.Len(t, fake.ringsSetCalls, 1)
	})

	t.Run("enables hardware GRO before TCP data splitting when the ring setting is unavailable", func(t *testing.T) {
		fake := newFakeNetlink(8, 4, testShareID)
		fake.rss.IndirectionTable = []uint32{0, 3, 1, 3, 2, 3}
		fake.rings.TCPDataSplit = netlink.NetDevTCPDataSplitUnknown
		fake.features[hardwareGROFeature] = netlink.NetDevFeature{Hardware: true}
		fake.install(t)

		_, err := NewManager(hivetest.Logger(t), &v2alpha1.RXQueueDeviceManagerConfig{
			Ifaces: []v2alpha1.RXQueueDeviceConfig{{IfName: testPhysicalIfName}},
		})
		require.NoError(t, err)
		require.Equal(t, []uint32{0, 0, 1, 1, 2, 2}, fake.rss.IndirectionTable)
		require.Equal(t, netlink.NetDevFeature{Hardware: true, Wanted: true, Active: true}, fake.features[hardwareGROFeature])
		require.Equal(t, netlink.NetDevTCPDataSplitEnabled, fake.rings.TCPDataSplit)
		require.Zero(t, fake.rings.HDSThreshold)
		require.Len(t, fake.rssSetCalls, 1)
		require.Equal(t, []map[string]bool{{hardwareGROFeature: true}}, fake.featureSetCalls)
		require.Len(t, fake.ringsSetCalls, 1)
		require.NotNil(t, fake.ringsSetCalls[0].HDSThreshold)
	})

	t.Run("enables TCP data splitting with active hardware GRO", func(t *testing.T) {
		fake := newFakeNetlink(8, 4, testShareID)
		fake.rss.IndirectionTable = []uint32{0, 1, 2, 0}
		fake.rings.TCPDataSplit = netlink.NetDevTCPDataSplitUnknown
		fake.features[hardwareGROFeature] = netlink.NetDevFeature{
			Hardware: true,
			Wanted:   true,
			Active:   true,
		}
		fake.install(t)

		_, err := NewManager(hivetest.Logger(t), &v2alpha1.RXQueueDeviceManagerConfig{
			Ifaces: []v2alpha1.RXQueueDeviceConfig{{IfName: testPhysicalIfName}},
		})
		require.NoError(t, err)
		require.Empty(t, fake.rssSetCalls)
		require.Len(t, fake.ringsSetCalls, 1)
		require.Empty(t, fake.featureSetCalls)
	})

	t.Run("rejects unavailable hardware GRO before writing", func(t *testing.T) {
		tests := []struct {
			name    string
			feature netlink.NetDevFeature
		}{
			{
				name: "not supported by hardware",
			},
			{
				name: "fixed off",
				feature: netlink.NetDevFeature{
					Hardware: true,
					NoChange: true,
				},
			},
			{
				name: "requested but inactive",
				feature: netlink.NetDevFeature{
					Hardware: true,
					Wanted:   true,
				},
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				fake := newFakeNetlink(8, 4, testShareID)
				fake.rings.TCPDataSplit = netlink.NetDevTCPDataSplitUnknown
				fake.features[hardwareGROFeature] = tt.feature
				fake.install(t)

				_, err := NewManager(hivetest.Logger(t), &v2alpha1.RXQueueDeviceManagerConfig{
					Ifaces: []v2alpha1.RXQueueDeviceConfig{{IfName: testPhysicalIfName}},
				})
				require.ErrorIs(t, err, unix.EOPNOTSUPP)
				require.Empty(t, fake.rssSetCalls)
				require.Empty(t, fake.ringsSetCalls)
				require.Empty(t, fake.featureSetCalls)
			})
		}
	})

	t.Run("restores RSS when enabling hardware GRO fails", func(t *testing.T) {
		fake := newFakeNetlink(8, 4, testShareID)
		fake.rss.IndirectionTable = []uint32{0, 3, 1, 3, 2, 3}
		fake.rings.TCPDataSplit = netlink.NetDevTCPDataSplitUnknown
		fake.features[hardwareGROFeature] = netlink.NetDevFeature{Hardware: true}
		originalRSS := cloneNetDevRSS(&fake.rss)
		boom := errors.New("feature update failed")
		fake.featuresSetError = boom
		fake.install(t)

		_, err := NewManager(hivetest.Logger(t), &v2alpha1.RXQueueDeviceManagerConfig{
			Ifaces: []v2alpha1.RXQueueDeviceConfig{{IfName: testPhysicalIfName}},
		})
		require.ErrorIs(t, err, boom)
		require.True(t, equalNetDevRSS(originalRSS, &fake.rss))
		require.Equal(t, netlink.NetDevFeature{Hardware: true}, fake.features[hardwareGROFeature])
		require.Len(t, fake.rssSetCalls, 2)
		require.Equal(t, []map[string]bool{{hardwareGROFeature: true}}, fake.featureSetCalls)
		require.Empty(t, fake.ringsSetCalls)
	})

	t.Run("restores hardware GRO and RSS when enabling TCP data splitting fails", func(t *testing.T) {
		fake := newFakeNetlink(8, 4, testShareID)
		fake.rss.IndirectionTable = []uint32{0, 3, 1, 3, 2, 3}
		fake.rings.TCPDataSplit = netlink.NetDevTCPDataSplitUnknown
		originalFeature := netlink.NetDevFeature{Hardware: true}
		fake.features[hardwareGROFeature] = originalFeature
		originalRSS := cloneNetDevRSS(&fake.rss)
		boom := errors.New("ring update failed")
		fake.ringsSetError = boom
		fake.install(t)

		_, err := NewManager(hivetest.Logger(t), &v2alpha1.RXQueueDeviceManagerConfig{
			Ifaces: []v2alpha1.RXQueueDeviceConfig{{IfName: testPhysicalIfName}},
		})
		require.ErrorIs(t, err, boom)
		require.True(t, equalNetDevRSS(originalRSS, &fake.rss))
		require.Equal(t, originalFeature, fake.features[hardwareGROFeature])
		require.Equal(t, netlink.NetDevTCPDataSplitUnknown, fake.rings.TCPDataSplit)
		require.Len(t, fake.rssSetCalls, 2)
		require.Equal(t, []map[string]bool{
			{hardwareGROFeature: true},
			{hardwareGROFeature: false},
		}, fake.featureSetCalls)
		require.Len(t, fake.ringsSetCalls, 1)
	})

	t.Run("restores hardware GRO and RSS when feature readback does not match", func(t *testing.T) {
		fake := newFakeNetlink(8, 4, testShareID)
		fake.rss.IndirectionTable = []uint32{0, 3, 1, 3, 2, 3}
		fake.rings.TCPDataSplit = netlink.NetDevTCPDataSplitUnknown
		originalFeature := netlink.NetDevFeature{Hardware: true}
		fake.features[hardwareGROFeature] = originalFeature
		originalRSS := cloneNetDevRSS(&fake.rss)
		fake.ignoreFeaturesSet = true
		fake.install(t)

		_, err := NewManager(hivetest.Logger(t), &v2alpha1.RXQueueDeviceManagerConfig{
			Ifaces: []v2alpha1.RXQueueDeviceConfig{{IfName: testPhysicalIfName}},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "hardware GRO read back incorrectly")
		require.True(t, equalNetDevRSS(originalRSS, &fake.rss))
		require.Equal(t, originalFeature, fake.features[hardwareGROFeature])
		require.Len(t, fake.rssSetCalls, 2)
		require.Equal(t, []map[string]bool{
			{hardwareGROFeature: true},
			{hardwareGROFeature: false},
		}, fake.featureSetCalls)
		require.Len(t, fake.ringsSetCalls, 2)
	})

	t.Run("requires TCP data splitting support before writing", func(t *testing.T) {
		fake := newFakeNetlink(8, 4, testShareID)
		fake.rings.TCPDataSplit = netlink.NetDevTCPDataSplitUnknown
		fake.install(t)

		_, err := NewManager(hivetest.Logger(t), &v2alpha1.RXQueueDeviceManagerConfig{
			Ifaces: []v2alpha1.RXQueueDeviceConfig{{IfName: testPhysicalIfName}},
		})
		require.ErrorIs(t, err, unix.EOPNOTSUPP)
		require.Empty(t, fake.rssSetCalls)
		require.Empty(t, fake.ringsSetCalls)
	})

	t.Run("does not change rings when the RSS update fails", func(t *testing.T) {
		fake := newFakeNetlink(8, 4, testShareID)
		originalRSS := cloneNetDevRSS(&fake.rss)
		boom := errors.New("RSS update failed")
		fake.rssSetError = boom
		fake.install(t)

		_, err := NewManager(hivetest.Logger(t), &v2alpha1.RXQueueDeviceManagerConfig{
			Ifaces: []v2alpha1.RXQueueDeviceConfig{{IfName: testPhysicalIfName}},
		})
		require.ErrorIs(t, err, boom)
		require.True(t, equalNetDevRSS(originalRSS, &fake.rss))
		require.Equal(t, netlink.NetDevTCPDataSplitDisabled, fake.rings.TCPDataSplit)
		require.Len(t, fake.rssSetCalls, 1)
		require.Empty(t, fake.ringsSetCalls)
	})

	t.Run("restores RSS when enabling TCP data splitting fails", func(t *testing.T) {
		fake := newFakeNetlink(8, 4, testShareID)
		fake.rss.IndirectionTable = []uint32{0, 3, 1, 3, 2, 3}
		originalRSS := cloneNetDevRSS(&fake.rss)
		boom := errors.New("ring update failed")
		fake.ringsSetError = boom
		fake.install(t)

		_, err := NewManager(hivetest.Logger(t), &v2alpha1.RXQueueDeviceManagerConfig{
			Ifaces: []v2alpha1.RXQueueDeviceConfig{{IfName: testPhysicalIfName}},
		})
		require.ErrorIs(t, err, boom)
		require.True(t, equalNetDevRSS(originalRSS, &fake.rss))
		require.Equal(t, netlink.NetDevTCPDataSplitDisabled, fake.rings.TCPDataSplit)
		require.Len(t, fake.rssSetCalls, 2)
		require.Len(t, fake.ringsSetCalls, 1)
	})

	t.Run("restores both settings when readback does not match", func(t *testing.T) {
		fake := newFakeNetlink(8, 4, testShareID)
		fake.rss.IndirectionTable = []uint32{0, 3, 1, 3, 2, 3}
		originalRSS := cloneNetDevRSS(&fake.rss)
		originalRings := fake.rings
		fake.ignoreRingsSet = true
		fake.install(t)

		_, err := NewManager(hivetest.Logger(t), &v2alpha1.RXQueueDeviceManagerConfig{
			Ifaces: []v2alpha1.RXQueueDeviceConfig{{IfName: testPhysicalIfName}},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "ring configuration read back incorrectly")
		require.True(t, equalNetDevRSS(originalRSS, &fake.rss))
		require.Equal(t, originalRings, fake.rings)
		require.Len(t, fake.rssSetCalls, 2)
		require.Len(t, fake.ringsSetCalls, 2)
	})

	t.Run("restores both settings when RSS readback does not match", func(t *testing.T) {
		fake := newFakeNetlink(8, 4, testShareID)
		originalRSS := cloneNetDevRSS(&fake.rss)
		originalRings := fake.rings
		fake.ignoreRSSSet = true
		fake.install(t)

		_, err := NewManager(hivetest.Logger(t), &v2alpha1.RXQueueDeviceManagerConfig{
			Ifaces: []v2alpha1.RXQueueDeviceConfig{{IfName: testPhysicalIfName}},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "RSS configuration read back incorrectly")
		require.True(t, equalNetDevRSS(originalRSS, &fake.rss))
		require.Equal(t, originalRings, fake.rings)
		require.Len(t, fake.rssSetCalls, 2)
		require.Len(t, fake.ringsSetCalls, 2)
	})

	t.Run("restores earlier NICs when later discovery fails", func(t *testing.T) {
		fake := newFakeNetlink(8, 4, testShareID)
		originalRSS := cloneNetDevRSS(&fake.rss)
		originalRings := fake.rings
		fake.links["eth1"] = &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{
			Name:        "eth1",
			Index:       testPhysicalIndex + 1,
			Flags:       net.FlagUp,
			NumRxQueues: 4,
		}}
		fake.install(t)

		firstQueueGet := netlinkNetDevQueueGet
		boom := errors.New("second NIC failed")
		netlinkNetDevQueueGet = func(ifIndex int, queueID uint32, queueType netlink.NetDevQueueType) (*netlink.NetDevQueue, error) {
			if ifIndex == testPhysicalIndex+1 {
				return nil, boom
			}
			return firstQueueGet(ifIndex, queueID, queueType)
		}

		_, err := NewManager(hivetest.Logger(t), &v2alpha1.RXQueueDeviceManagerConfig{
			Ifaces: []v2alpha1.RXQueueDeviceConfig{
				{IfName: testPhysicalIfName},
				{IfName: "eth1"},
			},
		})
		require.ErrorIs(t, err, boom)
		require.True(t, equalNetDevRSS(originalRSS, &fake.rss))
		require.Equal(t, originalRings, fake.rings)
		require.Len(t, fake.rssSetCalls, 2)
		require.Len(t, fake.ringsSetCalls, 2)
	})
}

func TestRXQueueReservations(t *testing.T) {
	fake := newFakeNetlink(8, 8, testShareID)
	fake.install(t)

	advertised := testDeviceWithCount(8, 2)
	firstAllocation := testAllocation(testShareID)
	firstDevice, err := advertised.Setup(firstAllocation)
	require.NoError(t, err)
	first := firstDevice.(*RXQueueDevice)
	require.Equal(t, uint32(7), first.PhysicalQueueID)

	retried, err := advertised.Setup(firstAllocation)
	require.NoError(t, err)
	require.Equal(t, first.PhysicalQueueID, retried.(*RXQueueDevice).PhysicalQueueID)

	secondShare := kube_types.UID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
	secondDevice, err := advertised.Setup(testAllocation(secondShare))
	require.NoError(t, err)
	require.Equal(t, uint32(6), secondDevice.(*RXQueueDevice).PhysicalQueueID)
	require.Empty(t, fake.leases, "DRA preparation must not create a kernel lease")

	thirdShare := kube_types.UID("ffffffff-1111-2222-3333-444444444444")
	_, err = advertised.Setup(testAllocation(thirdShare))
	require.ErrorIs(t, err, errNoAvailableRXQueue)

	require.NoError(t, first.Free(firstAllocation))
	reused, err := advertised.Setup(testAllocation(thirdShare))
	require.NoError(t, err)
	require.Equal(t, uint32(7), reused.(*RXQueueDevice).PhysicalQueueID)
}

func TestRXQueueReservationSkipsKernelLease(t *testing.T) {
	fake := newFakeNetlink(8, 8, testShareID)
	fake.leases[7] = &netlink.NetDevQueueLease{IfIndex: 99}
	fake.install(t)

	device, err := testDeviceWithCount(8, 2).Setup(testAllocation(testShareID))
	require.NoError(t, err)
	require.Equal(t, uint32(6), device.(*RXQueueDevice).PhysicalQueueID)
}

func TestRecoverRXQueueReservation(t *testing.T) {
	fake := newFakeNetlink(8, 8, testShareID)
	fake.install(t)

	device, err := testDevice(8).Setup(testAllocation(testShareID))
	require.NoError(t, err)
	data, err := device.MarshalBinary()
	require.NoError(t, err)

	manager := &RXQueueManager{}
	restoredDevice, err := manager.RestoreDevice(data)
	require.NoError(t, err)
	recovered, err := restoredDevice.Recover(testAllocation(testShareID))
	require.NoError(t, err)
	require.Equal(t, uint32(7), recovered.(*RXQueueDevice).PhysicalQueueID)

	_, err = restoredDevice.Recover(testAllocation(kube_types.UID("different-share")))
	require.ErrorIs(t, err, errInvalidAllocation)

	wrongInterface := testAllocation(testShareID)
	wrongInterface.Config.PodIfName = "net1"
	_, err = restoredDevice.Recover(wrongInterface)
	require.ErrorIs(t, err, errInvalidAllocation)
}
func TestDeviceMetadataAndSerialization(t *testing.T) {
	fake := newFakeNetlink(16, 16, testShareID)
	fake.install(t)

	advertised := testDevice(16)
	require.True(t, advertised.Match(v2alpha1.CiliumNetworkDriverDeviceFilter{}))
	require.True(t, advertised.Match(v2alpha1.CiliumNetworkDriverDeviceFilter{
		DeviceManagers: []string{types.DeviceManagerTypeRXQueue.String()},
		IfNames:        []string{testPhysicalIfName},
	}))
	require.False(t, advertised.Match(v2alpha1.CiliumNetworkDriverDeviceFilter{
		Drivers: []string{"ice"},
	}))

	device, err := advertised.Setup(testAllocation(testShareID))
	require.NoError(t, err)
	prepared := device.(*RXQueueDevice)
	require.True(t, prepared.Prepared)
	require.False(t, prepared.Bound)
	require.Equal(t, types.DefaultRXQueuePodIfName, prepared.PodIfName)
	require.Empty(t, prepared.HostIfName)
	require.Equal(t, uint32(15), prepared.PhysicalQueueID)
	require.Equal(t, uint32(1), prepared.VirtualQueueID)
	require.Empty(t, fake.leases)

	attrs := prepared.GetAttrs()
	require.EqualValues(t, 1, *attrs[types.RXQueueIDLabel].IntValue)
	require.Equal(t, prepared.PhysicalIfName, *attrs[types.IfNameLabel].StringValue)

	data, err := prepared.MarshalBinary()
	require.NoError(t, err)

	mgr := &RXQueueManager{}
	restoredDevice, err := mgr.RestoreDevice(data)
	require.NoError(t, err)
	restored := restoredDevice.(*RXQueueDevice)
	require.Equal(t, prepared.PhysicalIfName, restored.PhysicalIfName)
	require.Equal(t, prepared.ReservedQueueIDs, restored.ReservedQueueIDs)
	require.Equal(t, prepared.ShareID, restored.ShareID)
	require.Equal(t, prepared.PodIfName, restored.PodIfName)
	require.Equal(t, prepared.HostIfName, restored.HostIfName)
	require.Equal(t, prepared.PhysicalQueueID, restored.PhysicalQueueID)
	require.Equal(t, prepared.VirtualQueueID, restored.VirtualQueueID)
}

func TestValidateAllocation(t *testing.T) {
	require.ErrorIs(t, validateAllocation(types.DeviceAllocation{}), errInvalidAllocation)
	require.ErrorIs(t, validateAllocation(types.DeviceAllocation{ShareID: testShareID}), errInvalidAllocation)

	allocation := testAllocation(testShareID)
	allocation.ConsumedCapacity[types.RXQueuesCapacity] = apiresource.MustParse("2")
	require.ErrorIs(t, validateAllocation(allocation), errInvalidAllocation)

	require.NoError(t, validateAllocation(testAllocation(testShareID)))
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package rxqueue

import (
	"context"
	"encoding/json"
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
	testDestinationMAC = "02:00:00:00:00:02"
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
	links                map[string]netlink.Link
	leases               map[uint32]*netlink.NetDevQueueLease
	addedNetkit          *netlink.Netkit
	createErrors         map[uint32]error
	createRequests       []netlink.NetDevQueueCreateRequest
	realRXQueues         int
	rss                  netlink.NetDevRSS
	rings                netlink.NetDevRings
	features             map[string]netlink.NetDevFeature
	rssSetCalls          []netlink.NetDevRSSConfig
	ringsSetCalls        []netlink.NetDevRingsConfig
	featureSetCalls      []map[string]bool
	rssSetError          error
	ringsSetError        error
	featuresGetError     error
	featuresSetError     error
	ignoreRSSSet         bool
	ignoreRingsSet       bool
	ignoreFeaturesSet    bool
	flows                map[uint32]netlink.NetDevRxFlow
	flowInsertRequests   []netlink.NetDevRxFlow
	flowDeleteRequests   []uint32
	flowInsertError      error
	flowAnyLocationError error
	flowDeleteError      error
	flowListError        error
	flowAliasError       error
	ignoreFlowInsert     bool
	ignoreFlowDelete     bool
	nextFlowLocation     uint32
	hostIfName           string
	peerIfName           string
	addCalls             int
	deleteCalls          int
}

func newFakeNetlink(maxRXQueues, realRXQueues int, shareID kube_types.UID) *fakeNetlink {
	hwAddr, _ := net.ParseMAC("02:00:00:00:00:01")
	physical := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{
		Name:         testPhysicalIfName,
		Index:        testPhysicalIndex,
		MTU:          9000,
		HardwareAddr: hwAddr,
		Flags:        net.FlagUp,
		NumRxQueues:  maxRXQueues,
	}}
	hostIfName, peerIfName := allocationIfNames(testPhysicalIfName, shareID)
	indirectionTable := make([]uint32, realRXQueues*2)
	for i := range indirectionTable {
		indirectionTable[i] = uint32(i % realRXQueues)
	}
	return &fakeNetlink{
		links: map[string]netlink.Link{
			testPhysicalIfName: physical,
		},
		leases:       make(map[uint32]*netlink.NetDevQueueLease),
		createErrors: make(map[uint32]error),
		realRXQueues: realRXQueues,
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
		features:         make(map[string]netlink.NetDevFeature),
		flows:            make(map[uint32]netlink.NetDevRxFlow),
		nextFlowLocation: 100,
		hostIfName:       hostIfName,
		peerIfName:       peerIfName,
	}
}

func (f *fakeNetlink) install(t *testing.T) {
	t.Helper()

	originalLinkByName := netlinkLinkByName
	originalLinkAdd := netlinkLinkAdd
	originalLinkDel := netlinkLinkDel
	originalLinkSetAlias := netlinkLinkSetAlias
	originalLinkSetUp := netlinkLinkSetUp
	originalQueueGet := netlinkNetDevQueueGet
	originalQueueCreate := netlinkNetDevQueueCreate
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
		netlinkLinkAdd = originalLinkAdd
		netlinkLinkDel = originalLinkDel
		netlinkLinkSetAlias = originalLinkSetAlias
		netlinkLinkSetUp = originalLinkSetUp
		netlinkNetDevQueueGet = originalQueueGet
		netlinkNetDevQueueCreate = originalQueueCreate
		netlinkNetDevRSSGet = originalRSSGet
		netlinkNetDevRSSSet = originalRSSSet
		netlinkNetDevRingsGet = originalRingsGet
		netlinkNetDevRingsSet = originalRingsSet
		netlinkNetDevFeaturesGet = originalFeaturesGet
		netlinkNetDevFeaturesSet = originalFeaturesSet
		netlinkNetDevRxFlowInsert = originalFlowInsert
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
	netlinkLinkAdd = func(link netlink.Link) error {
		f.addCalls++
		netkit, ok := link.(*netlink.Netkit)
		if !ok {
			return errors.New("expected netkit link")
		}
		f.addedNetkit = netkit
		host := &netlink.Netkit{LinkAttrs: netlink.LinkAttrs{
			Name:  netkit.Attrs().Name,
			Index: testHostIndex,
			MTU:   netkit.Attrs().MTU,
			Alias: netkit.Attrs().Alias,
		}}
		peer := &netlink.Netkit{LinkAttrs: netlink.LinkAttrs{
			Name:  f.peerIfName,
			Index: testPeerIndex,
			MTU:   netkit.Attrs().MTU,
		}}
		f.links[f.hostIfName] = host
		f.links[f.peerIfName] = peer
		return nil
	}
	netlinkLinkDel = func(link netlink.Link) error {
		f.deleteCalls++
		delete(f.links, f.hostIfName)
		delete(f.links, f.peerIfName)
		for queueID, lease := range f.leases {
			if lease != nil && lease.IfIndex == testPeerIndex {
				delete(f.leases, queueID)
			}
		}
		return nil
	}
	netlinkLinkSetAlias = func(link netlink.Link, alias string) error {
		if f.flowAliasError != nil && link.Attrs().Name == f.hostIfName &&
			alias != ownershipAlias(f.hostIfName) {
			return f.flowAliasError
		}
		link.Attrs().Alias = alias
		return nil
	}
	netlinkLinkSetUp = func(link netlink.Link) error {
		link.Attrs().Flags |= net.FlagUp
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
	netlinkNetDevQueueCreate = func(req netlink.NetDevQueueCreateRequest) (uint32, error) {
		f.createRequests = append(f.createRequests, req)
		queueID := req.Lease.Queue.ID
		if err := f.createErrors[queueID]; err != nil {
			return 0, err
		}
		const virtualQueueID = 1
		f.leases[queueID] = &netlink.NetDevQueueLease{
			IfIndex: uint32(req.IfIndex),
			Queue: netlink.NetDevQueueID{
				ID:   virtualQueueID,
				Type: netlink.NetDevQueueTypeRx,
			},
		}
		return virtualQueueID, nil
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
	netlinkNetDevRxFlowInsert = func(dev string, flow netlink.NetDevRxFlow) (uint32, error) {
		if dev != testPhysicalIfName {
			return 0, unix.ENODEV
		}
		f.flowInsertRequests = append(f.flowInsertRequests, flow)
		if f.flowInsertError != nil {
			return 0, f.flowInsertError
		}
		if flow.Location == netlink.RX_CLS_LOC_ANY && f.flowAnyLocationError != nil {
			return 0, f.flowAnyLocationError
		}
		if f.leases[flow.Queue] == nil {
			return 0, errors.New("RX flow inserted before queue lease")
		}

		location := flow.Location
		if location == netlink.RX_CLS_LOC_ANY {
			location = f.nextFlowLocation
			for {
				if _, exists := f.flows[location]; !exists {
					break
				}
				location++
			}
			f.nextFlowLocation = location + 1
		}
		flow.Location = location
		if !f.ignoreFlowInsert {
			f.flows[location] = flow
		}
		return location, nil
	}
	netlinkNetDevRxFlowDelete = func(dev string, location uint32) error {
		if dev != testPhysicalIfName {
			return unix.ENODEV
		}
		f.flowDeleteRequests = append(f.flowDeleteRequests, location)
		if f.flowDeleteError != nil {
			return f.flowDeleteError
		}
		if !f.ignoreFlowDelete {
			delete(f.flows, location)
		}
		return nil
	}
	netlinkNetDevRxFlowList = func(dev string) ([]uint32, error) {
		if dev != testPhysicalIfName {
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
	}
}

func testAllocation(shareID kube_types.UID) types.DeviceAllocation {
	return types.DeviceAllocation{
		Config: types.DeviceConfig{RXQueue: &types.RXQueueConfig{
			DestinationMAC: testDestinationMAC,
		}},
		ShareID: shareID,
		ConsumedCapacity: map[resourceapi.QualifiedName]apiresource.Quantity{
			types.RXQueuesCapacity: apiresource.MustParse("1"),
		},
	}
}

func testRXFlow(queueID, location uint32) netlink.NetDevRxFlow {
	destinationMAC, err := net.ParseMAC(testDestinationMAC)
	if err != nil {
		panic(err)
	}
	return netlink.NetDevRxFlow{
		Match: netlink.EtherFlow{
			DstMAC:     destinationMAC,
			DstMACMask: net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		},
		Queue: queueID, Location: location,
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

func TestAllocationIfNames(t *testing.T) {
	host0, peer0 := allocationIfNames(testPhysicalIfName, testShareID)
	host1, peer1 := allocationIfNames(testPhysicalIfName, kube_types.UID("different-share"))

	require.Len(t, host0, types.MaxInterfaceNameLength)
	require.Len(t, peer0, types.MaxInterfaceNameLength)
	require.NotEqual(t, host0, peer0)
	require.NotEqual(t, host0, host1)
	require.NotEqual(t, peer0, peer1)
}

func TestRXFlowForAllocation(t *testing.T) {
	tests := []struct {
		name string
		mac  string
	}{
		{name: "empty"},
		{name: "invalid", mac: "not-a-mac"},
		{name: "EUI-64", mac: "02:00:00:ff:fe:00:00:02"},
		{name: "multicast", mac: "01:00:5e:00:00:01"},
		{name: "zero", mac: "00:00:00:00:00:00"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allocation := testAllocation(testShareID)
			allocation.Config.RXQueue.DestinationMAC = tt.mac

			_, _, err := rxFlowForAllocation(allocation)
			require.ErrorIs(t, err, errInvalidAllocation)
		})
	}

	t.Run("missing RX queue config", func(t *testing.T) {
		allocation := testAllocation(testShareID)
		allocation.Config.RXQueue = nil

		_, _, err := rxFlowForAllocation(allocation)
		require.ErrorIs(t, err, errInvalidAllocation)
	})

	t.Run("exact destination MAC", func(t *testing.T) {
		allocation := testAllocation(testShareID)
		allocation.Config.RXQueue.DestinationMAC = "02-00-00-00-00-AB"

		flow, normalizedMAC, err := rxFlowForAllocation(allocation)
		require.NoError(t, err)
		require.Equal(t, "02:00:00:00:00:ab", normalizedMAC)
		require.Equal(t, net.HardwareAddr{0x02, 0, 0, 0, 0, 0xab}, flow.DstMAC)
		require.Equal(t, net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, flow.DstMACMask)
		require.Nil(t, flow.SrcMAC)
		require.Nil(t, flow.SrcMACMask)
		require.Zero(t, flow.EthProto)
		require.Zero(t, flow.ProtoMask)
	})
}

func TestOwnedRXFlow(t *testing.T) {
	hostIfName, _ := allocationIfNames(testPhysicalIfName, testShareID)
	link := &netlink.Netkit{LinkAttrs: netlink.LinkAttrs{Name: hostIfName}}

	link.Alias = ownershipAlias(hostIfName)
	ownership, err := ownedRXFlow(link, hostIfName)
	require.NoError(t, err)
	require.Nil(t, ownership)

	link.Alias = rxFlowOwnershipAlias(hostIfName, rxFlowOwnership{100, testDestinationMAC})
	ownership, err = ownedRXFlow(link, hostIfName)
	require.NoError(t, err)
	require.Equal(t, &rxFlowOwnership{100, testDestinationMAC}, ownership)

	for _, alias := range []string{
		"",
		ownershipAlias(hostIfName) + ":invalid:" + testDestinationMAC,
		ownershipAlias(hostIfName) + ":0100:" + testDestinationMAC,
		ownershipAlias(hostIfName) + ":100:02:00:00:00:00:FF",
	} {
		link.Alias = alias
		_, err := ownedRXFlow(link, hostIfName)
		require.ErrorIs(t, err, errUnownedLink)
	}
}

func TestSetupAndFree(t *testing.T) {
	t.Run("leases highest free reserved queue and cleans up", func(t *testing.T) {
		fake := newFakeNetlink(8, 8, testShareID)
		fake.leases[7] = &netlink.NetDevQueueLease{IfIndex: 99}
		fake.install(t)

		advertised := testDeviceWithCount(8, 2)
		allocation := testAllocation(testShareID)
		device, err := advertised.Setup(allocation)
		require.NoError(t, err)

		prepared := device.(*RXQueueDevice)
		require.True(t, prepared.Prepared)
		require.Equal(t, uint32(6), prepared.PhysicalQueueID)
		require.Equal(t, uint32(1), prepared.VirtualQueueID)
		require.Equal(t, testDestinationMAC, prepared.RXFlowDestinationMAC)
		require.Equal(t, uint32(100), *prepared.RXFlowLocation)
		require.Equal(t, fake.peerIfName, prepared.KernelIfName())
		require.Equal(t, 1, fake.addCalls)
		require.Len(t, fake.createRequests, 1)
		require.Equal(t, uint32(6), fake.createRequests[0].Lease.Queue.ID)
		require.Equal(t, testPeerIndex, fake.createRequests[0].IfIndex)
		require.Len(t, fake.flowInsertRequests, 1)
		require.Equal(t, uint32(6), fake.flowInsertRequests[0].Queue)
		require.Equal(t, uint32(netlink.RX_CLS_LOC_ANY), fake.flowInsertRequests[0].Location)
		flow, ok := fake.flowInsertRequests[0].Match.(netlink.EtherFlow)
		require.True(t, ok)
		destinationMAC, err := net.ParseMAC(testDestinationMAC)
		require.NoError(t, err)
		require.Equal(t, destinationMAC, flow.DstMAC)
		require.Equal(t, net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, flow.DstMACMask)
		require.Contains(t, fake.flows, uint32(100))
		require.Equal(t, rxFlowOwnershipAlias(fake.hostIfName, rxFlowOwnership{100, testDestinationMAC}),
			fake.links[fake.hostIfName].Attrs().Alias)
		require.Equal(t, ownershipAlias(fake.peerIfName), fake.links[fake.peerIfName].Attrs().Alias)
		require.Equal(t, netlink.NETKIT_MODE_L2, fake.addedNetkit.Mode)
		require.Equal(t, netlink.NETKIT_POLICY_FORWARD, fake.addedNetkit.Policy)
		require.Equal(t, netlink.NETKIT_POLICY_FORWARD, fake.addedNetkit.PeerPolicy)
		require.Equal(t, 9000, fake.addedNetkit.Attrs().MTU)
		require.Equal(t, netkitTxQLen, fake.addedNetkit.Attrs().TxQLen)
		require.NotZero(t, fake.links[fake.hostIfName].Attrs().Flags&net.FlagUp)

		require.NoError(t, prepared.Free(allocation))
		require.Equal(t, 1, fake.deleteCalls)
		require.NotContains(t, fake.links, fake.hostIfName)
		require.NotContains(t, fake.leases, uint32(6))
		require.Empty(t, fake.flows)
		require.Equal(t, []uint32{100}, fake.flowDeleteRequests)
	})

	t.Run("uses an explicit free rule location when the driver rejects automatic allocation", func(t *testing.T) {
		tests := []struct {
			name string
			err  error
		}{
			{name: "invalid argument", err: unix.EINVAL},
			{name: "no space", err: unix.ENOSPC},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				fake := newFakeNetlink(8, 8, testShareID)
				fake.flowAnyLocationError = tt.err
				fake.flows[0] = testRXFlow(0, 0)
				fake.flows[2] = testRXFlow(0, 2)
				fake.install(t)

				device, err := testDevice(8).Setup(testAllocation(testShareID))
				require.NoError(t, err)
				prepared := device.(*RXQueueDevice)
				require.Equal(t, uint32(1), *prepared.RXFlowLocation)
				require.Len(t, fake.flowInsertRequests, 2)
				require.Equal(t, uint32(netlink.RX_CLS_LOC_ANY), fake.flowInsertRequests[0].Location)
				require.Equal(t, uint32(1), fake.flowInsertRequests[1].Location)
				require.Contains(t, fake.flows, uint32(0))
				require.Contains(t, fake.flows, uint32(1))
				require.Contains(t, fake.flows, uint32(2))

				require.NoError(t, prepared.Free(testAllocation(testShareID)))
				require.Equal(t, []uint32{1}, fake.flowDeleteRequests)
				require.Contains(t, fake.flows, uint32(0))
				require.NotContains(t, fake.flows, uint32(1))
				require.Contains(t, fake.flows, uint32(2))
			})
		}
	})

	t.Run("rolls back when explicit rule location discovery fails", func(t *testing.T) {
		fake := newFakeNetlink(8, 8, testShareID)
		fake.flowAnyLocationError = unix.ENOSPC
		fake.flowListError = unix.EIO
		fake.install(t)

		_, err := testDevice(8).Setup(testAllocation(testShareID))
		require.ErrorIs(t, err, unix.ENOSPC)
		require.ErrorIs(t, err, unix.EIO)
		require.Equal(t, 1, fake.deleteCalls)
		require.Empty(t, fake.leases)
		require.Empty(t, fake.flows)
	})

	t.Run("busy queue race falls through to next queue", func(t *testing.T) {
		fake := newFakeNetlink(8, 8, testShareID)
		fake.createErrors[7] = unix.EBUSY
		fake.install(t)

		device, err := testDeviceWithCount(8, 2).Setup(testAllocation(testShareID))
		require.NoError(t, err)
		prepared := device.(*RXQueueDevice)
		require.Equal(t, uint32(6), prepared.PhysicalQueueID)
		require.Len(t, fake.createRequests, 2)
		require.Equal(t, uint32(7), fake.createRequests[0].Lease.Queue.ID)
		require.Equal(t, uint32(6), fake.createRequests[1].Lease.Queue.ID)
	})

	t.Run("no free queue rolls back netkit pair", func(t *testing.T) {
		fake := newFakeNetlink(8, 8, testShareID)
		fake.leases[7] = &netlink.NetDevQueueLease{IfIndex: 98}
		fake.leases[6] = &netlink.NetDevQueueLease{IfIndex: 99}
		fake.install(t)

		_, err := testDeviceWithCount(8, 2).Setup(testAllocation(testShareID))
		require.ErrorIs(t, err, errNoAvailableRXQueue)
		require.Equal(t, 1, fake.deleteCalls)
		require.NotContains(t, fake.links, fake.hostIfName)
	})

	t.Run("driver rejection rolls back netkit pair", func(t *testing.T) {
		fake := newFakeNetlink(8, 8, testShareID)
		fake.createErrors[7] = unix.EOPNOTSUPP
		fake.install(t)

		_, err := testDevice(8).Setup(testAllocation(testShareID))
		require.ErrorIs(t, err, unix.EOPNOTSUPP)
		require.Equal(t, 1, fake.deleteCalls)
	})

	t.Run("flow insertion failure rolls back lease and netkit pair", func(t *testing.T) {
		fake := newFakeNetlink(8, 8, testShareID)
		fake.flowInsertError = unix.EOPNOTSUPP
		fake.install(t)

		_, err := testDevice(8).Setup(testAllocation(testShareID))
		require.ErrorIs(t, err, unix.EOPNOTSUPP)
		require.Equal(t, 1, fake.deleteCalls)
		require.NotContains(t, fake.links, fake.hostIfName)
		require.Empty(t, fake.leases)
		require.Empty(t, fake.flows)
		require.Empty(t, fake.flowDeleteRequests)
	})

	t.Run("flow ownership failure rolls back rule lease and netkit pair", func(t *testing.T) {
		fake := newFakeNetlink(8, 8, testShareID)
		fake.flowAliasError = unix.EIO
		fake.install(t)

		_, err := testDevice(8).Setup(testAllocation(testShareID))
		require.ErrorIs(t, err, unix.EIO)
		require.Equal(t, []uint32{100}, fake.flowDeleteRequests)
		require.Equal(t, 1, fake.deleteCalls)
		require.NotContains(t, fake.links, fake.hostIfName)
		require.Empty(t, fake.leases)
		require.Empty(t, fake.flows)
	})

	t.Run("missing inserted flow rolls back rule lease and netkit pair", func(t *testing.T) {
		fake := newFakeNetlink(8, 8, testShareID)
		fake.ignoreFlowInsert = true
		fake.install(t)

		_, err := testDevice(8).Setup(testAllocation(testShareID))
		require.ErrorContains(t, err, "was not present after insertion")
		require.Equal(t, []uint32{100}, fake.flowDeleteRequests)
		require.Equal(t, 1, fake.deleteCalls)
		require.NotContains(t, fake.links, fake.hostIfName)
		require.Empty(t, fake.leases)
		require.Empty(t, fake.flows)
	})

	t.Run("flow verification failure rolls back rule lease and netkit pair", func(t *testing.T) {
		fake := newFakeNetlink(8, 8, testShareID)
		fake.flowListError = unix.EIO
		fake.install(t)

		_, err := testDevice(8).Setup(testAllocation(testShareID))
		require.ErrorIs(t, err, unix.EIO)
		require.Equal(t, []uint32{100}, fake.flowDeleteRequests)
		require.Equal(t, 1, fake.deleteCalls)
		require.Empty(t, fake.leases)
		require.Empty(t, fake.flows)
	})

	t.Run("adopts an existing lease on retry", func(t *testing.T) {
		fake := newFakeNetlink(8, 8, testShareID)
		fake.links[fake.hostIfName] = &netlink.Netkit{LinkAttrs: netlink.LinkAttrs{
			Name: fake.hostIfName, Index: testHostIndex, Alias: ownershipAlias(fake.hostIfName),
		}}
		fake.links[fake.peerIfName] = &netlink.Netkit{LinkAttrs: netlink.LinkAttrs{
			Name: fake.peerIfName, Index: testPeerIndex, Alias: ownershipAlias(fake.peerIfName),
		}}
		fake.leases[7] = &netlink.NetDevQueueLease{
			IfIndex: testPeerIndex,
			Queue: netlink.NetDevQueueID{
				ID:   1,
				Type: netlink.NetDevQueueTypeRx,
			},
		}
		fake.install(t)

		device, err := testDevice(8).Setup(testAllocation(testShareID))
		require.NoError(t, err)
		prepared := device.(*RXQueueDevice)
		require.Equal(t, uint32(7), prepared.PhysicalQueueID)
		require.Equal(t, uint32(1), prepared.VirtualQueueID)
		require.Zero(t, fake.addCalls)
		require.Empty(t, fake.createRequests)
		require.Len(t, fake.flowInsertRequests, 1)
		require.Equal(t, uint32(100), *prepared.RXFlowLocation)
		require.Contains(t, fake.flows, uint32(100))
		require.Equal(t, rxFlowOwnershipAlias(fake.hostIfName, rxFlowOwnership{100, testDestinationMAC}), fake.links[fake.hostIfName].Attrs().Alias)
	})

	t.Run("completes ownership of an existing lease on retry", func(t *testing.T) {
		fake := newFakeNetlink(8, 8, testShareID)
		fake.links[fake.hostIfName] = &netlink.Netkit{LinkAttrs: netlink.LinkAttrs{
			Name: fake.hostIfName, Index: testHostIndex, Alias: ownershipAlias(fake.hostIfName),
		}}
		fake.links[fake.peerIfName] = &netlink.Netkit{LinkAttrs: netlink.LinkAttrs{
			Name: fake.peerIfName, Index: testPeerIndex,
		}}
		fake.leases[7] = &netlink.NetDevQueueLease{
			IfIndex: testPeerIndex,
			Queue: netlink.NetDevQueueID{
				ID:   1,
				Type: netlink.NetDevQueueTypeRx,
			},
		}
		fake.install(t)

		device, err := testDevice(8).Setup(testAllocation(testShareID))
		require.NoError(t, err)
		require.Equal(t, uint32(7), device.(*RXQueueDevice).PhysicalQueueID)
		require.Equal(t, ownershipAlias(fake.peerIfName), fake.links[fake.peerIfName].Attrs().Alias)
		require.Zero(t, fake.addCalls)
		require.Zero(t, fake.deleteCalls)
		require.Len(t, fake.flowInsertRequests, 1)
	})

	t.Run("adopts an existing flow without inserting another", func(t *testing.T) {
		fake := newFakeNetlink(8, 8, testShareID)
		fake.links[fake.hostIfName] = &netlink.Netkit{LinkAttrs: netlink.LinkAttrs{
			Name: fake.hostIfName, Index: testHostIndex,
			Alias: rxFlowOwnershipAlias(fake.hostIfName, rxFlowOwnership{100, testDestinationMAC}),
		}}
		fake.links[fake.peerIfName] = &netlink.Netkit{LinkAttrs: netlink.LinkAttrs{
			Name: fake.peerIfName, Index: testPeerIndex, Alias: ownershipAlias(fake.peerIfName),
		}}
		fake.leases[7] = &netlink.NetDevQueueLease{
			IfIndex: testPeerIndex,
			Queue:   netlink.NetDevQueueID{ID: 1, Type: netlink.NetDevQueueTypeRx},
		}
		fake.flows[100] = testRXFlow(7, 100)
		fake.install(t)

		device, err := testDevice(8).Setup(testAllocation(testShareID))
		require.NoError(t, err)
		prepared := device.(*RXQueueDevice)
		require.Equal(t, uint32(7), prepared.PhysicalQueueID)
		require.Equal(t, uint32(100), *prepared.RXFlowLocation)
		require.Empty(t, fake.flowInsertRequests)
		require.Empty(t, fake.flowDeleteRequests)
		require.Zero(t, fake.addCalls)
	})

	t.Run("recreates a missing owned flow", func(t *testing.T) {
		fake := newFakeNetlink(8, 8, testShareID)
		fake.nextFlowLocation = 101
		fake.links[fake.hostIfName] = &netlink.Netkit{LinkAttrs: netlink.LinkAttrs{
			Name: fake.hostIfName, Index: testHostIndex,
			Alias: rxFlowOwnershipAlias(fake.hostIfName, rxFlowOwnership{100, testDestinationMAC}),
		}}
		fake.links[fake.peerIfName] = &netlink.Netkit{LinkAttrs: netlink.LinkAttrs{
			Name: fake.peerIfName, Index: testPeerIndex, Alias: ownershipAlias(fake.peerIfName),
		}}
		fake.leases[7] = &netlink.NetDevQueueLease{
			IfIndex: testPeerIndex,
			Queue:   netlink.NetDevQueueID{ID: 1, Type: netlink.NetDevQueueTypeRx},
		}
		fake.install(t)

		device, err := testDevice(8).Setup(testAllocation(testShareID))
		require.NoError(t, err)
		prepared := device.(*RXQueueDevice)
		require.Equal(t, uint32(101), *prepared.RXFlowLocation)
		require.Len(t, fake.flowInsertRequests, 1)
		require.Contains(t, fake.flows, uint32(101))
		require.Equal(t, rxFlowOwnershipAlias(fake.hostIfName, rxFlowOwnership{101, testDestinationMAC}), fake.links[fake.hostIfName].Attrs().Alias)
	})

	t.Run("refuses owned flow for a different destination", func(t *testing.T) {
		fake := newFakeNetlink(8, 8, testShareID)
		const otherDestinationMAC = "02:00:00:00:00:03"
		fake.links[fake.hostIfName] = &netlink.Netkit{LinkAttrs: netlink.LinkAttrs{
			Name: fake.hostIfName, Index: testHostIndex,
			Alias: rxFlowOwnershipAlias(fake.hostIfName, rxFlowOwnership{100, otherDestinationMAC}),
		}}
		fake.links[fake.peerIfName] = &netlink.Netkit{LinkAttrs: netlink.LinkAttrs{
			Name: fake.peerIfName, Index: testPeerIndex, Alias: ownershipAlias(fake.peerIfName),
		}}
		fake.leases[7] = &netlink.NetDevQueueLease{
			IfIndex: testPeerIndex,
			Queue:   netlink.NetDevQueueID{ID: 1, Type: netlink.NetDevQueueTypeRx},
		}
		fake.flows[100] = testRXFlow(7, 100)
		fake.install(t)

		_, err := testDevice(8).Setup(testAllocation(testShareID))
		require.ErrorIs(t, err, errInvalidAllocation)
		require.Empty(t, fake.flowInsertRequests)
		require.Empty(t, fake.flowDeleteRequests)
		require.Zero(t, fake.deleteCalls)
	})

	t.Run("replaces an incomplete owned pair on retry", func(t *testing.T) {
		fake := newFakeNetlink(8, 8, testShareID)
		fake.links[fake.hostIfName] = &netlink.Netkit{LinkAttrs: netlink.LinkAttrs{
			Name: fake.hostIfName, Index: testHostIndex, Alias: ownershipAlias(fake.hostIfName),
		}}
		fake.links[fake.peerIfName] = &netlink.Netkit{LinkAttrs: netlink.LinkAttrs{
			Name: fake.peerIfName, Index: testPeerIndex,
		}}
		fake.install(t)

		device, err := testDevice(8).Setup(testAllocation(testShareID))
		require.NoError(t, err)
		require.Equal(t, uint32(7), device.(*RXQueueDevice).PhysicalQueueID)
		require.Equal(t, 1, fake.deleteCalls)
		require.Equal(t, 1, fake.addCalls)
	})

	t.Run("deletes an owned flow before replacing an incomplete pair", func(t *testing.T) {
		fake := newFakeNetlink(8, 8, testShareID)
		fake.nextFlowLocation = 101
		fake.links[fake.hostIfName] = &netlink.Netkit{LinkAttrs: netlink.LinkAttrs{
			Name: fake.hostIfName, Index: testHostIndex,
			Alias: rxFlowOwnershipAlias(fake.hostIfName, rxFlowOwnership{100, testDestinationMAC}),
		}}
		fake.links[fake.peerIfName] = &netlink.Netkit{LinkAttrs: netlink.LinkAttrs{
			Name: fake.peerIfName, Index: testPeerIndex, Alias: ownershipAlias(fake.peerIfName),
		}}
		fake.flows[100] = testRXFlow(7, 100)
		fake.install(t)

		device, err := testDevice(8).Setup(testAllocation(testShareID))
		require.NoError(t, err)
		prepared := device.(*RXQueueDevice)
		require.Equal(t, uint32(101), *prepared.RXFlowLocation)
		require.Equal(t, []uint32{100}, fake.flowDeleteRequests)
		require.NotContains(t, fake.flows, uint32(100))
		require.Contains(t, fake.flows, uint32(101))
		require.Equal(t, 1, fake.deleteCalls)
		require.Equal(t, 1, fake.addCalls)
	})

	t.Run("preserves an incomplete pair when flow cleanup fails", func(t *testing.T) {
		fake := newFakeNetlink(8, 8, testShareID)
		fake.links[fake.hostIfName] = &netlink.Netkit{LinkAttrs: netlink.LinkAttrs{
			Name: fake.hostIfName, Index: testHostIndex,
			Alias: rxFlowOwnershipAlias(fake.hostIfName, rxFlowOwnership{100, testDestinationMAC}),
		}}
		fake.links[fake.peerIfName] = &netlink.Netkit{LinkAttrs: netlink.LinkAttrs{
			Name: fake.peerIfName, Index: testPeerIndex, Alias: ownershipAlias(fake.peerIfName),
		}}
		fake.flows[100] = testRXFlow(7, 100)
		fake.flowDeleteError = unix.EIO
		fake.install(t)

		_, err := testDevice(8).Setup(testAllocation(testShareID))
		require.ErrorIs(t, err, unix.EIO)
		require.Contains(t, fake.links, fake.hostIfName)
		require.Contains(t, fake.flows, uint32(100))
		require.Zero(t, fake.deleteCalls)
		require.Zero(t, fake.addCalls)
	})

	t.Run("refuses an existing unowned link", func(t *testing.T) {
		fake := newFakeNetlink(8, 8, testShareID)
		fake.links[fake.hostIfName] = &netlink.Netkit{LinkAttrs: netlink.LinkAttrs{
			Name: fake.hostIfName, Index: testHostIndex,
		}}
		fake.install(t)

		_, err := testDevice(8).Setup(testAllocation(testShareID))
		require.ErrorIs(t, err, errUnownedLink)
		require.Zero(t, fake.deleteCalls)
	})

	t.Run("serialized names must match share ID", func(t *testing.T) {
		fake := newFakeNetlink(8, 8, testShareID)
		fake.install(t)

		prepared := testDevice(8).prepared("wrong-host", "wrong-peer", 7, 1, testDestinationMAC, 100)
		_, err := prepared.Setup(testAllocation(testShareID))
		require.ErrorIs(t, err, errInvalidAllocation)
		require.ErrorIs(t, prepared.Free(testAllocation(testShareID)), errInvalidAllocation)
		require.Zero(t, fake.deleteCalls)
	})

	t.Run("flow deletion failure preserves the lease for retry", func(t *testing.T) {
		fake := newFakeNetlink(8, 8, testShareID)
		fake.install(t)

		device, err := testDevice(8).Setup(testAllocation(testShareID))
		require.NoError(t, err)
		prepared := device.(*RXQueueDevice)
		fake.flowDeleteError = unix.EIO

		err = prepared.Free(testAllocation(testShareID))
		require.ErrorIs(t, err, unix.EIO)
		require.Contains(t, fake.links, fake.hostIfName)
		require.Contains(t, fake.leases, prepared.PhysicalQueueID)
		require.Contains(t, fake.flows, *prepared.RXFlowLocation)
		require.Zero(t, fake.deleteCalls)

		fake.flowDeleteError = nil
		require.NoError(t, prepared.Free(testAllocation(testShareID)))
		require.NotContains(t, fake.links, fake.hostIfName)
		require.Empty(t, fake.flows)
	})

	t.Run("failed flow deletion readback preserves the lease for retry", func(t *testing.T) {
		fake := newFakeNetlink(8, 8, testShareID)
		fake.install(t)

		device, err := testDevice(8).Setup(testAllocation(testShareID))
		require.NoError(t, err)
		prepared := device.(*RXQueueDevice)
		fake.ignoreFlowDelete = true

		err = prepared.Free(testAllocation(testShareID))
		require.ErrorContains(t, err, "remained after deletion")
		require.Contains(t, fake.links, fake.hostIfName)
		require.Contains(t, fake.leases, prepared.PhysicalQueueID)
		require.Contains(t, fake.flows, *prepared.RXFlowLocation)
		require.Zero(t, fake.deleteCalls)

		fake.ignoreFlowDelete = false
		require.NoError(t, prepared.Free(testAllocation(testShareID)))
		require.NotContains(t, fake.links, fake.hostIfName)
		require.Empty(t, fake.flows)
	})

	t.Run("flow metadata mismatch refuses cleanup", func(t *testing.T) {
		fake := newFakeNetlink(8, 8, testShareID)
		fake.install(t)

		device, err := testDevice(8).Setup(testAllocation(testShareID))
		require.NoError(t, err)
		prepared := device.(*RXQueueDevice)
		fake.links[fake.hostIfName].Attrs().Alias = rxFlowOwnershipAlias(
			fake.hostIfName, rxFlowOwnership{101, testDestinationMAC},
		)

		err = prepared.Free(testAllocation(testShareID))
		require.ErrorIs(t, err, errUnownedLink)
		require.Contains(t, fake.links, fake.hostIfName)
		require.Contains(t, fake.leases, prepared.PhysicalQueueID)
		require.Contains(t, fake.flows, *prepared.RXFlowLocation)
		require.Empty(t, fake.flowDeleteRequests)
		require.Zero(t, fake.deleteCalls)
	})
}

func TestRecover(t *testing.T) {
	t.Run("recreates the persisted queue lease and flow rule", func(t *testing.T) {
		fake := newFakeNetlink(8, 8, testShareID)
		fake.nextFlowLocation = 200
		fake.install(t)

		restored := testDeviceWithCount(8, 2).prepared(
			fake.hostIfName, fake.peerIfName, 6, 1, testDestinationMAC, 100,
		)
		device, err := restored.Recover(testAllocation(testShareID))
		require.NoError(t, err)

		recovered := device.(*RXQueueDevice)
		require.Equal(t, restored.PhysicalQueueID, recovered.PhysicalQueueID)
		require.Equal(t, restored.VirtualQueueID, recovered.VirtualQueueID)
		require.Equal(t, restored.RXFlowLocation, recovered.RXFlowLocation)
		require.Len(t, fake.createRequests, 1)
		require.Equal(t, uint32(6), fake.createRequests[0].Lease.Queue.ID)
		require.Len(t, fake.flowInsertRequests, 1)
		require.Equal(t, uint32(100), fake.flowInsertRequests[0].Location)
	})

	t.Run("rejects a different virtual queue ID", func(t *testing.T) {
		fake := newFakeNetlink(8, 8, testShareID)
		fake.install(t)

		restored := testDeviceWithCount(8, 2).prepared(
			fake.hostIfName, fake.peerIfName, 6, 2, testDestinationMAC, 100,
		)
		_, err := restored.Recover(testAllocation(testShareID))
		require.ErrorIs(t, err, errInvalidAllocation)
		require.Equal(t, 1, fake.deleteCalls)
		require.NotContains(t, fake.links, fake.hostIfName)
	})

	t.Run("requires prepared device state", func(t *testing.T) {
		fake := newFakeNetlink(8, 8, testShareID)
		fake.install(t)

		_, err := testDevice(8).Recover(testAllocation(testShareID))
		require.ErrorIs(t, err, errInvalidAllocation)
		require.Empty(t, fake.createRequests)
	})
}

func TestDeviceMetadataAndSerialization(t *testing.T) {
	advertised := testDevice(16)
	require.True(t, advertised.Match(v2alpha1.CiliumNetworkDriverDeviceFilter{}))
	require.True(t, advertised.Match(v2alpha1.CiliumNetworkDriverDeviceFilter{
		DeviceManagers: []string{types.DeviceManagerTypeRXQueue.String()},
		IfNames:        []string{testPhysicalIfName},
	}))
	require.False(t, advertised.Match(v2alpha1.CiliumNetworkDriverDeviceFilter{
		Drivers: []string{"ice"},
	}))

	prepared := advertised.prepared("zrxh12345678901", "zrxp12345678901", 15, 1, testDestinationMAC, 100)
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
	require.Equal(t, prepared.HostIfName, restored.HostIfName)
	require.Equal(t, prepared.PeerIfName, restored.PeerIfName)
	require.Equal(t, prepared.PhysicalQueueID, restored.PhysicalQueueID)
	require.Equal(t, prepared.VirtualQueueID, restored.VirtualQueueID)
	require.Equal(t, prepared.RXFlowDestinationMAC, restored.RXFlowDestinationMAC)
	require.Equal(t, prepared.RXFlowLocation, restored.RXFlowLocation)
	require.NotSame(t, prepared.RXFlowLocation, restored.RXFlowLocation)
	*restored.RXFlowLocation = 101
	require.Equal(t, uint32(100), *prepared.RXFlowLocation)
}

func TestDeviceStateRXFlowValidation(t *testing.T) {
	location := uint32(100)
	valid := deviceState{
		PhysicalIfName:       testPhysicalIfName,
		TotalRXQueues:        8,
		ReservedQueueIDs:     []uint32{7},
		Prepared:             true,
		HostIfName:           "zrxh12345678901",
		PeerIfName:           "zrxp12345678901",
		PhysicalQueueID:      7,
		VirtualQueueID:       1,
		RXFlowDestinationMAC: testDestinationMAC,
		RXFlowLocation:       &location,
	}

	tests := []struct {
		name   string
		mutate func(*deviceState)
	}{
		{
			name: "missing destination MAC",
			mutate: func(state *deviceState) {
				state.RXFlowDestinationMAC = ""
			},
		},
		{
			name: "missing location",
			mutate: func(state *deviceState) {
				state.RXFlowLocation = nil
			},
		},
		{
			name: "unprepared",
			mutate: func(state *deviceState) {
				state.Prepared = false
			},
		},
		{
			name: "invalid destination MAC",
			mutate: func(state *deviceState) {
				state.RXFlowDestinationMAC = "not-a-mac"
			},
		},
		{
			name: "non-canonical destination MAC",
			mutate: func(state *deviceState) {
				state.RXFlowDestinationMAC = "02:00:00:00:00:AB"
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := valid
			tt.mutate(&state)
			data, err := json.Marshal(state)
			require.NoError(t, err)

			err = (&RXQueueDevice{}).UnmarshalBinary(data)
			require.Error(t, err)
		})
	}

	t.Run("accepts state written before flow steering", func(t *testing.T) {
		state := valid
		state.RXFlowDestinationMAC = ""
		state.RXFlowLocation = nil
		data, err := json.Marshal(state)
		require.NoError(t, err)

		restored := &RXQueueDevice{}
		require.NoError(t, restored.UnmarshalBinary(data))
		require.Empty(t, restored.RXFlowDestinationMAC)
		require.Nil(t, restored.RXFlowLocation)
	})
}

func TestValidateAllocation(t *testing.T) {
	require.ErrorIs(t, validateAllocation(types.DeviceAllocation{}), errInvalidAllocation)
	require.ErrorIs(t, validateAllocation(types.DeviceAllocation{ShareID: testShareID}), errInvalidAllocation)

	allocation := testAllocation(testShareID)
	allocation.ConsumedCapacity[types.RXQueuesCapacity] = apiresource.MustParse("2")
	require.ErrorIs(t, validateAllocation(allocation), errInvalidAllocation)

	require.NoError(t, validateAllocation(testAllocation(testShareID)))
}

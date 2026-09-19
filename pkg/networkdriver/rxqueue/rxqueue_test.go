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
	links          map[string]netlink.Link
	leases         map[uint32]*netlink.NetDevQueueLease
	addedNetkit    *netlink.Netkit
	createErrors   map[uint32]error
	createRequests []netlink.NetDevQueueCreateRequest
	realRXQueues   int
	rss            netlink.NetDevRSS
	rings          netlink.NetDevRings
	rssSetCalls    []netlink.NetDevRSSConfig
	ringsSetCalls  []netlink.NetDevRingsConfig
	rssSetError    error
	ringsSetError  error
	ignoreRSSSet   bool
	ignoreRingsSet bool
	hostIfName     string
	peerIfName     string
	addCalls       int
	deleteCalls    int
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
		hostIfName: hostIfName,
		peerIfName: peerIfName,
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
		return nil
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
		require.Equal(t, fake.peerIfName, prepared.KernelIfName())
		require.Equal(t, 1, fake.addCalls)
		require.Len(t, fake.createRequests, 1)
		require.Equal(t, uint32(6), fake.createRequests[0].Lease.Queue.ID)
		require.Equal(t, testPeerIndex, fake.createRequests[0].IfIndex)
		require.Equal(t, ownershipAlias(fake.hostIfName), fake.links[fake.hostIfName].Attrs().Alias)
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

		prepared := testDevice(8).prepared("wrong-host", "wrong-peer", 7, 1)
		_, err := prepared.Setup(testAllocation(testShareID))
		require.ErrorIs(t, err, errInvalidAllocation)
		require.ErrorIs(t, prepared.Free(testAllocation(testShareID)), errInvalidAllocation)
		require.Zero(t, fake.deleteCalls)
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

	prepared := advertised.prepared("zrxh12345678901", "zrxp12345678901", 15, 1)
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
}

func TestValidateAllocation(t *testing.T) {
	require.ErrorIs(t, validateAllocation(types.DeviceAllocation{}), errInvalidAllocation)
	require.ErrorIs(t, validateAllocation(types.DeviceAllocation{ShareID: testShareID}), errInvalidAllocation)

	allocation := testAllocation(testShareID)
	allocation.ConsumedCapacity[types.RXQueuesCapacity] = apiresource.MustParse("2")
	require.ErrorIs(t, validateAllocation(allocation), errInvalidAllocation)

	require.NoError(t, validateAllocation(testAllocation(testShareID)))
}

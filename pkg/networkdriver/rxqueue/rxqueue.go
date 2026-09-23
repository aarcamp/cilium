// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package rxqueue

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"sync"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	resourceapi "k8s.io/api/resource/v1"
	apiresource "k8s.io/apimachinery/pkg/api/resource"
	kube_types "k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/networkdriver/types"
)

const (
	defaultReservedRXQueues = 1
	netkitPeerRXQueues      = 2
	netkitTxQLen            = 1000

	hostIfNamePrefix = "zrxh"
	peerIfNamePrefix = "zrxp"
	ownershipPrefix  = "cilium-zcrx:"
)

var (
	errNoInterfaces         = errors.New("no RX queue interfaces configured")
	errDuplicateInterface   = errors.New("duplicate RX queue interface")
	errInsufficientRXQueues = errors.New("insufficient RX queues")
	errNoAvailableRXQueue   = errors.New("no reserved RX queue is available")
	errInvalidAllocation    = errors.New("invalid RX queue allocation")
	errUnownedLink          = errors.New("refusing to use link not owned by the RX queue manager")

	netlinkLinkByName        = safenetlink.LinkByName
	netlinkLinkAdd           = netlink.LinkAdd
	netlinkLinkDel           = netlink.LinkDel
	netlinkLinkSetAlias      = netlink.LinkSetAlias
	netlinkLinkSetUp         = netlink.LinkSetUp
	netlinkNetDevQueueGet    = netlink.NetDevQueueGet
	netlinkNetDevQueueCreate = netlink.NetDevQueueCreate
)

type RXQueueManager struct {
	devices []*RXQueueDevice
}

func NewManager(logger *slog.Logger, cfg *v2alpha1.RXQueueDeviceManagerConfig) (*RXQueueManager, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	mgr := &RXQueueManager{}
	for _, iface := range cfg.Ifaces {
		count := iface.Count
		if count == 0 {
			count = defaultReservedRXQueues
		}

		dev, err := discoverDevice(iface.IfName, count)
		if err != nil {
			return nil, err
		}
		mgr.devices = append(mgr.devices, dev)

		logger.Debug("discovered RX queues for leasing",
			"device", iface.IfName,
			"activeRXQueues", dev.TotalRXQueues,
			"reservedRXQueues", dev.ReservedQueueIDs,
		)
	}

	return mgr, nil
}

func validateConfig(cfg *v2alpha1.RXQueueDeviceManagerConfig) error {
	if cfg == nil || len(cfg.Ifaces) == 0 {
		return errNoInterfaces
	}

	seen := make(map[string]struct{}, len(cfg.Ifaces))
	for _, iface := range cfg.Ifaces {
		if iface.IfName == "" {
			return errors.New("RX queue interface name is empty")
		}
		if err := types.ValidateInterfaceName(iface.IfName); err != nil {
			return fmt.Errorf("invalid RX queue interface %q: %w", iface.IfName, err)
		}
		if iface.Count < 0 {
			return fmt.Errorf("RX queue count for %s must be positive", iface.IfName)
		}
		if _, exists := seen[iface.IfName]; exists {
			return fmt.Errorf("%w: %s", errDuplicateInterface, iface.IfName)
		}
		seen[iface.IfName] = struct{}{}
	}

	return nil
}

func (m *RXQueueManager) Type() types.DeviceManagerType {
	return types.DeviceManagerTypeRXQueue
}

func (m *RXQueueManager) Run(ctx context.Context, publish func([]types.Device)) error {
	devices := make([]types.Device, 0, len(m.devices))
	for _, dev := range m.devices {
		devices = append(devices, dev)
	}
	publish(devices)
	<-ctx.Done()
	return nil
}

func (m *RXQueueManager) RestoreDevice(data []byte) (types.Device, error) {
	dev := &RXQueueDevice{}
	if err := dev.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return dev, nil
}

func discoverDevice(ifName string, reserved int) (*RXQueueDevice, error) {
	link, err := netlinkLinkByName(ifName)
	if err != nil {
		return nil, fmt.Errorf("failed to find RX queue interface %s: %w", ifName, err)
	}

	total, err := activeRXQueueCount(link)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect RX queues on %s: %w", ifName, err)
	}
	if total <= reserved {
		return nil, fmt.Errorf("%w: %s has %d active RX queues; reserving %d would leave none for normal receive processing",
			errInsufficientRXQueues, ifName, total, reserved)
	}

	hwAddr := ""
	if link.Attrs().HardwareAddr != nil {
		hwAddr = link.Attrs().HardwareAddr.String()
	}

	return &RXQueueDevice{
		PhysicalIfName:   ifName,
		HardwareAddress:  hwAddr,
		MTU:              link.Attrs().MTU,
		TotalRXQueues:    total,
		ReservedQueueIDs: reservedRXQueueIDs(total, reserved),
	}, nil
}

func activeRXQueueCount(link netlink.Link) (int, error) {
	attrs := link.Attrs()
	if attrs.Flags&net.FlagUp == 0 {
		return 0, errors.New("interface is down")
	}
	if attrs.NumRxQueues <= 0 {
		return 0, errors.New("interface reports no RX queues")
	}

	for queueID := 0; queueID < attrs.NumRxQueues; queueID++ {
		_, err := netlinkNetDevQueueGet(attrs.Index, uint32(queueID), netlink.NetDevQueueTypeRx)
		if err == nil {
			continue
		}
		if errors.Is(err, unix.EINVAL) {
			return queueID, nil
		}
		return 0, fmt.Errorf("queue-get for queue %d: %w", queueID, err)
	}

	return attrs.NumRxQueues, nil
}

func reservedRXQueueIDs(total, count int) []uint32 {
	if count <= 0 || total <= count {
		return nil
	}

	queues := make([]uint32, 0, count)
	for i := 0; i < count; i++ {
		queues = append(queues, uint32(total-1-i))
	}
	return queues
}

type RXQueueDevice struct {
	PhysicalIfName   string   `json:"physicalIfName"`
	HardwareAddress  string   `json:"hardwareAddress,omitempty"`
	MTU              int      `json:"mtu,omitempty"`
	TotalRXQueues    int      `json:"totalRXQueues"`
	ReservedQueueIDs []uint32 `json:"reservedQueueIDs"`

	Prepared        bool   `json:"prepared,omitempty"`
	HostIfName      string `json:"hostIfName,omitempty"`
	PeerIfName      string `json:"peerIfName,omitempty"`
	PhysicalQueueID uint32 `json:"physicalQueueID,omitempty"`
	VirtualQueueID  uint32 `json:"virtualQueueID,omitempty"`

	mu sync.Mutex
}

func (d *RXQueueDevice) GetAttrs() map[resourceapi.QualifiedName]resourceapi.DeviceAttribute {
	attrs := map[resourceapi.QualifiedName]resourceapi.DeviceAttribute{
		types.IfNameLabel:        {StringValue: ptr.To(d.PhysicalIfName)},
		types.KernelIfNameLabel:  {StringValue: ptr.To(d.PhysicalIfName)},
		types.DeviceManagerLabel: {StringValue: ptr.To(types.DeviceManagerTypeRXQueue.String())},
	}
	if d.HardwareAddress != "" {
		attrs[types.HWAddrLabel] = resourceapi.DeviceAttribute{StringValue: ptr.To(d.HardwareAddress)}
	}
	if d.Prepared {
		virtualQueueID := int64(d.VirtualQueueID)
		attrs[types.RXQueueIDLabel] = resourceapi.DeviceAttribute{IntValue: &virtualQueueID}
	}
	return attrs
}

func (d *RXQueueDevice) GetCapacity() map[resourceapi.QualifiedName]resourceapi.DeviceCapacity {
	one := apiresource.MustParse("1")
	capacity := *apiresource.NewQuantity(int64(len(d.ReservedQueueIDs)), apiresource.DecimalSI)

	return map[resourceapi.QualifiedName]resourceapi.DeviceCapacity{
		types.RXQueuesCapacity: {
			Value: capacity,
			RequestPolicy: &resourceapi.CapacityRequestPolicy{
				Default:     ptr.To(one),
				ValidValues: []apiresource.Quantity{one},
			},
		},
	}
}

func (d *RXQueueDevice) AllowMultipleAllocations() bool {
	return true
}

func (d *RXQueueDevice) Setup(allocation types.DeviceAllocation) (types.Device, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.setup(allocation, d.ReservedQueueIDs)
}

func (d *RXQueueDevice) Recover(allocation types.DeviceAllocation) (types.Device, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.Prepared {
		return nil, fmt.Errorf("%w: device has no prepared RX queue state", errInvalidAllocation)
	}
	if !slices.Contains(d.ReservedQueueIDs, d.PhysicalQueueID) {
		return nil, fmt.Errorf("%w: stored RX queue %d is not reserved",
			errInvalidAllocation, d.PhysicalQueueID)
	}

	recovered, err := d.setup(allocation, []uint32{d.PhysicalQueueID})
	if err != nil {
		return nil, err
	}
	if recovered.VirtualQueueID != d.VirtualQueueID {
		recoveryErr := fmt.Errorf(
			"%w: recovered virtual RX queue ID %d does not match stored ID %d",
			errInvalidAllocation, recovered.VirtualQueueID, d.VirtualQueueID,
		)
		if cleanupErr := recovered.Free(allocation); cleanupErr != nil {
			recoveryErr = errors.Join(recoveryErr,
				fmt.Errorf("failed to clean up recovered RX queue device: %w", cleanupErr))
		}
		return nil, recoveryErr
	}

	return recovered, nil
}

func (d *RXQueueDevice) setup(
	allocation types.DeviceAllocation,
	physicalQueueIDs []uint32,
) (*RXQueueDevice, error) {
	if err := validateAllocation(allocation); err != nil {
		return nil, err
	}

	hostIfName, peerIfName := allocationIfNames(d.PhysicalIfName, allocation.ShareID)
	if d.Prepared && (d.HostIfName != hostIfName || d.PeerIfName != peerIfName) {
		return nil, fmt.Errorf("%w: stored netkit names do not match share ID", errInvalidAllocation)
	}

	if prepared, exists, err := d.adoptExisting(hostIfName, peerIfName, physicalQueueIDs); err != nil {
		return nil, err
	} else if exists {
		return prepared, nil
	}

	physical, err := netlinkLinkByName(d.PhysicalIfName)
	if err != nil {
		return nil, fmt.Errorf("failed to find physical interface %s: %w", d.PhysicalIfName, err)
	}
	if physical.Attrs().Flags&net.FlagUp == 0 {
		return nil, fmt.Errorf("physical interface %s is down", d.PhysicalIfName)
	}

	return d.createLease(physical, hostIfName, peerIfName, physicalQueueIDs)
}

func validateAllocation(allocation types.DeviceAllocation) error {
	if allocation.ShareID == "" {
		return fmt.Errorf("%w: share ID is required", errInvalidAllocation)
	}

	requested, exists := allocation.ConsumedCapacity[types.RXQueuesCapacity]
	if !exists {
		return fmt.Errorf("%w: consumed %s capacity is required",
			errInvalidAllocation, types.RXQueuesCapacity)
	}
	one := apiresource.MustParse("1")
	if requested.Cmp(one) != 0 {
		return fmt.Errorf("%w: %s must consume exactly one RX queue, got %s",
			errInvalidAllocation, types.RXQueuesCapacity, requested.String())
	}

	return nil
}

func allocationIfNames(ifName string, shareID kube_types.UID) (string, string) {
	sum := sha256.Sum256([]byte(ifName + "\x00" + string(shareID)))
	suffix := fmt.Sprintf("%x", sum[:])[:11]
	return hostIfNamePrefix + suffix, peerIfNamePrefix + suffix
}

func ownershipAlias(ifName string) string {
	return ownershipPrefix + ifName
}

func (d *RXQueueDevice) adoptExisting(
	hostIfName, peerIfName string,
	physicalQueueIDs []uint32,
) (*RXQueueDevice, bool, error) {
	host, err := netlinkLinkByName(hostIfName)
	if err != nil {
		if errors.As(err, &netlink.LinkNotFoundError{}) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("failed to inspect existing host link %s: %w", hostIfName, err)
	}
	if err := validateOwnedNetkit(host, ownershipAlias(hostIfName)); err != nil {
		return nil, true, err
	}

	peer, err := netlinkLinkByName(peerIfName)
	if err != nil {
		return nil, true, fmt.Errorf("failed to find peer for existing RX queue link %s: %w", hostIfName, err)
	}
	if _, ok := peer.(*netlink.Netkit); !ok {
		return nil, true, fmt.Errorf("%w: %s", errUnownedLink, peer.Attrs().Name)
	}
	peerAlias := ownershipAlias(peerIfName)
	switch peer.Attrs().Alias {
	case peerAlias:
	case "":
		// The host alias is part of the atomic link-create request, while the
		// peer alias must be applied afterward. Complete that interrupted step.
		if err := netlinkLinkSetAlias(peer, peerAlias); err != nil {
			return nil, true, fmt.Errorf("failed to mark existing netkit peer %s as owned: %w", peerIfName, err)
		}
	default:
		return nil, true, fmt.Errorf("%w: %s", errUnownedLink, peer.Attrs().Name)
	}

	for _, physicalQueueID := range physicalQueueIDs {
		queue, err := netlinkNetDevQueueGetByName(d.PhysicalIfName, physicalQueueID)
		if err != nil {
			return nil, true, err
		}
		if leaseMatches(queue.Lease, peer.Attrs().Index) {
			return d.prepared(hostIfName, peerIfName, physicalQueueID, queue.Lease.Queue.ID), true, nil
		}
	}

	// A prior setup stopped after creating the pair but before creating its
	// lease. Remove the manager-owned partial state and let setup start again.
	if err := netlinkLinkDel(host); err != nil {
		return nil, true, fmt.Errorf("failed to clean up incomplete netkit host %s: %w", hostIfName, err)
	}
	return nil, false, nil
}

func validateOwnedNetkit(link netlink.Link, wantAlias string) error {
	if _, ok := link.(*netlink.Netkit); !ok || link.Attrs().Alias != wantAlias {
		return fmt.Errorf("%w: %s", errUnownedLink, link.Attrs().Name)
	}
	return nil
}

func (d *RXQueueDevice) createLease(
	physical netlink.Link,
	hostIfName, peerIfName string,
	physicalQueueIDs []uint32,
) (prepared *RXQueueDevice, err error) {
	netkit := &netlink.Netkit{
		LinkAttrs: netlink.LinkAttrs{
			Name:   hostIfName,
			MTU:    d.MTU,
			TxQLen: netkitTxQLen,
			Alias:  ownershipAlias(hostIfName),
		},
		Mode:       netlink.NETKIT_MODE_L2,
		Policy:     netlink.NETKIT_POLICY_FORWARD,
		PeerPolicy: netlink.NETKIT_POLICY_FORWARD,
	}
	netkit.SetPeerAttrs(&netlink.LinkAttrs{
		Name:        peerIfName,
		MTU:         d.MTU,
		NumRxQueues: netkitPeerRXQueues,
	})

	if err := netlinkLinkAdd(netkit); err != nil {
		return nil, fmt.Errorf("failed to create netkit pair %s/%s: %w", hostIfName, peerIfName, err)
	}

	host, err := netlinkLinkByName(hostIfName)
	if err != nil {
		_ = netlinkLinkDel(netkit)
		return nil, fmt.Errorf("failed to find created netkit host %s: %w", hostIfName, err)
	}

	cleanup := true
	defer func() {
		if !cleanup {
			return
		}
		if cleanupErr := netlinkLinkDel(host); cleanupErr != nil {
			err = errors.Join(err, fmt.Errorf("failed to clean up netkit host %s: %w", hostIfName, cleanupErr))
		}
	}()

	peer, err := netlinkLinkByName(peerIfName)
	if err != nil {
		return nil, fmt.Errorf("failed to find created netkit peer %s: %w", peerIfName, err)
	}
	if err := netlinkLinkSetAlias(host, ownershipAlias(hostIfName)); err != nil {
		return nil, fmt.Errorf("failed to mark netkit host %s as owned: %w", hostIfName, err)
	}
	if err := netlinkLinkSetAlias(peer, ownershipAlias(peerIfName)); err != nil {
		return nil, fmt.Errorf("failed to mark netkit peer %s as owned: %w", peerIfName, err)
	}
	if err := netlinkLinkSetUp(host); err != nil {
		return nil, fmt.Errorf("failed to bring netkit host %s up: %w", hostIfName, err)
	}

	for _, physicalQueueID := range physicalQueueIDs {
		queue, err := netlinkNetDevQueueGet(physical.Attrs().Index, physicalQueueID, netlink.NetDevQueueTypeRx)
		if err != nil {
			return nil, fmt.Errorf("failed to inspect reserved RX queue %s/%d: %w",
				d.PhysicalIfName, physicalQueueID, err)
		}
		if queue.Lease != nil {
			continue
		}

		virtualQueueID, err := netlinkNetDevQueueCreate(netlink.NetDevQueueCreateRequest{
			IfIndex: peer.Attrs().Index,
			Type:    netlink.NetDevQueueTypeRx,
			Lease: netlink.NetDevQueueLease{
				IfIndex: uint32(physical.Attrs().Index),
				Queue: netlink.NetDevQueueID{
					ID:   physicalQueueID,
					Type: netlink.NetDevQueueTypeRx,
				},
			},
		})
		if errors.Is(err, unix.EBUSY) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("failed to lease RX queue %s/%d: %w",
				d.PhysicalIfName, physicalQueueID, err)
		}

		queue, err = netlinkNetDevQueueGet(physical.Attrs().Index, physicalQueueID, netlink.NetDevQueueTypeRx)
		if err != nil {
			return nil, fmt.Errorf("failed to verify RX queue lease %s/%d: %w",
				d.PhysicalIfName, physicalQueueID, err)
		}
		if !leaseMatches(queue.Lease, peer.Attrs().Index) || queue.Lease.Queue.ID != virtualQueueID {
			return nil, fmt.Errorf("kernel returned an unexpected lease for RX queue %s/%d",
				d.PhysicalIfName, physicalQueueID)
		}

		cleanup = false
		return d.prepared(hostIfName, peerIfName, physicalQueueID, virtualQueueID), nil
	}

	return nil, fmt.Errorf("%w on %s", errNoAvailableRXQueue, d.PhysicalIfName)
}

func netlinkNetDevQueueGetByName(ifName string, queueID uint32) (*netlink.NetDevQueue, error) {
	link, err := netlinkLinkByName(ifName)
	if err != nil {
		return nil, fmt.Errorf("failed to find physical interface %s: %w", ifName, err)
	}
	queue, err := netlinkNetDevQueueGet(link.Attrs().Index, queueID, netlink.NetDevQueueTypeRx)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect RX queue %s/%d: %w", ifName, queueID, err)
	}
	return queue, nil
}

func leaseMatches(lease *netlink.NetDevQueueLease, peerIfIndex int) bool {
	return lease != nil &&
		lease.IfIndex == uint32(peerIfIndex) &&
		lease.Queue.Type == netlink.NetDevQueueTypeRx
}

func (d *RXQueueDevice) prepared(
	hostIfName, peerIfName string,
	physicalQueueID, virtualQueueID uint32,
) *RXQueueDevice {
	return &RXQueueDevice{
		PhysicalIfName:   d.PhysicalIfName,
		HardwareAddress:  d.HardwareAddress,
		MTU:              d.MTU,
		TotalRXQueues:    d.TotalRXQueues,
		ReservedQueueIDs: slices.Clone(d.ReservedQueueIDs),
		Prepared:         true,
		HostIfName:       hostIfName,
		PeerIfName:       peerIfName,
		PhysicalQueueID:  physicalQueueID,
		VirtualQueueID:   virtualQueueID,
	}
}

func (d *RXQueueDevice) Free(allocation types.DeviceAllocation) error {
	if !d.Prepared || d.HostIfName == "" {
		return nil
	}

	if err := validateAllocation(allocation); err != nil {
		return err
	}
	hostIfName, peerIfName := allocationIfNames(d.PhysicalIfName, allocation.ShareID)
	if d.HostIfName != hostIfName || d.PeerIfName != peerIfName {
		return fmt.Errorf("%w: stored netkit names do not match share ID", errInvalidAllocation)
	}

	host, err := netlinkLinkByName(d.HostIfName)
	if err != nil {
		if errors.As(err, &netlink.LinkNotFoundError{}) {
			return nil
		}
		return fmt.Errorf("failed to find netkit host %s: %w", d.HostIfName, err)
	}
	if err := validateOwnedNetkit(host, ownershipAlias(d.HostIfName)); err != nil {
		return err
	}
	if err := netlinkLinkDel(host); err != nil {
		return fmt.Errorf("failed to delete netkit host %s: %w", d.HostIfName, err)
	}
	return nil
}

func (d *RXQueueDevice) Match(filter v2alpha1.CiliumNetworkDriverDeviceFilter) bool {
	if len(filter.DeviceManagers) != 0 &&
		!slices.Contains(filter.DeviceManagers, types.DeviceManagerTypeRXQueue.String()) {
		return false
	}
	if len(filter.IfNames) != 0 && !slices.Contains(filter.IfNames, d.PhysicalIfName) {
		return false
	}

	return len(filter.PFNames) == 0 &&
		len(filter.ParentIfNames) == 0 &&
		len(filter.PCIAddrs) == 0 &&
		len(filter.VendorIDs) == 0 &&
		len(filter.DeviceIDs) == 0 &&
		len(filter.Drivers) == 0
}

func (d *RXQueueDevice) IfName() string {
	if d.Prepared {
		return d.PeerIfName
	}
	return d.PhysicalIfName
}

func (d *RXQueueDevice) KernelIfName() string {
	return d.IfName()
}

// Merge is a no-op because RX queue inventory is derived entirely from the
// current physical interface. Allocation-specific state lives separately.
func (d *RXQueueDevice) Merge(_ types.Device) {}

type deviceState struct {
	PhysicalIfName   string   `json:"physicalIfName"`
	HardwareAddress  string   `json:"hardwareAddress,omitempty"`
	MTU              int      `json:"mtu,omitempty"`
	TotalRXQueues    int      `json:"totalRXQueues"`
	ReservedQueueIDs []uint32 `json:"reservedQueueIDs"`
	Prepared         bool     `json:"prepared,omitempty"`
	HostIfName       string   `json:"hostIfName,omitempty"`
	PeerIfName       string   `json:"peerIfName,omitempty"`
	PhysicalQueueID  uint32   `json:"physicalQueueID,omitempty"`
	VirtualQueueID   uint32   `json:"virtualQueueID,omitempty"`
}

func (d *RXQueueDevice) MarshalBinary() ([]byte, error) {
	return json.Marshal(deviceState{
		PhysicalIfName:   d.PhysicalIfName,
		HardwareAddress:  d.HardwareAddress,
		MTU:              d.MTU,
		TotalRXQueues:    d.TotalRXQueues,
		ReservedQueueIDs: d.ReservedQueueIDs,
		Prepared:         d.Prepared,
		HostIfName:       d.HostIfName,
		PeerIfName:       d.PeerIfName,
		PhysicalQueueID:  d.PhysicalQueueID,
		VirtualQueueID:   d.VirtualQueueID,
	})
}

func (d *RXQueueDevice) UnmarshalBinary(data []byte) error {
	var state deviceState
	if err := json.Unmarshal(data, &state); err != nil {
		return err
	}
	if state.PhysicalIfName == "" {
		return errors.New("RX queue device is missing its physical interface name")
	}
	if len(state.ReservedQueueIDs) == 0 {
		return errors.New("RX queue device has no reserved queues")
	}
	if state.Prepared && (state.HostIfName == "" || state.PeerIfName == "") {
		return errors.New("prepared RX queue device is missing its netkit interface names")
	}

	d.PhysicalIfName = state.PhysicalIfName
	d.HardwareAddress = state.HardwareAddress
	d.MTU = state.MTU
	d.TotalRXQueues = state.TotalRXQueues
	d.ReservedQueueIDs = slices.Clone(state.ReservedQueueIDs)
	d.Prepared = state.Prepared
	d.HostIfName = state.HostIfName
	d.PeerIfName = state.PeerIfName
	d.PhysicalQueueID = state.PhysicalQueueID
	d.VirtualQueueID = state.VirtualQueueID
	return nil
}

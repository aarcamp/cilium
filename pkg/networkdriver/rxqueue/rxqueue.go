// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package rxqueue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strings"
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
	mainRSSContext          = 0
	firstLeasedRXQueueID    = 1
	hardwareGROFeature      = "rx-gro-hw"

	ownershipPrefix = "cilium-zcrx:"
)

var (
	errNoInterfaces         = errors.New("no RX queue interfaces configured")
	errDuplicateInterface   = errors.New("duplicate RX queue interface")
	errInsufficientRXQueues = errors.New("insufficient RX queues")
	errNoAvailableRXQueue   = errors.New("no reserved RX queue is available")
	errInvalidAllocation    = errors.New("invalid RX queue allocation")
	errUnownedLink          = errors.New("refusing to use link not owned by the RX queue manager")
	errActiveLease          = errors.New("RX queue lease is still active")

	netlinkLinkByName         = safenetlink.LinkByName
	netlinkLinkSetAlias       = netlink.LinkSetAlias
	netlinkNetDevQueueGet     = netlink.NetDevQueueGet
	netlinkNetDevRSSGet       = netlink.NetDevRSSGet
	netlinkNetDevRSSSet       = netlink.NetDevRSSSet
	netlinkNetDevRingsGet     = netlink.NetDevRingsGet
	netlinkNetDevRingsSet     = netlink.NetDevRingsSet
	netlinkNetDevFeaturesGet  = netlink.NetDevFeaturesGet
	netlinkNetDevFeaturesSet  = netlink.NetDevFeaturesSet
	netlinkNetDevRxFlowInsert = netlink.NetDevRxFlowInsert
	netlinkNetDevRxFlowDelete = netlink.NetDevRxFlowDelete
	netlinkNetDevRxFlowList   = netlink.NetDevRxFlowList
)

type RXQueueManager struct {
	devices      []*RXQueueDevice
	reservations map[string]*queueReservations
	mu           sync.Mutex
}

func NewManager(logger *slog.Logger, cfg *v2alpha1.RXQueueDeviceManagerConfig) (*RXQueueManager, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	mgr := &RXQueueManager{reservations: make(map[string]*queueReservations)}
	var programmed []*rxQueueNICState
	for _, iface := range cfg.Ifaces {
		count := iface.Count
		if count == 0 {
			count = defaultReservedRXQueues
		}

		dev, err := discoverDevice(iface.IfName, count)
		if err != nil {
			return nil, rollbackRXQueueNICs(programmed, err)
		}
		dev.reservations = mgr.reservationsFor(dev.PhysicalIfName)
		state, err := prepareRXQueueNIC(dev)
		if err != nil {
			return nil, rollbackRXQueueNICs(programmed, err)
		}
		programmed = append(programmed, state)
		mgr.devices = append(mgr.devices, dev)

		logger.Debug("prepared RX queues for leasing",
			"device", iface.IfName,
			"activeRXQueues", dev.TotalRXQueues,
			"reservedRXQueues", dev.ReservedQueueIDs,
			"rssUpdated", state.rssChanged,
			"tcpDataSplitUpdated", state.ringsChanged,
			"hardwareGROUpdated", state.hardwareGROChanged,
		)
	}

	return mgr, nil
}

type rxQueueNICState struct {
	ifName               string
	ifIndex              int
	originalRSS          *netlink.NetDevRSS
	originalRings        netlink.NetDevRings
	originalHardwareGRO  netlink.NetDevFeature
	hardwareGROInspected bool
	rssChanged           bool
	ringsChanged         bool
	hardwareGROChanged   bool
}

func prepareRXQueueNIC(dev *RXQueueDevice) (_ *rxQueueNICState, retErr error) {
	link, err := netlinkLinkByName(dev.PhysicalIfName)
	if err != nil {
		return nil, fmt.Errorf("failed to find RX queue interface %s: %w", dev.PhysicalIfName, err)
	}

	rss, err := netlinkNetDevRSSGet(link.Attrs().Index, mainRSSContext)
	if err != nil {
		return nil, fmt.Errorf("failed to read RSS configuration on %s: %w", dev.PhysicalIfName, err)
	}
	if rss == nil {
		return nil, fmt.Errorf("failed to read RSS configuration on %s: empty response", dev.PhysicalIfName)
	}
	desiredTable, err := rssTableWithoutReservedQueues(rss.IndirectionTable, dev.TotalRXQueues, dev.ReservedQueueIDs)
	if err != nil {
		return nil, fmt.Errorf("invalid RSS configuration on %s: %w", dev.PhysicalIfName, err)
	}

	rings, err := netlinkNetDevRingsGet(link.Attrs().Index)
	if err != nil {
		return nil, fmt.Errorf("failed to read ring configuration on %s: %w", dev.PhysicalIfName, err)
	}
	if rings == nil {
		return nil, fmt.Errorf("failed to read ring configuration on %s: empty response", dev.PhysicalIfName)
	}

	state := &rxQueueNICState{
		ifName:        dev.PhysicalIfName,
		ifIndex:       link.Attrs().Index,
		originalRSS:   cloneNetDevRSS(rss),
		originalRings: *rings,
	}
	defer func() {
		if retErr == nil {
			return
		}
		if err := state.restore(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("failed to roll back NIC configuration on %s: %w", state.ifName, err))
		}
	}()

	requiresHardwareGRO := rings.TCPDataSplit == netlink.NetDevTCPDataSplitUnknown
	if requiresHardwareGRO {
		if err := state.inspectHardwareGRO(); err != nil {
			return nil, err
		}
	}

	expectedRSS := cloneNetDevRSS(rss)
	expectedRSS.IndirectionTable = desiredTable
	if !slices.Equal(rss.IndirectionTable, desiredTable) {
		if err := netlinkNetDevRSSSet(state.ifIndex, mainRSSContext, netlink.NetDevRSSConfig{IndirectionTable: desiredTable}); err != nil {
			return nil, fmt.Errorf("failed to exclude reserved queues from RSS on %s: %w", state.ifName, err)
		}
		state.rssChanged = true
	}

	if requiresHardwareGRO {
		if err := state.enableHardwareGRO(); err != nil {
			return nil, err
		}
	}

	expectedRings := *rings
	expectedRings.TCPDataSplit = netlink.NetDevTCPDataSplitEnabled
	expectedRings.HDSThreshold = 0
	if rings.TCPDataSplit != expectedRings.TCPDataSplit || rings.HDSThreshold != expectedRings.HDSThreshold {
		config := netlink.NetDevRingsConfig{
			TCPDataSplit: &expectedRings.TCPDataSplit,
			HDSThreshold: &expectedRings.HDSThreshold,
		}
		err := netlinkNetDevRingsSet(state.ifIndex, config)
		if err != nil && !requiresHardwareGRO {
			// mlx5 advertises the generic TCP data split ring setting, but
			// rejects enabling it until rx-gro-hw is active. Negotiate that
			// dependency only after the generic operation fails so other
			// drivers are not forced to enable hardware GRO.
			if featureErr := state.enableHardwareGRO(); featureErr == nil {
				requiresHardwareGRO = true
				err = netlinkNetDevRingsSet(state.ifIndex, config)
			} else {
				err = errors.Join(err, featureErr)
			}
		}
		if err != nil {
			return nil, fmt.Errorf("failed to enable TCP data splitting on %s: %w", state.ifName, err)
		}
		state.ringsChanged = true
	}

	if err := verifyRXQueueNIC(state.ifName, state.ifIndex, expectedRSS, &expectedRings, requiresHardwareGRO); err != nil {
		return nil, err
	}

	return state, nil
}

func (s *rxQueueNICState) inspectHardwareGRO() error {
	features, err := netlinkNetDevFeaturesGet(s.ifIndex)
	if err != nil {
		return fmt.Errorf("failed to read features on %s: %w", s.ifName, err)
	}
	hardwareGRO, ok := features[hardwareGROFeature]
	if !ok || !hardwareGRO.Hardware || (!hardwareGRO.Active && (hardwareGRO.NoChange || hardwareGRO.Wanted)) {
		return fmt.Errorf("TCP data splitting is not supported on %s: %w", s.ifName, unix.EOPNOTSUPP)
	}
	s.originalHardwareGRO = hardwareGRO
	s.hardwareGROInspected = true
	return nil
}

func (s *rxQueueNICState) enableHardwareGRO() error {
	if !s.hardwareGROInspected {
		if err := s.inspectHardwareGRO(); err != nil {
			return err
		}
	}
	if s.originalHardwareGRO.Active {
		return nil
	}
	if err := netlinkNetDevFeaturesSet(s.ifIndex, map[string]bool{hardwareGROFeature: true}); err != nil {
		return fmt.Errorf("failed to enable hardware GRO on %s: %w", s.ifName, err)
	}
	s.hardwareGROChanged = true
	return nil
}

func rssTableWithoutReservedQueues(table []uint32, total int, reserved []uint32) ([]uint32, error) {
	if len(table) == 0 {
		return nil, errors.New("RSS indirection table is empty")
	}
	if total <= 0 {
		return nil, errors.New("no active RX queues")
	}

	reservedSet := make(map[uint32]struct{}, len(reserved))
	for _, queueID := range reserved {
		if uint64(queueID) >= uint64(total) {
			return nil, fmt.Errorf("reserved queue %d exceeds the %d active RX queues", queueID, total)
		}
		if _, exists := reservedSet[queueID]; exists {
			return nil, fmt.Errorf("reserved queue %d is duplicated", queueID)
		}
		reservedSet[queueID] = struct{}{}
	}

	allowed := make([]uint32, 0, total-len(reservedSet))
	counts := make([]int, total)
	for queueID := 0; queueID < total; queueID++ {
		if _, reserved := reservedSet[uint32(queueID)]; !reserved {
			allowed = append(allowed, uint32(queueID))
		}
	}
	if len(allowed) == 0 {
		return nil, errors.New("no RX queue remains available for RSS")
	}

	result := slices.Clone(table)
	for _, queueID := range table {
		if uint64(queueID) >= uint64(total) {
			return nil, fmt.Errorf("indirection table references queue %d, but only %d RX queues are active", queueID, total)
		}
		if _, reserved := reservedSet[queueID]; !reserved {
			counts[queueID]++
		}
	}

	// Keep queues excluded by the existing RSS policy excluded.
	candidates := make([]uint32, 0, len(allowed))
	for _, queueID := range allowed {
		if counts[queueID] != 0 {
			candidates = append(candidates, queueID)
		}
	}
	if len(candidates) == 0 {
		candidates = allowed
	}

	for i, queueID := range result {
		if _, reserved := reservedSet[queueID]; !reserved {
			continue
		}

		replacement := candidates[0]
		for _, candidate := range candidates[1:] {
			if counts[candidate] < counts[replacement] {
				replacement = candidate
			}
		}
		result[i] = replacement
		counts[replacement]++
	}

	return result, nil
}

func cloneNetDevRSS(rss *netlink.NetDevRSS) *netlink.NetDevRSS {
	if rss == nil {
		return nil
	}
	clone := *rss
	clone.IndirectionTable = slices.Clone(rss.IndirectionTable)
	clone.HashKey = slices.Clone(rss.HashKey)
	return &clone
}

func equalNetDevRSS(a, b *netlink.NetDevRSS) bool {
	return a != nil && b != nil &&
		a.Context == b.Context &&
		a.HashFunction == b.HashFunction &&
		slices.Equal(a.IndirectionTable, b.IndirectionTable) &&
		slices.Equal(a.HashKey, b.HashKey) &&
		a.InputTransformation == b.InputTransformation
}

func verifyRXQueueNIC(ifName string, ifIndex int, wantRSS *netlink.NetDevRSS, wantRings *netlink.NetDevRings, requiresHardwareGRO bool) error {
	rss, err := netlinkNetDevRSSGet(ifIndex, mainRSSContext)
	if err != nil {
		return fmt.Errorf("failed to verify RSS configuration on %s: %w", ifName, err)
	}
	if !equalNetDevRSS(rss, wantRSS) {
		return fmt.Errorf("RSS configuration read back incorrectly on %s", ifName)
	}

	rings, err := netlinkNetDevRingsGet(ifIndex)
	if err != nil {
		return fmt.Errorf("failed to verify ring configuration on %s: %w", ifName, err)
	}
	if rings == nil || *rings != *wantRings {
		return fmt.Errorf("ring configuration read back incorrectly on %s", ifName)
	}

	if requiresHardwareGRO {
		features, err := netlinkNetDevFeaturesGet(ifIndex)
		if err != nil {
			return fmt.Errorf("failed to verify hardware GRO on %s: %w", ifName, err)
		}
		feature, ok := features[hardwareGROFeature]
		if !ok || !feature.Active {
			return fmt.Errorf("hardware GRO read back incorrectly on %s", ifName)
		}
	}

	return nil
}

func (s *rxQueueNICState) restore() error {
	var errs []error
	if s.ringsChanged {
		if err := netlinkNetDevRingsSet(s.ifIndex, netlink.NetDevRingsConfig{
			TCPDataSplit: &s.originalRings.TCPDataSplit,
			HDSThreshold: &s.originalRings.HDSThreshold,
		}); err != nil {
			errs = append(errs, fmt.Errorf("restore ring configuration: %w", err))
		} else {
			rings, err := netlinkNetDevRingsGet(s.ifIndex)
			if err != nil {
				errs = append(errs, fmt.Errorf("verify restored ring configuration: %w", err))
			} else if rings == nil || *rings != s.originalRings {
				errs = append(errs, errors.New("restored ring configuration did not match its original state"))
			}
		}
	}
	if s.hardwareGROChanged {
		if err := netlinkNetDevFeaturesSet(s.ifIndex, map[string]bool{hardwareGROFeature: s.originalHardwareGRO.Wanted}); err != nil {
			errs = append(errs, fmt.Errorf("restore hardware GRO: %w", err))
		} else {
			features, err := netlinkNetDevFeaturesGet(s.ifIndex)
			if err != nil {
				errs = append(errs, fmt.Errorf("verify restored hardware GRO: %w", err))
			} else if feature, ok := features[hardwareGROFeature]; !ok || feature != s.originalHardwareGRO {
				errs = append(errs, errors.New("restored hardware GRO did not match its original state"))
			}
		}
	}
	if s.rssChanged {
		if err := netlinkNetDevRSSSet(s.ifIndex, mainRSSContext, netlink.NetDevRSSConfig{IndirectionTable: s.originalRSS.IndirectionTable}); err != nil {
			errs = append(errs, fmt.Errorf("restore RSS configuration: %w", err))
		} else {
			rss, err := netlinkNetDevRSSGet(s.ifIndex, mainRSSContext)
			if err != nil {
				errs = append(errs, fmt.Errorf("verify restored RSS configuration: %w", err))
			} else if !equalNetDevRSS(rss, s.originalRSS) {
				errs = append(errs, errors.New("restored RSS configuration did not match its original state"))
			}
		}
	}
	return errors.Join(errs...)
}

func rollbackRXQueueNICs(states []*rxQueueNICState, cause error) error {
	for i := len(states) - 1; i >= 0; i-- {
		if err := states[i].restore(); err != nil {
			cause = errors.Join(cause, fmt.Errorf("failed to roll back NIC configuration on %s: %w", states[i].ifName, err))
		}
	}
	return cause
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
	dev.reservations = m.reservationsFor(dev.PhysicalIfName)
	if err := dev.restoreReservation(); err != nil {
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

	Prepared          bool           `json:"prepared,omitempty"`
	Bound             bool           `json:"bound,omitempty"`
	ShareID           kube_types.UID `json:"shareID,omitempty"`
	PodIfName         string         `json:"podIfName,omitempty"`
	HostIfName        string         `json:"hostIfName,omitempty"`
	OriginalHostAlias string         `json:"originalHostAlias,omitempty"`
	PhysicalQueueID   uint32         `json:"physicalQueueID,omitempty"`
	VirtualQueueID    uint32         `json:"virtualQueueID,omitempty"`
	rxFlows           []rxFlowState
	reservations      *queueReservations

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

	return d.reserve(allocation, d.ReservedQueueIDs)
}

func (d *RXQueueDevice) Recover(allocation types.DeviceAllocation) (types.Device, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.Prepared || d.ShareID != allocation.ShareID {
		return nil, fmt.Errorf("%w: stored RX queue state does not match allocation", errInvalidAllocation)
	}
	podIfName := allocation.Config.PodIfName
	if podIfName == "" {
		podIfName = types.DefaultRXQueuePodIfName
	}
	if d.PodIfName != podIfName {
		return nil, fmt.Errorf("%w: stored RX queue state does not match allocation", errInvalidAllocation)
	}
	if err := validateAllocation(allocation); err != nil {
		return nil, err
	}
	if !slices.Contains(d.ReservedQueueIDs, d.PhysicalQueueID) {
		return nil, fmt.Errorf("%w: stored RX queue %d is not reserved", errInvalidAllocation, d.PhysicalQueueID)
	}
	if err := d.restoreReservation(); err != nil {
		return nil, err
	}
	return d.clone(), nil
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

func ownershipAlias(ifName string) string {
	return ownershipPrefix + ifName
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

func leaseMatches(lease *netlink.NetDevQueueLease, peerIfIndex int, peerNetNSID int32) bool {
	return lease != nil &&
		lease.IfIndex == uint32(peerIfIndex) &&
		lease.Queue.Type == netlink.NetDevQueueTypeRx &&
		lease.NetNSIDSet &&
		lease.NetNSID == peerNetNSID
}

func (d *RXQueueDevice) Free(allocation types.DeviceAllocation) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.Prepared {
		return nil
	}
	if err := validateAllocation(allocation); err != nil {
		return err
	}
	if d.ShareID != allocation.ShareID {
		return fmt.Errorf("%w: stored RX queue state does not match allocation", errInvalidAllocation)
	}

	queue, err := netlinkNetDevQueueGetByName(d.PhysicalIfName, d.PhysicalQueueID)
	if err != nil {
		return err
	}
	if queue.Lease != nil {
		return fmt.Errorf("%w: %s/%d", errActiveLease, d.PhysicalIfName, d.PhysicalQueueID)
	}

	locations := ownershipFromFlowStates(d.rxFlows).locations
	var host netlink.Link
	if d.HostIfName != "" {
		host, err = netlinkLinkByName(d.HostIfName)
		if err != nil && !errors.As(err, &netlink.LinkNotFoundError{}) {
			return fmt.Errorf("failed to find Pod netkit host %s: %w", d.HostIfName, err)
		}
		if err == nil {
			ownership, ownershipErr := ownedRXFlows(host, string(d.ShareID), d.OriginalHostAlias)
			if ownershipErr != nil {
				return ownershipErr
			}
			locations = ownership.locations
		}
	}
	if err := deleteRXFlows(d.PhysicalIfName, locations); err != nil {
		return fmt.Errorf("failed to delete RX flow rules for %s: %w", d.PhysicalIfName, err)
	}
	if host != nil && strings.HasPrefix(host.Attrs().Alias, ownershipAlias(string(d.ShareID))) {
		if err := netlinkLinkSetAlias(host, d.OriginalHostAlias); err != nil {
			return fmt.Errorf("failed to restore alias on Pod netkit host %s: %w", d.HostIfName, err)
		}
	}
	d.releaseReservation()
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
		return d.PodIfName
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
	PhysicalIfName    string         `json:"physicalIfName"`
	HardwareAddress   string         `json:"hardwareAddress,omitempty"`
	MTU               int            `json:"mtu,omitempty"`
	TotalRXQueues     int            `json:"totalRXQueues"`
	ReservedQueueIDs  []uint32       `json:"reservedQueueIDs"`
	Prepared          bool           `json:"prepared,omitempty"`
	Bound             bool           `json:"bound,omitempty"`
	ShareID           kube_types.UID `json:"shareID,omitempty"`
	PodIfName         string         `json:"podIfName,omitempty"`
	HostIfName        string         `json:"hostIfName,omitempty"`
	OriginalHostAlias string         `json:"originalHostAlias,omitempty"`
	PhysicalQueueID   uint32         `json:"physicalQueueID,omitempty"`
	VirtualQueueID    uint32         `json:"virtualQueueID,omitempty"`
	RXFlows           []rxFlowState  `json:"rxFlows,omitempty"`
}

func (d *RXQueueDevice) MarshalBinary() ([]byte, error) {
	return json.Marshal(deviceState{
		PhysicalIfName:    d.PhysicalIfName,
		HardwareAddress:   d.HardwareAddress,
		MTU:               d.MTU,
		TotalRXQueues:     d.TotalRXQueues,
		ReservedQueueIDs:  d.ReservedQueueIDs,
		Prepared:          d.Prepared,
		Bound:             d.Bound,
		ShareID:           d.ShareID,
		PodIfName:         d.PodIfName,
		HostIfName:        d.HostIfName,
		OriginalHostAlias: d.OriginalHostAlias,
		PhysicalQueueID:   d.PhysicalQueueID,
		VirtualQueueID:    d.VirtualQueueID,
		RXFlows:           slices.Clone(d.rxFlows),
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
	if state.Prepared && (state.ShareID == "" || state.PodIfName == "") {
		return errors.New("prepared RX queue device is missing its allocation identity")
	}
	if state.Bound && (!state.Prepared || state.HostIfName == "") {
		return errors.New("bound RX queue device is missing its Pod netkit host name")
	}
	if !state.Bound && len(state.RXFlows) != 0 {
		return errors.New("unbound RX queue device contains RX flow rules")
	}
	if !state.Prepared && len(state.RXFlows) != 0 {
		return errors.New("unprepared RX queue device contains RX flow rules")
	}
	if len(state.RXFlows) != 0 {
		flows := make([]types.RXQueueFlow, 0, len(state.RXFlows))
		locations := make(map[uint32]struct{}, len(state.RXFlows))
		for _, flow := range state.RXFlows {
			if flow.Location >= netlink.RX_CLS_LOC_LAST {
				return fmt.Errorf("RX flow location %d is invalid", flow.Location)
			}
			if _, exists := locations[flow.Location]; exists {
				return fmt.Errorf("RX flow location %d is duplicated", flow.Location)
			}
			locations[flow.Location] = struct{}{}
			flows = append(flows, flow.Flow)
		}
		normalized, err := normalizeRXFlows(flows)
		if err != nil {
			return err
		}
		if !slices.Equal(normalized, flows) {
			return errors.New("RX flow rules are not in canonical order")
		}
	}

	d.PhysicalIfName = state.PhysicalIfName
	d.HardwareAddress = state.HardwareAddress
	d.MTU = state.MTU
	d.TotalRXQueues = state.TotalRXQueues
	d.ReservedQueueIDs = slices.Clone(state.ReservedQueueIDs)
	d.Prepared = state.Prepared
	d.Bound = state.Bound
	d.ShareID = state.ShareID
	d.PodIfName = state.PodIfName
	d.HostIfName = state.HostIfName
	d.OriginalHostAlias = state.OriginalHostAlias
	d.PhysicalQueueID = state.PhysicalQueueID
	d.VirtualQueueID = state.VirtualQueueID
	d.rxFlows = slices.Clone(state.RXFlows)
	return nil
}

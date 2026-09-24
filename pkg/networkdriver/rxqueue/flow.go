// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package rxqueue

import (
	"cmp"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"

	"github.com/cilium/cilium/pkg/networkdriver/types"
)

const rxFlowAliasTag = ":flows:"

type rxFlowState struct {
	Flow     types.RXQueueFlow `json:"flow"`
	Location uint32            `json:"location"`
}

type rxFlowOwnership struct {
	digest    string
	locations []uint32
}

func normalizeRXFlows(flows []types.RXQueueFlow) ([]types.RXQueueFlow, error) {
	normalized := make([]types.RXQueueFlow, 0, len(flows))
	seen := make(map[types.RXQueueFlow]struct{}, len(flows))
	for _, flow := range flows {
		flow.DestinationIP = flow.DestinationIP.Unmap()
		if !flow.DestinationIP.IsValid() || !flow.DestinationIP.IsGlobalUnicast() {
			return nil, fmt.Errorf("%w: invalid RX flow destination IP %q",
				errInvalidAllocation, flow.DestinationIP)
		}
		if flow.DestinationPort == 0 {
			return nil, fmt.Errorf("%w: RX flow destination port must be between 1 and 65535",
				errInvalidAllocation)
		}
		switch flow.Protocol {
		case corev1.ProtocolTCP, corev1.ProtocolUDP:
		default:
			return nil, fmt.Errorf("%w: RX flow protocol must be TCP or UDP, got %q",
				errInvalidAllocation, flow.Protocol)
		}
		if _, exists := seen[flow]; exists {
			continue
		}
		seen[flow] = struct{}{}
		normalized = append(normalized, flow)
	}

	slices.SortFunc(normalized, func(a, b types.RXQueueFlow) int {
		if n := a.DestinationIP.Compare(b.DestinationIP); n != 0 {
			return n
		}
		if n := cmp.Compare(a.DestinationPort, b.DestinationPort); n != 0 {
			return n
		}
		return cmp.Compare(a.Protocol, b.Protocol)
	})
	return normalized, nil
}

func rxFlowMatch(flow types.RXQueueFlow) (netlink.NetDevRxFlowMatch, error) {
	mask := net.IP(net.CIDRMask(flow.DestinationIP.BitLen(), flow.DestinationIP.BitLen()))
	switch {
	case flow.DestinationIP.Is4() && flow.Protocol == corev1.ProtocolTCP:
		return netlink.TCP4Flow{TCPIP4Fields: netlink.TCPIP4Fields{
			DstIP:       net.IP(flow.DestinationIP.AsSlice()),
			DstIPMask:   mask,
			DstPort:     flow.DestinationPort,
			DstPortMask: ^uint16(0),
		}}, nil
	case flow.DestinationIP.Is4() && flow.Protocol == corev1.ProtocolUDP:
		return netlink.UDP4Flow{TCPIP4Fields: netlink.TCPIP4Fields{
			DstIP:       net.IP(flow.DestinationIP.AsSlice()),
			DstIPMask:   mask,
			DstPort:     flow.DestinationPort,
			DstPortMask: ^uint16(0),
		}}, nil
	case flow.DestinationIP.Is6() && flow.Protocol == corev1.ProtocolTCP:
		return netlink.TCP6Flow{TCPIP6Fields: netlink.TCPIP6Fields{
			DstIP:       net.IP(flow.DestinationIP.AsSlice()),
			DstIPMask:   mask,
			DstPort:     flow.DestinationPort,
			DstPortMask: ^uint16(0),
		}}, nil
	case flow.DestinationIP.Is6() && flow.Protocol == corev1.ProtocolUDP:
		return netlink.UDP6Flow{TCPIP6Fields: netlink.TCPIP6Fields{
			DstIP:       net.IP(flow.DestinationIP.AsSlice()),
			DstIPMask:   mask,
			DstPort:     flow.DestinationPort,
			DstPortMask: ^uint16(0),
		}}, nil
	default:
		return nil, fmt.Errorf("%w: unsupported RX flow %s/%s",
			errInvalidAllocation, flow.DestinationIP, flow.Protocol)
	}
}

func rxFlowDigest(flows []types.RXQueueFlow) string {
	hash := sha256.New()
	var port [2]byte
	for _, flow := range flows {
		if flow.DestinationIP.Is4() {
			_, _ = hash.Write([]byte{4})
		} else {
			_, _ = hash.Write([]byte{6})
		}
		_, _ = hash.Write(flow.DestinationIP.AsSlice())
		binary.BigEndian.PutUint16(port[:], flow.DestinationPort)
		_, _ = hash.Write(port[:])
		_, _ = hash.Write([]byte(flow.Protocol))
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func rxFlowOwnershipAlias(ifName string, ownership rxFlowOwnership) string {
	locations := make([]string, 0, len(ownership.locations))
	for _, location := range ownership.locations {
		locations = append(locations, strconv.FormatUint(uint64(location), 10))
	}
	return ownershipAlias(ifName) + rxFlowAliasTag + ownership.digest + ":" + strings.Join(locations, ",")
}

func ownedRXFlows(link netlink.Link, ifName string) (rxFlowOwnership, error) {
	if _, ok := link.(*netlink.Netkit); !ok {
		return rxFlowOwnership{}, fmt.Errorf("%w: %s", errUnownedLink, link.Attrs().Name)
	}

	base := ownershipAlias(ifName)
	if link.Attrs().Alias == base {
		return rxFlowOwnership{}, nil
	}

	suffix, found := strings.CutPrefix(link.Attrs().Alias, base+rxFlowAliasTag)
	if !found {
		return rxFlowOwnership{}, fmt.Errorf("%w: %s", errUnownedLink, link.Attrs().Name)
	}
	digest, locationList, found := strings.Cut(suffix, ":")
	if !found || len(digest) != sha256.Size*2 {
		return rxFlowOwnership{}, fmt.Errorf("%w: %s", errUnownedLink, link.Attrs().Name)
	}
	decoded, err := hex.DecodeString(digest)
	if err != nil || hex.EncodeToString(decoded) != digest || locationList == "" {
		return rxFlowOwnership{}, fmt.Errorf("%w: %s", errUnownedLink, link.Attrs().Name)
	}

	values := strings.Split(locationList, ",")
	locations := make([]uint32, 0, len(values))
	seen := make(map[uint32]struct{}, len(values))
	for _, value := range values {
		location, err := strconv.ParseUint(value, 10, 32)
		if err != nil || strconv.FormatUint(location, 10) != value {
			return rxFlowOwnership{}, fmt.Errorf("%w: %s", errUnownedLink, link.Attrs().Name)
		}
		location32 := uint32(location)
		if location32 >= netlink.RX_CLS_LOC_LAST {
			return rxFlowOwnership{}, fmt.Errorf("%w: %s", errUnownedLink, link.Attrs().Name)
		}
		if _, exists := seen[location32]; exists {
			return rxFlowOwnership{}, fmt.Errorf("%w: %s", errUnownedLink, link.Attrs().Name)
		}
		seen[location32] = struct{}{}
		locations = append(locations, location32)
	}
	return rxFlowOwnership{digest: digest, locations: locations}, nil
}

func ownershipFromFlowStates(flows []rxFlowState) rxFlowOwnership {
	if len(flows) == 0 {
		return rxFlowOwnership{}
	}
	targets := make([]types.RXQueueFlow, 0, len(flows))
	locations := make([]uint32, 0, len(flows))
	for _, flow := range flows {
		targets = append(targets, flow.Flow)
		locations = append(locations, flow.Location)
	}
	return rxFlowOwnership{digest: rxFlowDigest(targets), locations: locations}
}

func (d *RXQueueDevice) SetRXQueueFlows(flows []types.RXQueueFlow) (types.Device, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.Prepared || d.HostIfName == "" {
		return nil, fmt.Errorf("%w: RX flows require a prepared queue", errInvalidAllocation)
	}
	desired, err := normalizeRXFlows(flows)
	if err != nil {
		return nil, err
	}

	host, err := netlinkLinkByName(d.HostIfName)
	if err != nil {
		return nil, fmt.Errorf("failed to find netkit host %s: %w", d.HostIfName, err)
	}
	ownership, err := ownedRXFlows(host, d.HostIfName)
	if err != nil {
		return nil, err
	}

	states, err := d.reconcileRXFlows(host, desired, ownership)
	if err != nil {
		return nil, err
	}

	updated := d.prepared(
		d.HostIfName,
		d.PeerIfName,
		d.PhysicalQueueID,
		d.VirtualQueueID,
	)
	updated.rxFlows = slices.Clone(states)
	return updated, nil
}

func (d *RXQueueDevice) reconcileRXFlows(
	host netlink.Link,
	desired []types.RXQueueFlow,
	ownership rxFlowOwnership,
) (_ []rxFlowState, retErr error) {
	if len(desired) == 0 {
		if err := deleteRXFlows(d.PhysicalIfName, ownership.locations); err != nil {
			return nil, err
		}
		if err := netlinkLinkSetAlias(host, ownershipAlias(d.HostIfName)); err != nil {
			return nil, fmt.Errorf("failed to clear RX flow ownership on netkit host %s: %w",
				d.HostIfName, err)
		}
		return nil, nil
	}

	digest := rxFlowDigest(desired)
	originalAlias := host.Attrs().Alias
	if len(ownership.locations) != 0 && ownership.digest != digest {
		if err := deleteRXFlows(d.PhysicalIfName, ownership.locations); err != nil {
			return nil, fmt.Errorf("failed to replace RX flow rules on %s: %w", d.PhysicalIfName, err)
		}
		if err := netlinkLinkSetAlias(host, ownershipAlias(d.HostIfName)); err != nil {
			return nil, fmt.Errorf("failed to clear replaced RX flow ownership on netkit host %s: %w",
				d.HostIfName, err)
		}
		ownership = rxFlowOwnership{}
		originalAlias = ownershipAlias(d.HostIfName)
	}
	if len(ownership.locations) > len(desired) {
		return nil, fmt.Errorf("%w: netkit host %s records %d RX flow rules for %d targets",
			errInvalidAllocation, d.HostIfName, len(ownership.locations), len(desired))
	}

	var inserted []uint32
	defer func() {
		if retErr == nil {
			return
		}
		for i := len(inserted) - 1; i >= 0; i-- {
			if err := deleteRXFlowIfExists(d.PhysicalIfName, inserted[i]); err != nil {
				retErr = errors.Join(retErr, fmt.Errorf("failed to roll back RX flow rule %s/%d: %w",
					d.PhysicalIfName, inserted[i], err))
			}
		}
		if err := netlinkLinkSetAlias(host, originalAlias); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("failed to restore RX flow ownership on netkit host %s: %w",
				d.HostIfName, err))
		}
	}()

	locations, err := netlinkNetDevRxFlowList(d.PhysicalIfName)
	if err != nil {
		return nil, fmt.Errorf("failed to list RX flow rules on %s: %w", d.PhysicalIfName, err)
	}

	for i, target := range desired {
		if i < len(ownership.locations) && slices.Contains(locations, ownership.locations[i]) {
			continue
		}

		requestedLocation := uint32(netlink.RX_CLS_LOC_ANY)
		if i < len(ownership.locations) {
			requestedLocation = ownership.locations[i]
		}
		location, err := ensureRXFlow(
			d.PhysicalIfName,
			d.PhysicalQueueID,
			target,
			requestedLocation,
		)
		if err != nil {
			return nil, err
		}
		inserted = append(inserted, location)
		if i < len(ownership.locations) {
			ownership.locations[i] = location
		} else {
			ownership.locations = append(ownership.locations, location)
		}
		ownership.digest = digest
		if err := netlinkLinkSetAlias(host, rxFlowOwnershipAlias(d.HostIfName, ownership)); err != nil {
			return nil, fmt.Errorf("failed to record RX flow ownership on netkit host %s: %w",
				d.HostIfName, err)
		}
	}

	ownership.digest = digest
	wantAlias := rxFlowOwnershipAlias(d.HostIfName, ownership)
	if err := netlinkLinkSetAlias(host, wantAlias); err != nil {
		return nil, fmt.Errorf("failed to record RX flow ownership on netkit host %s: %w",
			d.HostIfName, err)
	}

	states := make([]rxFlowState, len(desired))
	for i := range desired {
		states[i] = rxFlowState{Flow: desired[i], Location: ownership.locations[i]}
	}
	return states, nil
}

func ensureRXFlow(
	ifName string,
	queueID uint32,
	flow types.RXQueueFlow,
	requestedLocation uint32,
) (_ uint32, retErr error) {
	match, err := rxFlowMatch(flow)
	if err != nil {
		return 0, err
	}
	location, err := insertRXFlow(ifName, netlink.NetDevRxFlow{
		Match:    match,
		Queue:    queueID,
		Location: requestedLocation,
	})
	if err != nil {
		return 0, fmt.Errorf("failed to steer %s destination %s:%d to RX queue %s/%d: %w",
			flow.Protocol, flow.DestinationIP, flow.DestinationPort, ifName, queueID, err)
	}
	cleanup := true
	defer func() {
		if !cleanup {
			return
		}
		if err := netlinkNetDevRxFlowDelete(ifName, location); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("failed to clean up RX flow rule %s/%d: %w",
				ifName, location, err))
		}
	}()
	if requestedLocation != netlink.RX_CLS_LOC_ANY && location != requestedLocation {
		return 0, fmt.Errorf("driver returned RX flow location %d, want %d",
			location, requestedLocation)
	}

	locations, err := netlinkNetDevRxFlowList(ifName)
	if err != nil {
		return 0, fmt.Errorf("failed to verify RX flow rule %s/%d: %w", ifName, location, err)
	}
	if !slices.Contains(locations, location) {
		return 0, fmt.Errorf("RX flow rule %s/%d was not present after insertion", ifName, location)
	}

	cleanup = false
	return location, nil
}

func insertRXFlow(ifName string, flow netlink.NetDevRxFlow) (uint32, error) {
	location, err := netlinkNetDevRxFlowInsert(ifName, flow)
	if err == nil {
		return location, nil
	}

	// The ethtool UAPI makes driver-assigned locations optional.
	if !errors.Is(err, unix.EINVAL) && !errors.Is(err, unix.ENOSPC) {
		return 0, err
	}

	locations, listErr := netlinkNetDevRxFlowList(ifName)
	if listErr != nil {
		return 0, errors.Join(
			fmt.Errorf("driver-assigned RX flow location failed: %w", err),
			fmt.Errorf("failed to list RX flow rules: %w", listErr),
		)
	}

	flow.Location = firstAvailableRXFlowLocation(locations)
	location, explicitErr := netlinkNetDevRxFlowInsert(ifName, flow)
	if explicitErr != nil {
		return 0, errors.Join(
			fmt.Errorf("driver-assigned RX flow location failed: %w", err),
			fmt.Errorf("explicit RX flow location %d failed: %w", flow.Location, explicitErr),
		)
	}
	return location, nil
}

func firstAvailableRXFlowLocation(locations []uint32) uint32 {
	used := make(map[uint32]struct{}, len(locations))
	for _, location := range locations {
		used[location] = struct{}{}
	}
	for location := uint32(0); ; location++ {
		if _, exists := used[location]; !exists {
			return location
		}
	}
}

func deleteRXFlows(ifName string, locations []uint32) error {
	var errs []error
	for _, location := range locations {
		if err := deleteRXFlowIfExists(ifName, location); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func deleteRXFlowIfExists(ifName string, location uint32) error {
	locations, err := netlinkNetDevRxFlowList(ifName)
	if err != nil {
		return fmt.Errorf("failed to list RX flow rules on %s: %w", ifName, err)
	}
	if !slices.Contains(locations, location) {
		return nil
	}
	if err := netlinkNetDevRxFlowDelete(ifName, location); err != nil {
		return fmt.Errorf("failed to delete RX flow rule %s/%d: %w", ifName, location, err)
	}
	locations, err = netlinkNetDevRxFlowList(ifName)
	if err != nil {
		return fmt.Errorf("failed to verify deletion of RX flow rule %s/%d: %w", ifName, location, err)
	}
	if slices.Contains(locations, location) {
		return fmt.Errorf("RX flow rule %s/%d remained after deletion", ifName, location)
	}
	return nil
}

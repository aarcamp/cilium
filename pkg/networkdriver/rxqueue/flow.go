// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package rxqueue

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/networkdriver/types"
)

type rxFlowOwnership struct {
	location       uint32
	destinationMAC string
}

func rxFlowForAllocation(allocation types.DeviceAllocation) (netlink.EtherFlow, string, error) {
	if allocation.Config.RXQueue == nil || allocation.Config.RXQueue.DestinationMAC == "" {
		return netlink.EtherFlow{}, "", fmt.Errorf("%w: RX queue destination MAC is required", errInvalidAllocation)
	}

	mac, err := parseRXFlowDestinationMAC(allocation.Config.RXQueue.DestinationMAC)
	if err != nil {
		return netlink.EtherFlow{}, "", fmt.Errorf("%w: invalid RX queue destination MAC: %v", errInvalidAllocation, err)
	}
	return netlink.EtherFlow{
		DstMAC:     mac,
		DstMACMask: net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	}, mac.String(), nil
}

func parseRXFlowDestinationMAC(value string) (net.HardwareAddr, error) {
	mac, err := net.ParseMAC(value)
	if err != nil {
		return nil, err
	}
	if len(mac) != 6 {
		return nil, errors.New("must contain exactly 6 bytes")
	}
	if mac[0]&1 != 0 {
		return nil, errors.New("must be a unicast address")
	}
	allZero := true
	for _, b := range mac {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return nil, errors.New("must not be the zero address")
	}
	return mac, nil
}

func rxFlowOwnershipAlias(ifName string, ownership rxFlowOwnership) string {
	return fmt.Sprintf("%s:%d:%s", ownershipAlias(ifName), ownership.location, ownership.destinationMAC)
}

func ownedRXFlow(link netlink.Link, ifName string) (*rxFlowOwnership, error) {
	if _, ok := link.(*netlink.Netkit); !ok {
		return nil, fmt.Errorf("%w: %s", errUnownedLink, link.Attrs().Name)
	}

	base := ownershipAlias(ifName)
	if link.Attrs().Alias == base {
		return nil, nil
	}
	suffix, found := strings.CutPrefix(link.Attrs().Alias, base+":")
	if !found {
		return nil, fmt.Errorf("%w: %s", errUnownedLink, link.Attrs().Name)
	}
	locationValue, destinationMAC, found := strings.Cut(suffix, ":")
	if !found {
		return nil, fmt.Errorf("%w: %s", errUnownedLink, link.Attrs().Name)
	}
	location, err := strconv.ParseUint(locationValue, 10, 32)
	if err != nil || strconv.FormatUint(location, 10) != locationValue {
		return nil, fmt.Errorf("%w: %s", errUnownedLink, link.Attrs().Name)
	}
	mac, err := parseRXFlowDestinationMAC(destinationMAC)
	if err != nil || mac.String() != destinationMAC {
		return nil, fmt.Errorf("%w: %s", errUnownedLink, link.Attrs().Name)
	}
	return &rxFlowOwnership{
		location:       uint32(location),
		destinationMAC: destinationMAC,
	}, nil
}

func ensureRXFlow(
	ifName string,
	queueID uint32,
	flow netlink.EtherFlow,
	destinationMAC string,
	host netlink.Link,
	existing *rxFlowOwnership,
	requestedLocation uint32,
) (_ uint32, retErr error) {
	if existing != nil {
		if existing.destinationMAC != destinationMAC {
			return 0, fmt.Errorf("%w: existing RX flow on %s has destination MAC %s, want %s",
				errInvalidAllocation, ifName, existing.destinationMAC, destinationMAC)
		}
		if requestedLocation != netlink.RX_CLS_LOC_ANY && existing.location != requestedLocation {
			return 0, fmt.Errorf("%w: existing RX flow location %d does not match stored location %d",
				errInvalidAllocation, existing.location, requestedLocation)
		}
		locations, err := netlinkNetDevRxFlowList(ifName)
		if err != nil {
			return 0, fmt.Errorf("failed to list RX flow rules on %s: %w", ifName, err)
		}
		if slices.Contains(locations, existing.location) {
			return existing.location, nil
		}
	}

	location, err := insertRXFlow(ifName, netlink.NetDevRxFlow{
		Match:    flow,
		Queue:    queueID,
		Location: requestedLocation,
	})
	if err != nil {
		return 0, fmt.Errorf("failed to steer destination MAC %s to RX queue %s/%d: %w",
			destinationMAC, ifName, queueID, err)
	}
	cleanup := true
	defer func() {
		if !cleanup {
			return
		}
		if err := netlinkNetDevRxFlowDelete(ifName, location); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("failed to clean up RX flow rule %s/%d: %w", ifName, location, err))
		}
	}()
	if requestedLocation != netlink.RX_CLS_LOC_ANY && location != requestedLocation {
		return 0, fmt.Errorf("driver returned RX flow location %d, want %d",
			location, requestedLocation)
	}

	// Record the returned location before readback so an interrupted setup can
	// find the rule on retry.
	ownership := rxFlowOwnership{location: location, destinationMAC: destinationMAC}
	if err := netlinkLinkSetAlias(host, rxFlowOwnershipAlias(host.Attrs().Name, ownership)); err != nil {
		return 0, fmt.Errorf("failed to record RX flow rule on netkit host %s: %w", host.Attrs().Name, err)
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

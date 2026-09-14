// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package rxqueue

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	bpfgen "github.com/cilium/cilium/pkg/datapath/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
)

const zcrxRedirectMapName = bpfgen.ZCRXRedirectMapCiliumZcrx

func zcrxRedirectLinksPath() string {
	return filepath.Join(bpf.CiliumPath(), "zcrx", "links")
}

type zcrxRedirectKey = bpfgen.ZCRXRedirectZcrxRedirectKey
type zcrxRedirectValue = bpfgen.ZCRXRedirectZcrxRedirectValue

func ensureZCRXRedirectProgram(ifNames []string) error {
	var objects bpfgen.ZCRXRedirectObjects
	if err := bpfgen.LoadZCRXRedirectObjects(&objects, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: bpf.TCGlobalsPath()},
	}); err != nil {
		return fmt.Errorf("load ZCRX redirect program: %w", err)
	}
	defer objects.Close()

	linksPath := zcrxRedirectLinksPath()
	if err := bpf.MkdirBPF(linksPath); err != nil {
		return fmt.Errorf("create ZCRX redirect link directory: %w", err)
	}

	desired := make(map[string]struct{}, len(ifNames))
	for _, ifName := range ifNames {
		device, err := safenetlink.LinkByName(ifName)
		if err != nil {
			return fmt.Errorf("find ZCRX redirect interface %s: %w", ifName, err)
		}

		pinName := strconv.Itoa(device.Attrs().Index)
		if err := upsertZCRXRedirectLink(objects.CilZcrxRedir, device.Attrs().Index, filepath.Join(linksPath, pinName)); err != nil {
			return fmt.Errorf("attach ZCRX redirect to %s: %w", ifName, err)
		}
		desired[pinName] = struct{}{}
	}

	entries, err := os.ReadDir(linksPath)
	if err != nil {
		return fmt.Errorf("list ZCRX redirect links: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if _, ok := desired[entry.Name()]; ok {
			continue
		}
		if err := bpf.UnpinLink(filepath.Join(linksPath, entry.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove obsolete ZCRX redirect link %s: %w", entry.Name(), err)
		}
	}

	return nil
}

func upsertZCRXRedirectLink(program *ebpf.Program, ifIndex int, pin string) error {
	err := bpf.UpdateLink(pin, program)
	if err == nil {
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, unix.ENOLINK) {
		return err
	}
	if errors.Is(err, unix.ENOLINK) {
		if err := os.Remove(pin); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("unpin defunct link: %w", err)
		}
	}

	attached, err := link.AttachTCX(link.TCXOptions{
		Program:   program,
		Attach:    ebpf.AttachTCXIngress,
		Interface: ifIndex,
		Anchor:    link.Head(),
	})
	if err != nil {
		return err
	}
	defer attached.Close()

	if err := attached.Pin(pin); err != nil {
		return fmt.Errorf("pin link at %s: %w", pin, err)
	}
	return nil
}

func zcrxRedirectKeyFor(physicalIfIndex int, destinationMAC net.HardwareAddr) (zcrxRedirectKey, error) {
	if physicalIfIndex <= 0 {
		return zcrxRedirectKey{}, errors.New("physical interface index must be positive")
	}
	if len(destinationMAC) != 6 {
		return zcrxRedirectKey{}, errors.New("destination MAC must contain exactly 6 bytes")
	}

	key := zcrxRedirectKey{IngressIfindex: uint32(physicalIfIndex)}
	copy(key.DestinationMac[:], destinationMAC)
	return key, nil
}

func openZCRXRedirectMap() (*ebpf.Map, error) {
	redirectMap, err := ebpf.LoadPinnedMap(filepath.Join(bpf.TCGlobalsPath(), zcrxRedirectMapName), nil)
	if err != nil {
		return nil, fmt.Errorf("open ZCRX redirect map: %w", err)
	}
	return redirectMap, nil
}

func ensureZCRXRedirect(physicalIfIndex, netkitIfIndex int, destinationMAC net.HardwareAddr) (bool, error) {
	if netkitIfIndex <= 0 {
		return false, errors.New("netkit interface index must be positive")
	}
	key, err := zcrxRedirectKeyFor(physicalIfIndex, destinationMAC)
	if err != nil {
		return false, err
	}
	want := zcrxRedirectValue{NetkitIfindex: uint32(netkitIfIndex)}

	redirectMap, err := openZCRXRedirectMap()
	if err != nil {
		return false, err
	}
	defer redirectMap.Close()

	if err := redirectMap.Update(&key, &want, ebpf.UpdateNoExist); err == nil {
		return true, nil
	} else if !errors.Is(err, unix.EEXIST) {
		return false, fmt.Errorf("add ZCRX redirect: %w", err)
	}

	var existing zcrxRedirectValue
	if err := redirectMap.Lookup(&key, &existing); err != nil {
		return false, fmt.Errorf("read existing ZCRX redirect: %w", err)
	}
	if existing != want {
		return false, fmt.Errorf("destination MAC %s on ifindex %d is already redirected to ifindex %d",
			destinationMAC, physicalIfIndex, existing.NetkitIfindex)
	}
	return false, nil
}

func deleteZCRXRedirect(physicalIfIndex, netkitIfIndex int, destinationMAC net.HardwareAddr) error {
	key, err := zcrxRedirectKeyFor(physicalIfIndex, destinationMAC)
	if err != nil {
		return err
	}

	redirectMap, err := openZCRXRedirectMap()
	if err != nil {
		return err
	}
	defer redirectMap.Close()

	var existing zcrxRedirectValue
	if err := redirectMap.Lookup(&key, &existing); errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("read ZCRX redirect before deletion: %w", err)
	}
	if existing.NetkitIfindex != uint32(netkitIfIndex) {
		return fmt.Errorf("refusing to delete ZCRX redirect for destination MAC %s on ifindex %d: target is ifindex %d, want %d",
			destinationMAC, physicalIfIndex, existing.NetkitIfindex, netkitIfIndex)
	}

	if err := redirectMap.Delete(&key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete ZCRX redirect: %w", err)
	}
	return nil
}

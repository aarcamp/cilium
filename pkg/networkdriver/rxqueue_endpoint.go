// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"cmp"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/cilium/statedb"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"

	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/networkdriver/types"
)

type portReference struct {
	number uint16
	name   string
}

func validateRXQueueConfig(config *types.RXQueueConfig) error {
	if config == nil {
		return fmt.Errorf("%w: RX queue endpoint is required", errUnexpectedInput)
	}

	switch {
	case config.PodEndpoint == nil && config.ServiceEndpoint == nil:
		return fmt.Errorf("%w: exactly one of podEndpoint or serviceEndpoint is required", errUnexpectedInput)
	case config.PodEndpoint != nil && config.ServiceEndpoint != nil:
		return fmt.Errorf("%w: podEndpoint and serviceEndpoint are mutually exclusive", errUnexpectedInput)
	case config.PodEndpoint != nil:
		if _, err := parsePortReference(config.PodEndpoint.Port); err != nil {
			return fmt.Errorf("%w: invalid podEndpoint port: %v", errUnexpectedInput, err)
		}
		if err := validateRXQueueProtocol(config.PodEndpoint.Protocol); err != nil {
			return fmt.Errorf("%w: invalid podEndpoint protocol: %v", errUnexpectedInput, err)
		}
	case config.ServiceEndpoint.ServiceName == "":
		return fmt.Errorf("%w: serviceEndpoint serviceName is required", errUnexpectedInput)
	default:
		if _, err := parsePortReference(config.ServiceEndpoint.Port); err != nil {
			return fmt.Errorf("%w: invalid serviceEndpoint port: %v", errUnexpectedInput, err)
		}
	}

	return nil
}

func validateRXQueueProtocol(protocol corev1.Protocol) error {
	switch protocol {
	case corev1.ProtocolTCP, corev1.ProtocolUDP:
		return nil
	default:
		return fmt.Errorf("protocol must be TCP or UDP, got %q", protocol)
	}
}

func parsePortReference(value string) (portReference, error) {
	if value == "" {
		return portReference{}, fmt.Errorf("port is required")
	}

	if strings.IndexFunc(value, func(r rune) bool { return r < '0' || r > '9' }) == -1 {
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil || port == 0 {
			return portReference{}, fmt.Errorf("port number %q must be between 1 and 65535", value)
		}
		return portReference{number: uint16(port)}, nil
	}

	if errs := validation.IsValidPortName(value); len(errs) != 0 {
		return portReference{}, fmt.Errorf("invalid port name %q: %s", value, strings.Join(errs, "; "))
	}
	return portReference{name: value}, nil
}

// resolveRXQueueFlows returns the flows that config steers to the RX queue
// allocated to pod. Watch channels for the Service state it reads are added
// to ws, so a caller can resolve again when that state changes.
func resolveRXQueueFlows(
	txn statedb.ReadTxn,
	services statedb.Table[*loadbalancer.Service],
	backends statedb.Table[*loadbalancer.Backend],
	ws *statedb.WatchSet,
	pod *slim_corev1.Pod,
	config *types.RXQueueConfig,
) ([]types.RXQueueFlow, error) {
	ips, err := rxQueuePodIPs(pod)
	if err != nil {
		return nil, err
	}

	var flows []types.RXQueueFlow
	if config.PodEndpoint != nil {
		port, err := podEndpointPort(pod, config.PodEndpoint)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			flows = append(flows, types.RXQueueFlow{
				DestinationIP:   ip,
				DestinationPort: port,
				Protocol:        config.PodEndpoint.Protocol,
			})
		}
	} else {
		flows, err = serviceEndpointFlows(txn, services, backends, ws, pod.Namespace, ips, config.ServiceEndpoint)
		if err != nil {
			return nil, err
		}
	}

	slices.SortFunc(flows, func(a, b types.RXQueueFlow) int {
		return cmp.Or(
			a.DestinationIP.Compare(b.DestinationIP),
			cmp.Compare(a.DestinationPort, b.DestinationPort),
			cmp.Compare(a.Protocol, b.Protocol),
		)
	})
	return flows, nil
}

func rxQueuePodIPs(pod *slim_corev1.Pod) ([]netip.Addr, error) {
	var ips []netip.Addr
	for _, podIP := range pod.Status.PodIPs {
		ip, err := netip.ParseAddr(podIP.IP)
		if err != nil {
			return nil, fmt.Errorf("Pod %s/%s has invalid IP %q: %w", pod.Namespace, pod.Name, podIP.IP, err)
		}
		if ip = ip.Unmap(); !slices.Contains(ips, ip) {
			ips = append(ips, ip)
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("Pod %s/%s has no IP addresses", pod.Namespace, pod.Name)
	}
	return ips, nil
}

func podEndpointPort(pod *slim_corev1.Pod, endpoint *types.RXQueuePodEndpoint) (uint16, error) {
	port, err := parsePortReference(endpoint.Port)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid podEndpoint port: %v", errUnexpectedInput, err)
	}
	if port.name == "" {
		return port.number, nil
	}

	for _, containers := range [][]slim_corev1.Container{pod.Spec.Containers, pod.Spec.InitContainers} {
		for _, container := range containers {
			for _, containerPort := range container.Ports {
				protocol := corev1.Protocol(containerPort.Protocol)
				if protocol == "" {
					protocol = corev1.ProtocolTCP
				}
				if containerPort.Name == port.name && protocol == endpoint.Protocol &&
					containerPort.ContainerPort > 0 && containerPort.ContainerPort <= math.MaxUint16 {
					return uint16(containerPort.ContainerPort), nil
				}
			}
		}
	}
	return 0, fmt.Errorf("Pod %s/%s has no %s port named %q", pod.Namespace, pod.Name, endpoint.Protocol, port.name)
}

// serviceEndpointFlows returns the Service backends that are addresses of the
// Pod. The EndpointSlice controller has already resolved the Service port's
// targetPort against the Pod's container ports.
func serviceEndpointFlows(
	txn statedb.ReadTxn,
	services statedb.Table[*loadbalancer.Service],
	backends statedb.Table[*loadbalancer.Backend],
	ws *statedb.WatchSet,
	namespace string,
	ips []netip.Addr,
	endpoint *types.RXQueueServiceEndpoint,
) ([]types.RXQueueFlow, error) {
	name := loadbalancer.NewServiceName(namespace, endpoint.ServiceName)
	service, _, watch, found := services.GetWatch(txn, loadbalancer.ServiceByName(name))
	ws.Add(watch)
	if !found {
		return nil, fmt.Errorf("Service %s was not found", name)
	}
	portName, err := servicePortName(service, endpoint.Port)
	if err != nil {
		return nil, err
	}

	serviceBackends, watch := loadbalancer.ListBackendsByServiceName(txn, backends, name)
	ws.Add(watch)
	var flows []types.RXQueueFlow
	for backend := range loadbalancer.PreferredBackendsByAddress(serviceBackends) {
		ip := backend.Address.Addr().Unmap()
		if backend.ClusterID != 0 || !slices.Contains(ips, ip) {
			continue
		}
		// The unnamed port of a single-port Service has no name on its backends.
		if portName == "" && len(backend.PortNames) != 0 ||
			portName != "" && !slices.Contains(backend.PortNames, portName) {
			continue
		}
		protocol := corev1.Protocol(backend.Address.Protocol())
		if err := validateRXQueueProtocol(protocol); err != nil {
			return nil, fmt.Errorf("Service %s port %s: %w", name, endpoint.Port, err)
		}
		flows = append(flows, types.RXQueueFlow{
			DestinationIP:   ip,
			DestinationPort: backend.Address.Port(),
			Protocol:        protocol,
		})
	}
	if len(flows) == 0 {
		return nil, fmt.Errorf("Service %s has no endpoint on this Pod for port %s", name, endpoint.Port)
	}
	return flows, nil
}

func servicePortName(service *loadbalancer.Service, value string) (string, error) {
	port, err := parsePortReference(value)
	if err != nil {
		return "", fmt.Errorf("%w: invalid serviceEndpoint port: %v", errUnexpectedInput, err)
	}
	if port.name != "" {
		if _, found := service.PortNames[port.name]; !found {
			return "", fmt.Errorf("Service %s has no port %q", service.Name, value)
		}
		return port.name, nil
	}

	var names []string
	for name, number := range service.PortNames {
		if number == port.number {
			names = append(names, name)
		}
	}
	switch len(names) {
	case 0:
		return "", fmt.Errorf("Service %s has no port %q", service.Name, value)
	case 1:
		return names[0], nil
	default:
		return "", fmt.Errorf("Service %s has multiple ports numbered %s; select one by name", service.Name, value)
	}
}

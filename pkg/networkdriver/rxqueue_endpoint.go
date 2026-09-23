// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/cilium/cilium/pkg/networkdriver/types"
)

type rxQueueFlowTarget struct {
	IP       netip.Addr
	Port     uint16
	Protocol corev1.Protocol
}

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

func resolveRXQueueFlowTargets(
	pod *corev1.Pod,
	service *corev1.Service,
	podIPs []netip.Addr,
	config *types.RXQueueConfig,
) ([]rxQueueFlowTarget, error) {
	if err := validateRXQueueConfig(config); err != nil {
		return nil, err
	}
	if pod == nil {
		return nil, fmt.Errorf("%w: consuming pod is required", errUnexpectedInput)
	}

	ips, err := normalizePodIPs(podIPs)
	if err != nil {
		return nil, err
	}

	if config.PodEndpoint != nil {
		port, err := resolvePodEndpointPort(pod, config.PodEndpoint)
		if err != nil {
			return nil, err
		}
		return flowTargets(ips, port, config.PodEndpoint.Protocol), nil
	}

	port, protocol, err := resolveServiceEndpointPort(pod, service, config.ServiceEndpoint)
	if err != nil {
		return nil, err
	}
	ips, err = filterServiceIPFamilies(service, ips)
	if err != nil {
		return nil, err
	}
	return flowTargets(ips, port, protocol), nil
}

func normalizePodIPs(podIPs []netip.Addr) ([]netip.Addr, error) {
	seen := make(map[netip.Addr]struct{}, len(podIPs))
	for _, ip := range podIPs {
		ip = ip.Unmap()
		if !ip.IsValid() || !ip.IsGlobalUnicast() {
			return nil, fmt.Errorf("%w: invalid pod IP %q", errUnexpectedInput, ip)
		}
		seen[ip] = struct{}{}
	}
	if len(seen) == 0 {
		return nil, fmt.Errorf("%w: consuming pod has no IP addresses", errUnexpectedInput)
	}

	ips := make([]netip.Addr, 0, len(seen))
	for ip := range seen {
		ips = append(ips, ip)
	}
	slices.SortFunc(ips, netip.Addr.Compare)
	return ips, nil
}

func resolvePodEndpointPort(pod *corev1.Pod, endpoint *types.RXQueuePodEndpoint) (uint16, error) {
	port, err := parsePortReference(endpoint.Port)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid podEndpoint port: %v", errUnexpectedInput, err)
	}
	if port.name == "" {
		return port.number, nil
	}

	resolved, err := lookupContainerPort(pod, port.name, endpoint.Protocol)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", errUnexpectedInput, err)
	}
	return resolved, nil
}

func resolveServiceEndpointPort(
	pod *corev1.Pod,
	service *corev1.Service,
	endpoint *types.RXQueueServiceEndpoint,
) (uint16, corev1.Protocol, error) {
	if service == nil {
		return 0, "", fmt.Errorf("%w: Service %s/%s was not found",
			errUnexpectedInput, pod.Namespace, endpoint.ServiceName)
	}
	if service.Namespace != pod.Namespace || service.Name != endpoint.ServiceName {
		return 0, "", fmt.Errorf("%w: resolved Service %s/%s does not match %s/%s",
			errUnexpectedInput, service.Namespace, service.Name, pod.Namespace, endpoint.ServiceName)
	}
	if len(service.Spec.Selector) == 0 {
		return 0, "", fmt.Errorf("%w: Service %s/%s has no pod selector",
			errUnexpectedInput, service.Namespace, service.Name)
	}
	if !labels.SelectorFromSet(service.Spec.Selector).Matches(labels.Set(pod.Labels)) {
		return 0, "", fmt.Errorf("%w: Service %s/%s does not select pod %s",
			errUnexpectedInput, service.Namespace, service.Name, pod.Name)
	}

	servicePort, err := findServicePort(service, endpoint.Port)
	if err != nil {
		return 0, "", fmt.Errorf("%w: %v", errUnexpectedInput, err)
	}
	protocol := servicePort.Protocol
	if protocol == "" {
		protocol = corev1.ProtocolTCP
	}
	if err := validateRXQueueProtocol(protocol); err != nil {
		return 0, "", fmt.Errorf("%w: Service %s/%s port %s: %v",
			errUnexpectedInput, service.Namespace, service.Name, endpoint.Port, err)
	}

	if servicePort.TargetPort.Type == intstr.Int {
		port := servicePort.TargetPort.IntValue()
		if port == 0 {
			port = int(servicePort.Port)
		}
		if errs := validation.IsValidPortNum(port); len(errs) != 0 {
			return 0, "", fmt.Errorf("%w: Service %s/%s has invalid targetPort %d",
				errUnexpectedInput, service.Namespace, service.Name, port)
		}
		return uint16(port), protocol, nil
	}

	port, err := lookupContainerPort(pod, servicePort.TargetPort.String(), protocol)
	if err != nil {
		return 0, "", fmt.Errorf("%w: Service %s/%s: %v",
			errUnexpectedInput, service.Namespace, service.Name, err)
	}
	return port, protocol, nil
}

func findServicePort(service *corev1.Service, value string) (*corev1.ServicePort, error) {
	port, err := parsePortReference(value)
	if err != nil {
		return nil, err
	}

	var matches []*corev1.ServicePort
	for i := range service.Spec.Ports {
		servicePort := &service.Spec.Ports[i]
		if (port.name != "" && servicePort.Name == port.name) ||
			(port.name == "" && servicePort.Port == int32(port.number)) {
			matches = append(matches, servicePort)
		}
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("Service %s/%s has no port %q", service.Namespace, service.Name, value)
	}
	if len(matches) > 1 {
		return nil, fmt.Errorf("Service %s/%s has multiple ports numbered %s; select one by name",
			service.Namespace, service.Name, value)
	}
	return matches[0], nil
}

func lookupContainerPort(pod *corev1.Pod, name string, protocol corev1.Protocol) (uint16, error) {
	for _, containers := range [][]corev1.Container{pod.Spec.Containers, pod.Spec.InitContainers} {
		for _, container := range containers {
			for _, port := range container.Ports {
				if port.Name != name {
					continue
				}
				portProtocol := port.Protocol
				if portProtocol == "" {
					portProtocol = corev1.ProtocolTCP
				}
				if portProtocol != protocol {
					continue
				}
				if errs := validation.IsValidPortNum(int(port.ContainerPort)); len(errs) != 0 {
					return 0, fmt.Errorf("named port %q has invalid port number %d", name, port.ContainerPort)
				}
				return uint16(port.ContainerPort), nil
			}
		}
	}
	return 0, fmt.Errorf("pod %s/%s has no %s port named %q", pod.Namespace, pod.Name, protocol, name)
}

func filterServiceIPFamilies(service *corev1.Service, ips []netip.Addr) ([]netip.Addr, error) {
	if len(service.Spec.IPFamilies) == 0 {
		return ips, nil
	}

	want4, want6 := false, false
	for _, family := range service.Spec.IPFamilies {
		switch family {
		case corev1.IPv4Protocol:
			want4 = true
		case corev1.IPv6Protocol:
			want6 = true
		}
	}

	filtered := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if ip.Is4() && want4 || ip.Is6() && want6 {
			filtered = append(filtered, ip)
		}
	}
	if len(filtered) == 0 {
		return nil, fmt.Errorf("%w: pod has no IP in a family used by Service %s/%s",
			errUnexpectedInput, service.Namespace, service.Name)
	}
	return filtered, nil
}

func flowTargets(ips []netip.Addr, port uint16, protocol corev1.Protocol) []rxQueueFlowTarget {
	targets := make([]rxQueueFlowTarget, 0, len(ips))
	for _, ip := range ips {
		targets = append(targets, rxQueueFlowTarget{IP: ip, Port: port, Protocol: protocol})
	}
	return targets
}

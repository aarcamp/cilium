// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/cilium/cilium/pkg/networkdriver/types"
)

func TestValidateRXQueueConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  *types.RXQueueConfig
		wantErr string
	}{
		{
			name:    "missing endpoint",
			config:  &types.RXQueueConfig{},
			wantErr: "exactly one of podEndpoint or serviceEndpoint is required",
		},
		{
			name: "both endpoints",
			config: &types.RXQueueConfig{
				PodEndpoint:     &types.RXQueuePodEndpoint{Port: "9000", Protocol: corev1.ProtocolTCP},
				ServiceEndpoint: &types.RXQueueServiceEndpoint{ServiceName: "storage", Port: "rpc"},
			},
			wantErr: "mutually exclusive",
		},
		{
			name: "unsupported pod protocol",
			config: &types.RXQueueConfig{
				PodEndpoint: &types.RXQueuePodEndpoint{Port: "9000", Protocol: corev1.ProtocolSCTP},
			},
			wantErr: "protocol must be TCP or UDP",
		},
		{
			name: "invalid pod port",
			config: &types.RXQueueConfig{
				PodEndpoint: &types.RXQueuePodEndpoint{Port: "0", Protocol: corev1.ProtocolTCP},
			},
			wantErr: "between 1 and 65535",
		},
		{
			name: "missing service name",
			config: &types.RXQueueConfig{
				ServiceEndpoint: &types.RXQueueServiceEndpoint{Port: "rpc"},
			},
			wantErr: "serviceName is required",
		},
		{
			name: "valid pod endpoint",
			config: &types.RXQueueConfig{
				PodEndpoint: &types.RXQueuePodEndpoint{Port: "rpc", Protocol: corev1.ProtocolTCP},
			},
		},
		{
			name: "valid service endpoint",
			config: &types.RXQueueConfig{
				ServiceEndpoint: &types.RXQueueServiceEndpoint{ServiceName: "storage", Port: "9000"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRXQueueConfig(tt.config)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.wantErr)
			require.ErrorIs(t, err, errUnexpectedInput)
		})
	}
}

func TestResolveRXQueuePodEndpoint(t *testing.T) {
	pod := rxQueueTestPod()
	ips := []netip.Addr{
		netip.MustParseAddr("2001:db8::10"),
		netip.MustParseAddr("192.0.2.10"),
		netip.MustParseAddr("192.0.2.10"),
	}

	t.Run("numeric port", func(t *testing.T) {
		targets, err := resolveRXQueueFlowTargets(pod, nil, ips, &types.RXQueueConfig{
			PodEndpoint: &types.RXQueuePodEndpoint{Port: "9000", Protocol: corev1.ProtocolTCP},
		})
		require.NoError(t, err)
		require.Equal(t, []rxQueueFlowTarget{
			{IP: netip.MustParseAddr("192.0.2.10"), Port: 9000, Protocol: corev1.ProtocolTCP},
			{IP: netip.MustParseAddr("2001:db8::10"), Port: 9000, Protocol: corev1.ProtocolTCP},
		}, targets)
	})

	t.Run("named port", func(t *testing.T) {
		targets, err := resolveRXQueueFlowTargets(pod, nil, ips, &types.RXQueueConfig{
			PodEndpoint: &types.RXQueuePodEndpoint{Port: "dns", Protocol: corev1.ProtocolUDP},
		})
		require.NoError(t, err)
		require.Equal(t, uint16(5353), targets[0].Port)
		require.Equal(t, corev1.ProtocolUDP, targets[0].Protocol)
	})
}

func TestResolveRXQueueServiceEndpoint(t *testing.T) {
	pod := rxQueueTestPod()
	ips := []netip.Addr{
		netip.MustParseAddr("192.0.2.10"),
		netip.MustParseAddr("2001:db8::10"),
	}
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "storage"},
		Spec: corev1.ServiceSpec{
			Selector:   map[string]string{"app": "storage"},
			IPFamilies: []corev1.IPFamily{corev1.IPv6Protocol},
			Ports: []corev1.ServicePort{
				{
					Name:       "rpc",
					Port:       9000,
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromString("rpc"),
				},
			},
		},
	}

	targets, err := resolveRXQueueFlowTargets(pod, service, ips, &types.RXQueueConfig{
		ServiceEndpoint: &types.RXQueueServiceEndpoint{ServiceName: "storage", Port: "rpc"},
	})
	require.NoError(t, err)
	require.Equal(t, []rxQueueFlowTarget{{
		IP:       netip.MustParseAddr("2001:db8::10"),
		Port:     8080,
		Protocol: corev1.ProtocolTCP,
	}}, targets)
}

func TestResolveRXQueueServiceEndpointErrors(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*corev1.Pod, *corev1.Service)
		port    string
		wantErr string
	}{
		{
			name: "service does not select pod",
			mutate: func(_ *corev1.Pod, service *corev1.Service) {
				service.Spec.Selector = map[string]string{"app": "other"}
			},
			port:    "rpc",
			wantErr: "does not select pod",
		},
		{
			name: "ambiguous service port number",
			mutate: func(_ *corev1.Pod, service *corev1.Service) {
				service.Spec.Ports = append(service.Spec.Ports, corev1.ServicePort{
					Name:       "metrics",
					Port:       9000,
					Protocol:   corev1.ProtocolUDP,
					TargetPort: intstr.FromInt32(9090),
				})
			},
			port:    "9000",
			wantErr: "select one by name",
		},
		{
			name: "unsupported service protocol",
			mutate: func(_ *corev1.Pod, service *corev1.Service) {
				service.Spec.Ports[0].Protocol = corev1.ProtocolSCTP
			},
			port:    "rpc",
			wantErr: "protocol must be TCP or UDP",
		},
		{
			name: "missing named target port",
			mutate: func(_ *corev1.Pod, service *corev1.Service) {
				service.Spec.Ports[0].TargetPort = intstr.FromString("missing")
			},
			port:    "rpc",
			wantErr: "has no TCP port named",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := rxQueueTestPod()
			service := rxQueueTestService()
			tt.mutate(pod, service)

			_, err := resolveRXQueueFlowTargets(
				pod,
				service,
				[]netip.Addr{netip.MustParseAddr("192.0.2.10")},
				&types.RXQueueConfig{
					ServiceEndpoint: &types.RXQueueServiceEndpoint{
						ServiceName: "storage",
						Port:        tt.port,
					},
				},
			)
			require.ErrorContains(t, err, tt.wantErr)
			require.ErrorIs(t, err, errUnexpectedInput)
		})
	}
}

func rxQueueTestPod() *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "storage-0",
			Labels:    map[string]string{"app": "storage"},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "storage",
				Ports: []corev1.ContainerPort{
					{Name: "rpc", ContainerPort: 8080, Protocol: corev1.ProtocolTCP},
					{Name: "dns", ContainerPort: 5353, Protocol: corev1.ProtocolUDP},
				},
			}},
		},
	}
}

func rxQueueTestService() *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "storage"},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"app": "storage"},
			Ports: []corev1.ServicePort{{
				Name:       "rpc",
				Port:       9000,
				Protocol:   corev1.ProtocolTCP,
				TargetPort: intstr.FromString("rpc"),
			}},
		},
	}
}

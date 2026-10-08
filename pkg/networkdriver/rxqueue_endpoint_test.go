// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"net/netip"
	"testing"

	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/loadbalancer"

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

type rxQueueServiceFixture struct {
	db       *statedb.DB
	services statedb.RWTable[*loadbalancer.Service]
	backends statedb.RWTable[*loadbalancer.Backend]
}

func newRXQueueServiceFixture(t *testing.T) rxQueueServiceFixture {
	db := statedb.New()
	services, err := loadbalancer.NewServicesTable(loadbalancer.DefaultConfig, db)
	require.NoError(t, err)
	backends, err := loadbalancer.NewBackendsTable(db)
	require.NoError(t, err)
	return rxQueueServiceFixture{db: db, services: services, backends: backends}
}

func (f rxQueueServiceFixture) upsert(service *loadbalancer.Service, backends ...*loadbalancer.Backend) {
	wtxn := f.db.WriteTxn(f.services, f.backends)
	f.services.Insert(wtxn, service)
	for _, backend := range backends {
		backend.ServiceName = service.Name
		f.backends.Insert(wtxn, backend)
	}
	wtxn.Commit()
}

func (f rxQueueServiceFixture) resolve(pod *slim_corev1.Pod, config *types.RXQueueConfig) ([]types.RXQueueFlow, error) {
	return resolveRXQueueFlows(f.db.ReadTxn(), f.services, f.backends, statedb.NewWatchSet(), pod, config)
}

func rxQueueTestPod() *slim_corev1.Pod {
	return &slim_corev1.Pod{
		ObjectMeta: slim_metav1.ObjectMeta{Namespace: "default", Name: "storage-0"},
		Spec: slim_corev1.PodSpec{
			Containers: []slim_corev1.Container{{
				Ports: []slim_corev1.ContainerPort{
					{Name: "rpc", ContainerPort: 8080},
					{Name: "dns", ContainerPort: 5353, Protocol: slim_corev1.ProtocolUDP},
				},
			}},
		},
		Status: slim_corev1.PodStatus{
			PodIPs: []slim_corev1.PodIP{{IP: "2001:db8::10"}, {IP: "192.0.2.10"}, {IP: "192.0.2.10"}},
		},
	}
}

func rxQueueTestBackend(protocol, addr string, port uint16, portNames ...string) *loadbalancer.Backend {
	return &loadbalancer.Backend{
		Address: loadbalancer.NewL3n4Addr(protocol, cmtypes.MustParseAddrCluster(addr),
			port, loadbalancer.ScopeExternal),
		PortNames: portNames,
	}
}

func TestResolveRXQueuePodEndpoint(t *testing.T) {
	f := newRXQueueServiceFixture(t)
	pod := rxQueueTestPod()

	flows, err := f.resolve(pod, &types.RXQueueConfig{
		PodEndpoint: &types.RXQueuePodEndpoint{Port: "9000", Protocol: corev1.ProtocolTCP},
	})
	require.NoError(t, err)
	require.Equal(t, []types.RXQueueFlow{
		{DestinationIP: netip.MustParseAddr("192.0.2.10"), DestinationPort: 9000, Protocol: corev1.ProtocolTCP},
		{DestinationIP: netip.MustParseAddr("2001:db8::10"), DestinationPort: 9000, Protocol: corev1.ProtocolTCP},
	}, flows)

	flows, err = f.resolve(pod, &types.RXQueueConfig{
		PodEndpoint: &types.RXQueuePodEndpoint{Port: "dns", Protocol: corev1.ProtocolUDP},
	})
	require.NoError(t, err)
	require.Equal(t, uint16(5353), flows[0].DestinationPort)

	_, err = f.resolve(pod, &types.RXQueueConfig{
		PodEndpoint: &types.RXQueuePodEndpoint{Port: "dns", Protocol: corev1.ProtocolTCP},
	})
	require.ErrorContains(t, err, "no TCP port named")

	pod.Status.PodIPs = nil
	_, err = f.resolve(pod, &types.RXQueueConfig{
		PodEndpoint: &types.RXQueuePodEndpoint{Port: "9000", Protocol: corev1.ProtocolTCP},
	})
	require.ErrorContains(t, err, "has no IP addresses")
}

func TestResolveRXQueueServiceEndpoint(t *testing.T) {
	f := newRXQueueServiceFixture(t)
	pod := rxQueueTestPod()
	f.upsert(&loadbalancer.Service{
		Name:      loadbalancer.NewServiceName("default", "storage"),
		PortNames: map[string]uint16{"rpc": 9000, "metrics": 9100},
	},
		rxQueueTestBackend(loadbalancer.TCP, "192.0.2.10", 8080, "rpc"),
		rxQueueTestBackend(loadbalancer.TCP, "2001:db8::10", 8080, "rpc"),
		rxQueueTestBackend(loadbalancer.TCP, "192.0.2.11", 8080, "rpc"),
		rxQueueTestBackend(loadbalancer.TCP, "192.0.2.10", 9100, "metrics"),
	)
	f.upsert(&loadbalancer.Service{
		Name:      loadbalancer.NewServiceName("default", "dns"),
		PortNames: map[string]uint16{"dns-tcp": 53, "dns-udp": 53},
	})
	f.upsert(&loadbalancer.Service{
		Name:      loadbalancer.NewServiceName("default", "unnamed"),
		PortNames: map[string]uint16{"": 9000},
	}, rxQueueTestBackend(loadbalancer.UDP, "192.0.2.10", 9001))
	f.upsert(&loadbalancer.Service{
		Name:      loadbalancer.NewServiceName("default", "other"),
		PortNames: map[string]uint16{"rpc": 9000},
	}, rxQueueTestBackend(loadbalancer.TCP, "192.0.2.11", 8080, "rpc"))

	want := []types.RXQueueFlow{
		{DestinationIP: netip.MustParseAddr("192.0.2.10"), DestinationPort: 8080, Protocol: corev1.ProtocolTCP},
		{DestinationIP: netip.MustParseAddr("2001:db8::10"), DestinationPort: 8080, Protocol: corev1.ProtocolTCP},
	}
	for _, port := range []string{"rpc", "9000"} {
		flows, err := f.resolve(pod, &types.RXQueueConfig{
			ServiceEndpoint: &types.RXQueueServiceEndpoint{ServiceName: "storage", Port: port},
		})
		require.NoError(t, err, port)
		require.Equal(t, want, flows, port)
	}

	flows, err := f.resolve(pod, &types.RXQueueConfig{
		ServiceEndpoint: &types.RXQueueServiceEndpoint{ServiceName: "unnamed", Port: "9000"},
	})
	require.NoError(t, err)
	require.Equal(t, []types.RXQueueFlow{{
		DestinationIP: netip.MustParseAddr("192.0.2.10"), DestinationPort: 9001, Protocol: corev1.ProtocolUDP,
	}}, flows)

	for _, tt := range []struct {
		service, port, wantErr string
	}{
		{"missing", "rpc", "was not found"},
		{"storage", "admin", "has no port"},
		{"dns", "53", "multiple ports numbered 53"},
		{"other", "rpc", "has no endpoint on this Pod"},
	} {
		_, err := f.resolve(pod, &types.RXQueueConfig{
			ServiceEndpoint: &types.RXQueueServiceEndpoint{ServiceName: tt.service, Port: tt.port},
		})
		require.ErrorContains(t, err, tt.wantErr, tt.service)
	}
}

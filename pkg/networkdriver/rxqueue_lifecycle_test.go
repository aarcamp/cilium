// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/endpoint"
)

func TestRXQueueEndpointEventsCoalesce(t *testing.T) {
	driver := &Driver{rxQueueReconcile: make(chan struct{}, 1)}
	ep := &endpoint.Endpoint{K8sNamespace: "default", K8sPodName: "storage-0"}

	driver.EndpointCreated(ep)
	driver.EndpointRestored(ep)
	driver.EndpointDeleted(ep, endpoint.DeleteConfig{})
	require.Len(t, driver.rxQueueReconcile, 1)

	<-driver.rxQueueReconcile
	driver.EndpointCreated(&endpoint.Endpoint{})
	require.Empty(t, driver.rxQueueReconcile)
}

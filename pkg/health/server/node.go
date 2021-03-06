// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"github.com/cilium/cilium/api/v1/models"
)

type healthNode struct {
	*models.NodeElement

	// During setNodes(), we perform mark-and-sweep to get rid of IPs that
	// should no longer be probed. If deletionMark is true after the set
	// of nodes is updated, this node can be removed.
	deletionMark bool
}

// NewHealthNode creates a new node structure based on the specified model.
func NewHealthNode(elem *models.NodeElement) healthNode {
	return healthNode{
		NodeElement: elem,
	}
}

// PrimaryIP returns the primary IP address of the node.
func (n *healthNode) PrimaryIP() string {
	if n.NodeElement.PrimaryAddress.IPV4.Enabled {
		return n.NodeElement.PrimaryAddress.IPV4.IP
	}
	return n.NodeElement.PrimaryAddress.IPV6.IP
}

// HealthIP returns the IP address of the health endpoint for the node.
func (n *healthNode) HealthIP() string {
	if n.NodeElement.HealthEndpointAddress == nil {
		return ""
	}
	if n.NodeElement.HealthEndpointAddress.IPV4.Enabled {
		return n.NodeElement.HealthEndpointAddress.IPV4.IP
	}
	return n.NodeElement.HealthEndpointAddress.IPV6.IP
}

// Addresses returns a map of the node's addresses -> "primary" bool
func (n *healthNode) Addresses() map[*models.NodeAddressingElement]bool {
	addresses := map[*models.NodeAddressingElement]bool{}
	if n.NodeElement.PrimaryAddress != nil {
		addr := n.NodeElement.PrimaryAddress
		addresses[addr.IPV4] = addr.IPV4.Enabled
		addresses[addr.IPV6] = addr.IPV6.Enabled
	}
	if n.NodeElement.HealthEndpointAddress != nil {
		addresses[n.NodeElement.HealthEndpointAddress.IPV4] = false
		addresses[n.NodeElement.HealthEndpointAddress.IPV6] = false
	}
	for _, elem := range n.NodeElement.SecondaryAddresses {
		addresses[elem] = false
	}
	return addresses
}

// Copyright 2019 Authors of Cilium
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

package ipam

import (
	"fmt"
	"net"
	"sync"

	"github.com/cilium/cilium/pkg/k8s"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/node"

	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	k8score "k8s.io/kubernetes/pkg/apis/core"
)

var (
	sharedNodeStore *nodeStore
	initNodeStore   sync.Once
)

type nodeStore struct {
	mutex   lock.RWMutex
	ownNode *ciliumv2.CiliumNode
}

func newNodeStore() *nodeStore {
	log.Infof("Subscribed to CiliumNode custom resource for node %s", node.GetName())
	store := &nodeStore{}
	ciliumNPClient := k8s.CiliumClient()

	//ciliumNodeSelector := fields.ParseSelectorOrDie("metadata.name=" + node.GetName())
	ciliumNodeStore := cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
	ciliumNodeInformer := informer.NewInformerWithStore(
		cache.NewListWatchFromClient(ciliumNPClient.CiliumV2().RESTClient(),
			"ciliumnodes", v1.NamespaceAll, fields.Everything()),
		&ciliumv2.CiliumNode{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				if node, ok := obj.(*ciliumv2.CiliumNode); ok {
					log.Infof("New CiliumNode %+v", node)
					store.mutex.Lock()
					store.ownNode = node.DeepCopy()
					store.mutex.Unlock()
				} else {
					log.Warning("Unknown CiliumNode object received: %+v", obj)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				if node, ok := newObj.(*ciliumv2.CiliumNode); ok {
					log.Debugf("Updated CiliumNode %+v", node)
					store.mutex.Lock()
					store.ownNode = node.DeepCopy()
					store.mutex.Unlock()
				} else {
					log.Warning("Unknown CiliumNode object received: %+v", newObj)
				}
			},
			DeleteFunc: func(obj interface{}) {
				if node, ok := obj.(*ciliumv2.CiliumNode); ok {
					log.Debugf("Deleted CiliumNode %+v", node)
					store.mutex.Lock()
					store.ownNode = nil
					store.mutex.Unlock()
				} else {
					log.Warning("Unknown CiliumNode object received: %+v", obj)
				}
			},
		},
		func(obj interface{}) interface{} {
			cnp, _ := obj.(*ciliumv2.CiliumNode)
			return cnp
		},
		ciliumNodeStore,
	)

	go ciliumNodeInformer.Run(wait.NeverStop)

	log.Infof("Waiting for CiliumNode custom resource %s to synchronize...", node.GetName())
	if ok := cache.WaitForCacheSync(wait.NeverStop, ciliumNodeInformer.HasSynced); !ok {
		log.Fatalf("Unable to synchronize CiliumNode custom resource for node %s", node.GetName())
	} else {
		log.Infof("Successfully synchronized CiliumNode custom resource for node %s", node.GetName())
	}

	return store
}

func (n *nodeStore) allocate(ip net.IP) (*ciliumv2.AllocationIP, error) {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	if n.ownNode == nil {
		return nil, fmt.Errorf("CiliumNode for own node is not available")
	}

	if n.ownNode.Spec.IPAM.Available == nil {
		return nil, fmt.Errorf("No IPs available")
	}

	ipInfo, ok := n.ownNode.Spec.IPAM.Available[ip.String()]
	if !ok {
		return nil, fmt.Errorf("IP %s is not available", ip.String())
	}

	return &ipInfo, nil
}

func (n *nodeStore) allocateNext(allocated map[string]ciliumv2.AllocationIP, family Family) (net.IP, *ciliumv2.AllocationIP, error) {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	if n.ownNode == nil {
		return nil, nil, fmt.Errorf("CiliumNode for own node is not available")
	}

	for ip, ipInfo := range n.ownNode.Spec.IPAM.Available {
		if _, ok := allocated[ip]; !ok {
			parsedIP := net.ParseIP(ip)
			if parsedIP == nil {
				log.Warning("Unable to parse IP %s in CiliumNode %s", ip, n.ownNode.Name)
				continue
			}

			if DeriveFamily(parsedIP) != family {
				continue
			}

			return parsedIP, &ipInfo, nil
		}
	}

	return nil, nil, fmt.Errorf("No more IPs available")
}

type crdAllocator struct {
	store     *nodeStore
	mutex     lock.RWMutex
	allocated map[string]ciliumv2.AllocationIP
	family    Family
}

func newCRDAllocator(family Family) Allocator {
	initNodeStore.Do(func() {
		sharedNodeStore = newNodeStore()
	})

	allocator := &crdAllocator{
		allocated: map[string]ciliumv2.AllocationIP{},
		family:    family,
		store:     sharedNodeStore,
	}

	return allocator
}

func (a *crdAllocator) Allocate(ip net.IP) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	if _, ok := a.allocated[ip.String()]; ok {
		return fmt.Errorf("IP already in use")
	}

	ipInfo, err := a.store.allocate(ip)
	if err != nil {
		return err
	}

	a.allocated[ip.String()] = *ipInfo

	return nil
}

func (a *crdAllocator) Release(ip net.IP) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	if _, ok := a.allocated[ip.String()]; !ok {
		return fmt.Errorf("IP %s is not allocated", ip.String())
	}

	delete(a.allocated, ip.String())

	return nil
}

func (a *crdAllocator) Snapshot(r *k8score.RangeAllocation) error {
	return nil
}

func (a *crdAllocator) AllocateNext() (net.IP, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	ip, ipInfo, err := a.store.allocateNext(a.allocated, a.family)
	if err != nil {
		return nil, err
	}

	a.allocated[ip.String()] = *ipInfo
	return ip, nil
}

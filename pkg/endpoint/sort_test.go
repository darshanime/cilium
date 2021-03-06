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

// +build !privileged_tests

package endpoint

import (
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/checker"

	. "gopkg.in/check.v1"
)

func (s *EndpointSuite) TestOrderEndpointModelAsc(c *C) {
	eps := []*models.Endpoint{
		{ID: 5},
		{ID: 1000},
		{ID: 1},
		{ID: 3},
		{ID: 2},
	}
	epsWant := []*models.Endpoint{
		{ID: 1},
		{ID: 2},
		{ID: 3},
		{ID: 5},
		{ID: 1000},
	}
	OrderEndpointModelAsc(eps)
	c.Assert(eps, checker.DeepEquals, epsWant)
}

func (s *EndpointSuite) TestOrderEndpointAsc(c *C) {
	eps := []*Endpoint{
		{ID: 5},
		{ID: 1000},
		{ID: 1},
		{ID: 3},
		{ID: 2},
	}
	epsWant := []*Endpoint{
		{ID: 1},
		{ID: 2},
		{ID: 3},
		{ID: 5},
		{ID: 1000},
	}
	OrderEndpointAsc(eps)
	c.Assert(eps, checker.DeepEquals, epsWant)
}

// Copyright 2019 Istio Authors
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

package data

import (
	"bytes"

	"github.com/gogo/protobuf/jsonpb"
	"github.com/gogo/protobuf/types"

	"istio.io/istio/galley/pkg/config/resource"
)

var (
	// EntryN1I1V1 is a test resource.Entry
	EntryN1I1V1 = &resource.Entry{
		Metadata: resource.Metadata{
			Name:    resource.NewName("n1", "i1"),
			Version: "v1",
		},
		Item: parseStruct(`
{
	"n1_i1": "v1"
}`),
	}

	// EntryN1I1V1Broken is a test resource.Entry
	EntryN1I1V1Broken = &resource.Entry{
		Metadata: resource.Metadata{
			Name:    resource.NewName("n1", "i1"),
			Version: "v1",
		},
		Item: nil,
	}

	// EntryN1I1V2 is a test resource.Entry
	EntryN1I1V2 = &resource.Entry{
		Metadata: resource.Metadata{
			Name:    resource.NewName("n1", "i1"),
			Version: "v2",
		},
		Item: parseStruct(`
{
	"n1_i1": "v2"
}`),
	}

	// EntryN2I2V1 is a test resource.Entry
	EntryN2I2V1 = &resource.Entry{
		Metadata: resource.Metadata{
			Name:    resource.NewName("n2", "i2"),
			Version: "v1",
		},
		Item: parseStruct(`
{
	"n2_i2": "v1"
}`),
	}

	// EntryN2I2V2 is a test resource.Entry
	EntryN2I2V2 = &resource.Entry{
		Metadata: resource.Metadata{
			Name:    resource.NewName("n2", "i2"),
			Version: "v2",
		},
		Item: parseStruct(`{
	"n2_i2": "v2"
}`),
	}

	// EntryN3I3V1 is a test resource.Entry
	EntryN3I3V1 = &resource.Entry{
		Metadata: resource.Metadata{
			Name:    resource.NewName("n3", "i3"),
			Version: "v1",
		},
		Item: parseStruct(`{
	"n3_i3": "v1"
}`),
	}

	// EntryI1V1NoNamespace is a test resource.Entry
	EntryI1V1NoNamespace = &resource.Entry{
		Metadata: resource.Metadata{
			Name:    resource.NewName("", "i1"),
			Version: "v1",
		},
		Item: parseStruct(`{
		"n1_i1": "v1"
	}`),
	}
)

func parseStruct(s string) *types.Struct {
	m := jsonpb.Unmarshaler{}

	str := &types.Struct{}
	err := m.Unmarshal(bytes.NewReader([]byte(s)), str)
	if err != nil {
		panic(err)
	}

	return str
}

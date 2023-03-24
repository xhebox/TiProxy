// Copyright 2023 PingCAP, Inc.
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

package mysql

import "bytes"

type Handshake struct {
	Ver          string
	ConnectionID uint32
	Salt         []byte
	Filter       byte
	Cap          Capability
}

// NewHandshake parses the initial handshake received from the server.
func NewHandshake(data []byte) Handshake {
	r := Handshake{}
	pos := 1
	// skip mysql version
	ver, n := ParseNullTermString(data[1:])
	r.Ver = ver
	pos += n
	// skip connection id
	// skip salt first part
	// skip filter
	pos += 4 + 8 + 1

	// capability lower 2 bytes
	capability := uint32(Endian.Uint16(data[pos : pos+2]))
	pos += 2

	if len(data) > pos {
		// skip server charset + status
		pos += 1 + 2
		// capability flags (upper 2 bytes)
		capability = uint32(Endian.Uint16(data[pos:pos+2]))<<16 | capability

		// skip auth data len or [00]
		// skip reserved (all [00])
		// skip salt second part
		// skip auth plugin
	}
	return Capability(capability)
}

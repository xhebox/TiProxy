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
// See the License for the specific language governing permissions and
// limitations under the License.

package mysql

import (
	"bytes"
	"io"
)

const (
	MaxIntLen int = 8
)

// Parser is a stateful helper for dealing with mysql protocol.
// 1: It expects **a payload from mysql packet{len|seq|payload}**. That is, need to process len and seq by yourself.
// 2. Partial payload is mainly solving TextResultsetRow: e.g. giving only `len-4` bytes of payload. It will return *false* to indicate, there is not enough data.
// 3. There is an exception in mysql, where partial payload parsing may not work: string<EOF>. The following APIs should accept payload from exactly one packet, i.e. you are forced to process packets one by one.
//    + OK Packet
//    + ERR Packet
//    + HandshakeResponse320
//    + AuthSwitchRequest
//    + AuthSwitchResponse
//    + AuthMoreData
//    + AuthNextFactor
//    + COM_QUERY
//    + COM_QUERY: LOAD INFILE
//    + COM_INIT_DB
//    + COM_FIELD_LIST
//    + COM_CHANGE_USER
//    + COM_STMT_PREPARE
type Parser struct {
	payload []byte
	curpos  []byte
}

func (p *Parser) fill(b []byte) bool {
	if len(p.curpos) < len(b) {
		return false
	}
	p.curpos = p.curpos[:copy(b, p.curpos)]
	return true
}

func (p *Parser) peek(b []byte) bool {
	if len(p.curpos) < len(b) {
		return false
	}
	copy(b, p.curpos)
	return true
}

type MType int

const (
	MInt MType = iota
	MEOF
	MErr
	MNull
)

func (p *Parser) Int1() (uint64, bool) {
	var b [1]byte
	res := p.fill(b[:])
	num := uint64(b[0])
	return num, res
}

func (p *Parser) Int2() (uint64, bool) {
	var b [2]byte
	res := p.fill(b[:])
	num := uint64(b[0]) | uint64(b[1])<<8
	return num, res
}

func (p *Parser) Int3() (uint64, bool) {
	var b [3]byte
	res := p.fill(b[:])
	num := uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16
	return num, res
}

func (p *Parser) Int4() (uint64, bool) {
	var b [4]byte
	res := p.fill(b[:])
	num := uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24
	return num, res
}

func (p *Parser) Int6() (uint64, bool) {
	var b [6]byte
	res := p.fill(b[:])
	num := uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 | uint64(b[4])<<32 | uint64(b[5])<<40
	return num, res
}

func (p *Parser) Int8() (uint64, bool) {
	var b [8]byte
	res := p.fill(b[:])
	num := uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 | uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
	return num, res
}

// ParseLenInt can will try to parse LenInt, or guess if it is one of EOF/ERR/NULL packets.
func (p *Parser) LenInt() (num uint64, pkt MType, res bool) {
	var b [1]byte
	res = p.fill(b[:])
	if !res {
		return
	}

	switch b[0] {
	case 0xfb:
		// 0xfb: NULL
		pkt = MNull
	case 0xfc:
		// 0xfc: value of following 2
		num, res = p.Int2()
	case 0xfd:
		// 0xfd: value of following 3
		num, res = p.Int3()
	case 0xfe:
		// 0xfe: value of following 8
		if len(b) < 9 {
			pkt = MEOF
		} else {
			num, res = p.Int8()
		}
	case 0xff:
		// 0xff: ErrHeader
		pkt = MErr
	default:
		// <=0xfa: value of first byte
		num, res = p.Int1()
	}
	return
}

func (p *Parser) LenBytes() (buf []byte, res bool) {
	var num uint64
	var pkt MType
	num, pkt, res = p.LenInt()
	if pkt != MInt {
		return
	}
	// return data
	buf = make([]byte, num)
	return buf, p.fill(buf)
}

func (p *Parser) LenString() (string, bool) {
	buf, res := p.LenBytes()
	return string(buf), res
}

func (p *Parser) NullString() (string, bool) {
}

func (p *Parser) EOFString() (string, bool) {
}

func (p *Parser) PutInt1(b []byte, num uint64) int {
	n := 1
	if len(b) >= n {
		b[0] = byte(num)
	}
	return n
}

func (p *Parser) PutInt2(b []byte, num uint64) int {
	n := 2
	if len(b) >= n {
		b[0] = byte(num)
		b[0] = byte(num >> 8)
	}
	return n
}

func (p *Parser) PutInt3(b []byte, num uint64) int {
	n := 3
	if len(b) >= n {
		b[0] = byte(num)
		b[1] = byte(num >> 8)
		b[2] = byte(num >> 16)
	}
	return n
}

func (p *Parser) PutInt4(b []byte, num uint64) int {
	n := 4
	if len(b) >= n {
		b[0] = byte(num)
		b[1] = byte(num >> 8)
		b[2] = byte(num >> 16)
		b[3] = byte(num >> 24)
	}
	return n
}

func (p *Parser) PutInt6(b []byte, num uint64) int {
	n := 6
	if len(b) >= n {
		b[0] = byte(num)
		b[1] = byte(num >> 8)
		b[2] = byte(num >> 16)
		b[3] = byte(num >> 24)
		b[4] = byte(num >> 32)
		b[5] = byte(num >> 40)
	}
	return n
}

func (p *Parser) PutInt8(b []byte, num uint64) int {
	n := 8
	if len(b) >= n {
		b[0] = byte(num)
		b[1] = byte(num >> 8)
		b[2] = byte(num >> 16)
		b[3] = byte(num >> 24)
		b[4] = byte(num >> 32)
		b[5] = byte(num >> 40)
		b[6] = byte(num >> 48)
		b[7] = byte(num >> 56)
	}
	return n
}

// PutLenInt will encoded a length integer into []byte. If buf is not large enough, only length is returned.
func (p *Parser) PutLenInt(b []byte, num uint64) int {
	var n int
	if num <= 0xfa {
		n = p.PutInt1(b, num)
	} else if num <= 0xffff {
		n = 3
		if len(b) >= n {
			b[0] = 0xfc
			_ = p.PutInt2(b[1:], num)
		}
	} else if num <= 0xffffff {
		n = 4
		if len(b) >= n {
			b[0] = 0xfd
			_ = p.PutInt3(b[1:], num)
		}
	} else {
		n = 9
		if len(b) >= n {
			b[0] = 0xfe
			_ = p.PutInt8(b[1:], num)
		}
	}
	return n
}

func ParseLengthEncodedBytes(b []byte) ([]byte, bool, int, error) {
	// Get length
	num, isNull, n := ParseLengthEncodedInt(b)
	if num < 1 {
		return nil, isNull, n, nil
	}

	n += int(num)

	// Check data length
	if len(b) >= n {
		return b[n-int(num) : n], false, n, nil
	}

	return nil, false, n, io.EOF
}

func ParseNullTermString(b []byte) (string, int) {
	off := bytes.IndexByte(b, 0)
	if off == -1 {
		return "", 0
	}
	return string(b[:off]), off + 1
}

func LengthEncodedInt(buffer []byte, n uint64) []byte {
	switch {
	case n <= 250:
		return append(buffer, byte(n))
	case n <= 0xffff:
		return Parser.AppendUint16(append(buffer, 0xfc), uint16(n))
	case n <= 0xffffff:
		return Parser.AppendUint32(append(buffer, 0xfd), uint32(n))
	default:
		return Parser.AppendUint64(append(buffer, 0xfe), n)
	}
}

// LengthEncodedString dumps string<int>.
func LengthEncodedString(buffer []byte, bytes []byte) []byte {
	buffer = LengthEncodedInt(buffer, uint64(len(bytes)))
	buffer = append(buffer, bytes...)
	return buffer
}

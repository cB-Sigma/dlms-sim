package sim

import (
	"encoding/binary"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"

	"github.com/cB-Sigma/dlms/is15959"
)

// The meter side of GET, SET and ACTION "with list" (IEC 62056-5-3:2023),
// written apart from package dlms: get-request-with-list,
// set-request-with-list and -with-list-and-first-datablock (the value list
// then arrives in data blocks), action-request-with-list and
// -with-list-and-first-pblock. Answers longer than BlockSize go in blocks
// whose raw data is the encoded result list.

// listState is a SET or ACTION with list whose values arrive in blocks.
type listState struct {
	set   bool
	descs [][]byte // 9-octet descriptors
	buf   []byte
	block uint32
}

// isList reports an APDU listRequest handles.
func isList(s *session, apdu []byte) bool {
	switch [2]byte{apdu[0], apdu[1]} {
	case [2]byte{0xC0, 0x03}, [2]byte{0xC1, 0x04}, [2]byte{0xC1, 0x05}, [2]byte{0xC3, 0x03}, [2]byte{0xC3, 0x05}:
		return true
	case [2]byte{0xC1, 0x03}:
		return s.list != nil && s.list.set
	case [2]byte{0xC3, 0x06}:
		return s.list != nil && !s.list.set
	}
	return false
}

// count reads a SEQUENCE OF quantity.
func count(b []byte) (int, []byte, bool) {
	n, sz := readLen(b)
	if n < 0 || n > 255 {
		return 0, nil, false
	}
	return n, b[sz:], true
}

// dataLen is the length of one encoded Data at the start of b.
func dataLen(b []byte) (int, bool) {
	src := b
	if _, err := axdr.NewDataDecoder(&src).Decode(&src); err != nil {
		return 0, false
	}
	return len(b) - len(src), true
}

func (m *Meter) listRequest(s *session, apdu []byte) []byte {
	inv := apdu[2]
	b := apdu[3:]
	switch [2]byte{apdu[0], apdu[1]} {
	case [2]byte{0xC0, 0x03}:
		return m.getList(s, inv, b)
	case [2]byte{0xC1, 0x04}, [2]byte{0xC1, 0x05}:
		n, rest, ok := count(b)
		if !ok {
			return []byte{0xC5, 0x01, inv, 0x03}
		}
		var descs [][]byte
		for range n {
			if len(rest) < 10 || rest[9] != 0 {
				return []byte{0xC5, 0x01, inv, 0x03}
			}
			descs, rest = append(descs, rest[:9]), rest[10:]
		}
		if apdu[1] == 0x04 {
			return m.setList(s, inv, descs, rest, nil)
		}
		s.list = &listState{set: true, descs: descs, block: 1}
		return m.listBlock(s, inv, rest)
	case [2]byte{0xC3, 0x03}, [2]byte{0xC3, 0x05}:
		n, rest, ok := count(b)
		if !ok || len(rest) < 9*n {
			return []byte{0xC7, 0x01, inv, actOther, 0x00}
		}
		var descs [][]byte
		for range n {
			descs, rest = append(descs, rest[:9]), rest[9:]
		}
		if apdu[1] == 0x03 {
			return m.actionList(s, inv, descs, rest)
		}
		s.list = &listState{descs: descs, block: 1}
		return m.listBlock(s, inv, rest)
	}
	return m.listBlock(s, inv, b) // C1 03, C3 06
}

// listBlock takes one DataBlock-SA of a SET or ACTION with list.
func (m *Meter) listBlock(s *session, inv byte, b []byte) []byte {
	st := s.list
	fail := func() []byte {
		s.list = nil
		if st != nil && st.set {
			return []byte{0xC5, 0x03, inv, 0x03, 0, 0, 0, 0}
		}
		return []byte{0xC7, 0x01, inv, actOther, 0x00}
	}
	if st == nil || len(b) < 6 {
		return fail()
	}
	last := b[0] != 0
	n := binary.BigEndian.Uint32(b[1:5])
	l, sz := readLen(b[5:])
	if n != st.block || l < 0 || 5+sz+l != len(b) {
		return fail()
	}
	st.buf = append(st.buf, b[5+sz:]...)
	if !last {
		st.block++
		if st.set {
			return binary.BigEndian.AppendUint32([]byte{0xC5, 0x02, inv}, n)
		}
		return binary.BigEndian.AppendUint32([]byte{0xC7, 0x04, inv}, n)
	}
	s.list = nil
	if st.set {
		return m.setList(s, inv, st.descs, st.buf, &n)
	}
	m.mu.Lock()
	m.actBlocks += int(n)
	m.mu.Unlock()
	return m.actionList(s, inv, st.descs, st.buf)
}

func descOf(d []byte) (uint16, string, int8) {
	return binary.BigEndian.Uint16(d), obisOf(d[2:8]), int8(d[8])
}

// getList answers get-request-with-list.
func (m *Meter) getList(s *session, inv byte, b []byte) []byte {
	n, rest, ok := count(b)
	if !ok {
		return getResult(inv, 3)
	}
	out := appendLen(nil, n)
	for range n {
		if len(rest) < 10 {
			return getResult(inv, 3)
		}
		one := append([]byte{0xC0, 0x01, inv}, rest[:10]...)
		sel := rest[9]
		rest = rest[10:]
		if sel == 1 {
			if len(rest) < 1 {
				return getResult(inv, 3)
			}
			dl, ok := dataLen(rest[1:])
			if !ok {
				return getResult(inv, 3)
			}
			one = append(one, rest[:1+dl]...)
			rest = rest[1+dl:]
		}
		src := one
		req, err := gdlms.DecodeGetRequestNormal(&src)
		if err != nil {
			return getResult(inv, 3)
		}
		if !m.allowed(s, req.AttributeInfo.ClassID, req.AttributeInfo.InstanceID.String(), req.AttributeInfo.AttributeID, is15959.Read) {
			out = append(out, 0x01, 0x03)
			continue
		}
		data, rsc := m.get(req)
		if rsc != 0 {
			out = append(out, 0x01, rsc)
			continue
		}
		out = append(append(out, 0x00), data...)
	}
	if len(rest) != 0 {
		return getResult(inv, 3)
	}
	m.mu.Lock()
	m.lists++
	m.mu.Unlock()
	if len(out) <= m.BlockSize {
		return append([]byte{0xC4, 0x03, inv}, out...)
	}
	s.pending, s.block = out, 0
	return m.nextBlock(s, inv)
}

// setList applies set-request-with-list values; block is the last block
// number when they came in blocks.
func (m *Meter) setList(s *session, inv byte, descs [][]byte, values []byte, block *uint32) []byte {
	refuse := func() []byte {
		if block != nil {
			return binary.BigEndian.AppendUint32([]byte{0xC5, 0x03, inv, 0x03}, *block)
		}
		return []byte{0xC5, 0x01, inv, 0x03}
	}
	n, rest, ok := count(values)
	if !ok || n != len(descs) {
		return refuse()
	}
	vals := make([]axdr.DlmsData, n)
	for i := range n {
		src := rest
		v, err := axdr.NewDataDecoder(&src).Decode(&src)
		if err != nil {
			return refuse()
		}
		vals[i], rest = v, src
	}
	if len(rest) != 0 {
		return refuse()
	}
	res := appendLen(nil, n)
	m.mu.Lock()
	m.lists++
	for i, d := range descs {
		cls, obis, attr := descOf(d)
		m.mu.Unlock()
		allowed := m.allowed(s, cls, obis, attr, is15959.Write)
		m.mu.Lock()
		if !allowed {
			res = append(res, 0x03)
			continue
		}
		v := vals[i]
		m.sets = append(m.sets, Request{Class: cls, OBIS: obis, ID: attr, Value: &v, Client: s.client})
		m.objects[key(cls, obis, attr)] = v
		res = append(res, 0x00)
	}
	m.mu.Unlock()
	if block != nil {
		return binary.BigEndian.AppendUint32(append([]byte{0xC5, 0x04, inv}, res...), *block)
	}
	return append([]byte{0xC5, 0x05, inv}, res...)
}

// actionList runs action-request-with-list methods in order.
func (m *Meter) actionList(s *session, inv byte, descs [][]byte, params []byte) []byte {
	n, rest, ok := count(params)
	if !ok || n != len(descs) {
		return []byte{0xC7, 0x01, inv, actOther, 0x00}
	}
	out := appendLen(nil, n)
	for _, d := range descs {
		src := rest
		v, err := axdr.NewDataDecoder(&src).Decode(&src)
		if err != nil {
			return []byte{0xC7, 0x01, inv, actOther, 0x00}
		}
		rest = src
		var param *axdr.DlmsData
		if v.Tag != axdr.TagNull {
			param = &v
		}
		cls, obis, id := descOf(d)
		if !m.allowed(s, cls, obis, id, is15959.Exec) {
			out = append(out, 0x03, 0x00)
			continue
		}
		md := gdlms.CreateMethodDescriptor(cls, obis, id)
		m.mu.Lock()
		m.actions = append(m.actions, Request{Class: cls, OBIS: obis, ID: id, Value: param, Client: s.client})
		res, ret := m.cosemAction(gdlms.ActionRequestNormal{InvokePriority: inv, MethodInfo: *md, MethodParam: param})
		m.mu.Unlock()
		if ret == nil {
			out = append(out, res, 0x00)
			continue
		}
		data, rsc := encode(ret)
		if rsc != 0 {
			out = append(out, actOther, 0x00)
			continue
		}
		out = append(append(out, res, 0x01, 0x00), data...)
	}
	if len(rest) != 0 {
		return []byte{0xC7, 0x01, inv, actOther, 0x00}
	}
	m.mu.Lock()
	m.lists++
	m.mu.Unlock()
	if len(out) <= m.BlockSize {
		return append([]byte{0xC7, 0x03, inv}, out...)
	}
	s.actOut, s.actOutN = out, 0
	return m.nextActionBlock(s, inv)
}

func appendLen(b []byte, n int) []byte {
	l, _ := axdr.EncodeLength(n)
	return append(b, l...)
}

// Lists reports how many requests with list the meter served.
func (m *Meter) Lists() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lists
}

package sim

import (
	"encoding/binary"
	"fmt"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"

	"github.com/cB-Sigma/dlms/is15959"
)

// A meter reached over M-Bus (EN 13757-1:2021 9.2.1, 8.2.4) has no
// association exchange: APDUs arrive on a pre-established association.
// The M-Bus simulator hands them to HandleAPDU unprotected (the M-Bus
// side opens and seals general-glo-ciphering itself).

// Session is a pre-established association.
type Session struct{ s session }

// PreEstablished returns an association of a client that is open without
// an AARQ.
func (m *Meter) PreEstablished(client uint16) *Session {
	m.mu.Lock()
	if m.BlockSize == 0 {
		m.BlockSize = 180
	}
	m.mu.Unlock()
	return &Session{s: session{client: client, associated: true}}
}

// HandleAPDU answers one xDLMS APDU on a session.
func (m *Meter) HandleAPDU(sess *Session, apdu []byte) []byte {
	return m.handle(&sess.s, apdu)
}

// ActionBlocks reports how many ACTION parameter blocks the meter received.
func (m *Meter) ActionBlocks() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.actBlocks
}

// actionAnswer is the action-response of a finished ACTION: normal, or
// with-pblock when the return parameters are longer than BlockSize (IEC
// 62056-5-3:2023 action-response-with-pblock, the rest fetched with
// action-request-next-pblock).
func (m *Meter) actionAnswer(s *session, invoke, res byte, ret *axdr.DlmsData) []byte {
	if ret == nil {
		return []byte{0xC7, 0x01, invoke, res, 0x00}
	}
	data, rsc := encode(ret)
	if rsc != 0 {
		return []byte{0xC7, 0x01, invoke, res, 0x00}
	}
	if len(data) <= m.BlockSize {
		return cat([]byte{0xC7, 0x01, invoke, res, 0x01, 0x00}, data)
	}
	s.actOut, s.actOutN = data, 0
	return m.nextActionBlock(s, invoke)
}

func (m *Meter) nextActionBlock(s *session, invoke byte) []byte {
	n := min(m.BlockSize, len(s.actOut))
	chunk := s.actOut[:n]
	s.actOut = s.actOut[n:]
	s.actOutN++
	last := byte(0)
	if len(s.actOut) == 0 {
		last = 1
	}
	out := []byte{0xC7, 0x02, invoke, last, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(out[4:], s.actOutN)
	l, _ := axdr.EncodeLength(len(chunk))
	return cat(out, l, chunk)
}

// actionBlock handles an ACTION in parameter blocks and the requests for
// the next block of an answer.
func (m *Meter) actionBlock(s *session, apdu []byte) []byte {
	invoke := apdu[2]
	fail := func() []byte {
		s.actMethod, s.actBuf = nil, nil
		return []byte{0xC7, 0x01, invoke, actOther, 0x00}
	}
	b := apdu[3:]
	switch apdu[1] {
	case 0x02: // next-pblock of our answer
		if len(s.actOut) == 0 || len(b) < 4 || binary.BigEndian.Uint32(b) != s.actOutN {
			return fail()
		}
		return m.nextActionBlock(s, invoke)
	case 0x04: // with-first-pblock: the method descriptor, then the block
		if len(b) < 9 {
			return fail()
		}
		md := gdlms.CreateMethodDescriptor(binary.BigEndian.Uint16(b), obisOf(b[2:8]), int8(b[8]))
		s.actMethod, s.actBuf, s.actBlock = md, nil, 1
		b = b[9:]
	default: // with-pblock
		if s.actMethod == nil {
			return fail()
		}
	}
	if len(b) < 6 {
		return fail()
	}
	last := b[0] != 0
	n := binary.BigEndian.Uint32(b[1:5])
	l, sz := readLen(b[5:])
	if n != s.actBlock || l < 0 || 5+sz+l != len(b) {
		return fail()
	}
	m.mu.Lock()
	m.actBlocks++
	m.mu.Unlock()
	s.actBuf = append(s.actBuf, b[5+sz:]...)
	if !last {
		s.actBlock++
		out := []byte{0xC7, 0x04, invoke, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(out[3:], n)
		return out
	}
	src := s.actBuf
	v, err := axdr.NewDataDecoder(&src).Decode(&src)
	md := s.actMethod
	s.actMethod, s.actBuf = nil, nil
	if err != nil || len(src) != 0 {
		return []byte{0xC7, 0x01, invoke, actOther, 0x00}
	}
	req := gdlms.ActionRequestNormal{InvokePriority: invoke, MethodInfo: *md, MethodParam: &v}
	if !m.allowed(s, md.ClassID, md.InstanceID.String(), md.MethodID, is15959.Exec) {
		return []byte{0xC7, 0x01, invoke, 0x03, 0x00}
	}
	m.mu.Lock()
	m.actions = append(m.actions, Request{Class: md.ClassID, OBIS: md.InstanceID.String(), ID: md.MethodID, Value: &v, Client: s.client})
	res, ret := m.cosemAction(req)
	m.mu.Unlock()
	return m.actionAnswer(s, invoke, res, ret)
}

func obisOf(b []byte) string {
	return fmt.Sprintf("%d.%d.%d.%d.%d.%d", b[0], b[1], b[2], b[3], b[4], b[5])
}

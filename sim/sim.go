// Package sim is a DLMS/COSEM meter simulator for tests: a TCP server
// speaking the IEC 62056-47 wrapper that accepts an association (no
// security or low-level security), answers GET (normal, with block
// transfer for large data, and range-selective access on profiles), and
// records SET and ACTION requests. With HLS set it also plays the meter
// side of DLMS security (hls.go, general.go) and the security setup object
// (setup.go). It is not a conformance reference.
package sim

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"

	"github.com/cB-Sigma/dlms/hdlc"
	"github.com/cB-Sigma/dlms/is15959"
	"github.com/cB-Sigma/dlms/wrapper"
)

// Meter is a simulated meter.
type Meter struct {
	// UDPAnswerFromOtherPort makes ListenUDP answer from another port
	// than the one requests arrive on. Set before ListenUDP.
	UDPAnswerFromOtherPort bool

	// HangUpAfterAction, while above 0, makes the meter close the
	// connection after executing an ACTION, before answering it (a
	// cellular link dropping); each counts it down. Set under the
	// meter's lock (Lock).
	HangUpAfterAction int

	// Password for low-level security; empty accepts any association.
	Password string
	// RefusePublic refuses the public client's (16) association, as a
	// meter whose utility closed it does.
	RefusePublic bool
	// Loc is the meter clock's zone (default Asia/Kolkata).
	Loc *time.Location
	// BlockSize is the largest GET data sent in one response; larger data
	// goes out in blocks (default 180).
	BlockSize int
	// ActionHandler, when set, answers ACTIONs first (tests): ok false
	// leaves the method to the meter's own objects.
	ActionHandler func(class uint16, obis string, method int8, param *axdr.DlmsData) (result byte, ret *axdr.DlmsData, ok bool)
	// ServerAddress is the meter's wrapper port, and its upper HDLC
	// address (default 1).
	ServerAddress uint16
	// HDLC data link layer (hdlc.go): lower (physical) address and the
	// server address size (1, 2 or 4 octets; default 1), our negotiable
	// parameters (zero: the defaults) and the inactivity time-out (0: none).
	HDLCAddress     int
	HDLCAddressSize int
	HDLCParams      hdlc.Params
	HDLCInactivity  time.Duration
	// HDLCUserData, when set, goes in the user data subfield of the
	// meter's UA (IEC 62056-7-6 9.3, ISO/IEC 13239 5.5.3.2.3).
	HDLCUserData []byte
	// HDLCIdentify gives the meter's physical layer the identification
	// service (IEC 62056-42 6.3.3): the COSEM stack is answered.
	HDLCIdentify bool
	// HLS, when set, requires HLS-GMAC from every client but the public
	// client (16), and ciphers APDUs after the association.
	HLS *HLS
	// ClientHLS gives some clients their own authentication and keys
	// instead of HLS (an IS 15959 meter reader with low-level security
	// and ciphered APDUs, a firmware client with HLS); a client in
	// neither is served without security.
	ClientHLS map[uint16]*HLS
	// Spec, when set, makes the meter refuse the attributes and methods
	// an IS 15959 profile gives the client's association no right to
	// (objects the profile does not list are not checked).
	Spec *is15959.Spec
	// PushSecurity, when set, protects pushed data-notifications with
	// general-glo-ciphering under these keys (IS 15959 Part 2 Amendment
	// 2); PushSecurity.SystemTitle is the meter's.
	PushSecurity *HLS

	// profileRows is the entries of an IS 15959 meter's load profiles (Recapture).
	profileRows int

	mu       sync.Mutex
	objects  map[string]axdr.DlmsData
	profiles map[string]*Profile
	sets     []Request
	actions  []Request
	assocs   int
	refused  int
	// contextRefused counts AARQs refused for their application context.
	contextRefused int
	blocks         int
	actBlocks      int
	lists          int // requests with list served (list.go)
	ln             net.Listener
	serverIC       uint32
	staleIC        int
	dedicated      int
	// security setup state (setup.go)
	signed        int
	badSignatures int
	certs         []*x509.Certificate
	tlsKey        *ecdsa.PrivateKey
	keyChanges    int
	forms         map[byte]int // protected request tags seen
	broadcasts    int
	badBroadcasts int
	bcastLast     atomic.Uint32 // highest counter taken under the broadcast key (bcastSeen)
	denied        int
	pushIC        uint32
	lastPush      []byte
	image         imageState
	tokenStatus   *uint8 // SetTokenStatus
	// transports (hdlc.go, ListenUDP)
	stations  []*hdlc.Station
	events    [][]byte
	lns       []net.Listener
	pcs       []net.PacketConn
	outs      []net.Conn // DialOut connections
	discarded int        // WPDUs dropped for their version or wPort
	uiAPDUs   int        // APDUs received in HDLC UI frames
	userData  []HDLCUserData
	frmrs     []string // FRMR sent, as the station logs them
	rlrqs     map[uint16]int
}

// RLRQs is how many release requests a client sent (IEC 62056-9-7 9.2).
func (m *Meter) RLRQs(client uint16) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.rlrqs[client]
}

// hlsOf is the security configuration a session's client is held to.
func (m *Meter) hlsOf(s *session) *HLS {
	if h, ok := m.ClientHLS[s.client]; ok {
		return h
	}
	return m.HLS
}

// Request is a recorded SET or ACTION.
type Request struct {
	Class  uint16
	OBIS   string
	ID     int8 // attribute or method
	Value  *axdr.DlmsData
	Client uint16
}

// Profile is a profile generic object.
type Profile struct {
	Columns []Column
	Rows    [][]*axdr.DlmsData // first column is the clock
}

// Column is one capture object.
type Column struct {
	Class uint16
	OBIS  string
	Attr  int8
}

func key(class uint16, obis string, attr int8) string {
	return fmt.Sprintf("%d/%s/%d", class, obis, attr)
}

// Set stores an attribute value.
func (m *Meter) Set(class uint16, obis string, attr int8, v *axdr.DlmsData) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.objects == nil {
		m.objects = map[string]axdr.DlmsData{}
	}
	m.objects[key(class, obis, attr)] = *v
}

// Register stores a register's value and scaler_unit.
func (m *Meter) Register(obis string, v *axdr.DlmsData, scaler int8, unit uint8) {
	m.Set(3, obis, 2, v)
	m.Set(3, obis, 3, axdr.CreateAxdrStructure([]*axdr.DlmsData{axdr.CreateAxdrInteger(scaler), axdr.CreateAxdrEnum(unit)}))
}

// SetProfile stores a profile generic object.
func (m *Meter) SetProfile(obis string, p *Profile) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.profiles == nil {
		m.profiles = map[string]*Profile{}
	}
	m.profiles[obis] = p
}

// AddRow appends a row to a profile.
func (m *Meter) AddRow(obis string, row ...*axdr.DlmsData) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.profiles[obis]
	p.Rows = append(p.Rows, row)
}

// Sets returns the recorded SET requests.
func (m *Meter) Sets() []Request {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Request(nil), m.sets...)
}

// Actions returns the recorded ACTION requests.
func (m *Meter) Actions() []Request {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Request(nil), m.actions...)
}

// Lock takes the lock that guards the behaviour switches (HangUpAfterAction).
func (m *Meter) Lock() { m.mu.Lock() }

// Unlock releases the lock Lock took.
func (m *Meter) Unlock() { m.mu.Unlock() }

// Associations reports accepted and refused associations.
func (m *Meter) Associations() (accepted, refused int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.assocs, m.refused
}

// ContextRefusals is how many AARQs were refused because they proposed an
// application context other than HLS.Context.
func (m *Meter) ContextRefusals() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.contextRefused
}

// Blocks reports how many GET responses went out as data blocks.
func (m *Meter) Blocks() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.blocks
}

// Listen serves on addr ("127.0.0.1:0") until Close.
func (m *Meter) Listen(addr string) (string, error) {
	if m.Loc == nil {
		loc, err := time.LoadLocation("Asia/Kolkata")
		if err != nil {
			return "", err
		}
		m.Loc = loc
	}
	if m.BlockSize == 0 {
		m.BlockSize = 180
	}
	if m.ServerAddress == 0 {
		m.ServerAddress = 1
	}
	m.mu.Lock()
	if m.objects == nil {
		m.objects = map[string]axdr.DlmsData{}
	}
	if m.profiles == nil {
		m.profiles = map[string]*Profile{}
	}
	m.mu.Unlock()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	m.ln = ln
	m.mu.Unlock()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go m.serve(c)
		}
	}()
	return ln.Addr().String(), nil
}

// Close stops listening.
func (m *Meter) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, l := range m.lns {
		_ = l.Close()
	}
	for _, pc := range m.pcs {
		_ = pc.Close()
	}
	m.lns, m.pcs = nil, nil
	m.closeOut()
	if m.ln == nil {
		return nil
	}
	return m.ln.Close()
}

// boundWPort reports a destination wPort the meter serves: its logical
// device, or the all-station address, which is never answered
// (IEC 62056-4-7 5.3.5, 6.2.5.2, Table 1).
func (m *Meter) boundWPort(p uint16) bool {
	return p == m.ServerAddress || p == wrapper.AllStation
}

// Discarded counts WPDUs the meter dropped for their version or wPort.
func (m *Meter) Discarded() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.discarded
}

func (m *Meter) discard() {
	m.mu.Lock()
	m.discarded++
	m.mu.Unlock()
}

// ListenUDP serves the wrapper over UDP at addr until Close: one WPDU per
// datagram each way (IEC 62056-4-7 5.2, 5.3.3); a session per client
// address and port.
func (m *Meter) ListenUDP(addr string) (string, error) {
	m.prepare()
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return "", err
	}
	out := pc
	if m.UDPAnswerFromOtherPort {
		// A modem or meter that answers from another socket than the
		// one it listens on.
		if out, err = net.ListenPacket("udp", "127.0.0.1:0"); err != nil {
			_ = pc.Close()
			return "", err
		}
	}
	m.mu.Lock()
	m.pcs = append(m.pcs, pc)
	if out != pc {
		m.pcs = append(m.pcs, out)
	}
	m.mu.Unlock()
	go func() {
		sessions := map[string]*session{}
		buf := make([]byte, 65536)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			h, apdu, err := wrapper.ParseDatagram(buf[:n])
			if err != nil || !m.boundWPort(h.Dst) {
				m.discard()
				continue
			}
			key := fmt.Sprintf("%s/%d", from, h.Src)
			s := sessions[key]
			if s == nil {
				s = &session{client: h.Src}
				sessions[key] = s
			}
			resp := m.handle(s, append([]byte(nil), apdu...))
			if resp == nil || h.Dst == wrapper.AllStation {
				continue
			}
			b, err := wrapper.Encode(m.ServerAddress, h.Src, resp)
			if err == nil {
				_, _ = out.WriteTo(b, from)
			}
		}
	}()
	return pc.LocalAddr().String(), nil
}

type session struct {
	hangUp     bool // close the connection instead of answering
	client     uint16
	associated bool
	pending    []byte // remaining GET data for block transfer
	block      uint32
	hls        *hlsSession
	unwrapped  bool // handling a request secured() has unprotected
	inSigned   bool // handling the content of a general-signing request
	// A SET in data blocks (set-request-with-first-datablock, then
	// with-datablock): the attribute, the octets so far and the next block.
	setAttr  *gdlms.AttributeDescriptor
	setBuf   []byte
	setBlock uint32
	// An ACTION in parameter blocks (with-first-pblock, then with-pblock)
	// and an ACTION answer sent in pblocks (mbus.go).
	actMethod *gdlms.MethodDescriptor
	actBuf    []byte
	actBlock  uint32
	actOut    []byte
	actOutN   uint32
	// A SET or ACTION with list whose values arrive in blocks (list.go).
	list *listState
}

// serve answers WPDUs on a TCP connection (IEC 62056-4-7 6.3): each one
// read whole however it arrives; another version or a wPort the meter does
// not serve is discarded.
func (m *Meter) serve(c net.Conn) {
	defer c.Close()
	var s session
	for {
		h, apdu, err := wrapper.ReadWPDU(c)
		if errors.Is(err, wrapper.ErrVersion) {
			m.discard()
			continue
		}
		if err != nil {
			return
		}
		if !m.boundWPort(h.Dst) {
			m.discard()
			continue
		}
		s.client = h.Src
		resp := m.handle(&s, apdu)
		if s.hangUp {
			return // executed, the answer lost with the connection
		}
		if resp == nil || h.Dst == wrapper.AllStation {
			continue
		}
		out, err := wrapper.Encode(m.ServerAddress, s.client, resp)
		if err != nil {
			return
		}
		if _, err := c.Write(out); err != nil {
			return
		}
	}
}

var (
	aareAccepted = []byte{
		0x61, 0x29,
		0xA1, 0x09, 0x06, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x01, // LN, no ciphering
		0xA2, 0x03, 0x02, 0x01, 0x00, // accepted
		0xA3, 0x05, 0xA1, 0x03, 0x02, 0x01, 0x00, // no diagnostic
		0xBE, 0x10, 0x04, 0x0E, 0x08, 0x00, 0x06, 0x5F, 0x1F, 0x04, 0x00, 0x00, 0x18, 0x1D, 0x00, 0xB4, 0x00, 0x07,
	}
	aareRefused = []byte{
		0x61, 0x17,
		0xA1, 0x09, 0x06, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x01,
		0xA2, 0x03, 0x02, 0x01, 0x01, // rejected permanent
		0xA3, 0x05, 0xA1, 0x03, 0x02, 0x01, 0x0D, // authentication failure
	}
	aareContextRefused = []byte{
		0x61, 0x17,
		0xA1, 0x09, 0x06, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x01,
		0xA2, 0x03, 0x02, 0x01, 0x01, // rejected permanent
		0xA3, 0x05, 0xA1, 0x03, 0x02, 0x01, 0x02, // application context name not supported
	}
)

func (m *Meter) handle(s *session, apdu []byte) []byte {
	if len(apdu) < 2 {
		return nil
	}
	switch apdu[0] {
	case 0x60: // AARQ
		pw := callingAuthValue(apdu)
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.RefusePublic && s.client == 16 {
			m.refused++
			return aareRefused
		}
		if m.hlsOf(s) != nil && s.client != 16 {
			return m.hlsAARQ(s, apdu)
		}
		if m.Password != "" && pw != m.Password {
			m.refused++
			return aareRefused
		}
		m.assocs++
		s.associated = true
		return aareAccepted
	case 0x62: // RLRQ
		m.mu.Lock()
		if m.rlrqs == nil {
			m.rlrqs = map[uint16]int{}
		}
		m.rlrqs[s.client]++
		m.mu.Unlock()
		// A ciphered RLRQ is checked and answered with a ciphered RLRE
		// (IEC 62056-5-3:2023 6.3); nil means silently discarded.
		if r, ok := m.release(s, apdu); ok {
			return r
		}
		s.associated = false
		return []byte{0x63, 0x03, 0x80, 0x01, 0x00}
	}
	if m.hlsOf(s) != nil && s.client != 16 {
		if apdu[0] == 0xDF {
			return m.signedRequest(s, apdu)
		}
		if s.hls != nil && s.hls.signing && !s.inSigned {
			return []byte{0xD8, 0x01, 0x01} // signing required
		}
		_, ok := securedRequests[apdu[0]]
		if ok || apdu[0] == 0xDB || apdu[0] == 0xDC || apdu[0] == 0xDD {
			if m.policyOf(s) == 0 {
				return []byte{0xD8, 0x01, 0x01}
			}
			return m.secured(s, apdu)
		}
		// With protected APDUs, plain ones arrive only through secured.
		if m.policyOf(s) != 0 && !s.unwrapped {
			return []byte{0xD8, 0x01, 0x01}
		}
	}
	if s.hls != nil && s.hls.pending && apdu[0] == 0xC3 && apdu[1] == 0x01 {
		src := apdu
		req, err := gdlms.DecodeActionRequestNormal(&src)
		if err == nil && req.MethodInfo.ClassID == 15 && req.MethodInfo.InstanceID.String() == "0.0.40.0.0.255" &&
			req.MethodInfo.MethodID == 1 && req.MethodParam != nil {
			// gosem decodes an octet string as hex text.
			hx, _ := req.MethodParam.Value.(string)
			param, _ := hex.DecodeString(hx)
			return m.replyToHLS(s, req.InvokePriority, param)
		}
		return []byte{0xD8, 0x01, 0x01}
	}
	if !s.associated {
		return []byte{0xD8, 0x01, 0x01} // exception: service not allowed
	}
	switch {
	case isList(s, apdu):
		return m.listRequest(s, apdu)
	case apdu[0] == 0xC0 && apdu[1] == 0x01:
		src := apdu
		req, err := gdlms.DecodeGetRequestNormal(&src)
		if err != nil {
			return getResult(apdu[2], 3) // temporary failure
		}
		if !m.allowed(s, req.AttributeInfo.ClassID, req.AttributeInfo.InstanceID.String(), req.AttributeInfo.AttributeID, is15959.Read) {
			return getResult(req.InvokePriority, 3) // read-write-denied
		}
		data, rsc := m.get(req)
		if rsc != 0 {
			return getResult(req.InvokePriority, rsc)
		}
		if len(data) <= m.BlockSize {
			return append([]byte{0xC4, 0x01, req.InvokePriority, 0x00}, data...)
		}
		s.pending, s.block = data, 0
		return m.nextBlock(s, req.InvokePriority)
	case apdu[0] == 0xC0 && apdu[1] == 0x02:
		if len(s.pending) == 0 {
			return getResult(apdu[2], 3)
		}
		return m.nextBlock(s, apdu[2])
	case apdu[0] == 0xC1 && apdu[1] == 0x01:
		src := apdu
		req, err := gdlms.DecodeSetRequestNormal(&src)
		if err != nil {
			return []byte{0xC5, 0x01, apdu[2], 0x03}
		}
		if !m.allowed(s, req.AttributeInfo.ClassID, req.AttributeInfo.InstanceID.String(), req.AttributeInfo.AttributeID, is15959.Write) {
			return []byte{0xC5, 0x01, req.InvokePriority, 0x03} // read-write-denied
		}
		m.mu.Lock()
		v := req.Value
		m.sets = append(m.sets, Request{Class: req.AttributeInfo.ClassID, OBIS: req.AttributeInfo.InstanceID.String(), ID: req.AttributeInfo.AttributeID, Value: &v, Client: s.client})
		m.objects[key(req.AttributeInfo.ClassID, req.AttributeInfo.InstanceID.String(), req.AttributeInfo.AttributeID)] = v
		m.mu.Unlock()
		return []byte{0xC5, 0x01, req.InvokePriority, 0x00}
	case apdu[0] == 0xC1 && (apdu[1] == 0x02 || apdu[1] == 0x03):
		return m.setBlock(s, apdu)
	case apdu[0] == 0xC3 && (apdu[1] == 0x02 || apdu[1] == 0x04 || apdu[1] == 0x06):
		return m.actionBlock(s, apdu)
	case apdu[0] == 0xC3 && apdu[1] == 0x01:
		src := apdu
		req, err := gdlms.DecodeActionRequestNormal(&src)
		if err != nil {
			return []byte{0xC7, 0x01, apdu[2], 0x03, 0x00}
		}
		if !m.allowed(s, req.MethodInfo.ClassID, req.MethodInfo.InstanceID.String(), req.MethodInfo.MethodID, is15959.Exec) {
			return []byte{0xC7, 0x01, req.InvokePriority, 0x03, 0x00} // read-write-denied
		}
		m.mu.Lock()
		m.actions = append(m.actions, Request{Class: req.MethodInfo.ClassID, OBIS: req.MethodInfo.InstanceID.String(), ID: req.MethodInfo.MethodID, Value: req.MethodParam, Client: s.client})
		if m.HangUpAfterAction > 0 {
			m.HangUpAfterAction--
			s.hangUp = true
		}
		if m.HLS != nil && s.hls != nil && req.MethodInfo.ClassID == 64 && req.MethodInfo.InstanceID.String() == m.HLS.setupOBIS() {
			res, ret := m.setupAction(s, req)
			m.mu.Unlock()
			if ret == nil {
				return []byte{0xC7, 0x01, req.InvokePriority, res, 0x00}
			}
			data, rsc := encode(ret)
			if rsc != 0 {
				return []byte{0xC7, 0x01, req.InvokePriority, actOther, 0x00}
			}
			return cat([]byte{0xC7, 0x01, req.InvokePriority, res, 0x01, 0x00}, data)
		}
		res, ret := m.cosemAction(req)
		m.mu.Unlock()
		return m.actionAnswer(s, req.InvokePriority, res, ret)
	}
	return []byte{0xD8, 0x01, 0x02}
}

// setBlock handles a SET in data blocks (IEC 62056-5-3:2023 7.3.3):
// set-request-with-first-datablock names the attribute, each block is
// acknowledged with set-response-datablock and the last with
// set-response-last-datablock carrying the result of the whole SET.
func (m *Meter) setBlock(s *session, apdu []byte) []byte {
	invoke := apdu[2]
	fail := func(code byte) []byte {
		s.setAttr, s.setBuf = nil, nil
		return []byte{0xC5, 0x03, invoke, code, 0, 0, 0, 0}
	}
	b := apdu[3:]
	if apdu[1] == 0x02 {
		if len(b) < 10 || b[9] != 0 { // no selective access in a block SET here
			return fail(3)
		}
		cls := binary.BigEndian.Uint16(b[0:2])
		ln := b[2:8]
		attr := int8(b[8])
		obis := fmt.Sprintf("%d.%d.%d.%d.%d.%d", ln[0], ln[1], ln[2], ln[3], ln[4], ln[5])
		if !m.allowed(s, cls, obis, attr, is15959.Write) {
			return fail(3) // read-write-denied
		}
		s.setAttr, s.setBuf, s.setBlock = gdlms.CreateAttributeDescriptor(cls, obis, attr), nil, 1
		b = b[10:]
	} else if s.setAttr == nil {
		return fail(3)
	}
	if len(b) < 6 {
		return fail(3)
	}
	last := b[0] != 0
	n := binary.BigEndian.Uint32(b[1:5])
	l, sz := readLen(b[5:])
	if n != s.setBlock || l < 0 || 5+sz+l != len(b) {
		return fail(3)
	}
	s.setBuf = append(s.setBuf, b[5+sz:]...)
	if !last {
		s.setBlock++
		out := []byte{0xC5, 0x02, invoke, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(out[3:], n)
		return out
	}
	data := s.setBuf
	dec := axdr.NewDataDecoder(&data)
	v, err := dec.Decode(&data)
	a := s.setAttr
	s.setAttr, s.setBuf = nil, nil
	out := []byte{0xC5, 0x03, invoke, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(out[4:], n)
	if err != nil || len(data) != 0 {
		out[3] = 3
		return out
	}
	m.mu.Lock()
	m.sets = append(m.sets, Request{Class: a.ClassID, OBIS: a.InstanceID.String(), ID: a.AttributeID, Value: &v, Client: s.client})
	m.objects[key(a.ClassID, a.InstanceID.String(), a.AttributeID)] = v
	m.mu.Unlock()
	return out
}

func getResult(invoke byte, code byte) []byte {
	return []byte{0xC4, 0x01, invoke, 0x01, code}
}

func (m *Meter) nextBlock(s *session, invoke byte) []byte {
	m.mu.Lock()
	m.blocks++
	m.mu.Unlock()
	n := min(m.BlockSize, len(s.pending))
	chunk := s.pending[:n]
	s.pending = s.pending[n:]
	s.block++
	last := byte(0)
	if len(s.pending) == 0 {
		last = 1
	}
	var b bytes.Buffer
	b.Write([]byte{0xC4, 0x02, invoke, last})
	_ = binary.Write(&b, binary.BigEndian, s.block)
	b.WriteByte(0x00) // raw data
	l, _ := axdr.EncodeLength(len(chunk))
	b.Write(l)
	b.Write(chunk)
	return b.Bytes()
}

// get returns the encoded data of an attribute, or a data-access-result.
func (m *Meter) get(req gdlms.GetRequestNormal) ([]byte, byte) {
	a := req.AttributeInfo
	obis := a.InstanceID.String()
	m.mu.Lock()
	defer m.mu.Unlock()
	if a.ClassID == 7 {
		p := m.profiles[obis]
		if p == nil {
			return nil, 4 // object undefined
		}
		switch a.AttributeID {
		case 2:
			rows := p.Rows
			if req.SelectiveAccessInfo != nil {
				rows = m.inRange(p, req.SelectiveAccessInfo)
			}
			var list []*axdr.DlmsData
			for _, r := range rows {
				list = append(list, axdr.CreateAxdrStructure(r))
			}
			return encode(axdr.CreateAxdrArray(list))
		case 3:
			var cols []*axdr.DlmsData
			for _, c := range p.Columns {
				cols = append(cols, axdr.CreateAxdrStructure([]*axdr.DlmsData{
					axdr.CreateAxdrLongUnsigned(c.Class), axdr.CreateAxdrOctetString(c.OBIS),
					axdr.CreateAxdrInteger(c.Attr), axdr.CreateAxdrLongUnsigned(0),
				}))
			}
			return encode(axdr.CreateAxdrArray(cols))
		case 7: // entries_in_use
			if _, ok := m.objects[key(7, obis, 7)]; !ok {
				return encode(axdr.CreateAxdrDoubleLongUnsigned(uint32(len(p.Rows))))
			}
		}
		if v, ok := m.objects[key(7, obis, a.AttributeID)]; ok {
			return encode(&v)
		}
		return nil, 4
	}
	if a.ClassID == 64 && m.HLS != nil && obis == m.HLS.setupOBIS() {
		return m.setupAttribute(a.AttributeID)
	}
	if a.ClassID == 18 && a.AttributeID == 6 {
		m.imageStatusRead(obis)
	}
	if a.ClassID == 8 && obis == "0.0.1.0.0.255" && a.AttributeID == 2 {
		if _, ok := m.objects[key(8, obis, 2)]; !ok {
			return encode(axdr.CreateAxdrOctetString(fmt.Sprintf("%x", clock(time.Now(), m.Loc))))
		}
	}
	v, ok := m.objects[key(a.ClassID, obis, a.AttributeID)]
	if !ok {
		return nil, 4
	}
	return encode(&v)
}

// inRange filters profile rows by a range descriptor (IEC 62056-6-2:2023
// 4.3.6.2.9): the restricting object names the column compared, which
// must be one of the profile's capture objects; from and to are
// date-times.
func (m *Meter) inRange(p *Profile, acc *gdlms.SelectiveAccessDescriptor) [][]*axdr.DlmsData {
	items, _ := acc.AccessParameter.Value.([]*axdr.DlmsData)
	if acc.AccessSelector == 2 && len(items) == 4 { // by entry (1-based, to 0 the last)
		from, to := int(num(items[0])), int(num(items[1]))
		if to == 0 || to > len(p.Rows) {
			to = len(p.Rows)
		}
		if from < 1 || from > to {
			return nil
		}
		return p.Rows[from-1 : to]
	}
	if acc.AccessSelector != gdlms.AccessSelectorRange || len(items) != 4 {
		return nil
	}
	col := -1
	if ro, _ := items[0].Value.([]*axdr.DlmsData); len(ro) == 4 {
		ln, _ := octetsOf(ro[1])
		for i, c := range p.Columns {
			if len(ln) == 6 && uint16(num(ro[0])) == c.Class && hex.EncodeToString(ln) == obisHex(c.OBIS) && int8(num(ro[2])) == c.Attr {
				col = i
			}
		}
	}
	from, ok1 := parseClock(items[1], m.Loc)
	to, ok2 := parseClock(items[2], m.Loc)
	if col < 0 || !ok1 || !ok2 {
		return nil
	}
	var out [][]*axdr.DlmsData
	for _, r := range p.Rows {
		t, ok := parseClock(r[col], m.Loc)
		if ok && !t.Before(from) && !t.After(to) {
			out = append(out, r)
		}
	}
	return out
}

func encode(d *axdr.DlmsData) ([]byte, byte) {
	b, err := d.Encode()
	if err != nil {
		return nil, 3
	}
	return b, 0
}

// Clock encodes t as a COSEM date-time octet string in loc (deviation not
// specified), for rows and the clock object.
func Clock(t time.Time, loc *time.Location) *axdr.DlmsData {
	return axdr.CreateAxdrOctetString(fmt.Sprintf("%x", clock(t, loc)))
}

func clock(t time.Time, loc *time.Location) []byte {
	t = t.In(loc)
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b, uint16(t.Year()))
	wd := int(t.Weekday())
	if wd == 0 {
		wd = 7
	}
	b[2], b[3], b[4], b[5], b[6], b[7], b[8] = byte(t.Month()), byte(t.Day()), byte(wd), byte(t.Hour()), byte(t.Minute()), byte(t.Second()), 0
	binary.BigEndian.PutUint16(b[9:], 0x8000)
	if t.IsDST() {
		b[11] = 0x80 // clock_status: daylight saving active
	}
	return b
}

func parseClock(d *axdr.DlmsData, loc *time.Location) (time.Time, bool) {
	s, ok := d.Value.(string)
	if !ok || len(s) != 24 {
		return time.Time{}, false
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return time.Time{}, false
	}
	year := int(binary.BigEndian.Uint16(b[0:2]))
	l := loc
	if dev := binary.BigEndian.Uint16(b[9:11]); dev != 0x8000 {
		l = time.FixedZone("", -int(int16(dev))*60)
	}
	return time.Date(year, time.Month(b[2]), int(b[3]), int(b[5]), int(b[6]), int(b[7]), 0, l), true
}

// callingAuthValue finds the password in an AARQ (context tag 0xAC holding
// a GraphicString 0x80).
func callingAuthValue(aarq []byte) string {
	if len(aarq) < 2 {
		return ""
	}
	b := aarq[2:]
	for len(b) >= 2 {
		tag, l := b[0], int(b[1])
		if len(b) < 2+l {
			return ""
		}
		if tag == 0xAC && l >= 2 && b[2] == 0x80 {
			n := int(b[3])
			if 4+n <= 2+l {
				return string(b[4 : 4+n])
			}
		}
		b = b[2+l:]
	}
	return ""
}

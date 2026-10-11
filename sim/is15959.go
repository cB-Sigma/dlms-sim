package sim

// An IS 15959 meter: every object, profile, event log and push setup of
// an is15959 profile, with the associations the standard defines (public
// client without security, meter reader with low-level security, utility
// settings and firmware clients with HLS (mechanism 2, or 5), APDU protection per
// association), access rights enforced per client, the methods commands
// use (disconnect control, script tables, image transfer) acting on the
// meter's state, and pushes sent as data-notifications.

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"
	"gitlab.com/circutor-library/gosem/pkg/hdlc"

	"github.com/cB-Sigma/dlms/is15959"
)

// Keys are one association's keys (16 bytes each, suite 0).
type Keys struct {
	Key, AuthKey []byte
}

// IS15959Options configure NewIS15959.
type IS15959Options struct {
	Serial      string // meter serial number (default "00000001")
	Flag        string // manufacturer FLAG ID, 3 letters (default "SGM")
	Password    string // meter reader LLS secret (default "ABCDEFGH")
	HLSSecret   string // utility settings HLS secret, mechanism 2 (default "UTILITYSECRET016")
	FWSecret    string // firmware association HLS secret (default "FIRMWARESECRET16")
	HLSKeys     Keys   // global keys (utility settings, firmware; default for the others)
	ReaderKeys  Keys   // meter reader global keys (default HLSKeys)
	PushKeys    Keys   // push association global keys (default HLSKeys)
	IHDKeys     Keys   // the IHD association's own global keys (default 0x60…, 0x61…)
	SystemTitle []byte // the meter's (default FLAG ‖ 5 serial bytes)
	Rows        int    // rows per profile and event log (default 4)
	Now         time.Time
}

func (o *IS15959Options) defaults() {
	if o.Serial == "" {
		o.Serial = "00000001"
	}
	if o.Flag == "" {
		o.Flag = "SGM"
	}
	if o.Password == "" {
		o.Password = "ABCDEFGH"
	}
	if o.HLSSecret == "" {
		o.HLSSecret = "UTILITYSECRET016"
	}
	if o.FWSecret == "" {
		o.FWSecret = "FIRMWARESECRET16"
	}
	if o.SystemTitle == nil {
		st := []byte(o.Flag)
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], serialNumber(o.Serial))
		o.SystemTitle = append(st, n[3:]...)
	}
	if o.Rows == 0 {
		o.Rows = 4
	}
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	key := func(k *Keys, seed byte) {
		if k.Key == nil {
			k.Key = bytes.Repeat([]byte{seed}, 16)
		}
		if k.AuthKey == nil {
			k.AuthKey = bytes.Repeat([]byte{seed + 1}, 16)
		}
	}
	// One global key serves the reader, settings, firmware and push
	// associations (Part 2 clause 7.3.1 as amended).
	key(&o.HLSKeys, 0x30)
	if o.ReaderKeys.Key == nil {
		o.ReaderKeys = o.HLSKeys
	}
	if o.PushKeys.Key == nil {
		o.PushKeys = o.HLSKeys
	}
	key(&o.IHDKeys, 0x60)
}

func serialNumber(s string) uint64 {
	var n uint64
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + uint64(c-'0')
		}
	}
	return n
}

// DeviceID is the meter's device ID: FLAG ID followed by the serial
// number (IS 15959 Part 2 push capture objects).
func (o IS15959Options) DeviceID() string { return o.Flag + o.Serial }

// nameplateYear is the simulated year of manufacture: the year before now.
func (o IS15959Options) nameplateYear() int {
	if o.Now.IsZero() {
		return time.Now().Year() - 1
	}
	return o.Now.Year() - 1
}

// NewIS15959 builds a meter for an is15959 profile.
func NewIS15959(spec *is15959.Spec, o IS15959Options) *Meter {
	o.defaults()
	m := &Meter{Spec: spec, Password: "", ClientHLS: map[uint16]*HLS{}}
	loc, _ := time.LoadLocation("Asia/Kolkata")
	m.Loc = loc
	for _, a := range spec.Associations {
		policy := policyOf(a.Security)
		switch {
		case a.Auth == "low":
			k := o.ReaderKeys
			m.ClientHLS[a.Client] = &HLS{Mechanism: 1, Secret: []byte(o.Password), Policy: policy,
				SystemTitle: o.SystemTitle, Key: k.Key, AuthKey: k.AuthKey}
		case strings.HasPrefix(a.Auth, "hls"):
			// Global keys are common to the reader, settings, firmware
			// and push associations (Part 2 clause 7.3.1, Amendment 1).
			k := o.HLSKeys
			h := &HLS{Mechanism: 5, Policy: policy, SystemTitle: o.SystemTitle, Key: k.Key, AuthKey: k.AuthKey,
				SetupOBIS: a.Setup, MasterKey: bytes.Repeat([]byte{0x50}, 16)}
			if a.Auth == "hls-aes" {
				h.Mechanism, h.Secret = 2, []byte(o.HLSSecret)
				if a.Role == is15959.FW {
					h.Secret = []byte(o.FWSecret)
				}
			}
			if a.Role == is15959.US {
				m.HLS = h
			} else {
				m.ClientHLS[a.Client] = h
			}
		}
		if a.Role == is15959.IHD {
			m.ClientHLS[a.Client] = &HLS{Unauthenticated: true, Policy: policy, SystemTitle: o.SystemTitle, Key: o.IHDKeys.Key, AuthKey: o.IHDKeys.AuthKey}
		}
		if a.Role == is15959.Push {
			m.PushSecurity = &HLS{Policy: policy, SystemTitle: o.SystemTitle, Key: o.PushKeys.Key, AuthKey: o.PushKeys.AuthKey}
		}
	}
	m.populate(o)
	return m
}

func policyOf(s string) byte {
	switch s {
	case "authenticated":
		return 0x10
	case "encrypted":
		return 0x20
	case "authenticated-encrypted":
		return 0x30
	}
	return 0
}

// unitCodes maps unit symbols the catalogue uses to the COSEM unit
// enumeration and the scaler the simulated meter reports with.
var unitCodes = map[string]struct {
	code   uint8
	scaler int8
}{
	"V": {35, -2}, "A": {33, -3}, "Hz": {44, -2}, "W": {27, 0}, "kW": {27, 0}, "VA": {28, 0}, "kVA": {28, 0},
	"var": {29, 0}, "kvar": {29, 0}, "Wh": {30, 0}, "kWh": {30, 0}, "VAh": {31, 0}, "kVAh": {31, 0},
	"varh": {32, 0}, "kvarh": {32, 0}, "min": {6, 0}, "s": {7, 0}, "h": {5, 0}, "d": {4, 0}, "%": {56, 0}, "": {255, -3},
}

func (m *Meter) populate(o IS15959Options) {
	sp := m.Spec
	n := uint32(1)
	value := func(ob is15959.Object) *axdr.DlmsData {
		n++
		switch ob.OBIS {
		case "0.0.96.1.0.255":
			return axdr.CreateAxdrOctetString(hex.EncodeToString([]byte(o.Serial)))
		case "0.0.96.1.2.255", "0.0.42.0.0.255":
			return axdr.CreateAxdrOctetString(hex.EncodeToString([]byte(o.DeviceID())))
		case "0.0.96.1.1.255":
			return axdr.CreateAxdrOctetString(hex.EncodeToString([]byte("SIGMA SIM")))
		// Nameplate values a real meter would carry, instead of the
		// placeholder a type gives ("V7" for the category, 63 for the year).
		case "0.0.96.1.4.255": // year of manufacture
			return axdr.CreateAxdrLongUnsigned(uint16(o.nameplateYear()))
		case "1.0.0.2.0.255": // firmware version
			return axdr.CreateAxdrOctetString(hex.EncodeToString([]byte("SIM-1.4.2")))
		case "0.0.94.91.11.255": // meter category
			return axdr.CreateAxdrOctetString(hex.EncodeToString([]byte("C1")))
		case "0.0.94.91.12.255": // current rating
			return axdr.CreateAxdrOctetString(hex.EncodeToString([]byte("10-60A")))
		case is15959.EventStatusWord:
			return axdr.CreateAxdrBitString(strings.Repeat("0", 128))
		}
		if v := plausible(ob); v != nil {
			return v
		}
		return sample(ob.Type, n, o.Now, m.Loc)
	}
	for _, ob := range sp.Objects {
		switch ob.Class {
		case is15959.ClassProfileGeneric:
			continue
		case is15959.ClassRegister, is15959.ClassExtendedRegister, is15959.ClassDemandRegister:
			if ob.Attr == 2 {
				u := unitCodes[ob.Unit]
				v := value(ob)
				m.Set(ob.Class, ob.OBIS, 2, v)
				m.Set(ob.Class, ob.OBIS, is15959.ScalerAttr(ob.Class), axdr.CreateAxdrStructure([]*axdr.DlmsData{axdr.CreateAxdrInteger(u.scaler), axdr.CreateAxdrEnum(u.code)}))
				switch ob.Class {
				case is15959.ClassExtendedRegister:
					m.Set(ob.Class, ob.OBIS, 5, Clock(o.Now.Add(-time.Hour), m.Loc))
				case is15959.ClassDemandRegister: // last_average_value, capture_time
					m.Set(ob.Class, ob.OBIS, 3, v)
					m.Set(ob.Class, ob.OBIS, 6, Clock(o.Now.Add(-time.Hour), m.Loc))
				}
				continue
			}
		case is15959.ClassClock:
			if ob.Attr == 2 {
				continue // the clock runs
			}
		}
		if ob.Class == is15959.ClassPushSetup && ob.Attr == 2 {
			if ps := sp.PushSetup(ob.OBIS); ps != nil {
				m.SetPushList(ob.OBIS, ps.Capture)
			} else {
				m.Set(ob.Class, ob.OBIS, 2, axdr.CreateAxdrArray(nil))
			}
			continue
		}
		m.Set(ob.Class, ob.OBIS, ob.Attr, value(ob))
	}
	m.profileRows = o.Rows
	for _, p := range sp.Profiles {
		m.profileOf(p, o)
	}
	for _, l := range sp.Events {
		m.eventLog(l, o)
	}
	// Disconnect control: connected (1), control_mode 4 (remote
	// disconnection and direct remote reconnection, local disconnection).
	m.Set(is15959.ClassDisconnect, is15959.DisconnectControl, 2, axdr.CreateAxdrBoolean(true))
	m.Set(is15959.ClassDisconnect, is15959.DisconnectControl, 3, axdr.CreateAxdrEnum(1))
	m.Set(is15959.ClassDisconnect, is15959.DisconnectControl, 4, axdr.CreateAxdrEnum(4))
	// The load limiter watches the active power register: its thresholds
	// are in that register's units (monitored_value, attribute 2).
	if sp.Object("0.0.17.0.0.255", 3) != nil && sp.Object("1.0.1.7.0.255", 2) != nil {
		m.Set(is15959.ClassLimiter, "0.0.17.0.0.255", 2, axdr.CreateAxdrStructure([]*axdr.DlmsData{
			axdr.CreateAxdrLongUnsigned(is15959.ClassRegister), axdr.CreateAxdrOctetString(obisHex("1.0.1.7.0.255")), axdr.CreateAxdrInteger(2)}))
	}
	m.image = imageState{blockSize: 64}
	m.Set(is15959.ClassImageTransfer, imageTransferOBIS(sp), 2, axdr.CreateAxdrDoubleLongUnsigned(64))
	m.Set(is15959.ClassImageTransfer, imageTransferOBIS(sp), 5, axdr.CreateAxdrBoolean(true))
	m.Set(is15959.ClassImageTransfer, imageTransferOBIS(sp), 6, axdr.CreateAxdrEnum(0))
}

func imageTransferOBIS(sp *is15959.Spec) string {
	for _, mt := range sp.Methods {
		if mt.Class == is15959.ClassImageTransfer {
			return mt.OBIS
		}
	}
	return "0.0.44.0.0.255"
}

// sample is a value of an A-XDR type for the simulated meter.
func sample(typ string, n uint32, now time.Time, loc *time.Location) *axdr.DlmsData {
	switch typ {
	case "boolean":
		return axdr.CreateAxdrBoolean(true)
	case "integer":
		return axdr.CreateAxdrInteger(int8(n % 100))
	case "long":
		return axdr.CreateAxdrLong(int16(n))
	case "double-long":
		return axdr.CreateAxdrDoubleLong(int32(n) * 10)
	case "unsigned":
		return axdr.CreateAxdrUnsigned(uint8(n))
	case "enum":
		return axdr.CreateAxdrEnum(1)
	case "long-unsigned":
		return axdr.CreateAxdrLongUnsigned(uint16(n * 7))
	case "double-long-unsigned", "":
		return axdr.CreateAxdrDoubleLongUnsigned(n * 1000)
	case "long64-unsigned":
		return axdr.CreateAxdrLong64Unsigned(uint64(n) * 1000)
	case "date-time":
		return Clock(now, loc)
	case "octet-string":
		return axdr.CreateAxdrOctetString(hex.EncodeToString([]byte(fmt.Sprintf("V%d", n))))
	case "visible-string":
		return axdr.CreateAxdrVisibleString(fmt.Sprintf("V%d", n))
	case "bit-string":
		return axdr.CreateAxdrBitString(strings.Repeat("0", 16))
	case "float32":
		return axdr.CreateAxdrFloat32(float32(n))
	case "array":
		return axdr.CreateAxdrArray(nil)
	case "structure":
		return axdr.CreateAxdrStructure(nil)
	}
	return axdr.CreateAxdrDoubleLongUnsigned(n)
}

// cell is the value a capture column holds in a simulated row.
func (m *Meter) cell(c is15959.Column, at time.Time, i int) *axdr.DlmsData {
	if c.Class == is15959.ClassClock || c.OBIS == "0.0.0.1.2.255" {
		return Clock(at, m.Loc)
	}
	if v, ok := m.objects[key(c.Class, c.OBIS, c.Attr)]; ok {
		if f, ok := v.Value.(uint32); ok {
			return axdr.CreateAxdrDoubleLongUnsigned(f + uint32(i))
		}
		if f, ok := v.Value.(uint16); ok {
			return axdr.CreateAxdrLongUnsigned(f + uint16(i))
		}
		cp := v
		return &cp
	}
	if is15959.IsTimeAttr(c.Class, c.Attr) {
		return Clock(at, m.Loc)
	}
	return axdr.CreateAxdrDoubleLongUnsigned(uint32(100 + i))
}

func columnsOf(cs []is15959.Column) []Column {
	out := make([]Column, len(cs))
	for i, c := range cs {
		out[i] = Column{Class: c.Class, OBIS: c.OBIS, Attr: c.Attr}
	}
	return out
}

func (m *Meter) profileOf(p is15959.Profile, o IS15959Options) {
	m.SetProfile(p.OBIS, m.buildProfile(p, o.Now, o.Rows))
	if !scalerBuffer(p) {
		m.Set(7, p.OBIS, 4, axdr.CreateAxdrDoubleLongUnsigned(uint32(p.Period/time.Second)))
	}
}

// buildProfile is a profile's buffer at now with rows entries (callers
// hold m.mu or have the meter to themselves).
func (m *Meter) buildProfile(p is15959.Profile, now time.Time, rows int) *Profile {
	pr := &Profile{Columns: columnsOf(p.Capture)}
	if scalerBuffer(p) {
		// A scaler profile: one entry holding each column's scaler_unit.
		var row []*axdr.DlmsData
		for _, c := range p.Capture {
			if v, ok := m.objects[key(c.Class, c.OBIS, c.Attr)]; ok {
				cp := v
				row = append(row, &cp)
			} else {
				row = append(row, axdr.CreateAxdrStructure([]*axdr.DlmsData{axdr.CreateAxdrInteger(0), axdr.CreateAxdrEnum(255)}))
			}
		}
		pr.Rows = [][]*axdr.DlmsData{row}
		return pr
	}
	step := p.Period
	if step == 0 {
		step = 24 * time.Hour
	}
	end := now.Truncate(step)
	for i := rows - 1; i >= 0; i-- {
		at := end.Add(-time.Duration(i) * step)
		row := make([]*axdr.DlmsData, len(p.Capture))
		for j, c := range p.Capture {
			if p.Period > 0 {
				if v := m.periodCell(c, at, now, p.Period, rows-i); v != nil {
					row[j] = v
					continue
				}
			}
			row[j] = m.cell(c, at, rows-i)
		}
		pr.Rows = append(pr.Rows, row)
	}
	if p.Period > 0 {
		m.keepLastAverages(p, pr)
	}
	return pr
}

// scalerBuffer reports whether a profile is a scaler profile.
func scalerBuffer(p is15959.Profile) bool {
	return strings.HasPrefix(p.OBIS, "1.0.94.91.") && p.Period == 0 && isScalerProfile(p)
}

func isScalerProfile(p is15959.Profile) bool {
	for _, c := range p.Capture {
		if c.Attr == 0 || c.Attr != is15959.ScalerAttr(c.Class) {
			return false
		}
	}
	return len(p.Capture) > 0
}

// eventLog fills an event log with one row per event code (up to Rows),
// the code in the event code column.
func (m *Meter) eventLog(l is15959.EventLog, o IS15959Options) {
	pr := &Profile{Columns: columnsOf(l.Capture)}
	for i, e := range l.Codes {
		if i >= o.Rows {
			break
		}
		at := o.Now.Add(-time.Duration(len(l.Codes)-i) * time.Hour).Truncate(time.Second)
		row := make([]*axdr.DlmsData, len(l.Capture))
		for j, c := range l.Capture {
			if c.OBIS == l.CodeOBIS || strings.HasPrefix(c.OBIS, "0.0.96.11.") {
				row[j] = axdr.CreateAxdrLongUnsigned(uint16(e.Code))
				continue
			}
			row[j] = m.cell(c, at, i)
		}
		pr.Rows = append(pr.Rows, row)
		m.Set(1, l.CodeOBIS, 2, axdr.CreateAxdrLongUnsigned(uint16(e.Code)))
	}
	m.SetProfile(l.OBIS, pr)
}

// allowed checks a client's right on an attribute or method (callers do
// not hold m.mu).
func (m *Meter) allowed(s *session, class uint16, obis string, id int8, want is15959.Right) bool {
	if m.Spec == nil {
		return true
	}
	role, ok := m.Spec.RoleOf(s.client)
	if !ok {
		return true
	}
	rights, listed := m.Spec.Access(class, obis, id, want == is15959.Exec)
	if !listed {
		return true
	}
	if rights.Of(role)&want == 0 {
		m.mu.Lock()
		m.denied++
		m.mu.Unlock()
		return false
	}
	return true
}

// Denied reports how many requests were refused for lack of access rights.
func (m *Meter) Denied() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.denied
}

// imageState is the image transfer object's state (class 18).
type imageState struct {
	blockSize uint32
	id        string
	size      uint32
	blocks    map[uint32][]byte
	status    uint8 // image_transfer_status
	activated []byte
	// slow: verify and activate answer temporary-failure and finish when
	// image_transfer_status is next read; slowFail makes that
	// verification fail.
	slow, slowFail bool
	// failAfter makes the block transfer fail once after that many
	// blocks were taken (a cut link); initiates and writes count calls.
	failAfter, initiates, writes int
}

// Image returns the last activated image.
func (m *Meter) Image() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]byte(nil), m.image.activated...)
}

// cosemAction applies an action's effect on the meter state (callers
// hold m.mu) and returns the action result and optional return data.
func (m *Meter) cosemAction(req gdlms.ActionRequestNormal) (byte, *axdr.DlmsData) {
	mi := req.MethodInfo
	obis := mi.InstanceID.String()
	if m.ActionHandler != nil {
		if res, ret, ok := m.ActionHandler(mi.ClassID, obis, mi.MethodID, req.MethodParam); ok {
			return res, ret
		}
	}
	switch mi.ClassID {
	case is15959.ClassDisconnect:
		return m.disconnectAction(obis, mi.MethodID)
	case ClassTokenGateway:
		return m.tokenAction(obis, mi.MethodID, req.MethodParam)
	case is15959.ClassScriptTable:
		// A billing (MD reset) script captures the billing profile.
		if p := m.Spec; p != nil && req.MethodParam != nil {
			for _, mt := range p.Methods {
				if mt.OBIS == obis && mt.Class == is15959.ClassScriptTable && mt.Name == "billing-reset" {
					if bp, ok := m.profiles["1.0.98.1.0.255"]; ok {
						row := make([]*axdr.DlmsData, len(bp.Columns))
						for j, c := range bp.Columns {
							row[j] = m.cell(is15959.Column{Class: c.Class, OBIS: c.OBIS, Attr: c.Attr}, time.Now(), len(bp.Rows))
						}
						bp.Rows = append(bp.Rows, row)
					}
					if v, ok := m.objects[key(1, "0.0.0.1.0.255", 2)]; ok {
						if n, ok := v.Value.(uint32); ok {
							m.objects[key(1, "0.0.0.1.0.255", 2)] = *axdr.CreateAxdrDoubleLongUnsigned(n + 1)
						}
					}
				}
			}
		}
	case is15959.ClassImageTransfer:
		return m.imageAction(obis, mi.MethodID, req.MethodParam)
	}
	return 0, nil
}

// disconnectAction runs remote_disconnect (1) and remote_reconnect (2) of
// a disconnect control object by its control_mode (IEC 62056-6-2:2023
// 4.5.8, Table 31, Figure 18): mode 0 allows neither; remote_reconnect
// connects directly in modes 2 and 4 and otherwise moves a disconnected
// object to ready_for_reconnection (output still off). A meter without a
// control_mode behaves as mode 4. Callers hold m.mu.
func (m *Meter) disconnectAction(obis string, method int8) (byte, *axdr.DlmsData) {
	mode := uint8(4)
	if v, ok := m.objects[key(70, obis, 4)]; ok {
		if n, ok := v.Value.(uint8); ok {
			mode = n
		}
	}
	state := uint8(1)
	if v, ok := m.objects[key(70, obis, 3)]; ok {
		if n, ok := v.Value.(uint8); ok {
			state = n
		}
	}
	if mode == 0 || mode > 6 {
		return 250, nil // other-reason: remote control is disabled
	}
	switch method {
	case 1: // remote_disconnect: transitions b and c
		state = 0
	case 2: // remote_reconnect
		switch {
		case state != 0: // only from Disconnected (transitions a and d)
		case mode == 2 || mode == 4:
			state = 1 // a
		default:
			state = 2 // d
		}
	default:
		return 3, nil
	}
	prev := m.objects[key(70, obis, 2)]
	m.objects[key(70, obis, 3)] = *axdr.CreateAxdrEnum(state)
	m.objects[key(70, obis, 2)] = *axdr.CreateAxdrBoolean(state == 1)
	// IS 16444 (Part 1) 11.5: every connection and disconnection is an
	// event (IS 15959 control log, codes 301 and 302).
	was, _ := prev.Value.(bool)
	switch {
	case state == 0 && (was || prev.Value == nil):
		m.raiseEvent(301, time.Now())
	case state == 1 && !was:
		m.raiseEvent(302, time.Now())
	}
	return 0, nil
}

// RaiseEvent makes the meter log an event, as a meter does when the
// condition occurs or clears (a magnet, the cover opened, a load switch
// operation): a row in the event log whose codes include it, with the
// clock at, the code and the log's other capture objects, and the log's
// event code object set to it. False when no log of the profile has the
// code.
func (m *Meter) RaiseEvent(code int, at time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.raiseEvent(code, at)
}

// raiseEvent is RaiseEvent for callers holding m.mu.
func (m *Meter) raiseEvent(code int, at time.Time) bool {
	if m.Spec == nil {
		return false
	}
	for _, l := range m.Spec.Events {
		has := false
		for _, e := range l.Codes {
			has = has || e.Code == code
		}
		p := m.profiles[l.OBIS]
		if !has || p == nil {
			continue
		}
		at = at.Truncate(time.Second)
		row := make([]*axdr.DlmsData, len(l.Capture))
		for j, c := range l.Capture {
			if c.OBIS == l.CodeOBIS || strings.HasPrefix(c.OBIS, "0.0.96.11.") {
				row[j] = axdr.CreateAxdrLongUnsigned(uint16(code))
				continue
			}
			row[j] = m.cell(c, at, len(p.Rows))
		}
		p.Rows = append(p.Rows, row)
		if m.objects == nil {
			m.objects = map[string]axdr.DlmsData{}
		}
		m.objects[key(1, l.CodeOBIS, 2)] = *axdr.CreateAxdrLongUnsigned(uint16(code))
		return true
	}
	return false
}

// ClassTokenGateway is the token gateway interface class (IEC
// 62056-6-2:2023 4.6.5).
const ClassTokenGateway = 115

// SetTokenStatus sets the status_code the simulated token gateway gives
// the tokens it receives (default 3, token execution result OK).
func (m *Meter) SetTokenStatus(code uint8) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokenStatus = &code
}

// tokenAction runs the token gateway's enter (method 1, octet-string):
// the token and its time are kept (attributes 2 and 3) and token_status
// (attribute 6) is set and returned.
func (m *Meter) tokenAction(obis string, method int8, p *axdr.DlmsData) (byte, *axdr.DlmsData) {
	if method != 1 {
		return 3, nil
	}
	tok, ok := octetsOf(p)
	if !ok {
		return 9, nil // type-unmatched
	}
	code := uint8(3)
	if m.tokenStatus != nil {
		code = *m.tokenStatus
	}
	m.objects[key(ClassTokenGateway, obis, 2)] = *axdr.CreateAxdrOctetString(hex.EncodeToString(tok))
	m.objects[key(ClassTokenGateway, obis, 3)] = *Clock(time.Now(), m.Loc)
	st := axdr.CreateAxdrStructure([]*axdr.DlmsData{axdr.CreateAxdrEnum(code), axdr.CreateAxdrBitString("")})
	m.objects[key(ClassTokenGateway, obis, 6)] = *st
	return 0, st
}

func (m *Meter) imageAction(obis string, method int8, p *axdr.DlmsData) (byte, *axdr.DlmsData) {
	im := &m.image
	status := func(s uint8) {
		im.status = s
		m.objects[key(18, obis, 6)] = *axdr.CreateAxdrEnum(s)
	}
	switch method {
	case 1: // image_transfer_initiate(identifier, size)
		f := items(p)
		if len(f) != 2 {
			return 9, nil // type-unmatched
		}
		id, _ := octetsOf(f[0])
		im.id, im.size, im.blocks = string(id), uint32(num(f[1])), map[uint32][]byte{}
		im.initiates++
		m.objects[key(18, obis, 4)] = *axdr.CreateAxdrDoubleLongUnsigned(0)
		status(1)
	case 2: // image_block_transfer(number, value)
		f := items(p)
		if im.status != 1 || len(f) != 2 {
			return 2, nil // temporary failure
		}
		if im.failAfter > 0 && len(im.blocks) >= im.failAfter {
			im.failAfter = 0
			return 250, nil // other-reason: the link was cut
		}
		im.writes++
		b, _ := octetsOf(f[1])
		n := uint32(num(f[0]))
		im.blocks[n] = b
		next := uint32(0)
		for {
			if _, ok := im.blocks[next]; !ok {
				break
			}
			next++
		}
		m.objects[key(18, obis, 4)] = *axdr.CreateAxdrDoubleLongUnsigned(next)
	case 3: // image_verify
		if im.slow {
			status(2) // verification initiated
			return 2, nil
		}
		img := im.assemble()
		if uint32(len(img)) != im.size {
			status(4) // verification failed
			return 250, nil
		}
		status(3)
	case 4: // image_activate
		if im.status != 3 {
			status(7)
			return 250, nil
		}
		if im.slow {
			status(5) // activation initiated
			return 2, nil
		}
		im.activated = im.assemble()
		status(6)
	default:
		return 3, nil
	}
	return 0, nil
}

// CutImageAfter makes the image block transfer fail once after n blocks
// were taken, as a link cut half way through a transfer.
func (m *Meter) CutImageAfter(n int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.image.failAfter = n
}

// ImageCalls returns how many image_transfer_initiate and
// image_block_transfer calls the meter took.
func (m *Meter) ImageCalls() (initiates, blocks int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.image.initiates, m.image.writes
}

// SlowImage makes image_verify and image_activate answer
// temporary-failure (IEC 62056-6-2:2023 4.4.6.6.7, 4.4.6.6.9) and finish
// when image_transfer_status is next read; fail makes the verification
// fail then.
func (m *Meter) SlowImage(slow, fail bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.image.slow, m.image.slowFail = slow, fail
}

// imageStatusRead finishes a slow verification or activation when the
// status is read (callers hold m.mu).
func (m *Meter) imageStatusRead(obis string) {
	im := &m.image
	set := func(s uint8) {
		im.status = s
		m.objects[key(18, obis, 6)] = *axdr.CreateAxdrEnum(s)
	}
	switch im.status {
	case 2: // verification initiated
		if im.slowFail || uint32(len(im.assemble())) != im.size {
			set(4)
		} else {
			set(3)
		}
	case 5: // activation initiated
		im.activated = im.assemble()
		set(6)
	}
}

func (im *imageState) assemble() []byte {
	var out []byte
	for i := uint32(0); ; i++ {
		b, ok := im.blocks[i]
		if !ok {
			return out
		}
		out = append(out, b...)
	}
}

// ImageDigest is the SHA-256 of the last activated image, hex.
func (m *Meter) ImageDigest() string {
	sum := sha256.Sum256(m.Image())
	return hex.EncodeToString(sum[:])
}

// SetEventStatus sets the bits of the event status word the event push
// sends (bit 0 is the first bit).
func (m *Meter) SetEventStatus(bits ...int) {
	b := []byte(strings.Repeat("0", 128))
	for _, i := range bits {
		if i >= 0 && i < len(b) {
			b[i] = '1'
		}
	}
	m.Set(1, is15959.EventStatusWord, 2, axdr.CreateAxdrBitString(string(b)))
}

// Push sends one data-notification from a push setup of the meter's
// profile to addr over "tcp" or "udp", with the wrapper (source port 1,
// destination the push client SAP), protected with general-glo-ciphering
// when PushSecurity is set.
func (m *Meter) Push(network, addr, setupOBIS string) error {
	apdu, err := m.pushAPDU(setupOBIS)
	if err != nil {
		return err
	}
	return sendWrapped(network, addr, m.pushClient(), apdu)
}

// DialOut behaves as a meter that cannot be reached by IP (on 4G behind
// carrier NAT): it opens a TCP connection to the head end at addr, sends
// the push of setupOBIS on it so the head end knows which meter called,
// then answers wrapper requests on that same connection until it closes,
// CloseOut or Close. Listen must have run (it sets the meter's defaults);
// its listener may be closed already.
func (m *Meter) DialOut(addr, setupOBIS string) error {
	apdu, err := m.pushAPDU(setupOBIS)
	if err != nil {
		return err
	}
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return err
	}
	if _, err := c.Write(wrapperFrame(m.pushClient(), apdu)); err != nil {
		_ = c.Close()
		return err
	}
	m.mu.Lock()
	m.outs = append(m.outs, c)
	m.mu.Unlock()
	go m.serve(c)
	return nil
}

// CloseOut closes the connections DialOut opened.
func (m *Meter) CloseOut() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closeOut()
}

// closeOut closes DialOut connections (callers hold m.mu).
func (m *Meter) closeOut() {
	for _, c := range m.outs {
		_ = c.Close()
	}
	m.outs = nil
}

// PushGBT sends the push in general-block-transfer blocks of blockSize
// bytes, one wrapper frame each (IS 15959 Part 2 table 2: general block
// transfer in the push association).
func (m *Meter) PushGBT(network, addr, setupOBIS string, blockSize int) error {
	apdu, err := m.pushAPDU(setupOBIS)
	if err != nil {
		return err
	}
	c, err := net.DialTimeout(network, addr, 5*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	for _, b := range GBTBlocks(apdu, blockSize) {
		if _, err := c.Write(wrapperFrame(m.pushClient(), b)); err != nil {
			return err
		}
	}
	return nil
}

// GBTBlocks splits an APDU into general-block-transfer APDUs (streaming,
// numbered from 1, the last with the last-block bit).
func GBTBlocks(apdu []byte, size int) [][]byte {
	var out [][]byte
	for n := 1; len(apdu) > 0; n++ {
		k := min(size, len(apdu))
		ctrl := byte(0x40)
		if k == len(apdu) {
			ctrl |= 0x80
		}
		b := []byte{0xE0, ctrl, byte(n >> 8), byte(n), 0, 0}
		b = append(b, berLen(k)...)
		b = append(b, apdu[:k]...)
		out = append(out, b)
		apdu = apdu[k:]
	}
	return out
}

// PushHDLC sends the push over TCP as HDLC UI frames (destination the
// push client, source the meter's upper address 1 and lower address
// 256), split into segments of at most maxInfo information bytes.
func (m *Meter) PushHDLC(addr, setupOBIS string, maxInfo int) error {
	apdu, err := m.pushAPDU(setupOBIS)
	if err != nil {
		return err
	}
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	for _, f := range HDLCFrames(m.pushClient(), cat([]byte{0xE6, 0xE7, 0x00}, apdu), maxInfo) {
		if _, err := c.Write(f); err != nil {
			return err
		}
	}
	return nil
}

// HDLCFrames builds UI frames (segmented when needed) from a meter to a
// client.
func HDLCFrames(client uint16, info []byte, maxInfo int) [][]byte {
	var out [][]byte
	src := []byte{0x00, 0x02, 0x04, 0x01} // upper 1 (00 02), lower 256 (04 01): IEC 62056-46 6.4.2.2 four-octet form
	for len(info) > 0 {
		k := min(maxInfo, len(info))
		seg := byte(0)
		if k < len(info) {
			seg = 0x08
		}
		n := 2 + 1 + len(src) + 1 + 2 + k + 2
		f := []byte{0x7E, 0xA0 | seg | byte(n>>8)&0x07, byte(n), byte(client<<1) | 0x01}
		f = append(f, src...)
		f = append(f, 0x13) // UI, final
		cs := hdlc.FCS(f[1:])
		f = append(f, byte(cs), byte(cs>>8))
		f = append(f, info[:k]...)
		cs = hdlc.FCS(f[1:])
		f = append(f, byte(cs), byte(cs>>8), 0x7E)
		out = append(out, f)
		info = info[k:]
	}
	return out
}

func (m *Meter) pushClient() uint16 {
	if a, ok := m.Spec.Association(is15959.Push); ok {
		return a.Client
	}
	return 64
}

func wrapperFrame(client uint16, apdu []byte) []byte {
	frame := make([]byte, 8, 8+len(apdu))
	binary.BigEndian.PutUint16(frame[0:], 1)
	binary.BigEndian.PutUint16(frame[2:], 1)
	binary.BigEndian.PutUint16(frame[4:], client)
	binary.BigEndian.PutUint16(frame[6:], uint16(len(apdu)))
	return append(frame, apdu...)
}

func sendWrapped(network, addr string, client uint16, apdu []byte) error {
	c, err := net.DialTimeout(network, addr, 5*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = c.Write(wrapperFrame(client, apdu))
	return err
}

// pushAPDU builds the (protected) data-notification of a push setup from
// its push_object_list.
func (m *Meter) pushAPDU(setupOBIS string) ([]byte, error) {
	if m.Spec == nil {
		return nil, errors.New("the meter has no IS 15959 profile")
	}
	ps := m.Spec.PushSetup(setupOBIS)
	if ps == nil {
		return nil, fmt.Errorf("profile %s has no push setup %s", m.Spec.ID, setupOBIS)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	capture := ps.Capture
	if v, ok := m.objects[key(is15959.ClassPushSetup, setupOBIS, 2)]; ok {
		capture = pushList(&v)
	}
	var body []*axdr.DlmsData
	for _, c := range capture {
		switch {
		case c.Class == is15959.ClassPushSetup && c.Attr == 1:
			body = append(body, axdr.CreateAxdrOctetString(obisHex(c.OBIS)))
		case c.Class == is15959.ClassClock:
			body = append(body, Clock(time.Now(), m.Loc))
		default:
			if v, ok := m.objects[key(c.Class, c.OBIS, c.Attr)]; ok {
				cp := v
				body = append(body, &cp)
			} else {
				body = append(body, axdr.CreateAxdrNull())
			}
		}
	}
	// The structure is encoded element by element: gosem encodes
	// null-data with a stray octet, and an object the meter cannot give
	// is null-data (IEC 62056-6-2:2023 4.4.8.2.2.2).
	data := cat([]byte{0x02}, berLen(len(body)))
	for _, e := range body {
		if e.Tag == axdr.TagNull {
			data = append(data, 0x00)
			continue
		}
		b, err := e.Encode()
		if err != nil {
			return nil, err
		}
		data = append(data, b...)
	}
	apdu := cat([]byte{0x0F, 0x40, 0x00, 0x00, 0x01, 0x00}, data)
	if h := m.PushSecurity; h != nil && h.Policy != 0 {
		m.pushIC++
		k := sessionKeys{policy: h.Policy, key: h.Key, ak: h.AuthKey}
		sealed := k.seal(h.Key, h.SystemTitle, m.pushIC, apdu, nil)
		apdu = cat([]byte{0xDB}, berLen(len(h.SystemTitle)), h.SystemTitle, berLen(len(sealed)), sealed)
	}
	m.lastPush = append([]byte(nil), apdu...)
	return apdu, nil
}

// PushRaw sends an APDU in a wrapper frame (tests of malformed pushes).
func PushRaw(network, addr string, apdu []byte) error {
	frame := make([]byte, 8, 8+len(apdu))
	binary.BigEndian.PutUint16(frame[0:], 1)
	binary.BigEndian.PutUint16(frame[2:], 1)
	binary.BigEndian.PutUint16(frame[4:], 64)
	binary.BigEndian.PutUint16(frame[6:], uint16(len(apdu)))
	c, err := net.DialTimeout(network, addr, 5*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = c.Write(append(frame, apdu...))
	return err
}

func obisHex(obis string) string {
	var b []byte
	for _, p := range strings.FieldsFunc(obis, func(r rune) bool { return r == '.' }) {
		var n int
		_, _ = fmt.Sscanf(p, "%d", &n)
		b = append(b, byte(n))
	}
	return hex.EncodeToString(b)
}

// SetPushList stores a push setup's push_object_list (class 40 attribute
// 2): what Push sends.
func (m *Meter) SetPushList(obis string, cols []is15959.Column) {
	var items []*axdr.DlmsData
	for _, c := range cols {
		attr := c.Attr
		if attr == 0 {
			attr = 2
		}
		items = append(items, axdr.CreateAxdrStructure([]*axdr.DlmsData{
			axdr.CreateAxdrLongUnsigned(c.Class), axdr.CreateAxdrOctetString(obisHex(c.OBIS)),
			axdr.CreateAxdrInteger(attr), axdr.CreateAxdrLongUnsigned(0),
		}))
	}
	m.Set(is15959.ClassPushSetup, obis, 2, axdr.CreateAxdrArray(items))
}

func pushList(d *axdr.DlmsData) []is15959.Column {
	var out []is15959.Column
	for _, it := range items(d) {
		f := items(it)
		if len(f) < 3 {
			continue
		}
		ln, _ := octetsOf(f[1])
		if len(ln) != 6 {
			continue
		}
		obis := fmt.Sprintf("%d.%d.%d.%d.%d.%d", ln[0], ln[1], ln[2], ln[3], ln[4], ln[5])
		out = append(out, is15959.Column{OBIS: obis, Class: uint16(num(f[0])), Attr: int8(num(f[2]))})
	}
	return out
}

// PushIC is the invocation counter of the meter's last protected push
// (0 before the first).
func (m *Meter) PushIC() uint32 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pushIC
}

// SetPushIC sets the invocation counter the next protected push follows
// (the next push carries n+1).
func (m *Meter) SetPushIC(n uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pushIC = n
}

// LastPush is the APDU the meter pushed last (to replay it in tests).
func (m *Meter) LastPush() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]byte(nil), m.lastPush...)
}

// Value returns an attribute's stored value.
func (m *Meter) Value(class uint16, obis string, attr int8) (axdr.DlmsData, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.objects[key(class, obis, attr)]
	return v, ok
}

// Rows returns a profile's rows.
func (m *Meter) Rows(obis string) [][]*axdr.DlmsData {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p := m.profiles[obis]; p != nil {
		return append([][]*axdr.DlmsData(nil), p.Rows...)
	}
	return nil
}

// plausibleValues are register values a household meter of the simulated
// rating (10-60 A) could show, instead of the stepped placeholders sample
// gives (a maximum demand of 32,000 W beside a load of 1.7 kW): demand in
// W and energy in Wh (scaler 0, unitCodes), durations in minutes, counts.
// Tariff registers share the total between them.
var plausibleValues = map[string]uint32{
	"maxDemandActive":            4200, // W, the month's highest demand
	"maxDemandApparent":          4500, // VA
	"billingCount":               12,
	"powerOnDuration":            41760,  // min, this billing period (29 days)
	"powerOnDurationTotal":       786240, // min, about a year and a half
	"powerFailureDuration":       380,    // min
	"activeEnergyImportPeriod":   182000, // Wh this billing period
	"apparentEnergyImportPeriod": 196000,
	"tamperCount":                2,
	"programmingCount":           3,
	"loadLimit":                  6000, // W, the limiter's threshold for the sanctioned load
	"powerFailures":              17,
}

func plausible(ob is15959.Object) *axdr.DlmsData {
	name := ob.Name
	tariff := 0
	if i := strings.LastIndex(name, "T"); i > 0 && i == len(name)-2 && name[i+1] >= '1' && name[i+1] <= '8' {
		tariff = int(name[i+1] - '0')
		name = name[:i]
	}
	v, ok := plausibleValues[name]
	if !ok {
		return nil
	}
	if tariff > 0 {
		// A tariff zone's share: its demand a little lower, its energy a part of the total.
		if strings.HasPrefix(name, "maxDemand") {
			v -= uint32(tariff) * 250
		} else {
			v /= 4
		}
	}
	switch ob.Type {
	case "long-unsigned":
		return axdr.CreateAxdrLongUnsigned(uint16(min(v, 65535)))
	case "unsigned":
		return axdr.CreateAxdrUnsigned(uint8(min(v, 255)))
	case "double-long":
		return axdr.CreateAxdrDoubleLong(int32(v))
	case "long64-unsigned":
		return axdr.CreateAxdrLong64Unsigned(uint64(v))
	case "double-long-unsigned", "":
		return axdr.CreateAxdrDoubleLongUnsigned(v)
	}
	return nil
}

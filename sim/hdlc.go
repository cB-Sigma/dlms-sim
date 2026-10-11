package sim

import (
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"gitlab.com/circutor-library/gosem/pkg/axdr"

	"github.com/cB-Sigma/dlms/hdlc"
	"github.com/cB-Sigma/dlms/phy"
)

// The meter's HDLC data link layer (IEC 62056-46, the IEC 62056-7-6
// profile) is our hdlc.Station: SNRM with parameter negotiation, windowed
// and segmented I frames both ways, UI frames for unconfirmed services and
// broadcasts (answered never), pending event notifications sent in UI
// frames at the right to talk, FRMR, DM and the inactivity time-out. The
// meter's addresses are the HDLC fields of Meter: upper ServerAddress
// (default 1), lower HDLCAddress, in HDLCAddressSize octets (default 1).

func (m *Meter) prepare() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Loc == nil {
		if loc, err := time.LoadLocation("Asia/Kolkata"); err == nil {
			m.Loc = loc
		}
	}
	if m.BlockSize == 0 {
		m.BlockSize = 180
	}
	if m.ServerAddress == 0 {
		m.ServerAddress = 1
	}
	if m.HDLCAddressSize == 0 {
		m.HDLCAddressSize = 1
	}
	if m.objects == nil {
		m.objects = map[string]axdr.DlmsData{}
	}
	if m.profiles == nil {
		m.profiles = map[string]*Profile{}
	}
	// The IEC HDLC setup object of the port (IEC 62056-6-2:2023 4.7.2,
	// class 23): windows, information field lengths, inter-octet and
	// inactivity time-outs, unless a test set them.
	p := m.HDLCParams
	if p.MaxInfoTX == 0 {
		p = hdlc.Defaults()
	}
	secs := uint16((m.HDLCInactivity + time.Second - 1) / time.Second)
	for attr, v := range map[int8]*axdr.DlmsData{
		3: axdr.CreateAxdrUnsigned(uint8(p.WindowTX)), 4: axdr.CreateAxdrUnsigned(uint8(p.WindowRX)),
		5: axdr.CreateAxdrLongUnsigned(uint16(p.MaxInfoTX)), 6: axdr.CreateAxdrLongUnsigned(uint16(p.MaxInfoRX)),
		7: axdr.CreateAxdrLongUnsigned(25), 8: axdr.CreateAxdrLongUnsigned(secs),
	} {
		k := key(23, HDLCSetupOBIS, attr)
		if _, ok := m.objects[k]; !ok {
			m.objects[k] = *v
		}
	}
}

// HDLCUserData is a user data subfield a client sent in an SNRM or DISC.
type HDLCUserData struct {
	Client int
	Frame  string // "SNRM" or "DISC"
	Data   []byte
}

// HDLCUserDataReceived lists the user data subfields clients sent.
func (m *Meter) HDLCUserDataReceived() []HDLCUserData {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]HDLCUserData(nil), m.userData...)
}

// HDLCFrameRejects lists the FRMR responses sent, with their reasons.
func (m *Meter) HDLCFrameRejects() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.frmrs...)
}

// HDLCSetupOBIS is the logical name of the simulated port's IEC HDLC
// setup object.
const HDLCSetupOBIS = "0.0.22.0.0.255"

// station builds a data link layer for one session.
func (m *Meter) station(calling bool) *hdlc.Station {
	m.prepare()
	var (
		mu       sync.Mutex
		sessions = map[int]*session{}
		ui       session // unconfirmed services (UI frames): never answered
	)
	st := &hdlc.Station{
		Upper: int(m.ServerAddress), Lower: m.HDLCAddress, Size: m.HDLCAddressSize,
		Own: m.HDLCParams, Inactivity: m.HDLCInactivity, Calling: calling,
		UserData: m.HDLCUserData,
		OnUserData: func(client int, kind hdlc.Kind, data []byte) {
			m.mu.Lock()
			defer m.mu.Unlock()
			m.userData = append(m.userData, HDLCUserData{Client: client, Frame: kind.String(), Data: append([]byte(nil), data...)})
		},
		Log: func(event string) {
			if strings.HasPrefix(event, "FRMR ") {
				m.mu.Lock()
				defer m.mu.Unlock()
				m.frmrs = append(m.frmrs, event)
			}
		},
		OnLink: func(client int, up bool) {
			mu.Lock()
			defer mu.Unlock()
			if up {
				sessions[client] = &session{client: uint16(client)}
			} else {
				delete(sessions, client)
			}
		},
	}
	st.Handle = func(client int, apdu []byte, unconfirmed bool) []byte {
		if unconfirmed {
			m.mu.Lock()
			m.uiAPDUs++
			m.mu.Unlock()
			// An unconfirmed service of the client's association (its
			// link is up), or of an unconfirmed association (a broadcast).
			mu.Lock()
			s := sessions[client]
			mu.Unlock()
			if s == nil {
				ui.client = uint16(client)
				s = &ui
			}
			m.handle(s, apdu)
			return nil
		}
		mu.Lock()
		s := sessions[client]
		if s == nil {
			s = &session{client: uint16(client)}
			sessions[client] = s
		}
		mu.Unlock()
		return m.handle(s, apdu)
	}
	m.mu.Lock()
	m.stations = append(m.stations, st)
	for _, e := range m.events {
		st.Queue(e)
	}
	m.events = nil
	m.mu.Unlock()
	return st
}

func (m *Meter) dropStation(st *hdlc.Station) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, s := range m.stations {
		if s == st {
			m.stations = append(m.stations[:i], m.stations[i+1:]...)
			return
		}
	}
}

// ServeHDLC answers one HDLC session on rw (a port handed over after an
// IEC 62056-21 mode E option select) and returns nil after the DISC that
// ends the link, or when the stream ends, and the read error otherwise.
func (m *Meter) ServeHDLC(rw io.ReadWriter) error {
	st := m.station(false)
	defer m.dropStation(st)
	st.StopAfterDISC = true
	return st.Serve(rw)
}

// ListenHDLC serves HDLC on TCP connections at addr, as a meter behind a
// serial-to-Ethernet converter, until Close.
func (m *Meter) ListenHDLC(addr string) (string, error) {
	m.prepare()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	m.lns = append(m.lns, ln)
	m.mu.Unlock()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				m.serveHDLC(c, false, nil)
			}()
		}
	}()
	return ln.Addr().String(), nil
}

// QueueEvent keeps an APDU (an EventNotificationRequest or a
// data-notification) to send in a UI frame from the management logical
// device at the next right to talk (IEC 62056-46 6.4.4.7, IEC 62056-7-6
// 9.4), on every open session, or the next one to open.
func (m *Meter) QueueEvent(apdu []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.stations) == 0 {
		m.events = append(m.events, append([]byte(nil), apdu...))
		return
	}
	for _, st := range m.stations {
		st.Queue(apdu)
	}
}

// CallHDLC makes the meter call a client at addr (TCP) to report an event
// (IEC 62056-46 6.4.4.8, IEC 62056-7-6 9.4 Figure 4): the APDU waits in a
// UI frame until the client gives the right to talk (an empty UI frame
// with P, an RR or an I frame); the CALLING DEVICE parameter is set for
// the call, so the meter also answers the CALLING physical address. The
// session ends when the client closes the connection.
func (m *Meter) CallHDLC(addr string, apdu []byte) error {
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	return m.serveHDLC(c, true, apdu)
}

// identified runs the identification stage of the meter's physical layer
// (IEC 62056-42 6.3.3) when HDLCIdentify is set, and returns the
// connection the data link layer reads.
func (m *Meter) identified(c net.Conn, own func(*uint16) bool) (net.Conn, error) {
	if !m.HDLCIdentify {
		return c, nil
	}
	prefix, err := phy.ServerIdentifyFunc(c, phy.COSEM, own, 25*time.Millisecond)
	if err != nil {
		return nil, err
	}
	return &phy.Prefixed{Conn: c, Prefix: prefix}, nil
}

// ownDevice answers identification requests without a device ID and
// those naming the meter's physical address.
func (m *Meter) ownDevice(d *uint16) bool {
	return d == nil || (m.HDLCAddressSize > 1 && int(*d) == m.HDLCAddress)
}

// serveHDLC runs one physical connection: identification, then the data
// link layer (a pending UI frame first, when the meter called).
func (m *Meter) serveHDLC(c net.Conn, calling bool, apdu []byte) error {
	m.prepare()
	c, err := m.identified(c, m.ownDevice)
	if err != nil {
		return err
	}
	st := m.station(calling)
	defer m.dropStation(st)
	if apdu != nil {
		st.Queue(apdu)
	}
	return st.Serve(c)
}

// ListenHDLCModem serves the meter behind a simulated Hayes modem (IEC
// 62056-42 annex A) on TCP connections at addr: a client dials number,
// gets CONNECT, and reaches the meter's physical and data link layers
// until it escapes and hangs up.
func (m *Meter) ListenHDLCModem(addr, number string, guard time.Duration) (*phy.ModemSim, string, error) {
	m.prepare()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, "", err
	}
	m.mu.Lock()
	m.lns = append(m.lns, ln)
	m.mu.Unlock()
	modem := &phy.ModemSim{Number: number, Guard: guard, Remote: func(c net.Conn) { _ = m.serveHDLC(c, false, nil) }}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _ = modem.Serve(c) }()
		}
	}()
	return modem, ln.Addr().String(), nil
}

// CallHDLCModem makes the meter call a client through a simulated Hayes
// modem (RING until ATA, CONNECT), then offers identification and sends
// the APDU in a UI frame at the right to talk, as CallHDLC.
func (m *Meter) CallHDLCModem(addr string, apdu []byte) error {
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	modem := &phy.ModemSim{Guard: 200 * time.Millisecond, Remote: func(line net.Conn) { _ = m.serveHDLC(line, true, apdu) }}
	return modem.Call(c)
}

// HDLCPending is the number of UI frames the open sessions still hold.
func (m *Meter) HDLCPending() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := len(m.events)
	for _, st := range m.stations {
		n += st.Pending()
	}
	return n
}

// HDLCUnconfirmed counts APDUs that came in UI frames (unconfirmed
// services and broadcasts).
func (m *Meter) HDLCUnconfirmed() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.uiAPDUs
}

// SetHDLCBusy makes the meter's open HDLC sessions busy for the next n
// polls: each is answered with RNR (IEC 62056-46 6.4.3.5).
func (m *Meter) SetHDLCBusy(n int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, st := range m.stations {
		st.SetBusy(n)
	}
}

// HDLCRNRs is how many RNR frames the open sessions have sent.
func (m *Meter) HDLCRNRs() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, st := range m.stations {
		n += st.RNRs()
	}
	return n
}

// HDLCLine is several simulated meters on one multi-drop line behind one
// converter (IEC 62056-7-6 9.6): every connection reaches all of them,
// each with its own physical (lower) address.
type HDLCLine struct {
	ln    net.Listener
	mu    sync.Mutex
	lines []*hdlc.Line
	conns int
}

// ListenHDLCLine serves the meters on one line at addr (TCP).
func ListenHDLCLine(addr string, meters ...*Meter) (*HDLCLine, string, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, "", err
	}
	l := &HDLCLine{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			line := &hdlc.Line{}
			for _, m := range meters {
				line.Stations = append(line.Stations, m.station(false))
			}
			l.mu.Lock()
			l.lines = append(l.lines, line)
			l.conns++
			l.mu.Unlock()
			go func() {
				defer c.Close()
				// One identification stage for the line: a request for a
				// device ID is answered by that meter only (6.3.3.2).
				own := func(d *uint16) bool {
					for _, m := range meters {
						if m.ownDevice(d) {
							return true
						}
					}
					return false
				}
				var err error
				if c, err = meters[0].identified(c, own); err != nil {
					return
				}
				_ = line.Serve(c)
				for i, m := range meters {
					m.dropStation(line.Stations[i])
				}
			}()
		}
	}()
	return l, ln.Addr().String(), nil
}

// Connections is how many connections the line has accepted.
func (l *HDLCLine) Connections() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.conns
}

// Violations counts polls that came while another meter had the right to
// talk.
func (l *HDLCLine) Violations() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, x := range l.lines {
		n += x.Violations()
	}
	return n
}

// Close stops listening.
func (l *HDLCLine) Close() error { return l.ln.Close() }

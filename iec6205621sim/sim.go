// Package iec6205621sim is an in-process IEC 62056-21 meter for tests,
// reached over TCP as through a transparent converter with 7E1 emulated
// (parity in bit 7). It follows the same clauses as the client:
//
//   - the request is answered only for its own device address, compared
//     without leading zeros, or the general (empty) address (item 22);
//     with WakeUp it answers only after an annex B.1 NUL wake-up message;
//   - modes A and B send the data message at once (mode B "at" its own
//     rate), then accept programming commands at 300 baud;
//   - mode C waits for the option select; without one it sends the data
//     message after tt (1.5 s to 2.2 s, 6.4.3.6); the rate changes only
//     when the option select's Z equals its own (6.4.3.2); an unsupported
//     Y gives the data readout (annex A); Y '1' opens programming mode
//     with the P0 operand;
//   - mode E (Escapes `\2`): V '2' Y '2' is confirmed with ACK 2 Z 2 CR LF
//     (7E1, Figure E.4) and the connection is handed to the DLMS
//     simulator's HDLC server;
//   - programming mode: P1 password (a wrong one is answered with B0 and
//     the session ends, annex A), R1/R5/R6 reads, R3 partial block reads
//     acknowledged with ACK and repeated on NAK (Figure 21), W1/W5 writes,
//     W3 partial block writes (Figure 22), an error message "(ERxx)" for
//     an unknown address or a refused write, NAK for a command whose BCC
//     is wrong (or the next NAKCommands commands but B0), the last answer
//     repeated on NAK, and B0;
//   - annex C formatted codes (Formatted): R2 and R4 (one record per
//     partial block) reads of register, season (with the access field),
//     load profile, group (wild cards), variable, parameter and
//     manufacturer-specific records; W2/W4 writes, resets and erases; E2
//     executes, the 0000 readouts answering with data;
//   - annex B.2 (FastWakeUp): a NUL string followed by a pause is
//     acknowledged with ACK, and the session ends on B1 with ACK;
//   - mode D (BaudChar '3' with PushEvery): the data message is pushed
//     on connection and then every PushEvery, without BCC (6.4.4).
package iec6205621sim

import (
	"bufio"
	"errors"
	"fmt"
	"math/bits"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	dlmssim "github.com/cB-Sigma/dlms-sim/sim"
	p "github.com/cB-Sigma/dlms/iec6205621"
)

// Meter is the simulator.
type Meter struct {
	Manufacturer string // e.g. "ISk" (lower-case third letter: 20 ms reaction)
	BaudChar     byte   // '5' mode C at 9600; 'E' mode B at 9600; 'M' mode A; '3' with PushEvery mode D
	Escapes      string // e.g. `\2` to offer mode E
	Model        string
	Address      string // answers only "/?<Address>!" (leading zeros ignored) and "/?!" when set
	Serial       string // sent in the P0 operand
	Password     string // P1 password; empty: access level 1, commands need none
	// Registers are address → "value" or "value*unit", read out in
	// address order and served to R1.
	Registers map[string]string
	// Profile is the load profile answer (data sets text) served to R5
	// P.01, split into two partial blocks.
	Profile string
	// Partial holds R3 answers by address: the partial block data, in
	// order (the last one ends with ETX).
	Partial map[string][]string
	// Formatted holds the annex C records by code (four hex digits) or,
	// for season records, code and data field (eight): "value*unit",
	// optionally ")(YY-MM-DD hh:mm". A load profile code holds its
	// answer's data lines. Served to R2/R4, W2/W4 and E2.
	Formatted map[string]string
	// Behaviour switches (under Lock).
	CorruptBCC   int  // corrupt the BCC of this many next data blocks
	NoParity     bool // send without the parity bit (a misconfigured converter)
	RefuseWrites bool // answer writes with the error message (ER04)
	NoBCC        bool // send the readout without STX, ETX and BCC
	WakeUp       bool // answer only a request after a NUL wake-up message
	FastWakeUp   bool // annex B.2: ACK a NUL string, then serve; end on B1 with ACK
	NAKCommands  int  // answer this many next commands with NAK
	RefuseModeE  bool // answer the binary option select with NAK
	// PushEvery, for a mode D meter, is the interval between pushes.
	PushEvery time.Duration
	// DLMS answers the binary (HDLC) phase of mode E; nil drops the line
	// after a binary mode option select.
	DLMS *dlmssim.Meter

	mu       sync.Mutex
	ln       net.Listener
	addr     string
	options  []string // "V Z Y" of each option select
	writes   []string
	profiles []string // R5 requests
	commands []string // every command received: "R1 1.8.0()", "B0 ", …
	rates    []int    // the rate each session's data went at
	sessions int
	naks     int
	wakeNULs []int // NUL characters before each request
	executes []string
	wakes    int // fast wake-ups acknowledged
	// parityErrors counts received characters with odd parity (the
	// client must send 7E1).
	parityErrors int
}

// Listen starts accepting on 127.0.0.1.
func (m *Meter) Listen() error {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.ln, m.addr = ln, ln.Addr().String()
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
	return nil
}

// Addr is the listening address.
func (m *Meter) Addr() string { m.mu.Lock(); defer m.mu.Unlock(); return m.addr }

// Stop closes the listener.
func (m *Meter) Stop() { m.mu.Lock(); defer m.mu.Unlock(); _ = m.ln.Close() }

// Lock and Unlock guard the fields.
func (m *Meter) Lock() { m.mu.Lock() }

// Unlock releases Lock.
func (m *Meter) Unlock() { m.mu.Unlock() }

func snapshot[T any](m *Meter, s *[]T) []T {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]T(nil), *s...)
}

// Options returns the option selects received ("V Z Y").
func (m *Meter) Options() []string { return snapshot(m, &m.options) }

// Writes returns "address(value)" of every accepted write.
func (m *Meter) Writes() []string { return snapshot(m, &m.writes) }

// ProfileRequests returns the R5 request data received.
func (m *Meter) ProfileRequests() []string { return snapshot(m, &m.profiles) }

// Commands returns every command message received, "C D data".
func (m *Meter) Commands() []string { return snapshot(m, &m.commands) }

// Rates returns the rate each session's data went at.
func (m *Meter) Rates() []int { return snapshot(m, &m.rates) }

// Executes returns the E2 commands received, "code(data)".
func (m *Meter) Executes() []string { return snapshot(m, &m.executes) }

// FastWakes returns how many fast wake-ups were acknowledged.
func (m *Meter) FastWakes() int { m.mu.Lock(); defer m.mu.Unlock(); return m.wakes }

// WakeNULs returns the number of NUL characters before each request.
func (m *Meter) WakeNULs() []int { return snapshot(m, &m.wakeNULs) }

// Counts returns sessions opened, NAKs received and characters received
// with a wrong parity bit.
func (m *Meter) Counts() (sessions, naks, parityErrors int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sessions, m.naks, m.parityErrors
}

type link struct {
	m    *Meter
	c    net.Conn
	r    *bufio.Reader
	last []byte // the last answer, repeated on NAK
}

func (l *link) ReadByte() (byte, error) {
	b, err := l.r.ReadByte()
	if err == nil && bits.OnesCount8(b)%2 == 1 {
		l.m.mu.Lock()
		l.m.parityErrors++
		l.m.mu.Unlock()
	}
	return b & 0x7f, err
}

func (l *link) send(b []byte) {
	l.m.mu.Lock()
	noParity := l.m.NoParity
	l.m.mu.Unlock()
	out := p.WithParity(b)
	if noParity {
		for i := range out {
			out[i] &= 0x7f
		}
	}
	_, _ = l.c.Write(out)
}

// answer sends a message and keeps it for a repeat; a block's BCC is
// corrupted while CorruptBCC lasts.
func (l *link) answer(b []byte) {
	l.last = b
	out := append([]byte(nil), b...)
	l.m.mu.Lock()
	if l.m.CorruptBCC > 0 && len(out) > 2 && out[0] == p.STX {
		l.m.CorruptBCC--
		out[len(out)-1] ^= 0x01
	}
	l.m.mu.Unlock()
	l.send(out)
}

// block answers with a data block.
func (l *link) block(data string, end byte) { l.answer(p.Block("", data, false, end)) }

// request reads the request line, counting NUL characters before it.
func (l *link) request() (string, int, error) {
	nuls := 0
	var b strings.Builder
	for b.Len() < 128 {
		c, err := l.ReadByte()
		if err != nil {
			return "", nuls, err
		}
		switch {
		case c == 0 && b.Len() == 0:
			nuls++
		case c == p.LF:
			return strings.TrimRight(b.String(), "\r"), nuls, nil
		default:
			b.WriteByte(c)
		}
	}
	return "", nuls, fmt.Errorf("line too long")
}

func (l *link) line() (string, error) {
	s, _, err := l.request()
	return s, err
}

// data is the readout data block, "!" CR LF included.
func (m *Meter) data() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var keys []string
	for k := range m.Registers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s(%s)\r\n", k, m.Registers[k])
	}
	b.WriteString("!\r\n")
	return b.String()
}

// readout sends the data message and records the rate it went at.
func (l *link) readout(rate int) {
	m := l.m
	m.mu.Lock()
	m.rates = append(m.rates, rate)
	noBCC := m.NoBCC
	m.mu.Unlock()
	if noBCC {
		l.send([]byte(m.data()))
		return
	}
	l.block(m.data(), p.ETX)
}

func (m *Meter) ident() string {
	return "/" + m.Manufacturer + string(m.BaudChar) + m.Escapes + m.Model + "\r\n"
}

func (m *Meter) serve(c net.Conn) {
	defer c.Close()
	l := &link{m: m, c: c, r: bufio.NewReader(c)}
	if m.BaudChar == p.ModeDBaudChar && m.PushEvery > 0 {
		m.push(l)
		return
	}
	id, err := p.ParseIdentification(m.ident())
	if err != nil {
		return
	}
	for {
		again, err := m.session(l, id)
		if err != nil || !again {
			return
		}
	}
}

// push sends mode D messages until the connection fails.
func (m *Meter) push(l *link) {
	m.mu.Lock()
	m.sessions++
	m.mu.Unlock()
	for {
		msg := p.WithParity(p.PushMessage(m.Manufacturer, m.Model, strings.TrimSuffix(m.data(), "!\r\n")))
		m.mu.Lock()
		m.rates = append(m.rates, p.ModeDBaud)
		every := m.PushEvery
		m.mu.Unlock()
		if _, err := l.c.Write(msg); err != nil {
			return
		}
		time.Sleep(every)
	}
}

// session serves one sign-on; again is true when the connection stays
// usable for another one (a sign-on after a readout).
func (m *Meter) session(l *link, id p.Identification) (again bool, err error) {
	m.mu.Lock()
	fast := m.FastWakeUp
	m.mu.Unlock()
	if fast {
		if err := m.fastWake(l); err != nil {
			return false, err
		}
	}
	req, nuls, err := l.request()
	if err != nil {
		return false, err
	}
	m.mu.Lock()
	m.wakeNULs = append(m.wakeNULs, nuls)
	wake := m.WakeUp
	m.mu.Unlock()
	if wake && nuls < p.WakeUpNULs(300)*9/10 {
		return true, nil // asleep: the request is not seen
	}
	if !strings.HasPrefix(req, "/?") || !strings.HasSuffix(req, "!") {
		return true, nil
	}
	if !p.SameAddress(req[2:len(req)-1], m.Address) {
		return true, nil
	}
	m.mu.Lock()
	m.sessions++
	m.mu.Unlock()
	l.send([]byte(m.ident()))
	switch id.Mode {
	case p.ModeA, p.ModeB:
		// Data at once; mode B first pauses while both ends change rate
		// (6.4.2.2). Programming commands may follow at 300 baud.
		if id.Mode == p.ModeB {
			time.Sleep(optionDelay)
		}
		l.readout(id.Baud)
		return false, m.program(l, false)
	}
	// Mode C and E: the option select, or the data after tt.
	_ = l.c.SetReadDeadline(time.Now().Add(1800 * time.Millisecond))
	opt, err := l.line()
	_ = l.c.SetReadDeadline(time.Time{})
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		l.readout(300)
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if len(opt) != 4 || opt[0] != p.ACK {
		l.readout(300) // an incorrect option select: readout at 300
		return true, nil
	}
	v, z, y := opt[1], opt[2], opt[3]
	m.mu.Lock()
	m.options = append(m.options, string(v)+" "+string(z)+" "+string(y))
	hdlc, refuseE := m.DLMS, m.RefuseModeE
	m.mu.Unlock()
	rate := 300
	if z == id.BaudChar {
		rate = id.Baud
	}
	// The option select's last character left the HHU 200 ms (six
	// characters at 300 baud) after its first; the meter answers tr later
	// at the new rate.
	time.Sleep(optionDelay)
	switch {
	case y == '2' && v == '2' && id.Mode == p.ModeE:
		// Annex E: confirm at the new rate (7E1), then 8N1 and HDLC.
		if refuseE {
			l.send([]byte{p.NAK})
			return false, nil
		}
		if hdlc == nil {
			return false, nil
		}
		l.send(p.ModeEConfirm(z))
		m.mu.Lock()
		m.rates = append(m.rates, rate)
		m.mu.Unlock()
		return false, hdlc.ServeHDLC(raw{l})
	case y == '1':
		m.mu.Lock()
		m.rates = append(m.rates, rate)
		m.mu.Unlock()
		l.answer(p.Block("P0", "("+m.Serial+")", true, p.ETX))
		return false, m.program(l, true)
	case y == '0':
		l.readout(rate)
		if fast {
			return false, m.signOff(l)
		}
	default:
		// Unsupported Y (manufacturer-specific 6 to 9, reserved): the
		// data readout at 300 baud (annex A).
		l.readout(300)
	}
	return true, nil
}

// program serves programming mode until B0, a wrong password or the
// end of the connection. partialOK: partial blocks (mode C only).
func (m *Meter) program(l *link, partialOK bool) error {
	m.mu.Lock()
	authed := m.Password == ""
	m.mu.Unlock()
	var pending []string // partial blocks still to send
	var writing string   // a partial block write in progress: address(value…
	for {
		msg, err := p.ReadMessage(l, true)
		if errors.Is(err, p.ErrBCC) {
			l.send([]byte{p.NAK}) // protocol error: repeat, please
			continue
		}
		if err != nil {
			return nil // the HHU went away
		}
		switch msg.Kind {
		case p.NAK:
			m.mu.Lock()
			m.naks++
			m.mu.Unlock()
			if l.last != nil {
				l.answer(l.last)
			}
			continue
		case p.ACK:
			if len(pending) > 0 {
				b := pending[0]
				pending = pending[1:]
				end := byte(p.EOT)
				if len(pending) == 0 {
					end = p.ETX
				}
				l.block(b, end)
			}
			continue
		case p.SOH:
		default:
			continue
		}
		m.mu.Lock()
		m.commands = append(m.commands, msg.Command+" "+msg.Data)
		nak := m.NAKCommands > 0 && msg.Command != "B0"
		if nak {
			m.NAKCommands--
		}
		m.mu.Unlock()
		if nak {
			l.send([]byte{p.NAK})
			continue
		}
		pending = nil
		switch cmd := msg.Command; {
		case cmd == "B0":
			return nil
		case cmd == "B1":
			l.answer([]byte{p.ACK}) // annex B.2 sign-off
			return nil
		case cmd == "P1":
			m.mu.Lock()
			ok := msg.Data == "("+m.Password+")"
			m.mu.Unlock()
			if !ok {
				// Annex A: an invalid password is answered with a break.
				l.answer(p.Block("B0", "", false, p.ETX))
				return nil
			}
			authed = true
			l.answer([]byte{p.ACK})
		case !authed:
			l.block("(ER01)", p.ETX)
		case cmd == "R3":
			addr := strings.TrimSuffix(msg.Data, ")")
			if i := strings.IndexByte(addr, '('); i >= 0 {
				addr = addr[:i]
			}
			m.mu.Lock()
			blocks := append([]string(nil), m.Partial[addr]...)
			m.mu.Unlock()
			if !partialOK || len(blocks) == 0 {
				l.block("(ER03)", p.ETX)
				continue
			}
			pending = blocks[1:]
			end := byte(p.EOT)
			if len(pending) == 0 {
				end = p.ETX
			}
			l.block(blocks[0], end)
		case cmd == "R2" || cmd == "R4" && partialOK:
			code, data, _ := strings.Cut(strings.TrimSuffix(msg.Data, ")"), "(")
			lines, e := m.formattedAnswer(code, data)
			if e != "" {
				l.block(e, p.ETX)
				continue
			}
			pending = sendLines(l, lines, cmd == "R4")
		case cmd == "E2":
			code, data, _ := strings.Cut(strings.TrimSuffix(msg.Data, ")"), "(")
			lines, ack, e := m.execute(code, data)
			switch {
			case e != "":
				l.block(e, p.ETX)
			case ack:
				l.answer([]byte{p.ACK})
			default:
				pending = sendLines(l, lines, false)
			}
		case cmd == "R1" || cmd == "R5" || cmd == "R6":
			i := strings.IndexByte(msg.Data, '(')
			if i < 0 {
				l.block("(ER02)", p.ETX)
				continue
			}
			addr := msg.Data[:i]
			if cmd == "R5" && strings.HasPrefix(addr, "P.") {
				m.mu.Lock()
				m.profiles = append(m.profiles, msg.Data)
				prof := m.Profile
				m.mu.Unlock()
				cut := strings.Index(prof, "\r\n")
				if cut < 0 || cut+2 >= len(prof) {
					l.block(prof, p.ETX)
					continue
				}
				pending = []string{prof[cut+2:]}
				l.block(prof[:cut+2], p.EOT)
				continue
			}
			m.mu.Lock()
			v, ok := m.Registers[addr]
			m.mu.Unlock()
			if !ok {
				l.block("(ER03)", p.ETX)
				continue
			}
			l.block(addr+"("+v+")", p.ETX)
		case cmd == "W1" || cmd == "W5" || cmd == "W2" || (cmd == "W3" || cmd == "W4") && partialOK:
			if (cmd == "W3" || cmd == "W4") && (msg.Partial || writing != "") {
				// Partial block write: the address is in the first block
				// only; each block is acknowledged (Figure 22).
				d := msg.Data
				if writing != "" {
					d = strings.TrimPrefix(d, "(")
					writing = strings.TrimSuffix(writing, ")")
				}
				writing += d
				if msg.Partial {
					l.answer([]byte{p.ACK})
					continue
				}
				msg.Data, writing = writing, ""
			}
			if cmd == "W2" || cmd == "W4" {
				code, value, _ := strings.Cut(strings.TrimSuffix(msg.Data, ")"), "(")
				if e := m.formattedWrite(code, value); e != "" {
					l.block(e, p.ETX)
				} else {
					l.answer([]byte{p.ACK})
				}
				continue
			}
			m.mu.Lock()
			refuse := m.RefuseWrites
			i := strings.IndexByte(msg.Data, '(')
			ok := i > 0 && strings.HasSuffix(msg.Data, ")")
			if !refuse && ok {
				m.Registers[msg.Data[:i]] = msg.Data[i+1 : len(msg.Data)-1]
				m.writes = append(m.writes, msg.Data)
			}
			m.mu.Unlock()
			switch {
			case refuse:
				l.block("(ER04)", p.ETX)
			case !ok:
				l.block("(ER02)", p.ETX)
			default:
				l.answer([]byte{p.ACK})
			}
		default:
			l.block("(ER05)", p.ETX)
		}
	}
}

// fastWake waits for a NUL string followed by a pause and answers it
// with ACK (annex B.2); anything else before that is not seen.
func (m *Meter) fastWake(l *link) error {
	nuls := 0
	for {
		if nuls > 0 {
			_ = l.c.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
		}
		c, err := l.ReadByte()
		_ = l.c.SetReadDeadline(time.Time{})
		var ne net.Error
		if nuls > 0 && errors.As(err, &ne) && ne.Timeout() {
			time.Sleep(15 * time.Millisecond) // Ta: at least 10 ms
			l.send([]byte{p.ACK})
			m.mu.Lock()
			m.wakes++
			m.mu.Unlock()
			return nil
		}
		if err != nil {
			return err
		}
		if c == 0 {
			nuls++
		} else {
			nuls = 0
		}
	}
}

// signOff waits for B1 after a readout of a fast-woken meter and
// acknowledges it.
func (m *Meter) signOff(l *link) error {
	for {
		msg, err := p.ReadMessage(l, true)
		if err != nil {
			return nil
		}
		if msg.Kind == p.SOH {
			m.mu.Lock()
			m.commands = append(m.commands, msg.Command+" "+msg.Data)
			m.mu.Unlock()
			if msg.Command == "B1" {
				l.send([]byte{p.ACK})
				return nil
			}
		}
	}
}

// sendLines answers with data lines, in one block or, for a partial
// block command, one line per block (the rest queued for ACKs).
func sendLines(l *link, lines []string, partial bool) []string {
	if !partial || len(lines) < 2 {
		l.block(strings.Join(lines, "\r\n"), p.ETX)
		return nil
	}
	l.block(lines[0], p.EOT)
	return lines[1:]
}

// optionDelay is the line time of an option select at 300 baud plus the
// meter's reaction time tr.
const optionDelay = 400 * time.Millisecond

// raw is the connection in the binary phase: no parity handling.
type raw struct{ l *link }

func (r raw) Read(b []byte) (int, error)  { return r.l.r.Read(b) }
func (r raw) Write(b []byte) (int, error) { return r.l.c.Write(b) }

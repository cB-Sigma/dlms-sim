package sim_test

import (
	"bytes"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/dlms-sim/sim"
	"github.com/cB-Sigma/dlms/hdlc"
	"github.com/cB-Sigma/dlms/phy"
)

func startHDLCMeter(t *testing.T) (*sim.Meter, string) {
	t.Helper()
	m := &sim.Meter{HDLCAddress: 0x11, HDLCAddressSize: 2, HDLCUserData: []byte("meter-ud")}
	addr, err := m.ListenHDLC("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m, addr
}

// The user data subfield end to end (IEC 62056-7-6 9.3, ISO/IEC 13239
// 5.5.3.2.3): our client puts its user data in the SNRM and the DISC, the
// simulated meter puts its own in the UA, each as identifier 0xFF followed
// by the data to the end of the information field, and each side reads
// the other's.
//
// Covers: SIG-IPE-2708
func TestHDLCUserDataSubfieldE2E(t *testing.T) {
	m, addr := startHDLCMeter(t)
	line, err := phy.NewPort(phy.Config{Open: func() (net.Conn, error) { return net.DialTimeout("tcp", addr, 2*time.Second) }, CommandTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	c, err := hdlc.NewClient(line, hdlc.Config{Client: 0x10, Server: hdlc.ServerAddress(1, 0x11, 2),
		UserData: []byte("snrm-ud"), DISCUserData: []byte("disc-ud"), ResponseTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	if got := c.PeerUserData(); string(got) != "meter-ud" {
		t.Errorf("the meter's user data %q, want meter-ud", got)
	}
	if err := c.Disconnect(); err != nil {
		t.Fatal(err)
	}
	got := m.HDLCUserDataReceived()
	if len(got) != 2 || got[0].Frame != "SNRM" || string(got[0].Data) != "snrm-ud" || got[1].Frame != "DISC" || string(got[1].Data) != "disc-ud" || got[0].Client != 0x10 {
		t.Errorf("the meter received %+v", got)
	}
}

// rawLink is a client written by hand, to send what our client never does.
type rawLink struct {
	t    *testing.T
	c    net.Conn
	scan hdlc.Scanner
	got  [][]byte
}

func (r *rawLink) send(control byte, info []byte) {
	r.t.Helper()
	b, err := hdlc.Frame{Dest: hdlc.ServerAddress(1, 0x11, 2), Src: hdlc.ClientAddress(0x10), Control: control, Info: info}.Encode()
	if err != nil {
		r.t.Fatal(err)
	}
	if _, err := r.c.Write(b); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rawLink) recv() hdlc.Frame {
	r.t.Helper()
	buf := make([]byte, 512)
	for len(r.got) == 0 {
		_ = r.c.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := r.c.Read(buf)
		if err != nil {
			r.t.Fatalf("no answer: %v", err)
		}
		r.got = append(r.got, r.scan.Feed(buf[:n], time.Now())...)
	}
	f, err := hdlc.Decode(r.got[0])
	r.got = r.got[1:]
	if err != nil {
		r.t.Fatal(err)
	}
	return f
}

func (r *rawLink) connect() {
	r.t.Helper()
	r.send(0x93, nil) // SNRM, P 1
	if f := r.recv(); hdlc.ParseControl(f.Control).Kind != hdlc.KindUA {
		r.t.Fatalf("SNRM answered with %v", hdlc.ParseControl(f.Control).Kind)
	}
}

// The simulated meter's FRMR carries the reason in the ISO/IEC 13239
// 5.5.3.4.2 modulo 8 layout (IEC 62056-46 6.4.3.10, 6.4.4.9.4): a control
// field it does not implement (REJ) sets W; an RR with an information field
// sets W and X; an N(R) for frames it never sent sets Z; an information
// field longer than negotiated sets Y. Each carries the rejected control
// field, the meter's V(S) and V(R) and C/R 0 (a command was rejected), and
// the meter logs the reason.
//
// Covers: SIG-IPE-2709
func TestHDLCFrameRejectReasonsE2E(t *testing.T) {
	m, addr := startHDLCMeter(t)
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	r := &rawLink{t: t, c: conn}
	for _, tc := range []struct {
		name    string
		control byte
		info    []byte
		want    hdlc.FrameReject
		reason  string
	}{
		{"REJ", 0x19, nil, hdlc.FrameReject{W: true}, "control field undefined or not implemented"},
		{"RR with information", 0x11, []byte{0x01}, hdlc.FrameReject{W: true, X: true}, "information field not permitted"},
		{"I with N(R) 3", 0x70, []byte{0xE6, 0xE6, 0x00, 0xC0}, hdlc.FrameReject{Z: true}, "invalid N(R)"},
		{"I of 200 octets", 0x10, bytes.Repeat([]byte{0xE6}, 200), hdlc.FrameReject{Y: true}, "information field too long"},
	} {
		r.connect()
		r.send(tc.control, tc.info)
		f := r.recv()
		if k := hdlc.ParseControl(f.Control); k.Kind != hdlc.KindFRMR || !k.PF {
			t.Fatalf("%s: answered with %+v", tc.name, k)
		}
		if len(f.Info) != 3 {
			t.Fatalf("%s: FRMR field % X, want three octets (Figure 18a)", tc.name, f.Info)
		}
		got, err := hdlc.DecodeFrameReject(f.Info, 8)
		if err != nil {
			t.Fatal(err)
		}
		want := tc.want
		want.Modulo, want.Control = 8, uint16(tc.control)
		if got != want {
			t.Errorf("%s: FRMR %+v, want %+v", tc.name, got, want)
		}
		if f.Info[1]&0x01 != 0 {
			t.Errorf("%s: bit 9 is not 0", tc.name)
		}
	}
	logs := m.HDLCFrameRejects()
	if len(logs) != 4 {
		t.Fatalf("the meter logged %d FRMR, want 4: %q", len(logs), logs)
	}
	for i, want := range []string{"undefined or not implemented", "not permitted", "invalid N(R)", "too long"} {
		if !strings.Contains(logs[i], want) {
			t.Errorf("log %q does not name %q", logs[i], want)
		}
	}
}

// quiet reports that nothing arrives for d.
func (r *rawLink) quiet(d time.Duration) bool {
	r.t.Helper()
	if len(r.got) > 0 {
		return false
	}
	buf := make([]byte, 512)
	_ = r.c.SetReadDeadline(time.Now().Add(d))
	n, err := r.c.Read(buf)
	if n > 0 {
		r.got = append(r.got, r.scan.Feed(buf[:n], time.Now())...)
		return false
	}
	var ne net.Error
	if err != nil && !(errors.As(err, &ne) && ne.Timeout()) {
		r.t.Fatal(err)
	}
	return true
}

// expect reads the next frame and checks its kind and F bit.
func (r *rawLink) expect(kind hdlc.Kind, final bool) hdlc.Frame {
	r.t.Helper()
	f := r.recv()
	if c := hdlc.ParseControl(f.Control); c.Kind != kind || c.PF != final {
		r.t.Fatalf("got %v F %v, want %v F %v", c.Kind, c.PF, kind, final)
	}
	return f
}

// P/F rules of the simulated meter in normal response mode (ISO/IEC 13239
// 5.4.3.1.2, 5.4.3.2.2, 5.5.3.3 a and b): a secondary sends only when
// polled, so an SNRM or DISC with P 0 gets no answer until the next command
// with P 1, which then gets the UA (or DM) with F 1 and is not otherwise
// acted on; when several mode-setting commands arrive before the poll, the
// answer is to the first. A command with P 1 is answered at once with F 1.
//
// Covers: SIG-IPE-2710, SIG-IPE-2711, SIG-IPE-2712
func TestHDLCPollFinalModeSettingE2E(t *testing.T) {
	_, addr := startHDLCMeter(t)
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	r := &rawLink{t: t, c: conn}
	const (
		snrm0, snrm1 = 0x83, 0x93
		disc0, disc1 = 0x43, 0x53
		rr1          = 0x11 // RR, P 1, N(R) 0
	)
	// SNRM with P 0: silence, then the poll gets the UA with F 1 and the
	// negotiated parameters.
	r.send(snrm0, nil)
	if !r.quiet(300 * time.Millisecond) {
		t.Fatal("an SNRM with P 0 was answered before a poll")
	}
	ua := r.expectAfter(rr1, hdlc.KindUA, true)
	if _, _, err := hdlc.DecodeParams(ua.Info); err != nil || len(ua.Info) == 0 {
		t.Errorf("the held UA lost its parameters: % X %v", ua.Info, err)
	}
	// The link is up: a poll now gets RR with F 1.
	r.send(rr1, nil)
	r.expect(hdlc.KindRR, true)
	// DISC with P 0: silence, then UA with F 1 at the poll; after it the
	// meter is disconnected, so the next poll gets DM.
	r.send(disc0, nil)
	if !r.quiet(300 * time.Millisecond) {
		t.Fatal("a DISC with P 0 was answered before a poll")
	}
	r.expectAfter(rr1, hdlc.KindUA, true)
	r.send(rr1, nil)
	r.expect(hdlc.KindDM, true)
	// A DISC with P 0 while disconnected: DM with F 1 at the poll.
	r.send(disc0, nil)
	if !r.quiet(200 * time.Millisecond) {
		t.Fatal("a DISC with P 0 was answered before a poll")
	}
	r.expectAfter(rr1, hdlc.KindDM, true)
	// Two mode-setting commands before the poll: the answer is to the
	// first (SNRM: UA), and the DISC after it is not acted on.
	r.send(snrm0, nil)
	r.send(disc0, nil)
	if !r.quiet(200 * time.Millisecond) {
		t.Fatal("answered before a poll")
	}
	r.expectAfter(rr1, hdlc.KindUA, true)
	r.send(rr1, nil)
	r.expect(hdlc.KindRR, true) // still linked
	// With P 1 the answer is at once, F 1.
	r.send(disc1, nil)
	r.expect(hdlc.KindUA, true)
	r.send(snrm1, nil)
	r.expect(hdlc.KindUA, true)
}

// A frame rejected without P (here REJ, not implemented) gets its FRMR, F 1,
// at the next poll, not at once; a mode-setting command ends the frame
// reject condition instead (ISO/IEC 13239 5.4.3.1.2, 5.5.3.4.2).
//
// Covers: SIG-IPE-2713
func TestHDLCPollFinalFrameRejectE2E(t *testing.T) {
	_, addr := startHDLCMeter(t)
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	r := &rawLink{t: t, c: conn}
	r.connect()
	r.send(0x09, nil) // REJ, P 0
	if !r.quiet(300 * time.Millisecond) {
		t.Fatal("an FRMR was sent without a poll")
	}
	f := r.expectAfter(0x11, hdlc.KindFRMR, true)
	if got, err := hdlc.DecodeFrameReject(f.Info, 8); err != nil || got.Control != 0x09 || !got.W {
		t.Errorf("FRMR %+v %v", got, err)
	}
	// Rejected again without P, then SNRM with P 1: the SNRM is actioned.
	r.connect()
	r.send(0x09, nil)
	if !r.quiet(200 * time.Millisecond) {
		t.Fatal("an FRMR was sent without a poll")
	}
	r.send(0x93, nil)
	r.expect(hdlc.KindUA, true)
	r.send(0x11, nil)
	r.expect(hdlc.KindRR, true)
}

// expectAfter sends a command and checks the answer.
func (r *rawLink) expectAfter(control byte, kind hdlc.Kind, final bool) hdlc.Frame {
	r.t.Helper()
	r.send(control, nil)
	return r.expect(kind, final)
}

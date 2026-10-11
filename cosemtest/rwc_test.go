package cosemtest

import (
	"net"
	"strings"
	"testing"
	"time"

	"gitlab.com/circutor-library/gosem/pkg/axdr"

	dlmssim "github.com/cB-Sigma/dlms-sim/sim"
	"github.com/cB-Sigma/dlms/cosem"
)

// portMeter serves one HDLC session of a simulated meter on the far end of
// a pipe and returns our end and the session's result.
func portMeter(t *testing.T, pw string) (*dlmssim.Meter, net.Conn, <-chan error) {
	t.Helper()
	m := &dlmssim.Meter{Password: pw}
	m.Register("1.0.1.8.0.255", axdr.CreateAxdrDoubleLongUnsigned(1234567), 0, 30) // Wh
	m.Register("1.0.12.7.0.255", axdr.CreateAxdrLongUnsigned(23050), -2, 35)       // 230.50 V
	m.Set(1, "0.0.96.1.0.255", 2, axdr.CreateAxdrOctetString("4d54523031"))
	ours, theirs := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- m.ServeHDLC(theirs); _ = theirs.Close() }()
	t.Cleanup(func() { _ = ours.Close() })
	return m, ours, done
}

// Covers: SIG-IPE-627
func TestPortClientOverHDLC(t *testing.T) {
	m, port, done := portMeter(t, "lnt12345")
	c, err := cosem.NewPortClient(port, cosem.PortOptions{Authentication: "low", Password: "lnt12345", Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Connect(); err != nil {
		t.Fatalf("SNRM: %v", err)
	}
	if err := c.Associate(); err != nil {
		t.Fatalf("AARQ: %v", err)
	}
	if acc, ref := m.Associations(); acc != 1 || ref != 0 {
		t.Errorf("associations %d accepted, %d refused", acc, ref)
	}
	v, unit, err := cosem.ReadScaled(c, cosem.Object{OBIS: "1.0.12.7.0.255", Class: cosem.ClassRegister}, nil)
	if err != nil || v != 230.5 || unit != "V" {
		t.Errorf("voltage %v %q %v", v, unit, err)
	}
	v, unit, err = cosem.ReadScaled(c, cosem.Object{OBIS: "1.0.1.8.0.255", Class: cosem.ClassRegister, Unit: "kWh?"}, nil)
	if err != nil || v != 1234567.0 || unit != "kWh?" {
		t.Errorf("energy %v %q %v (a configured unit wins)", v, unit, err)
	}
	if v, _, err := cosem.ReadScaled(c, cosem.Object{OBIS: "0.0.96.1.0.255", Class: cosem.ClassData}, nil); err != nil || v != "4d54523031" {
		t.Errorf("serial number %v %v", v, err)
	}
	// An object the meter does not have is refused for itself only.
	_, _, err = cosem.ReadScaled(c, cosem.Object{OBIS: "1.0.99.99.0.255", Class: cosem.ClassRegister}, nil)
	if err == nil || !cosem.Rejected(err) {
		t.Errorf("unknown object: %v (rejected %v)", err, cosem.Rejected(err))
	}
	if _, _, err := cosem.ReadScaled(c, cosem.Object{OBIS: "1.0.12.7.0.255", Class: cosem.ClassRegister}, nil); err != nil {
		t.Errorf("the link did not survive a rejected object: %v", err)
	}
	// Close releases the association and sends DISC, which ends the
	// meter's session cleanly.
	c.Close()
	c.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("meter session ended with %v, want a DISC", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the meter never saw DISC")
	}
}

// Covers: SIG-IPE-627
func TestPortClientFailures(t *testing.T) {
	// A wrong password: the association is refused, the link stays usable
	// to close.
	m, port, done := portMeter(t, "lnt12345")
	c, err := cosem.NewPortClient(port, cosem.PortOptions{Authentication: "low", Password: "wrong", Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	if err := c.Associate(); err == nil {
		t.Error("a wrong password was accepted")
	}
	if _, ref := m.Associations(); ref != 1 {
		t.Errorf("%d refusals", ref)
	}
	c.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("close hung")
	}
	// A port nobody answers on: the SNRM times out, closing does not hang.
	ours, theirs := net.Pipe()
	go func() {
		b := make([]byte, 256)
		for {
			if _, err := theirs.Read(b); err != nil {
				return
			}
		}
	}()
	c, err = cosem.NewPortClient(ours, cosem.PortOptions{Timeout: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Connect(); err == nil {
		t.Error("a silent port connected")
	}
	finished := make(chan struct{})
	go func() { c.Close(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("close hung on a silent port")
	}
	_ = theirs.Close()
	// Options the hand-over cannot honour.
	for _, o := range []cosem.PortOptions{
		{Authentication: "hls-gmac"}, {Authentication: "low"}, {ClientAddress: 200},
		{HDLCAddressSize: 3}, {ServerAddress: 300}, {HDLCAddressSize: 2, HDLCAddress: 200},
	} {
		a, b := net.Pipe()
		if _, err := cosem.NewPortClient(a, o); err == nil {
			t.Errorf("%+v accepted", o)
		}
		_ = a.Close()
		_ = b.Close()
	}
	if _, err := cosem.NewPortClient(nil, cosem.PortOptions{}); err == nil || !strings.Contains(err.Error(), "port") {
		t.Errorf("nil port: %v", err)
	}
}

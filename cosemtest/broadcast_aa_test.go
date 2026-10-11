package cosemtest

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"

	. "github.com/cB-Sigma/dlms/cosem"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"

	dlmssim "github.com/cB-Sigma/dlms-sim/sim"
)

// wrapperSender sends APDUs in IEC 62056-47 wrapper frames from client
// SAP src to server SAP dst (the test's supporting layer).
func wrapperSender(t *testing.T, addr string, src, dst uint16) (func([]byte) error, net.Conn) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return func(apdu []byte) error {
		h := make([]byte, 8)
		binary.BigEndian.PutUint16(h[0:], 1)
		binary.BigEndian.PutUint16(h[2:], src)
		binary.BigEndian.PutUint16(h[4:], dst)
		binary.BigEndian.PutUint16(h[6:], uint16(len(apdu)))
		_, err := c.Write(append(h, apdu...))
		return err
	}, c
}

// An unconfirmed AA to the all-station address (7.2.4.3): the AARQ with
// response-allowed FALSE and the initiate request under the broadcast key,
// unconfirmed set requests in each ciphering form, and the release; the
// meter applies them and never answers.
//
// Covers: SIG-IPE-660
func TestBroadcastAssociation(t *testing.T) {
	for _, suite := range []int{0, 1, 2} {
		for _, form := range []byte{CipherServiceSpecific, CipherGeneralGlo, CipherGeneral} {
			for _, lls := range []bool{false, true} {
				t.Run(fmt.Sprintf("suite%d/form%d/lls=%v", suite, form, lls), func(t *testing.T) {
					n := Suite(suite).KeyLen()
					bkey := bytes.Repeat([]byte{0x33}, n)
					h := &dlmssim.HLS{Policy: 0x30, Suite: byte(suite), SystemTitle: meterST, Key: bytes.Repeat([]byte{0x11}, n),
						AuthKey: bytes.Repeat([]byte{0x22}, n), BroadcastKey: bkey, Unauthenticated: !lls}
					if lls {
						h.Mechanism, h.Secret = 1, []byte("GROUPPW1")
					}
					sim := &dlmssim.Meter{HLS: h}
					sim.Set(1, "0.0.96.14.0.255", 2, axdr.CreateAxdrUnsigned(1))
					addr, err := sim.Listen("127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = sim.Close() })
					send, conn := wrapperSender(t, addr, 0x66, 0x7F)
					b := &Broadcaster{Send: send, IC: 1, Security: Security{Suite: Suite(suite), Policy: 0x30, SystemTitle: []byte("SGM\x00\x00\x00\x00\x01"),
						AuthKey: h.AuthKey, BroadcastKey: bkey, Ciphering: form}}
					if lls {
						b.Password = h.Secret
					}
					if err := b.Associate(); err != nil {
						t.Fatal(err)
					}
					for v := uint8(2); v <= 3; v++ {
						req, _ := gdlms.CreateSetRequestNormal(InvokeUnconfirmed, *gdlms.CreateAttributeDescriptor(1, "0.0.96.14.0.255", 2), nil, *axdr.CreateAxdrUnsigned(v)).Encode()
						if err := b.Request(req); err != nil {
							t.Fatal(err)
						}
					}
					if err := b.Release(); err != nil {
						t.Fatal(err)
					}
					ok := false
					for i := 0; i < 100 && !ok; i++ {
						time.Sleep(10 * time.Millisecond)
						acc, _ := sim.Releases()
						ok = sim.Broadcasts() == 2 && acc == 1
					}
					if !ok {
						acc, bad := sim.Releases()
						t.Fatalf("broadcasts %d (dropped %d), releases %d (discarded %d)", sim.Broadcasts(), sim.BadBroadcasts(), acc, bad)
					}
					if v, _ := sim.Value(1, "0.0.96.14.0.255", 2); v.Value != uint8(3) {
						t.Errorf("value %v, want 3", v.Value)
					}
					// Nothing was answered.
					_ = conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
					if n, _ := conn.Read(make([]byte, 64)); n != 0 {
						t.Errorf("the meter answered %d bytes in an unconfirmed AA", n)
					}
				})
			}
		}
	}
}

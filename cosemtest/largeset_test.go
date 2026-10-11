package cosemtest

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"

	dlmssim "github.com/cB-Sigma/dlms-sim/sim"
)

// A SET longer than 127 octets (a two-octet A-XDR length) is applied, and
// one longer than the meter's negotiated PDU size goes in blocks
// (set-request-with-first-datablock and with-datablock, IEC 62056-5-3:2023
// 7.3.3), with and without APDU protection.
//
// Covers: SIG-IPE-1140
func TestLargeSet(t *testing.T) {
	for _, policy := range []byte{0, 0x30} {
		for _, n := range []int{100, 128, 170, 400, 1500} {
			t.Run(fmt.Sprintf("policy%x/%d", policy, n), func(t *testing.T) {
				var r *secRig
				if policy == 0 {
					sim := &dlmssim.Meter{}
					sim.Set(1, "0.0.96.13.1.255", 2, axdr.CreateAxdrOctetString(""))
					addr, err := sim.Listen("127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = sim.Close() })
					m := &testMeter{ID: "L", Address: addr, Authentication: "none", ClientAddress: 16}
					if err := m.validate(); err != nil {
						t.Fatal(err)
					}
					r = &secRig{sim: sim, m: m, mt: &testConn{m: m}}
					t.Cleanup(r.mt.close)
				} else {
					r = newRig(t, 0, policy, nil)
				}
				if err := r.mt.connect(); err != nil {
					t.Fatal(err)
				}
				value := bytes.Repeat([]byte{0xA5, 0x5A, 0x01}, n/3+1)[:n]
				if err := r.mt.c.SetRequest(gdlms.CreateAttributeDescriptor(1, "0.0.96.13.1.255", 2), axdr.CreateAxdrOctetString(hex.EncodeToString(value))); err != nil {
					t.Fatalf("set of %d octets: %v", n, err)
				}
				got, _ := r.sim.Value(1, "0.0.96.13.1.255", 2)
				if s, _ := got.Value.(string); s != hex.EncodeToString(value) {
					t.Errorf("the meter holds %d hex digits, want %d", len(s), 2*n)
				}
			})
		}
	}
}

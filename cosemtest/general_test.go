package cosemtest

import (
	"fmt"
	"testing"

	dlmssim "github.com/cB-Sigma/dlms-sim/sim"
)

// Every general ciphering form and key-info in each suite it applies to,
// with and without general signing: three associations in a row each
// read a register, and the meter sees only the chosen APDU form.
//
// Covers: SIG-IPE-067, SIG-IPE-068
func TestGeneralCipheringMatrix(t *testing.T) {
	type tc struct {
		ciphering, key string
		suite          int
		policy         byte
		signing        bool
		tag            byte
	}
	var cases []tc
	for _, suite := range []int{0, 1, 2} {
		for _, policy := range []byte{0x10, 0x20, 0x30} {
			cases = append(cases,
				tc{"general-glo", "", suite, policy, false, 0xDB},
				tc{"general-ded", "", suite, policy, false, 0xDC},
				tc{"general", "identified", suite, policy, false, 0xDD},
				tc{"general", "wrapped", suite, policy, false, 0xDD})
			if suite != 0 {
				cases = append(cases,
					tc{"general", "agreed-one-pass", suite, policy, false, 0xDD},
					tc{"general", "agreed-static", suite, policy, false, 0xDD},
					tc{"general", "agreed-one-pass", suite, policy, true, 0xDD},
					tc{"service-specific", "", suite, policy, true, 0xC8})
			}
		}
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%s/%s/suite%d/policy%x/signed=%v", c.ciphering, c.key, c.suite, c.policy, c.signing), func(t *testing.T) {
			r := newRig(t, c.suite, c.policy, func(m *testMeter, h *dlmssim.HLS) {
				m.Ciphering, m.GeneralKey, m.Signing = c.ciphering, c.key, c.signing
				m.DedicatedKey = c.ciphering == "general-ded"
				h.RequireSigning = c.signing
			})
			for i := 0; i < 3; i++ {
				if err := r.read(t); err != nil {
					t.Fatalf("association %d: %v", i+1, err)
				}
				r.mt.close()
			}
			forms := r.sim.Forms()
			general := forms[0xDB] + forms[0xDC] + forms[0xDD]
			// With a dedicated key, HLS pass 3 goes under the global key
			// (general-glo), as the association is not yet established.
			want := 1
			if c.tag == 0xDC {
				want = 2
			}
			if forms[c.tag] == 0 || (c.tag >= 0xDB && len(forms) != want) || (c.tag < 0xDB && general != 0) {
				t.Errorf("the meter saw request forms %v, want only %#x", forms, c.tag)
			}
			if acc, bad := r.sim.Signed(); c.signing && (acc == 0 || bad != 0) {
				t.Errorf("signed requests accepted %d, refused %d", acc, bad)
			}
			if _, ref := r.sim.Associations(); ref != 0 {
				t.Errorf("%d associations refused", ref)
			}
		})
	}
}

// The client refuses a meter whose signature does not verify, and the
// meter refuses a client signing with a key it does not trust; with
// signing required, an unsigned meter answer is refused.
//
// Covers: SIG-IPE-068
func TestGeneralSigningRefusals(t *testing.T) {
	for _, suite := range []int{1, 2} {
		r := newRig(t, suite, 0x30, func(m *testMeter, h *dlmssim.HLS) {
			m.Signing, h.RequireSigning = true, true
			other := newPKI(t, suite)
			h.ClientKey = &other.clientSign.PublicKey // the meter trusts another client key
		})
		if err := r.read(t); err == nil {
			t.Errorf("suite %d: a client signing with an untrusted key was served", suite)
		}
		if _, bad := r.sim.Signed(); bad == 0 {
			t.Errorf("suite %d: the meter refused no signature", suite)
		}

		r = newRig(t, suite, 0x30, func(m *testMeter, h *dlmssim.HLS) {
			other := newPKI(t, suite)
			m.Signing, h.RequireSigning = true, true
			m.MeterSigningKey = pubPEM(t, &other.meterSign.PublicKey) // we trust another meter key
		})
		if err := r.read(t); err == nil {
			t.Errorf("suite %d: a meter signing with an untrusted key was accepted", suite)
		}

		// We require signing, the meter does not sign its answers.
		r = newRig(t, suite, 0x30, func(m *testMeter, h *dlmssim.HLS) { m.Signing, h.UnsignedAnswers = true, true })
		if err := r.read(t); err == nil {
			t.Errorf("suite %d: unsigned answers were accepted with signing on", suite)
		}
	}
}

package cosemtest

import (
	"bytes"
	"crypto/elliptic"
	"encoding/hex"
	"testing"

	. "github.com/cB-Sigma/dlms/cosem"

	"gitlab.com/circutor-library/gosem/pkg/axdr"

	dlmssim "github.com/cB-Sigma/dlms-sim/sim"
)

// Every mechanism, suite, protection policy and key choice against the
// simulator: associate, read a register over the association, three times
// in a row, with no refused association and no reused counter.
//
// Covers: SIG-IPE-047, SIG-IPE-048, SIG-IPE-050, SIG-IPE-051, SIG-IPE-052
func TestSecurityMatrix(t *testing.T) {
	for _, tc := range secCases() {
		t.Run(tc.name, func(t *testing.T) {
			n := Suite(tc.suite).KeyLen()
			key, ak := bytes.Repeat([]byte{0x11}, n), bytes.Repeat([]byte{0x22}, n)
			secret := bytes.Repeat([]byte{0x33}, 16)
			h := &dlmssim.HLS{Mechanism: tc.mechID, Secret: secret, Policy: tc.policy, Suite: byte(tc.suite),
				SystemTitle: []byte("LNT\x00\x00\x01\x23\x45"), Key: key, AuthKey: ak, FrameCounterOBIS: "0.0.43.1.3.255"}
			m := &testMeter{ID: "M", Authentication: tc.mech, Security: tc.security, Suite: tc.suite,
				BlockCipherKey: hex.EncodeToString(key), AuthenticationKey: hex.EncodeToString(ak), DedicatedKey: tc.dedicated,
				InvocationCounter: &FrameCounterObject{OBIS: "0.0.43.1.3.255"}, Password: string(secret)}
			if tc.mechID == 7 {
				curve := elliptic.P256()
				if tc.suite == 2 {
					curve = elliptic.P384()
				}
				meterKey, _, meterPub := ecKey(t, curve)
				clientKey, clientPriv, _ := ecKey(t, curve)
				h.SigningKey, h.ClientKey = meterKey, &clientKey.PublicKey
				m.SigningKey, m.MeterSigningKey = clientPriv, meterPub
			}
			sim := &dlmssim.Meter{}
			if tc.mechID >= 1 {
				sim.HLS = h
			}
			sim.Register("1.0.12.7.0.255", axdr.CreateAxdrLongUnsigned(23050), -2, 35)
			sim.Set(1, "0.0.43.1.3.255", 2, axdr.CreateAxdrDoubleLongUnsigned(777))
			addr, err := sim.Listen("127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = sim.Close() })
			m.Address = addr
			if err := m.validate(); err != nil {
				t.Fatal(err)
			}
			mt := &testConn{m: m}
			for i := 0; i < 3; i++ {
				if err := mt.connect(); err != nil {
					t.Fatalf("association %d: %v", i+1, err)
				}
				v, err := mt.get(3, "1.0.12.7.0.255", 2)
				if err != nil {
					t.Fatalf("read over association %d: %v", i+1, err)
				}
				if v.Value != uint16(23050) {
					t.Fatalf("read %v", v.Value)
				}
				mt.close()
			}
			if _, ref := sim.Associations(); ref != 0 || sim.StaleCounters() != 0 {
				t.Errorf("refused %d, stale counters %d", ref, sim.StaleCounters())
			}
			if tc.dedicated && sim.DedicatedKeys() != 3 {
				t.Errorf("%d associations agreed a dedicated key, want 3", sim.DedicatedKeys())
			}
		})
	}
}

// A wrong secret or key is refused by the meter, and a meter that answers
// with the wrong key is refused by us.
//
// Covers: SIG-IPE-047, SIG-IPE-052
func TestSecurityWrongKeys(t *testing.T) {
	key, ak := bytes.Repeat([]byte{0x11}, 16), bytes.Repeat([]byte{0x22}, 16)
	start := func(h *dlmssim.HLS) string {
		sim := &dlmssim.Meter{HLS: h}
		sim.Register("1.0.12.7.0.255", axdr.CreateAxdrLongUnsigned(1), 0, 35)
		addr, err := sim.Listen("127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = sim.Close() })
		return addr
	}
	try := func(m *testMeter) error {
		if err := m.validate(); err != nil {
			t.Fatal(err)
		}
		mt := &testConn{m: m}
		defer mt.close()
		return mt.connect()
	}
	st := []byte("LNT\x00\x00\x01\x23\x45")
	// Our authentication key differs: the meter refuses pass 3.
	addr := start(&dlmssim.HLS{Policy: 0x10, SystemTitle: st, Key: key, AuthKey: ak})
	if err := try(&testMeter{ID: "M", Address: addr, Authentication: "hls-gmac", Security: "authenticated",
		BlockCipherKey: hex.EncodeToString(key), AuthenticationKey: hex.EncodeToString(bytes.Repeat([]byte{0x23}, 16))}); err == nil {
		t.Error("a wrong authentication key associated")
	}
	// The meter's secret differs: its pass 4 answer does not verify (or it
	// refuses ours first).
	addr = start(&dlmssim.HLS{Mechanism: 6, Secret: []byte("meter-secret"), SystemTitle: st})
	if err := try(&testMeter{ID: "M", Address: addr, Authentication: "hls-sha256", Password: "other-secret"}); err == nil {
		t.Error("a wrong HLS secret associated")
	}
	// ECDSA: the meter signs with a key other than the one we trust.
	meterKey, _, _ := ecKey(t, elliptic.P256())
	_, _, otherPub := ecKey(t, elliptic.P256())
	clientKey, clientPriv, _ := ecKey(t, elliptic.P256())
	addr = start(&dlmssim.HLS{Mechanism: 7, Suite: 1, Policy: 0x30, SystemTitle: st, Key: key, AuthKey: ak,
		SigningKey: meterKey, ClientKey: &clientKey.PublicKey})
	err := try(&testMeter{ID: "M", Address: addr, Authentication: "hls-ecdsa", Suite: 1, Security: "authenticated-encrypted",
		BlockCipherKey: hex.EncodeToString(key), AuthenticationKey: hex.EncodeToString(ak), SigningKey: clientPriv, MeterSigningKey: otherPub})
	if err == nil {
		t.Error("a meter signing with an untrusted key associated")
	}
}

// Covers: SIG-IPE-050
func TestSecurityConfigurationChecks(t *testing.T) {
	for name, m := range map[string]testMeter{
		"ecdsa in suite 0":          {Authentication: "hls-ecdsa", Security: "authenticated-encrypted", Suite: 0},
		"suite 2 with 16-byte key":  {Authentication: "hls-gmac", Security: "authenticated", Suite: 2, BlockCipherKey: "000102030405060708090A0B0C0D0E0F", AuthenticationKey: "000102030405060708090A0B0C0D0E0F"},
		"dedicated key unprotected": {Authentication: "hls-md5", Password: "x", DedicatedKey: true},
		"md5 without secret":        {Authentication: "hls-md5"},
		"unknown security":          {Authentication: "low", Password: "x", Security: "signed"},
		"unknown mechanism":         {Authentication: "hls-sha512"},
	} {
		m.ID, m.Address = "M", "127.0.0.1:1"
		if err := m.validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

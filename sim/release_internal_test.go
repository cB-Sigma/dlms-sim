package sim

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func hx(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The meter side of a ciphered release (IEC 62056-5-3:2023 6.3, 7.2.5),
// fed the RLRQ of annex E.7: it deciphers, and the RLRE carries the
// InitiateResponse protected as in the AARE; a replayed, changed or
// unciphered-with-a-dedicated-key RLRQ is silently discarded.
//
// Covers: SIG-IPE-658
func TestReleaseAnnexE7(t *testing.T) {
	key, ak := hx(t, "000102030405060708090A0B0C0D0E0F"), hx(t, "D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF")
	rlrq := hx(t, "6239800100BE34043221303001234567"+
		"801302FF8A7874133D414CED25B42534D28DB0047720606B175BD52211BE68"+"41DB204D39EE6FDB8E356855")
	newSession := func() (*Meter, *session) {
		h := &HLS{Policy: 0x30, SystemTitle: hx(t, "4D4D4D0000000001"), Key: key, AuthKey: ak}
		m := &Meter{HLS: h}
		s := &session{client: 48, associated: true, hls: &hlsSession{clientST: hx(t, "4D4D4D0000BC614E"), keys: h.keysNow(),
			dedKey: hx(t, "00112233445566778899AABBCCDDEEFF"), lastIC: map[bool]uint32{false: 0x01234566}}}
		return m, s
	}
	m, s := newSession()
	resp, ok := m.release(s, rlrq)
	if !ok || len(resp) < 10 || resp[0] != 0x63 || s.associated {
		t.Fatalf("RLRE %X, still associated %v", resp, s.associated)
	}
	ui := aarqItems(resp)[0xBE]
	if len(ui) < 4 || ui[0] != 0x04 || ui[2] != 0x28 {
		t.Fatalf("RLRE user-information %X", ui)
	}
	plain, _, good := sessionKeys{policy: 0x30, key: key, ak: ak}.open(key, m.HLS.SystemTitle, ui[4:], nil)
	if !good || !bytes.Equal(plain, initiateResponse) {
		t.Errorf("the RLRE's InitiateResponse opens to %X (%v)", plain, good)
	}
	if acc, bad := m.Releases(); acc != 1 || bad != 0 {
		t.Errorf("releases %d, discarded %d", acc, bad)
	}
	// Replayed: the counter is not above the last one.
	if resp, ok := m.release(s, rlrq); !ok || resp != nil {
		t.Errorf("a replayed RLRQ was answered: %X", resp)
	}
	// Changed.
	m, s = newSession()
	bad := bytes.Clone(rlrq)
	bad[len(bad)-1] ^= 1
	if resp, ok := m.release(s, bad); !ok || resp != nil || !s.associated {
		t.Errorf("a changed RLRQ was answered: %X", resp)
	}
	// Without user-information: a plain RLRE.
	m, s = newSession()
	if resp, ok := m.release(s, []byte{0x62, 0x00}); !ok || !bytes.Equal(resp, []byte{0x63, 0x03, 0x80, 0x01, 0x00}) {
		t.Errorf("plain RLRQ answered %X", resp)
	}
}

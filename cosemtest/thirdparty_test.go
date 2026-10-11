package cosemtest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"

	. "github.com/cB-Sigma/dlms/cosem"

	dlmssim "github.com/cB-Sigma/dlms-sim/sim"
)

// tpRig is a meter that knows a third party, and a client acting for it.
func tpRig(t *testing.T, suite int, policy byte, ciphering, generalKey string, signedAnswers bool, configure func(*ThirdParty, *dlmssim.HLS)) (*secRig, *ecdsa.PrivateKey) {
	t.Helper()
	curve, _ := Suite(suite).Curve()
	tpKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r := newRig(t, suite, policy, func(m *testMeter, h *dlmssim.HLS) {
		m.Ciphering, m.GeneralKey = ciphering, generalKey
		m.DedicatedKey = ciphering == "general-ded"
		h.ThirdPartyST, h.ThirdPartyKey, h.ThirdPartySignedAnswers = tpST, &tpKey.PublicKey, signedAnswers
	})
	signed := signedAnswers
	settings := &ThirdParty{SystemTitle: fmt.Sprintf("%X", tpST), SigningKey: privPEM(t, tpKey), SignedResponses: &signed}
	if configure != nil {
		configure(settings, r.h)
	}
	tp, err := settings.Build(&r.m.hls.Security)
	if err != nil {
		t.Fatal(err)
	}
	r.m.hls.Security.ThirdParty = tp
	return r, tpKey
}

// Annex J.2: the request is signed by the third party and authenticated
// (or ciphered) by the client; the response is authenticated for the
// client and signed for the third party. Annex J.3: the response carries
// an unprotected general-ciphering layer for the third party.
//
// Covers: SIG-IPE-656
func TestThirdPartyLayers(t *testing.T) {
	type tc struct {
		ciphering, key string
		suite          int
		policy         byte
		signed         bool
		tag            byte
	}
	var cases []tc
	for _, suite := range []int{1, 2} {
		for _, signed := range []bool{true, false} {
			cases = append(cases,
				tc{"general", "identified", suite, 0x10, signed, 0xDD},
				tc{"general", "agreed-one-pass", suite, 0x30, signed, 0xDD},
				tc{"general-glo", "", suite, 0x10, signed, 0xDB},
				tc{"general-ded", "", suite, 0x30, signed, 0xDC})
		}
	}
	for _, c := range cases {
		name := fmt.Sprintf("J.%d/%s/%s/suite%d/policy%x", map[bool]int{true: 2, false: 3}[c.signed], c.ciphering, c.key, c.suite, c.policy)
		t.Run(name, func(t *testing.T) {
			r, _ := tpRig(t, c.suite, c.policy, c.ciphering, c.key, c.signed, nil)
			for i := 0; i < 2; i++ {
				if err := r.read(t); err != nil {
					t.Fatalf("association %d: %v", i+1, err)
				}
				r.mt.close()
			}
			if n := r.sim.ThirdPartyRequests(); n < 2 {
				t.Errorf("the meter accepted %d third-party requests", n)
			}
			// With a dedicated key, HLS pass 3 goes under the global key.
			want := 1
			if c.tag == 0xDC {
				want = 2
			}
			if forms := r.sim.Forms(); forms[c.tag] == 0 || len(forms) != want {
				t.Errorf("the meter saw request forms %v, want only %#x", forms, c.tag)
			}
			if _, bad := r.sim.Signed(); bad != 0 {
				t.Errorf("%d signatures refused", bad)
			}
		})
	}
}

// Each party's protection is checked: an unknown third party, a response
// not signed for the third party when the policy asks for it, a wrong
// signature for the third party, and a third party with service-specific
// ciphering.
//
// Covers: SIG-IPE-656
func TestThirdPartyRefusals(t *testing.T) {
	// The meter does not know the third party's key.
	r, _ := tpRig(t, 1, 0x10, "general", "identified", true, func(_ *ThirdParty, h *dlmssim.HLS) {
		other, _ := ecdsa.GenerateKey(h.ThirdPartyKey.Curve, rand.Reader)
		h.ThirdPartyKey = &other.PublicKey
	})
	if err := r.read(t); err == nil {
		t.Error("a request signed by a third party the meter does not know was answered")
	}
	// We ask for signed responses, the meter answers unprotected (J.3).
	r, _ = tpRig(t, 1, 0x10, "general", "identified", false, func(tp *ThirdParty, _ *dlmssim.HLS) { yes := true; tp.SignedResponses = &yes })
	if err := r.read(t); err == nil || !strings.Contains(r.mt.st.LastFailure().Error(), "did not sign") {
		t.Errorf("an unsigned response for the third party was accepted where signing is required: %v", err)
	}
	// The meter signs for the third party with the wrong key.
	r, _ = tpRig(t, 1, 0x10, "general", "identified", true, func(_ *ThirdParty, h *dlmssim.HLS) { h.ThirdPartyBadSignature = true })
	if err := r.read(t); err == nil {
		t.Error("a response wrongly signed for the third party was accepted")
	}
	// Service-specific ciphering cannot carry the third party's layer.
	r2 := newRig(t, 1, 0x10, nil)
	k, _ := ecdsa.GenerateKey(r2.keys.clientSign.Curve, rand.Reader)
	if _, err := (&ThirdParty{SystemTitle: fmt.Sprintf("%X", tpST), SigningKey: privPEM(t, k)}).Build(&r2.m.hls.Security); err == nil {
		t.Error("a third party was accepted with service-specific ciphering")
	}
	if _, err := (&ThirdParty{SystemTitle: "0011", SigningKey: privPEM(t, k)}).Build(&r2.m.hls.Security); err == nil {
		t.Error("a short third-party system title was accepted")
	}
}

// A third party that ciphers its own layer (5.7.3, Table 26): general-
// ciphering with a key agreed with the meter (one-pass or static), with
// authentication, encryption or both, alone or around its signature; the
// meter answers with the same kinds for it, inside our layer.
//
// Covers: SIG-IPE-659
func TestThirdPartyCiphering(t *testing.T) {
	for _, suite := range []int{1, 2} {
		for _, policy := range []string{"authenticated", "encrypted", "authenticated-encrypted"} {
			for _, scheme := range []string{"agreed-one-pass", "agreed-static"} {
				for _, sign := range []bool{true, false} {
					t.Run(fmt.Sprintf("suite%d/%s/%s/sign=%v", suite, policy, scheme, sign), func(t *testing.T) {
						r := tpCipherRig(t, suite, policy, scheme, sign, nil)
						for i := 0; i < 2; i++ {
							if err := r.read(t); err != nil {
								t.Fatalf("association %d: %v", i+1, err)
							}
							r.mt.close()
						}
						if n := r.sim.ThirdPartyRequests(); n < 2 {
							t.Errorf("the meter accepted %d third-party requests", n)
						}
						if _, bad := r.sim.Signed(); bad != 0 {
							t.Errorf("%d third-party layers refused", bad)
						}
					})
				}
			}
		}
	}
}

// The TP's ciphered layer is checked both ways: another authentication
// key or key agreement key at the meter, a response ciphered for the TP
// where none was asked, and settings that cannot work.
//
// Covers: SIG-IPE-659
func TestThirdPartyCipheringRefusals(t *testing.T) {
	r := tpCipherRig(t, 1, "authenticated", "agreed-one-pass", false, func(_ *ThirdParty, h *dlmssim.HLS) {
		h.ThirdPartyAuthKey = bytes.Repeat([]byte{0x5A}, 16)
	})
	if err := r.read(t); err == nil {
		t.Error("a TP layer authenticated with another key was accepted by the meter")
	}
	r = tpCipherRig(t, 1, "authenticated-encrypted", "agreed-static", false, func(_ *ThirdParty, h *dlmssim.HLS) {
		other, _ := ecdsa.GenerateKey(h.ThirdPartyKAKey.Curve, rand.Reader)
		h.ThirdPartyKAKey = &other.PublicKey
	})
	if err := r.read(t); err == nil {
		t.Error("a TP layer agreed with another static key was accepted by the meter")
	}
	// We ask for an answer ciphered for the TP but send no ciphered layer,
	// so the meter answers without one: refused.
	r = tpCipherRig(t, 1, "authenticated", "agreed-one-pass", true, func(tp *ThirdParty, _ *dlmssim.HLS) { yes := true; tp.Security, tp.CipheredResponses = "", &yes })
	if err := r.read(t); err == nil {
		t.Error("a response not ciphered for the TP was accepted where ciphering is required")
	}
	sec := &newRig(t, 1, 0x10, func(m *testMeter, _ *dlmssim.HLS) { m.Ciphering, m.GeneralKey = "general", "identified" }).m.hls.Security
	k, _ := ecdsa.GenerateKey(sec.SignKey.Curve, rand.Reader)
	for name, tp := range map[string]ThirdParty{
		"no protection":    {SystemTitle: fmt.Sprintf("%X", tpST), Sign: new(bool)},
		"identified key":   {SystemTitle: fmt.Sprintf("%X", tpST), SigningKey: privPEM(t, k), Security: "authenticated", GeneralKey: "identified"},
		"no auth key":      {SystemTitle: fmt.Sprintf("%X", tpST), SigningKey: privPEM(t, k), KeyAgreementKey: privPEM(t, k), Security: "authenticated"},
		"static no KA":     {SystemTitle: fmt.Sprintf("%X", tpST), SigningKey: privPEM(t, k), Security: "encrypted", GeneralKey: "agreed-static"},
		"unknown security": {SystemTitle: fmt.Sprintf("%X", tpST), SigningKey: privPEM(t, k), Security: "signed"},
	} {
		if _, err := tp.Build(sec); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// tpCipherRig is a meter and client where the TP ciphers its layer.
func tpCipherRig(t *testing.T, suite int, policy, scheme string, sign bool, configure func(*ThirdParty, *dlmssim.HLS)) *secRig {
	t.Helper()
	curve, _ := Suite(suite).Curve()
	tpSign, _ := ecdsa.GenerateKey(curve, rand.Reader)
	tpKA, _ := ecdsa.GenerateKey(curve, rand.Reader)
	ak := bytes.Repeat([]byte{0x3C}, Suite(suite).KeyLen())
	r := newRig(t, suite, 0x10, func(m *testMeter, h *dlmssim.HLS) {
		m.Ciphering, m.GeneralKey = "general", "identified"
		h.ThirdPartyST, h.ThirdPartyKey, h.ThirdPartySignedAnswers = tpST, &tpSign.PublicKey, sign
		h.ThirdPartyKAKey, h.ThirdPartyAuthKey = &tpKA.PublicKey, ak
	})
	s := sign
	settings := &ThirdParty{SystemTitle: fmt.Sprintf("%X", tpST), SigningKey: privPEM(t, tpSign), Sign: &s, Security: policy, GeneralKey: scheme,
		KeyAgreementKey: privPEM(t, tpKA), AuthenticationKey: fmt.Sprintf("%X", ak)}
	if configure != nil {
		configure(settings, r.h)
	}
	tp, err := settings.Build(&r.m.hls.Security)
	if err != nil {
		t.Fatal(err)
	}
	r.m.hls.Security.ThirdParty = tp
	return r
}

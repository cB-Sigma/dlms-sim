package cosemtest

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"testing"

	. "github.com/cB-Sigma/dlms/cosem"

	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"

	dlmssim "github.com/cB-Sigma/dlms-sim/sim"
	v44 "github.com/cB-Sigma/schc/v44"
)

// compressionRig is a rig whose meter and client both run V.44, with a
// 1200-octet data object to write and read.
func compressionRig(t *testing.T, suite int, policy byte, ciphering string, meter, client *v44.Params) (*secRig, []byte) {
	t.Helper()
	r := newRig(t, suite, policy, func(m *testMeter, h *dlmssim.HLS) {
		m.Ciphering = ciphering
		m.DedicatedKey = ciphering == "general-ded"
		h.Compression, h.CompressAnswers = meter, meter != nil
	})
	if client != nil {
		c := &Compression{Enabled: true, CompressRequests: true, Codewords: client.Codewords, MaxStringLength: client.MaxString, History: client.History}
		if err := c.Apply("M", &r.m.hls.Security); err != nil {
			t.Fatal(err)
		}
	}
	rng := rand.New(rand.NewSource(int64(suite)*16 + int64(policy)))
	value := make([]byte, 1200)
	for i := range value {
		value[i] = byte('0' + rng.Intn(10))
	}
	r.sim.Set(1, bigOBIS, 2, hexOctets(value))
	return r, value
}

// Compressed APDUs both ways in every form that carries compression
// (general-glo, general-ded, general ciphering), both suites that have it
// and every protection: the client compresses its requests then ciphers
// them, the meter deciphers then decompresses; the meter's compressed
// answers are deciphered then decompressed (IEC 62056-5-3:2023 5.3.6,
// Table 28, Figures 31 and 32).
//
// Covers: SIG-IPE-664
func TestCompressionEndToEnd(t *testing.T) {
	def := v44.DefaultParams()
	for _, suite := range []int{1, 2} {
		for _, ciphering := range []string{"general-glo", "general-ded", "general"} {
			for _, policy := range []byte{0x10, 0x20, 0x30} {
				t.Run(fmt.Sprintf("suite%d/%s/policy%x", suite, ciphering, policy), func(t *testing.T) {
					r, value := compressionRig(t, suite, policy, ciphering, &def, &def)
					if err := r.read(t); err != nil {
						t.Fatal(err)
					}
					// A repetitive set request is worth compressing (120 octets:
					// the simulated meter takes no longer set value).
					long := hexOctets(bytes.Repeat([]byte("0123456789"), 12))
					if err := r.mt.c.SetRequest(gdlms.CreateAttributeDescriptor(1, bigOBIS, 2), long); err != nil {
						t.Fatalf("set: %v (%v)", err, r.mt.st.LastFailure())
					}
					r.sim.Set(1, bigOBIS, 2, hexOctets(value))
					got, err := r.mt.get(1, bigOBIS, 2)
					if err != nil {
						t.Fatalf("get: %v (%v)", err, r.mt.st.LastFailure())
					}
					if b := octetBytes(got.Value); !bytes.Equal(b, value) {
						t.Fatalf("read back %T of %d octets", got.Value, len(b))
					}
					in, out := r.sim.Compressed()
					if in < 1 || out < 3 {
						t.Errorf("meter decompressed %d requests and compressed %d answers", in, out)
					}
				})
			}
		}
	}
}

// Settings that do not match the meter's fail with an error that says so
// and names our settings; a meter that compresses when we have not enabled
// compression is refused with an error saying how to enable it.
//
// Covers: SIG-IPE-664
func TestCompressionMismatch(t *testing.T) {
	def := v44.DefaultParams()
	// The meter's N7 is 255, ours 32: its long string extensions do not
	// parse with our Table 4 width.
	r, _ := compressionRig(t, 1, 0x30, "general-glo", &def, &v44.Params{MaxString: 32})
	if err := r.read(t); err != nil {
		t.Fatal(err) // a short answer has no long extension
	}
	r.sim.Set(1, bigOBIS, 2, hexOctets(bytes.Repeat([]byte("0123456789"), 100)))
	if _, err := r.mt.get(1, bigOBIS, 2); err == nil {
		t.Fatal("an answer with long extensions decoded with N7 32")
	}
	f := r.mt.st.LastFailure()
	if f == nil || !strings.Contains(f.Error(), "probably do not match") || !strings.Contains(f.Error(), "codewords 1525, maxStringLength 32, history the APDU") || !errors.Is(f, v44.ErrCorrupt) {
		t.Errorf("failure %v", f)
	}

	r, _ = compressionRig(t, 2, 0x30, "general", &def, nil)
	if err := r.read(t); err == nil {
		t.Fatal("compressed answers read without compression enabled")
	}
	if f := r.mt.st.LastFailure(); !errors.Is(f, ErrCompressionOff) {
		t.Errorf("failure %v, want the compression-off error", f)
	}
}

// A third party's general-ciphering layer may be compressed (IEC
// 62056-5-3:2023 Table 26, compression "Yes" for general-ciphering between
// a third party and the server): its request layer is compressed then
// ciphered, the meter's ciphered layer for it is deciphered then
// decompressed, in suites 1 and 2 and every protection; the unprotected
// layer of annex J.3 (Figure 32, compression with no protection) is
// decompressed too, while general-signing carries none (Table 26 "No").
//
// Covers: SIG-IPE-664
func TestThirdPartyCompression(t *testing.T) {
	def := v44.DefaultParams()
	enable := func(t *testing.T, r *secRig) {
		t.Helper()
		if err := (&Compression{Enabled: true, CompressRequests: true}).Apply("M", &r.m.hls.Security); err != nil {
			t.Fatal(err)
		}
	}
	setAndGet := func(t *testing.T, r *secRig) {
		t.Helper()
		if err := r.read(t); err != nil {
			t.Fatalf("read: %v (%v)", err, r.mt.st.LastFailure())
		}
		long := hexOctets(bytes.Repeat([]byte("0123456789"), 12))
		if err := r.mt.c.SetRequest(gdlms.CreateAttributeDescriptor(1, bigOBIS, 2), long); err != nil {
			t.Fatalf("set: %v (%v)", err, r.mt.st.LastFailure())
		}
		value := bytes.Repeat([]byte("meter-answer-"), 80)
		r.sim.Set(1, bigOBIS, 2, hexOctets(value))
		got, err := r.mt.get(1, bigOBIS, 2)
		if err != nil {
			t.Fatalf("get: %v (%v)", err, r.mt.st.LastFailure())
		}
		if !bytes.Equal(octetBytes(got.Value), value) {
			t.Fatal("read back a different value")
		}
	}
	for _, suite := range []int{1, 2} {
		for _, policy := range []string{"authenticated", "encrypted", "authenticated-encrypted"} {
			t.Run(fmt.Sprintf("ciphered/suite%d/%s", suite, policy), func(t *testing.T) {
				r := tpCipherRig(t, suite, policy, "agreed-one-pass", true, func(_ *ThirdParty, h *dlmssim.HLS) {
					h.Compression, h.CompressAnswers = &def, true
				})
				enable(t, r)
				setAndGet(t, r)
				in, out := r.sim.ThirdPartyCompressed()
				if in < 1 || out < 2 {
					t.Errorf("third-party layers: meter decompressed %d, compressed %d", in, out)
				}
			})
		}
		t.Run(fmt.Sprintf("J.3/suite%d", suite), func(t *testing.T) {
			r, _ := tpRig(t, suite, 0x30, "general", "identified", false, func(_ *ThirdParty, h *dlmssim.HLS) {
				h.Compression, h.CompressAnswers = &def, true
			})
			enable(t, r)
			setAndGet(t, r)
			in, out := r.sim.ThirdPartyCompressed()
			if in != 0 || out < 2 {
				t.Errorf("third-party layers: meter decompressed %d (general-signing carries none), compressed %d", in, out)
			}
		})
	}
	// The meter compresses its layer for the third party but compression
	// is not enabled for it here: refused, saying how to enable it.
	r, _ := tpRig(t, 1, 0x30, "general", "identified", false, func(_ *ThirdParty, h *dlmssim.HLS) {
		h.Compression, h.CompressAnswers = &def, true
	})
	if err := r.read(t); err == nil {
		t.Fatal("a compressed third-party layer was read with compression off")
	}
	if f := r.mt.st.LastFailure(); !errors.Is(f, ErrCompressionOff) {
		t.Errorf("failure %v, want the compression-off error", f)
	}
}

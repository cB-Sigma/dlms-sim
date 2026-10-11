// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package cosemtest

// The test rig: a simulated meter (package sim) and a Client configured
// from text settings, as an application configures one.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"testing"
	"time"

	. "github.com/cB-Sigma/dlms/cosem"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"

	dlmssim "github.com/cB-Sigma/dlms-sim/sim"
	"github.com/cB-Sigma/dlms/wrapper"
)

// testMeter is a meter's settings as the tests give them: its address on
// the wrapper over TCP, its client address and invocation counter object,
// and its security as text (SecurityConfig).
type testMeter struct {
	ID, Address       string
	ClientAddress     int
	Timeout           time.Duration
	InvocationCounter *FrameCounterObject

	Authentication    string
	Password          string
	Security          string
	Suite             int
	SystemTitle       string
	BlockCipherKey    string
	AuthenticationKey string
	DedicatedKey      bool
	SigningKey        string
	MeterSigningKey   string
	Ciphering         string
	GeneralKey        string
	MasterKey         string
	BroadcastKey      string
	Signing           bool
	KeyAgreementKey   string
	MeterKAKey        string
	ThirdParty        *ThirdParty
	Compression       *Compression

	hls *HLS
}

// validate builds the security settings and fills in the defaults.
func (m *testMeter) validate() error {
	c := SecurityConfig{Name: m.ID, Authentication: m.Authentication, Password: m.Password, Security: m.Security,
		Suite: m.Suite, SystemTitle: m.SystemTitle, BlockCipherKey: m.BlockCipherKey, AuthenticationKey: m.AuthenticationKey,
		DedicatedKey: m.DedicatedKey, SigningKey: m.SigningKey, MeterSigningKey: m.MeterSigningKey, Ciphering: m.Ciphering,
		GeneralKey: m.GeneralKey, MasterKey: m.MasterKey, BroadcastKey: m.BroadcastKey, Signing: m.Signing,
		KeyAgreementKey: m.KeyAgreementKey, MeterKAKey: m.MeterKAKey, ThirdParty: m.ThirdParty, Compression: m.Compression}
	h, _, err := c.Build()
	if err != nil {
		return err
	}
	m.hls = h
	if m.ClientAddress == 0 {
		m.ClientAddress = DefaultClientAddress(h.Mechanism)
	}
	if m.Timeout <= 0 {
		m.Timeout = 10 * time.Second
	}
	if m.InvocationCounter != nil && m.InvocationCounter.ClientAddress == 0 {
		m.InvocationCounter.ClientAddress = 16
	}
	return nil
}

// testConn is a Client of a testMeter, with the shortcuts the tests use.
type testConn struct {
	m  *testMeter
	cl *Client
	c  gdlms.Client     // the open association's client
	st *SecureTransport // the last association's secure transport
}

func (mt *testConn) client() *Client {
	if mt.cl == nil {
		m := mt.m
		mt.cl = NewClient(ClientConfig{
			Transport: func(client int) (gdlms.Transport, error) {
				return wrapper.New("tcp", m.Address, client, 1, m.Timeout)
			},
			Name: m.ID, Where: m.Address,
		})
	}
	m := mt.m
	cfg := &mt.cl.Config
	cfg.ClientAddress, cfg.HLS, cfg.Password, cfg.Timeout, cfg.InvocationCounter = m.ClientAddress, m.hls, []byte(m.Password), m.Timeout, m.InvocationCounter
	return mt.cl
}

// connect associates unless an association is open.
func (mt *testConn) connect() error {
	if mt.c != nil && mt.c.IsAssociated() {
		return nil
	}
	mt.close()
	cl := mt.client()
	err := cl.Connect()
	mt.st = cl.Secure()
	if err != nil {
		return err
	}
	mt.c = cl.Association().Client
	return nil
}

func (mt *testConn) close() {
	if mt.c == nil {
		return
	}
	mt.cl.Close()
	mt.c = nil
}

func (mt *testConn) get(class uint16, obis string, attr int8) (axdr.DlmsData, error) {
	return mt.cl.Get(class, obis, attr)
}

var (
	meterST  = []byte("LNT\x00\x00\x01\x23\x45")
	clientST = mustHexS("53474D0000000001")
)

func mustHexS(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func privPEM(t *testing.T, k *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
}

func pubPEM(t *testing.T, k *ecdsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// pki is the key material of one meter and client pair.
type pki struct {
	meterSign, meterKA, clientSign, clientKA *ecdsa.PrivateKey
}

func newPKI(t *testing.T, suite int) pki {
	t.Helper()
	curve := elliptic.P256()
	if suite == 2 {
		curve = elliptic.P384()
	}
	gen := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	return pki{gen(), gen(), gen(), gen()}
}

// secRig is a simulated HLS-GMAC meter and a configured client.
type secRig struct {
	sim  *dlmssim.Meter
	h    *dlmssim.HLS
	m    *testMeter
	mt   *testConn
	keys pki
}

func newRig(t *testing.T, suite int, policy byte, configure func(*testMeter, *dlmssim.HLS)) *secRig {
	t.Helper()
	n := Suite(suite).KeyLen()
	key, ak, master := bytes.Repeat([]byte{0x11}, n), bytes.Repeat([]byte{0x22}, n), bytes.Repeat([]byte{0x44}, n)
	security := map[byte]string{0x10: "authenticated", 0x20: "encrypted", 0x30: "authenticated-encrypted"}[policy]
	r := &secRig{}
	h := &dlmssim.HLS{Policy: policy, Suite: byte(suite), SystemTitle: meterST, Key: key, AuthKey: ak, MasterKey: master,
		FrameCounterOBIS: "0.0.43.1.3.255"}
	m := &testMeter{ID: "M", Authentication: "hls-gmac", Security: security, Suite: suite,
		BlockCipherKey: hex.EncodeToString(key), AuthenticationKey: hex.EncodeToString(ak), MasterKey: hex.EncodeToString(master),
		InvocationCounter: &FrameCounterObject{OBIS: "0.0.43.1.3.255"}}
	if suite != 0 {
		r.keys = newPKI(t, suite)
		h.SigningKey, h.KAKey = r.keys.meterSign, r.keys.meterKA
		h.ClientKey, h.ClientKAKey = &r.keys.clientSign.PublicKey, &r.keys.clientKA.PublicKey
		m.SigningKey, m.MeterSigningKey = privPEM(t, r.keys.clientSign), pubPEM(t, &r.keys.meterSign.PublicKey)
		m.KeyAgreementKey, m.MeterKAKey = privPEM(t, r.keys.clientKA), pubPEM(t, &r.keys.meterKA.PublicKey)
	}
	if configure != nil {
		configure(m, h)
	}
	sim := &dlmssim.Meter{HLS: h}
	sim.Register("1.0.12.7.0.255", axdr.CreateAxdrLongUnsigned(23050), -2, 35)
	sim.Set(1, "0.0.43.1.3.255", 2, axdr.CreateAxdrDoubleLongUnsigned(10))
	addr, err := sim.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sim.Close() })
	m.Address = addr
	if err := m.validate(); err != nil {
		t.Fatal(err)
	}
	r.sim, r.h, r.m = sim, h, m
	r.mt = &testConn{m: m}
	t.Cleanup(r.mt.close)
	return r
}

// read associates (if needed) and reads the voltage register.
func (r *secRig) read(t *testing.T) error {
	t.Helper()
	if err := r.mt.connect(); err != nil {
		return err
	}
	v, err := r.mt.get(3, "1.0.12.7.0.255", 2)
	if err != nil {
		return err
	}
	if v.Value != uint16(23050) {
		return fmt.Errorf("read %v", v.Value)
	}
	return nil
}

func ecKey(t *testing.T, c elliptic.Curve) (*ecdsa.PrivateKey, string, string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalECPrivateKey(k)
	pub, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	return k, string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}))
}

type secCase struct {
	name      string
	mech      string
	mechID    byte
	suite     int
	security  string
	policy    byte
	dedicated bool
}

func secCases() []secCase {
	var cases []secCase
	add := func(mech string, id byte, suite int, security string, policy byte, ded bool) {
		cases = append(cases, secCase{fmt.Sprintf("%s/suite%d/%s/ded=%v", mech, suite, security, ded), mech, id, suite, security, policy, ded})
	}
	for _, sec := range []struct {
		name   string
		policy byte
	}{{"authenticated", 0x10}, {"encrypted", 0x20}, {"authenticated-encrypted", 0x30}} {
		for _, suite := range []int{0, 1, 2} {
			add("hls-gmac", 5, suite, sec.name, sec.policy, false)
			add("hls-gmac", 5, suite, sec.name, sec.policy, true)
		}
		add("hls-ecdsa", 7, 1, sec.name, sec.policy, true)
		add("hls-ecdsa", 7, 2, sec.name, sec.policy, false)
	}
	for _, m := range []struct {
		name string
		id   byte
	}{{"hls-aes", 2}, {"hls-md5", 3}, {"hls-sha1", 4}, {"hls-sha256", 6}} {
		add(m.name, m.id, 0, "none", 0, false)
		add(m.name, m.id, 0, "authenticated-encrypted", 0x30, true)
	}
	add("low", 1, 0, "authenticated-encrypted", 0x30, false)
	return cases
}

// hexOctets is an octet-string value (gosem takes it as hex).
func hexOctets(b []byte) *axdr.DlmsData { return axdr.CreateAxdrOctetString(hex.EncodeToString(b)) }

// octetBytes is the bytes of a decoded octet-string.
func octetBytes(v any) []byte {
	switch x := v.(type) {
	case []byte:
		return x
	case string:
		b, _ := hex.DecodeString(x)
		return b
	}
	return nil
}

var tpST = []byte("TPH\x00\x00\x00\x00\x07")

const bigOBIS = "0.0.96.1.9.255"

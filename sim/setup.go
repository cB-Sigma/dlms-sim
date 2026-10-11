package sim

// The security setup object (class_id 64, version 1) of an HLS meter:
// attributes security_policy (2), security_suite (3), client_system_title
// (4), server_system_title (5) and certificates (6); methods
// security_activate (1), key_transfer (2), key_agreement (3),
// generate_key_pair (4), generate_certificate_request (5),
// import_certificate (6), export_certificate (7) and remove_certificate
// (8). New keys and policies apply from the next association; a new
// global unicast key resets the client's frame counter. key_transfer and
// key_agreement take key_id 0–3 (3 the master key, which unwraps later
// transfers).

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"strings"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"
)

// Action results.
const (
	actOK          = 0x00
	actTypeUnmatch = 0x0C
	actOther       = 0xFA
)

func (h *HLS) setupOBIS() string {
	if h.SetupOBIS == "" {
		return "0.0.43.0.0.255"
	}
	return h.SetupOBIS
}

func (h *HLS) curve() elliptic.Curve {
	if h.Suite == 2 {
		return elliptic.P384()
	}
	return elliptic.P256()
}

// SecurityPolicy is the security_policy attribute (version 1 bits: 2
// authenticated request, 3 encrypted request, 4 signed request, 5
// authenticated response, 6 encrypted response, 7 signed response).
func (m *Meter) SecurityPolicy() byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.policyBits()
}

func (m *Meter) policyBits() byte {
	h := m.HLS
	var b byte
	if h.Policy&0x10 != 0 {
		b |= 0x04 | 0x20
	}
	if h.Policy&0x20 != 0 {
		b |= 0x08 | 0x40
	}
	if h.RequireSigning {
		b |= 0x10 | 0x80
	}
	return b
}

// Keys returns the meter's current global unicast, broadcast and
// authentication keys.
func (m *Meter) Keys() (unicast, broadcast, auth []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return clone(m.HLS.Key), clone(m.HLS.BroadcastKey), clone(m.HLS.AuthKey)
}

// MasterKey returns the meter's current master key (KEK).
func (m *Meter) MasterKey() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return clone(m.HLS.MasterKey)
}

// KeyChanges is how many keys key_transfer and key_agreement changed.
func (m *Meter) KeyChanges() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.keyChanges
}

// Certificates returns the certificates the meter holds.
func (m *Meter) Certificates() []*x509.Certificate {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]*x509.Certificate(nil), m.certs...)
}

// SigningPublicKey is the meter's current signing public key.
func (m *Meter) SigningPublicKey() *ecdsa.PublicKey {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.HLS.SigningKey == nil {
		return nil
	}
	return &m.HLS.SigningKey.PublicKey
}

// KeyAgreementPublicKey is the meter's current key agreement public key.
func (m *Meter) KeyAgreementPublicKey() *ecdsa.PublicKey {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.HLS.KAKey == nil {
		return nil
	}
	return &m.HLS.KAKey.PublicKey
}

func num(d *axdr.DlmsData) int {
	if d == nil {
		return -1
	}
	switch v := d.Value.(type) {
	case uint8:
		return int(v)
	case int8:
		return int(v)
	case uint16:
		return int(v)
	case int16:
		return int(v)
	case uint32:
		return int(v)
	case int32:
		return int(v)
	case int:
		return v
	}
	return -1
}

func octetsOf(d *axdr.DlmsData) ([]byte, bool) {
	if d == nil {
		return nil, false
	}
	switch v := d.Value.(type) {
	case string:
		b, err := hex.DecodeString(v)
		return b, err == nil
	case []byte:
		return v, true
	}
	return nil, false
}

func items(d *axdr.DlmsData) []*axdr.DlmsData {
	if d == nil {
		return nil
	}
	v, _ := d.Value.([]*axdr.DlmsData)
	return v
}

func octetData(b []byte) *axdr.DlmsData { return axdr.CreateAxdrOctetString(hex.EncodeToString(b)) }

// setupAttribute answers a GET of the security setup object (callers hold
// m.mu).
func (m *Meter) setupAttribute(attr int8) ([]byte, byte) {
	h := m.HLS
	switch attr {
	case 2:
		return encode(axdr.CreateAxdrEnum(m.policyBits()))
	case 3:
		return encode(axdr.CreateAxdrEnum(h.Suite))
	case 5:
		return encode(octetData(h.SystemTitle))
	case 6:
		var list []*axdr.DlmsData
		for _, c := range m.certs {
			e, t := m.classify(c)
			list = append(list, axdr.CreateAxdrStructure([]*axdr.DlmsData{
				axdr.CreateAxdrEnum(e), axdr.CreateAxdrEnum(t),
				octetData(c.SerialNumber.Bytes()), octetData(c.RawIssuer), octetData(c.RawSubject), octetData(nil),
			}))
		}
		return encode(axdr.CreateAxdrArray(list))
	}
	return nil, 4
}

// classify gives a certificate's entity (0 server, 1 client, 2
// certification authority) and type (0 digital signature, 1 key
// agreement, 2 TLS).
func (m *Meter) classify(c *x509.Certificate) (entity, typ byte) {
	h := m.HLS
	pub, _ := c.PublicKey.(*ecdsa.PublicKey)
	own := func(k *ecdsa.PrivateKey) bool { return k != nil && pub != nil && k.PublicKey.Equal(pub) }
	switch {
	case c.IsCA:
		entity = 2
	case own(h.SigningKey) || own(h.KAKey) || own(m.tlsKey):
		entity = 0
	default:
		entity = 1
	}
	switch {
	case c.KeyUsage&x509.KeyUsageKeyAgreement != 0:
		typ = 1
	case c.KeyUsage&x509.KeyUsageDigitalSignature != 0 && len(c.ExtKeyUsage) > 0:
		typ = 2
	default:
		typ = 0
	}
	return entity, typ
}

// setupAction runs a security setup method (callers hold m.mu); the
// answer is an action result and optional return data.
func (m *Meter) setupAction(s *session, req gdlms.ActionRequestNormal) (byte, *axdr.DlmsData) {
	h := m.HLS
	p := req.MethodParam
	switch req.MethodInfo.MethodID {
	case 1: // security_activate: policy bits, never weaker
		bits := num(p)
		if bits < 0 || byte(bits)&m.policyBits() != m.policyBits() {
			return actOther, nil
		}
		b := byte(bits)
		var pol byte
		if b&0x24 != 0 {
			pol |= 0x10
		}
		if b&0x48 != 0 {
			pol |= 0x20
		}
		h.Policy, h.RequireSigning = pol, b&0x90 != 0
		return actOK, nil
	case 2: // key_transfer
		type change struct {
			id  int
			key []byte
		}
		var changes []change
		for _, it := range items(p) {
			f := items(it)
			if len(f) != 2 {
				return actTypeUnmatch, nil
			}
			w, ok := octetsOf(f[1])
			if !ok {
				return actTypeUnmatch, nil
			}
			key, ok := unwrap(h.MasterKey, w)
			id := num(f[0])
			if !ok || id < 0 || id > 3 || len(key) != len(h.MasterKey) {
				return actOther, nil
			}
			changes = append(changes, change{id, key})
		}
		if len(changes) == 0 {
			return actTypeUnmatch, nil
		}
		for _, c := range changes {
			m.setKey(c.id, c.key)
		}
		return actOK, nil
	case 3: // key_agreement: C(2e, 0s)
		if h.Suite == 0 || h.SigningKey == nil {
			return actOther, nil
		}
		var back []*axdr.DlmsData
		type change struct {
			id  int
			key []byte
		}
		var changes []change
		for _, it := range items(p) {
			f := items(it)
			if len(f) != 2 {
				return actTypeUnmatch, nil
			}
			data, ok := octetsOf(f[1])
			id := num(f[0])
			if !ok || id < 0 || id > 3 {
				return actTypeUnmatch, nil
			}
			eph := h.signedEphemeral(h.ClientKey, data, byte(id))
			if eph == nil {
				return actOther, nil
			}
			e, _ := ecdsa.GenerateKey(h.curve(), rand.Reader)
			pub := pointOf(&e.PublicKey)
			z := ecdhWith(e, eph)
			alg := h.algorithm()
			if id == 3 {
				alg = h.wrapAlgorithm()
			}
			changes = append(changes, change{id, h.deriveFor(z, alg, s.hls.clientST, h.SystemTitle)})
			back = append(back, axdr.CreateAxdrStructure([]*axdr.DlmsData{axdr.CreateAxdrEnum(uint8(id)), octetData(cat(pub, h.signWith(h.SigningKey, cat([]byte{byte(id)}, pub))))}))
		}
		if len(changes) == 0 {
			return actTypeUnmatch, nil
		}
		for _, c := range changes {
			m.setKey(c.id, c.key)
		}
		return actOK, axdr.CreateAxdrArray(back)
	case 4: // generate_key_pair
		k, err := ecdsa.GenerateKey(h.curve(), rand.Reader)
		if err != nil || h.Suite == 0 {
			return actOther, nil
		}
		switch num(p) {
		case 0:
			h.SigningKey = k
		case 1:
			h.KAKey = k
		case 2:
			m.tlsKey = k
		default:
			return actTypeUnmatch, nil
		}
		return actOK, nil
	case 5: // generate_certificate_request
		var k *ecdsa.PrivateKey
		switch num(p) {
		case 0:
			k = h.SigningKey
		case 1:
			k = h.KAKey
		case 2:
			k = m.tlsKey
		}
		if k == nil {
			return actOther, nil
		}
		der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject: pkix.Name{CommonName: strings.ToUpper(hex.EncodeToString(h.SystemTitle))},
		}, k)
		if err != nil {
			return actOther, nil
		}
		return actOK, octetData(der)
	case 6: // import_certificate
		der, ok := octetsOf(p)
		if !ok {
			return actTypeUnmatch, nil
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return actOther, nil
		}
		for i, old := range m.certs {
			if old.SerialNumber.Cmp(c.SerialNumber) == 0 && string(old.RawIssuer) == string(c.RawIssuer) {
				m.certs = append(m.certs[:i], m.certs[i+1:]...)
				break
			}
		}
		m.certs = append(m.certs, c)
		// A client certificate becomes the key the meter trusts.
		if e, t := m.classify(c); e == 1 {
			if pub, ok := c.PublicKey.(*ecdsa.PublicKey); ok {
				switch t {
				case 0:
					h.ClientKey = pub
				case 1:
					h.ClientKAKey = pub
				}
			}
		}
		return actOK, nil
	case 7, 8: // export_certificate, remove_certificate
		i := m.findCert(p)
		if i < 0 {
			return actOther, nil
		}
		if req.MethodInfo.MethodID == 7 {
			return actOK, octetData(m.certs[i].Raw)
		}
		m.certs = append(m.certs[:i], m.certs[i+1:]...)
		return actOK, nil
	}
	return actOther, nil
}

// findCert resolves a certificate_identification: structure {type enum,
// structure {entity, type, system title} (0) or {serial, issuer} (1)}.
func (m *Meter) findCert(p *axdr.DlmsData) int {
	f := items(p)
	if len(f) != 2 {
		return -1
	}
	opt := items(f[1])
	switch num(f[0]) {
	case 0:
		if len(opt) != 3 {
			return -1
		}
		st, _ := octetsOf(opt[2])
		want := strings.ToUpper(hex.EncodeToString(st))
		for i, c := range m.certs {
			e, t := m.classify(c)
			if int(e) == num(opt[0]) && int(t) == num(opt[1]) && strings.EqualFold(c.Subject.CommonName, want) {
				return i
			}
		}
	case 1:
		if len(opt) != 2 {
			return -1
		}
		serial, _ := octetsOf(opt[0])
		issuer, _ := octetsOf(opt[1])
		for i, c := range m.certs {
			if c.SerialNumber.Cmp(new(big.Int).SetBytes(serial)) == 0 && string(c.RawIssuer) == string(issuer) {
				return i
			}
		}
	}
	return -1
}

// setKey installs a new key for later associations (callers hold m.mu).
func (m *Meter) setKey(id int, key []byte) {
	h := m.HLS
	switch id {
	case 0:
		h.Key = key
		if h.FrameCounterOBIS != "" {
			m.objects[keyOf(1, h.FrameCounterOBIS, 2)] = *axdr.CreateAxdrDoubleLongUnsigned(0)
		}
	case 1:
		h.BroadcastKey = key
	case 2:
		h.AuthKey = key
	case 3:
		h.MasterKey = key
	}
	m.keyChanges++
}

func keyOf(class uint16, obis string, attr int8) string { return key(class, obis, attr) }

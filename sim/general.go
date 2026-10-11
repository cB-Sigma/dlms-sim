package sim

// General-glo-, general-ded- and general ciphering and general signing on
// the meter side, written apart from package dlms so the two check each
// other. See general.go in package dlms for the layouts and our reading of
// the authenticated data and the key derivation.

import (
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"math/big"
	"time"
)

type keyInfo struct {
	choice, id   byte
	params, data []byte
}

// general is a general-ciphering or general-signing APDU.
type general struct {
	hdr     [5][]byte // transaction-id, originator, recipient, date-time, other-information
	ki      *keyInfo
	content []byte
	sig     []byte
	key     []byte // the content key (not sent)
}

func octs(b []byte) []byte { return cat(berLen(len(b)), b) }

func (g *general) header() []byte {
	var out []byte
	for _, f := range g.hdr {
		out = append(out, octs(f)...)
	}
	return out
}

func (g *general) encode() []byte {
	out := cat([]byte{0xDD}, g.header())
	if g.ki == nil {
		out = append(out, 0)
	} else {
		out = append(out, 1, g.ki.choice)
		switch g.ki.choice {
		case 0:
			out = append(out, g.ki.id)
		case 1:
			out = append(out, g.ki.id)
			out = append(out, octs(g.ki.data)...)
		case 2:
			out = append(out, octs(g.ki.params)...)
			out = append(out, octs(g.ki.data)...)
		}
	}
	return append(out, octs(g.content)...)
}

type cursor struct {
	b  []byte
	ok bool
}

func (c *cursor) next() []byte {
	if !c.ok {
		return nil
	}
	n, sz := readLen(c.b)
	if n < 0 || sz+n > len(c.b) {
		c.ok = false
		return nil
	}
	v := c.b[sz : sz+n]
	c.b = c.b[sz+n:]
	return v
}

func (c *cursor) one() byte {
	if !c.ok || len(c.b) == 0 {
		c.ok = false
		return 0
	}
	v := c.b[0]
	c.b = c.b[1:]
	return v
}

func decodeGeneral(apdu []byte) (*general, bool) {
	c := &cursor{b: apdu[1:], ok: true}
	g := &general{}
	for i := range g.hdr {
		g.hdr[i] = c.next()
	}
	if c.one() == 1 {
		g.ki = &keyInfo{choice: c.one()}
		switch g.ki.choice {
		case 0:
			g.ki.id = c.one()
		case 1:
			g.ki.id = c.one()
			g.ki.data = c.next()
		case 2:
			g.ki.params = c.next()
			g.ki.data = c.next()
		default:
			return nil, false
		}
	}
	g.content = c.next()
	return g, c.ok && len(c.b) == 0
}

func decodeSigning(apdu []byte) (*general, []byte, bool) {
	c := &cursor{b: apdu[1:], ok: true}
	g := &general{}
	for i := range g.hdr {
		g.hdr[i] = c.next()
	}
	g.content = c.next()
	signed := apdu[1 : len(apdu)-len(c.b)]
	g.sig = c.next()
	return g, signed, c.ok && len(c.b) == 0
}

func encodeGloDed(tag byte, st, content []byte) []byte {
	return cat([]byte{tag}, octs(st), octs(content))
}

func decodeGloDed(apdu []byte) (st, content []byte, ok bool) {
	c := &cursor{b: apdu[1:], ok: true}
	st = c.next()
	content = c.next()
	return st, content, c.ok && len(c.b) == 0
}

// policyOf is the protection the session (or, before one, the meter)
// uses.
func (m *Meter) policyOf(s *session) byte {
	if s.hls != nil {
		return s.hls.keys.policy
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.hlsOf(s).Policy
}

func (h *HLS) algorithm() []byte {
	if h.Suite == 2 {
		return []byte{0x60, 0x85, 0x74, 0x05, 0x08, 0x03, 0x01}
	}
	return []byte{0x60, 0x85, 0x74, 0x05, 0x08, 0x03, 0x00}
}

// derive is the concatenation KDF: hash(00000001 ‖ Z ‖ alg ‖ U ‖ V).
func (h *HLS) derive(z, u, v []byte) []byte { return h.deriveFor(z, h.algorithm(), u, v) }

// wrapAlgorithm is the AES-WRAP algorithm ID (an agreed master key).
func (h *HLS) wrapAlgorithm() []byte {
	a := h.algorithm()
	return []byte{a[0], a[1], a[2], a[3], a[4], a[5], a[6] + 2}
}

func (h *HLS) deriveFor(z, alg, u, v []byte) []byte {
	in := cat([]byte{0, 0, 0, 1}, z, alg, u, v)
	if h.Suite == 2 {
		d := sha512.Sum384(in)
		return d[:32]
	}
	d := sha256.Sum256(in)
	return d[:16]
}

func ecdhWith(priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) []byte {
	if priv == nil || pub == nil {
		return nil
	}
	a, err := priv.ECDH()
	if err != nil {
		return nil
	}
	b, err := pub.ECDH()
	if err != nil {
		return nil
	}
	z, err := a.ECDH(b)
	if err != nil {
		return nil
	}
	return z
}

func pointOf(k *ecdsa.PublicKey) []byte {
	b, _ := k.Bytes()
	return b[1:]
}

func size(k *ecdsa.PublicKey) int { return (k.Curve.Params().BitSize + 7) / 8 }

func (h *HLS) hash(b []byte) []byte {
	if h.Suite == 2 {
		d := sha512.Sum384(b)
		return d[:]
	}
	d := sha256.Sum256(b)
	return d[:]
}

func (h *HLS) signWith(k *ecdsa.PrivateKey, data []byte) []byte {
	r, s, err := ecdsa.Sign(rand.Reader, k, h.hash(data))
	if err != nil {
		return nil
	}
	n := size(&k.PublicKey)
	out := make([]byte, 2*n)
	r.FillBytes(out[:n])
	s.FillBytes(out[n:])
	return out
}

func (h *HLS) verifyWith(k *ecdsa.PublicKey, data, sig []byte) bool {
	if k == nil || len(sig) != 2*size(k) {
		return false
	}
	n := size(k)
	return ecdsa.Verify(k, h.hash(data), new(big.Int).SetBytes(sig[:n]), new(big.Int).SetBytes(sig[n:]))
}

// signedEphemeral opens a signed ephemeral public key.
func (h *HLS) signedEphemeral(signer *ecdsa.PublicKey, data []byte, prefix ...byte) *ecdsa.PublicKey {
	if signer == nil || len(data) != 4*size(signer) {
		return nil
	}
	n := 2 * size(signer)
	if !h.verifyWith(signer, cat(prefix, data[:n]), data[n:]) {
		return nil
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(signer.Curve, cat([]byte{4}, data[:n]))
	if err != nil {
		return nil
	}
	return pub
}

// contentKey finds the key of a general-ciphering request (callers hold
// m.mu); nil when it cannot.
func (m *Meter) contentKey(s *session, g *general) []byte {
	h := m.hlsOf(s)
	if g.ki == nil {
		return nil
	}
	switch g.ki.choice {
	case 0:
		if g.ki.id == 0 {
			return s.hls.keys.key
		}
	case 1:
		k, ok := unwrap(h.MasterKey, g.ki.data)
		if ok {
			return k
		}
	case 2:
		if len(g.ki.params) != 1 {
			return nil
		}
		switch g.ki.params[0] {
		case 1:
			eph := h.signedEphemeral(h.ClientKey, g.ki.data)
			if z := ecdhWith(h.KAKey, eph); z != nil {
				return h.derive(z, g.hdr[1], g.hdr[2])
			}
		case 2:
			if z := ecdhWith(h.KAKey, h.ClientKAKey); z != nil {
				return h.derive(z, cat(g.hdr[1], []byte{byte(len(g.hdr[0]))}, g.hdr[0]), g.hdr[2])
			}
		}
	}
	return nil
}

// answerGeneral starts the general-ciphering response to g, with a fresh
// key of the kind the request used (callers hold m.mu).
func (m *Meter) answerGeneral(s *session, g *general) *general {
	h := m.hlsOf(s)
	out := &general{hdr: [5][]byte{g.hdr[0], h.SystemTitle, s.hls.clientST, cosemNow(), nil}}
	switch g.ki.choice {
	case 0:
		out.ki, out.key = &keyInfo{choice: 0, id: 0}, s.hls.keys.key
	case 1:
		out.key = make([]byte, len(h.MasterKey))
		_, _ = rand.Read(out.key)
		out.ki = &keyInfo{choice: 1, id: 0, data: wrap(h.MasterKey, out.key)}
	case 2:
		if g.ki.params[0] == 1 {
			e, _ := ecdsa.GenerateKey(h.KAKey.Curve, rand.Reader)
			pub := pointOf(&e.PublicKey)
			offer := cat(pub, h.signWith(h.SigningKey, pub))
			out.key = h.derive(ecdhWith(e, h.ClientKAKey), out.hdr[1], out.hdr[2])
			out.ki = &keyInfo{choice: 2, params: []byte{1}, data: offer}
		} else {
			out.key = h.derive(ecdhWith(h.KAKey, h.ClientKAKey), cat(out.hdr[1], []byte{byte(len(out.hdr[0]))}, out.hdr[0]), out.hdr[2])
			out.ki = &keyInfo{choice: 2, params: []byte{2}}
		}
	}
	return out
}

// signedRequest checks a general-signing request, handles its content and
// signs the answer.
func (m *Meter) signedRequest(s *session, apdu []byte) []byte {
	h := m.hlsOf(s)
	g, signed, ok := decodeSigning(apdu)
	m.mu.Lock()
	clientKey, signer := h.ClientKey, h.SigningKey
	m.mu.Unlock()
	if !ok || s.hls == nil || string(g.hdr[1]) != string(s.hls.clientST) || !h.verifyWith(clientKey, signed, g.sig) {
		m.mu.Lock()
		m.badSignatures++
		m.mu.Unlock()
		return []byte{0xD8, 0x01, 0x02}
	}
	s.inSigned = true
	resp := m.handle(s, g.content)
	s.inSigned = false
	if len(resp) == 0 || resp[0] == 0xD8 || h.UnsignedAnswers {
		return resp
	}
	out := &general{hdr: [5][]byte{g.hdr[0], h.SystemTitle, s.hls.clientST, cosemNow(), nil}, content: resp}
	body := cat(out.header(), octs(resp))
	m.mu.Lock()
	m.signed++
	m.mu.Unlock()
	return cat([]byte{0xDF}, body, octs(h.signWith(signer, body)))
}

// Signed is how many signed requests the meter accepted, and
// BadSignatures how many it refused.
func (m *Meter) Signed() (accepted, refused int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.signed, m.badSignatures
}

func cosemNow() []byte {
	t := time.Now().UTC()
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b, uint16(t.Year()))
	b[2], b[3], b[4], b[5], b[6], b[7] = byte(t.Month()), byte(t.Day()), 0xFF, byte(t.Hour()), byte(t.Minute()), byte(t.Second())
	return b
}

// wrap and unwrap are RFC 3394 AES key wrap (index form, section 2.2.1).
func wrap(kek, key []byte) []byte {
	block, _ := aes.NewCipher(kek)
	n := len(key) / 8
	a := []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}
	r := make([][]byte, n)
	for i := range r {
		r[i] = clone(key[8*i : 8*i+8])
	}
	for j := 0; j <= 5; j++ {
		for i := 1; i <= n; i++ {
			b := make([]byte, 16)
			block.Encrypt(b, cat(a, r[i-1]))
			t := uint64(n*j + i)
			a = b[:8]
			binary.BigEndian.PutUint64(a, binary.BigEndian.Uint64(a)^t)
			r[i-1] = b[8:]
		}
	}
	out := clone(a)
	for _, x := range r {
		out = append(out, x...)
	}
	return out
}

func unwrap(kek, c []byte) ([]byte, bool) {
	block, err := aes.NewCipher(kek)
	if err != nil || len(c) < 24 || len(c)%8 != 0 {
		return nil, false
	}
	n := len(c)/8 - 1
	a := clone(c[:8])
	r := make([][]byte, n)
	for i := range r {
		r[i] = clone(c[8+8*i : 16+8*i])
	}
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			t := uint64(n*j + i)
			x := clone(a)
			binary.BigEndian.PutUint64(x, binary.BigEndian.Uint64(x)^t)
			b := make([]byte, 16)
			block.Decrypt(b, cat(x, r[i-1]))
			a, r[i-1] = b[:8], b[8:]
		}
	}
	if subtle.ConstantTimeCompare(a, []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}) != 1 {
		return nil, false
	}
	var out []byte
	for _, x := range r {
		out = append(out, x...)
	}
	return out, true
}

// Forms counts the protected requests the meter received, by APDU tag.
func (m *Meter) Forms() map[byte]int {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[byte]int{}
	for k, v := range m.forms {
		out[k] = v
	}
	return out
}

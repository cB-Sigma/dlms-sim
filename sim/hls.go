package sim

// Application-layer security on the meter side: HLS authentication
// mechanisms 2–7, security suites 0–2, authentication-only,
// encryption-only or authenticated-encrypted APDUs, and glo- or ded-
// (dedicated key) protection. Written separately from the client code in
// package dlms, and both are checked against the Green Book's AES-GCM
// example, so the two check each other.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"math/big"

	"gitlab.com/circutor-library/gosem/pkg/axdr"

	v44 "github.com/cB-Sigma/schc/v44"
)

// HLS makes the simulated meter require high-level security (and APDU
// protection) from every client but the public client (16).
type HLS struct {
	Mechanism byte // 2–7 (default 5, GMAC)
	// Context, when 1 (logical name referencing without ciphering) or 3
	// (with ciphering), is the only application context the meter
	// accepts: an AARQ proposing another is refused with diagnostic 2
	// (application context name not supported), as meters configured for
	// one context do. 0 accepts either.
	Context     byte
	Secret      []byte // mechanisms 2, 3, 4 and 6
	Policy      byte   // 0x10 authentication, 0x20 encryption, 0x30 both; 0 unprotected
	Suite       byte   // 0, 1 or 2
	SystemTitle []byte // the meter's, 8 bytes
	Key         []byte // global unicast key
	AuthKey     []byte
	// SigningKey is the meter's key and ClientKey the client's public key
	// (mechanism 7).
	SigningKey *ecdsa.PrivateKey
	ClientKey  *ecdsa.PublicKey
	// FrameCounterOBIS, when set, is a class 1 object (readable by the
	// public client) holding the last client invocation counter; an AARQ
	// whose counter is not above it is refused, as real meters do.
	FrameCounterOBIS string
	// MasterKey is the KEK (key_transfer, wrapped keys); BroadcastKey the
	// global broadcast key.
	MasterKey    []byte
	BroadcastKey []byte
	// KAKey is the meter's key agreement key and ClientKAKey the client's
	// public one (general-ciphering agreed keys).
	KAKey       *ecdsa.PrivateKey
	ClientKAKey *ecdsa.PublicKey
	// RequireSigning makes associations need general-signing both ways
	// (also set by security_activate with the signed-request bit).
	RequireSigning bool
	// UnsignedAnswers makes the meter answer signed requests unsigned (a
	// misbehaving meter, for tests).
	UnsignedAnswers bool
	// SetupOBIS is the security setup object (default 0.0.43.0.0.255).
	SetupOBIS string
	// BroadcastAnswers makes the meter protect its service-specific
	// answers with the global broadcast key (security control bit 6).
	BroadcastAnswers bool
	// Unauthenticated takes associations without authentication but with
	// protected APDUs (the IS 15959 Part 2 IHD association).
	Unauthenticated bool
	// CompressedAnswers sets the compression bit (security control bit
	// 7) on its service-specific answers; the body is not compressed,
	// since a client must refuse such APDUs before opening them.
	CompressedAnswers bool
	// Compression is the meter's V.44 setting (IEC 62056-5-3:2023 5.3.6):
	// general-glo, general-ded and general ciphered requests with the
	// compression bit are deciphered, then decompressed with it (one that
	// does not decode is answered with an exception); nil refuses them.
	// CompressAnswers makes the meter compress its answers in those forms
	// before ciphering them.
	Compression     *v44.Params
	CompressAnswers bool
	// ThirdPartyST and ThirdPartyKey are a third party's system title and
	// signing public key (IEC 62056-5-3:2023 annex J): a request it signed
	// for the meter, inside the client's general-glo/ded or general
	// ciphering, is accepted, and the answer carries a layer for it inside
	// the client's: general-signing when ThirdPartySignedAnswers (J.2),
	// else general-ciphering with no protection (J.3).
	ThirdPartyST            []byte
	ThirdPartyKey           *ecdsa.PublicKey
	ThirdPartySignedAnswers bool
	// ThirdPartyKAKey and ThirdPartyAuthKey are the third party's static
	// key agreement public key and the authentication key it uses: a
	// request it ciphered in general-ciphering with an agreed key is
	// opened, and the answer ciphered for it the same way (5.7.3).
	ThirdPartyKAKey   *ecdsa.PublicKey
	ThirdPartyAuthKey []byte
	// ThirdPartyBadSignature makes the meter sign its answers for the
	// third party with a key the third party does not know (for tests).
	ThirdPartyBadSignature bool

	tpRequests, releases, badReleases int
	compressedIn, compressedOut       int
	tpCompressedIn, tpCompressedOut   int
}

// ThirdPartyCompressed is how many compressed third-party layers the meter
// decompressed, and how many of its layers for the third party it
// compressed.
func (m *Meter) ThirdPartyCompressed() (requests, answers int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.HLS == nil {
		return 0, 0
	}
	return m.HLS.tpCompressedIn, m.HLS.tpCompressedOut
}

// compress is V.44 of b when the meter compresses its answers (callers
// hold m.mu); ok says it did.
func (h *HLS) compress(b []byte) ([]byte, bool) {
	if !h.CompressAnswers || h.Compression == nil {
		return b, false
	}
	out, err := v44.Compress(*h.Compression, b)
	if err != nil {
		return b, false
	}
	return out, true
}

// decompress expands a compressed layer (callers hold m.mu); ok is false
// when the meter has no compression setting or it does not decode.
func (h *HLS) decompress(b []byte) ([]byte, bool) {
	if h.Compression == nil {
		return nil, false
	}
	out, err := v44.Decompress(*h.Compression, b)
	return out, err == nil
}

// Compressed is how many compressed requests the meter decompressed and
// how many answers it compressed.
func (m *Meter) Compressed() (requests, answers int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.HLS == nil {
		return 0, 0
	}
	return m.HLS.compressedIn, m.HLS.compressedOut
}

// inflate decompresses a deciphered request whose security control byte
// sc has the compression bit (callers hold no lock).
func (m *Meter) inflate(h *HLS, sc byte, plain []byte, ok bool) ([]byte, bool) {
	if !ok || sc&0x80 == 0 {
		return plain, ok
	}
	m.mu.Lock()
	p := h.Compression
	m.mu.Unlock()
	if p == nil {
		return nil, false
	}
	out, err := v44.Decompress(*p, plain)
	if err != nil {
		return nil, false
	}
	m.mu.Lock()
	h.compressedIn++
	m.mu.Unlock()
	return out, true
}

// deflate compresses an answer for general-glo, general-ded or general
// ciphering when the meter is set to, marking k's security control.
func (m *Meter) deflate(h *HLS, k *sessionKeys, resp []byte) []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !h.CompressAnswers || h.Compression == nil {
		return resp
	}
	out, err := v44.Compress(*h.Compression, resp)
	if err != nil {
		return resp
	}
	h.compressedOut++
	k.flags |= 0x80
	return out
}

// ThirdPartyRequests is how many third-party signed requests the meter
// accepted.
func (m *Meter) ThirdPartyRequests() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.HLS == nil {
		return 0
	}
	return m.HLS.tpRequests
}

// Releases is how many ciphered RLRQs the meter accepted, and
// BadReleases how many it silently discarded.
func (m *Meter) Releases() (accepted, discarded int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.HLS == nil {
		return 0, 0
	}
	return m.HLS.releases, m.HLS.badReleases
}

// Broadcasts is how many unconfirmed requests protected with the global
// broadcast key the meter accepted (and did not answer).
func (m *Meter) Broadcasts() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.broadcasts
}

// BadBroadcasts is how many broadcast requests the meter dropped (wrong
// key, confirmed service or replayed counter).
func (m *Meter) BadBroadcasts() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.badBroadcasts
}

// StaleCounters is how many associations were refused for a replayed
// invocation counter.
func (m *Meter) StaleCounters() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.staleIC
}

// DedicatedKeys is how many associations agreed a dedicated key.
func (m *Meter) DedicatedKeys() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.dedicated
}

// hlsSession is one connection's security state.
type hlsSession struct {
	clientST []byte
	ctos     []byte
	stoc     []byte
	dedKey   []byte
	pending  bool // passes 1–2 done, waiting for pass 3
	lastIC   map[bool]uint32
	dedIC    uint32
	keys     sessionKeys
	signing  bool   // requests and responses must be general-signed
	bcastIC  uint32 // last invocation counter under the broadcast key
	// unconfirmed: the AA was proposed with response-allowed FALSE (a
	// broadcast or group AA): nothing is ever answered in it.
	unconfirmed bool
}

func (h *HLS) mechanism() byte {
	if h.Mechanism == 0 {
		return 5
	}
	return h.Mechanism
}

// sessionKeys are the policy and keys an association started with; key
// changes through the security setup object apply to later associations.
type sessionKeys struct {
	policy, suite byte
	key, ak       []byte
	flags         byte // security control bits 6 and 7 to send
}

// keysNow snapshots the current policy and keys (callers hold m.mu).
func (h *HLS) keysNow() sessionKeys {
	return sessionKeys{policy: h.Policy, suite: h.Suite, key: clone(h.Key), ak: clone(h.AuthKey)}
}

func clone(b []byte) []byte { return append([]byte(nil), b...) }

// seal protects plain as SC ‖ IC ‖ body; extra is more authenticated
// data after SC ‖ AK (general-ciphering's header).
func (k sessionKeys) seal(key, st []byte, ic uint32, plain, extra []byte) []byte {
	sc := k.policy | k.suite | k.flags
	block, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCMWithTagSize(block, 12)
	nonce := make([]byte, 12)
	copy(nonce, st)
	binary.BigEndian.PutUint32(nonce[8:], ic)
	head := []byte{sc, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(head[1:], ic)
	switch k.policy {
	case 0x10:
		aad := cat([]byte{sc}, k.ak, extra, plain)
		return append(append(head, plain...), g.Seal(nil, nonce, nil, aad)...)
	case 0x20:
		iv := append(append([]byte{}, nonce...), 0, 0, 0, 2)
		out := make([]byte, len(plain))
		cipher.NewCTR(block, iv).XORKeyStream(out, plain)
		return append(head, out...)
	}
	return append(head, g.Seal(nil, nonce, plain, cat([]byte{sc}, k.ak, extra))...)
}

// open removes protection; ok is false when it does not verify or the
// security control byte has the compression bit.
func (k sessionKeys) open(key, st, payload, extra []byte) (plain []byte, ic uint32, ok bool) {
	return k.openSC(0x40, key, st, payload, extra)
}

// openCompressed is open that also takes the compression bit (general-glo,
// general-ded and general ciphering); the caller decompresses.
func (k sessionKeys) openCompressed(key, st, payload, extra []byte) (plain []byte, ic uint32, ok bool) {
	return k.openSC(0xC0, key, st, payload, extra)
}

// openSC is open ignoring the security control bits in free.
func (k sessionKeys) openSC(free byte, key, st, payload, extra []byte) (plain []byte, ic uint32, ok bool) {
	if len(payload) < 5 || payload[0]&^free != k.policy|k.suite || len(key) == 0 {
		return nil, 0, false
	}
	ic = binary.BigEndian.Uint32(payload[1:5])
	body := payload[5:]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, 0, false
	}
	g, _ := cipher.NewGCMWithTagSize(block, 12)
	nonce := make([]byte, 12)
	copy(nonce, st)
	binary.BigEndian.PutUint32(nonce[8:], ic)
	switch k.policy {
	case 0x10:
		if len(body) < 12 {
			return nil, 0, false
		}
		p := body[:len(body)-12]
		want := g.Seal(nil, nonce, nil, cat([]byte{payload[0]}, k.ak, extra, p))
		return p, ic, subtle.ConstantTimeCompare(want, body[len(body)-12:]) == 1
	case 0x20:
		iv := append(append([]byte{}, nonce...), 0, 0, 0, 2)
		out := make([]byte, len(body))
		cipher.NewCTR(block, iv).XORKeyStream(out, body)
		return out, ic, true
	}
	p, err := g.Open(nil, nonce, body, cat([]byte{payload[0]}, k.ak, extra))
	return p, ic, err == nil
}

// f is the meter's challenge answer for its mechanism; for GMAC and ECDSA
// see mechanisms.go in package dlms for the definitions.
func (h *HLS) f(k sessionKeys, fromST, toST, challenge, own []byte, ic uint32) []byte {
	switch h.mechanism() {
	case 2:
		block, _ := aes.NewCipher(h.Secret)
		p := make([]byte, (len(challenge)+15)/16*16)
		copy(p, challenge)
		for i := 0; i < len(p); i += 16 {
			block.Encrypt(p[i:i+16], p[i:i+16])
		}
		return p
	case 3:
		s := md5.Sum(append(append([]byte{}, challenge...), h.Secret...))
		return s[:]
	case 4:
		s := sha1.Sum(append(append([]byte{}, challenge...), h.Secret...))
		return s[:]
	case 5:
		sc := 0x10 | h.Suite
		block, _ := aes.NewCipher(k.key)
		g, _ := cipher.NewGCMWithTagSize(block, 12)
		nonce := make([]byte, 12)
		copy(nonce, fromST)
		binary.BigEndian.PutUint32(nonce[8:], ic)
		head := []byte{sc, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(head[1:], ic)
		aad := cat([]byte{sc}, k.ak, challenge)
		return append(head, g.Seal(nil, nonce, nil, aad)...)
	case 6:
		s := sha256.Sum256(cat(h.Secret, fromST, toST, challenge, own))
		return s[:]
	case 7:
		r, s, _ := ecdsa.Sign(rand.Reader, h.SigningKey, h.digest(cat(fromST, toST, challenge, own)))
		n := (h.SigningKey.Curve.Params().BitSize + 7) / 8
		out := make([]byte, 2*n)
		r.FillBytes(out[:n])
		s.FillBytes(out[n:])
		return out
	}
	return nil
}

// verify checks the client's f(StoC).
func (h *HLS) verify(s *hlsSession, got []byte) bool {
	switch h.mechanism() {
	case 5:
		if len(got) != 17 {
			return false
		}
		return subtle.ConstantTimeCompare(got, h.f(s.keys, s.clientST, h.SystemTitle, s.stoc, s.ctos, binary.BigEndian.Uint32(got[1:5]))) == 1
	case 7:
		n := (h.ClientKey.Curve.Params().BitSize + 7) / 8
		if len(got) != 2*n {
			return false
		}
		d := h.digest(cat(s.clientST, h.SystemTitle, s.stoc, s.ctos))
		return ecdsa.Verify(h.ClientKey, d, new(big.Int).SetBytes(got[:n]), new(big.Int).SetBytes(got[n:]))
	}
	return subtle.ConstantTimeCompare(got, h.f(s.keys, s.clientST, h.SystemTitle, s.stoc, s.ctos, 0)) == 1
}

func (h *HLS) digest(b []byte) []byte {
	if h.Suite == 2 {
		s := sha512.Sum384(b)
		return s[:]
	}
	s := sha256.Sum256(b)
	return s[:]
}

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func berLen(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	if n < 0x100 {
		return []byte{0x81, byte(n)}
	}
	return []byte{0x82, byte(n >> 8), byte(n)}
}

func readLen(b []byte) (n, size int) {
	switch {
	case len(b) == 0:
		return -1, 0
	case b[0] < 0x80:
		return int(b[0]), 1
	case b[0] == 0x81 && len(b) > 1:
		return int(b[1]), 2
	case b[0] == 0x82 && len(b) > 2:
		return int(b[1])<<8 | int(b[2]), 3
	}
	return -1, 0
}

// aarqItems reads an AARQ's elements.
func aarqItems(aarq []byte) map[byte][]byte {
	out := map[byte][]byte{}
	n, sz := readLen(aarq[1:])
	if n < 0 || 1+sz+n > len(aarq) {
		return out
	}
	b := aarq[1+sz : 1+sz+n]
	for len(b) >= 2 {
		l, s := readLen(b[1:])
		if l < 0 || 1+s+l > len(b) {
			break
		}
		out[b[0]] = b[1+s : 1+s+l]
		b = b[1+s+l:]
	}
	return out
}

// hlsAARQ handles passes 1 and 2 (callers hold m.mu).
func (m *Meter) hlsAARQ(s *session, aarq []byte) []byte {
	h := m.hlsOf(s)
	it := aarqItems(aarq)
	if v := it[0xA1]; h.Context != 0 && (len(v) != 9 || v[8] != h.Context) {
		m.refused++
		m.contextRefused++
		return aareContextRefused
	}
	mechName := it[0x8B]
	if h.Unauthenticated {
		if len(mechName) != 0 && mechName[len(mechName)-1] != 0 {
			m.refused++
			return aareRefused
		}
	} else if len(mechName) == 0 || mechName[len(mechName)-1] != h.mechanism() {
		m.refused++
		return aareRefused
	}
	var clientST, ctos []byte
	if v := it[0xA6]; len(v) == 10 && v[0] == 0x04 {
		clientST = v[2:]
	}
	if v := it[0xAC]; len(v) >= 2 && v[0] == 0x80 {
		l, sz := readLen(v[1:])
		ctos = v[1+sz : 1+sz+l]
	}
	lls := h.mechanism() == 1 || h.Unauthenticated
	if lls && !h.Unauthenticated && string(ctos) != string(h.Secret) {
		m.refused++
		return aareRefused
	}
	if (!lls && len(ctos) < 8) || (h.mechanism() >= 5 && len(clientST) != 8) {
		m.refused++
		return aareRefused
	}
	sess := &hlsSession{clientST: append([]byte(nil), clientST...), ctos: append([]byte(nil), ctos...), pending: true, lastIC: map[bool]uint32{},
		keys: h.keysNow(), signing: h.RequireSigning}
	k := sess.keys
	// xDLMS initiateRequest, protected with the global key when APDUs are.
	ui := it[0xBE]
	if len(ui) < 2 || ui[0] != 0x04 {
		m.refused++
		return aareRefused
	}
	l, sz := readLen(ui[1:])
	ir := ui[1+sz : 1+sz+l]
	var initIC uint32
	initAE := false // the initiate request was authenticated and encrypted
	if k.policy != 0 {
		if len(ir) < 2 || ir[0] != 0x21 {
			m.refused++
			return aareRefused
		}
		n, s2 := readLen(ir[1:])
		// An initiateRequest carrying a dedicated key is authenticated
		// and encrypted whatever the association's policy.
		kInit := k
		if pl := ir[1+s2:]; len(pl) > 0 && pl[0]&0x30 == 0x30 {
			kInit.policy, initAE = 0x30, true
		}
		initKey, content := k.key, ir[1+s2:1+s2+n]
		bcast := len(content) > 0 && content[0]&0x40 != 0
		if bcast {
			initKey = h.BroadcastKey // a broadcast AA's initiate request
		}
		p, ic, ok := kInit.open(initKey, clientST, content, nil)
		if !ok || (bcast && ic <= max(sess.bcastIC, m.bcastLast.Load())) {
			m.refused++
			return aareRefused
		}
		ir, initIC = p, ic
		if bcast {
			sess.bcastIC = ic
			m.bcastSeen(ic)
		} else {
			sess.lastIC[false] = ic
		}
	}
	// response-allowed FALSE: an unconfirmed AA (IEC 62056-5-3:2023
	// 7.2.4.3). Only the client can authenticate (no passes 3 and 4), and
	// the meter answers nothing.
	if unconfirmedInitiate(ir) {
		if !(h.mechanism() == 1 || h.Unauthenticated) {
			m.refused++
			return nil
		}
		sess.pending, sess.unconfirmed = false, true
		s.hls, s.associated = sess, true
		m.assocs++
		return nil
	}
	if len(ir) >= 3 && ir[0] == 0x01 && ir[1] == 0x01 {
		// IEC 62056-5-3:2023 5.5.1: a dedicated key travels only in an
		// authenticated and encrypted initiate request.
		if !initAE || len(ir) < 3+int(ir[2]) {
			m.refused++
			return aareRefused
		}
		sess.dedKey = append([]byte(nil), ir[3:3+int(ir[2])]...)
		m.dedicated++
	}
	if h.FrameCounterOBIS != "" && k.policy != 0 {
		k := key(1, h.FrameCounterOBIS, 2)
		if stored, ok := m.objects[k]; ok {
			if last, _ := stored.Value.(uint32); initIC <= last {
				m.refused++
				m.staleIC++
				return aareRefused
			}
		}
		m.objects[k] = *axdr.CreateAxdrDoubleLongUnsigned(initIC)
	}
	sess.stoc = make([]byte, 32)
	_, _ = rand.Read(sess.stoc)
	s.hls = sess
	diagnostic := byte(0x0E) // authentication required
	if lls {
		// Low-level security: the password was the proof; no passes 3–4.
		sess.pending, s.associated, diagnostic = false, true, 0
		m.assocs++
	}

	initiate := initiateResponse
	var uiOut []byte
	ctx := byte(0x01)
	if k.policy != 0 {
		kResp := k
		if sess.dedKey != nil {
			kResp.policy = 0x30 // answering a dedicated key: authenticated and encrypted
		}
		p := kResp.seal(k.key, h.SystemTitle, m.nextIC(), initiate, nil)
		uiOut = cat([]byte{0x28}, berLen(len(p)), p)
		ctx = 0x03
	} else {
		uiOut = initiate
	}
	if h.Context != 0 {
		ctx = h.Context
	}
	body := []byte{
		0xA1, 0x09, 0x06, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01, ctx,
		0xA2, 0x03, 0x02, 0x01, 0x00, // accepted
		0xA3, 0x05, 0xA1, 0x03, 0x02, 0x01, diagnostic,
		0xA4, 0x0A, 0x04, 0x08,
	}
	body = append(body, h.SystemTitle...)
	if !h.Unauthenticated {
		body = append(body, 0x88, 0x02, 0x07, 0x80) // responder ACSE requirements
		body = append(body, 0x89, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x02, h.mechanism())
	}
	if !lls {
		body = append(body, 0xAA, byte(2+len(sess.stoc)), 0x80, byte(len(sess.stoc)))
		body = append(body, sess.stoc...)
	}
	body = append(body, 0xBE)
	body = append(body, berLen(2+len(uiOut))...)
	body = append(body, 0x04)
	body = append(body, berLen(len(uiOut))...)
	body = append(body, uiOut...)
	return cat([]byte{0x61}, berLen(len(body)), body)
}

// unconfirmedInitiate says whether an xDLMS InitiateRequest has
// response-allowed FALSE.
func unconfirmedInitiate(ir []byte) bool {
	if len(ir) < 3 || ir[0] != 0x01 {
		return false
	}
	i := 2
	if ir[1] == 0x01 { // dedicated key
		if len(ir) < 3 {
			return false
		}
		i = 3 + int(ir[2])
	}
	return len(ir) > i+1 && ir[i] == 0x01 && ir[i+1] == 0x00
}

// initiateResponse is the meter's xDLMS InitiateResponse: DLMS version 6,
// conformance 00181D, max PDU 180, VAA name 0007.
var initiateResponse = []byte{0x08, 0x00, 0x06, 0x5F, 0x1F, 0x04, 0x00, 0x00, 0x18, 0x1D, 0x00, 0xB4, 0x00, 0x07}

// release answers an RLRQ (IEC 62056-5-3:2023 6.3, 7.2.5). When it
// carries a ciphered InitiateRequest, that must decipher with the global
// key under a fresh counter or the RLRQ is silently discarded (nil); the
// RLRE then carries the InitiateResponse protected as in the AARE. An
// RLRQ without one is answered with a plain RLRE. ok is false when the
// meter has no high-level security for this client (the caller answers).
func (m *Meter) release(s *session, apdu []byte) (resp []byte, ok bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h := m.hlsOf(s)
	if h == nil || s.client == 16 {
		return nil, false
	}
	plainRLRE := []byte{0x63, 0x03, 0x80, 0x01, 0x00}
	ui := aarqItems(apdu)[0xBE]
	if len(ui) == 0 {
		s.associated = false
		return plainRLRE, true
	}
	discard := func() ([]byte, bool) { h.badReleases++; return nil, true }
	if s.hls == nil || s.hls.keys.policy == 0 || ui[0] != 0x04 {
		return discard()
	}
	l, sz := readLen(ui[1:])
	if l < 0 || 1+sz+l > len(ui) {
		return discard()
	}
	ir := ui[1+sz : 1+sz+l]
	if len(ir) < 2 || ir[0] != 0x21 {
		return discard()
	}
	n, s2 := readLen(ir[1:])
	if n < 0 || 1+s2+n > len(ir) {
		return discard()
	}
	k := s.hls.keys
	content := ir[1+s2 : 1+s2+n]
	if len(content) > 0 && content[0]&0x30 == 0x30 {
		k.policy = 0x30
	}
	if s.hls.dedKey != nil && k.policy != 0x30 {
		return discard() // a dedicated key was used: authenticated encryption
	}
	if len(content) > 0 && content[0]&0x40 != 0 {
		// The release of a broadcast AA, under the broadcast key; an
		// unconfirmed AA's release is not answered.
		plain, ic, good := k.open(h.BroadcastKey, s.hls.clientST, content, nil)
		if !good || len(plain) == 0 || plain[0] != 0x01 || ic <= max(s.hls.bcastIC, m.bcastLast.Load()) || !s.hls.unconfirmed {
			return discard()
		}
		s.hls.bcastIC = ic
		m.bcastSeen(ic)
		h.releases++
		s.associated = false
		return nil, true
	}
	plain, ic, good := k.open(k.key, s.hls.clientST, content, nil)
	if last, seen := s.hls.lastIC[false]; !good || len(plain) == 0 || plain[0] != 0x01 || (seen && ic <= last) {
		return discard()
	}
	s.hls.lastIC[false] = ic
	h.releases++
	s.associated = false
	if s.hls.unconfirmed {
		return nil, true
	}
	p := k.seal(k.key, h.SystemTitle, m.nextIC(), initiateResponse, nil)
	uiOut := cat([]byte{0x28}, berLen(len(p)), p)
	body := cat([]byte{0x80, 0x01, 0x00, 0xBE}, berLen(2+len(uiOut)), []byte{0x04}, berLen(len(uiOut)), uiOut)
	return cat([]byte{0x63}, berLen(len(body)), body), true
}

// tpLayers records the protection a third party applied to a request.
type tpLayers struct {
	tx       []byte // the transaction-id the answer repeats
	signed   bool
	policy   byte // its general-ciphering layer's A and E bits, 0 if none
	scheme   byte // 1 one-pass, 2 static
	cipherTx []byte
}

// thirdPartyRequest removes a third party's layers (general-ciphering
// outside, general-signing inside) from a request; ok is false when one
// does not verify (callers hold no lock).
func (m *Meter) thirdPartyRequest(s *session, apdu []byte) (content []byte, tp *tpLayers, ok bool) {
	h := m.hlsOf(s)
	m.mu.Lock()
	defer m.mu.Unlock()
	bad := func() ([]byte, *tpLayers, bool) { m.badSignatures++; return nil, nil, false }
	tp = &tpLayers{}
	for len(apdu) > 0 && (apdu[0] == 0xDD || apdu[0] == 0xDF) {
		switch apdu[0] {
		case 0xDD:
			g, good := decodeGeneral(apdu)
			if !good || tp.policy != 0 || tp.signed || g.ki == nil || g.ki.choice != 2 || len(g.ki.params) != 1 || len(g.content) < 5 ||
				string(g.hdr[1]) != string(h.ThirdPartyST) || string(g.hdr[2]) != string(h.SystemTitle) {
				return bad()
			}
			key := h.tpContentKey(g)
			k := sessionKeys{policy: g.content[0] & 0x30, suite: h.Suite, ak: h.ThirdPartyAuthKey}
			plain, _, good := k.openCompressed(key, g.hdr[1], g.content, g.header())
			if !good || k.policy == 0 {
				return bad()
			}
			// A third party's general-ciphering layer may be compressed
			// (IEC 62056-5-3:2023 Table 26).
			if g.content[0]&0x80 != 0 {
				if plain, good = h.decompress(plain); !good {
					return bad()
				}
				h.tpCompressedIn++
			}
			tp.policy, tp.scheme, tp.cipherTx = k.policy, g.ki.params[0], g.hdr[0]
			if tp.tx == nil {
				tp.tx = g.hdr[0]
			}
			apdu = plain
		case 0xDF:
			g, signed, good := decodeSigning(apdu)
			if !good || tp.signed || h.ThirdPartyKey == nil || string(g.hdr[1]) != string(h.ThirdPartyST) || string(g.hdr[2]) != string(h.SystemTitle) ||
				!h.verifyWith(h.ThirdPartyKey, signed, g.sig) {
				return bad()
			}
			tp.signed = true
			if tp.tx == nil {
				tp.tx = g.hdr[0]
			}
			apdu = g.content
		}
	}
	h.tpRequests++
	return apdu, tp, true
}

// tpContentKey is the key a third party agreed for its general-ciphering
// layer (the meter is party V).
func (h *HLS) tpContentKey(g *general) []byte {
	switch g.ki.params[0] {
	case 1:
		eph := h.signedEphemeral(h.ThirdPartyKey, g.ki.data)
		if z := ecdhWith(h.KAKey, eph); z != nil {
			return h.derive(z, g.hdr[1], g.hdr[2])
		}
	case 2:
		if z := ecdhWith(h.KAKey, h.ThirdPartyKAKey); z != nil {
			return h.derive(z, cat(g.hdr[1], []byte{byte(len(g.hdr[0]))}, g.hdr[0]), g.hdr[2])
		}
	}
	return nil
}

// thirdPartyAnswer puts the meter's layers for the third party around a
// response: the kinds the request carried (signed inside, ciphered
// outside); a signature only with ThirdPartySignedAnswers; with no layer
// asked for, unprotected general-ciphering (J.3).
func (m *Meter) thirdPartyAnswer(s *session, tp *tpLayers, resp []byte) []byte {
	h := m.hlsOf(s)
	m.mu.Lock()
	defer m.mu.Unlock()
	hdr := [5][]byte{tp.tx, h.SystemTitle, h.ThirdPartyST, cosemNow(), nil}
	sign := tp.signed && h.ThirdPartySignedAnswers
	if !sign && tp.policy == 0 {
		sc := h.Suite
		if c, ok := h.compress(resp); ok {
			resp, sc = c, sc|0x80
			h.tpCompressedOut++
		}
		g := &general{hdr: hdr, content: cat([]byte{sc}, resp)}
		return g.encode()
	}
	if sign {
		out := &general{hdr: hdr}
		body := cat(out.header(), octs(resp))
		signer := h.SigningKey
		if h.ThirdPartyBadSignature {
			signer, _ = ecdsa.GenerateKey(signer.Curve, rand.Reader)
		}
		resp = cat([]byte{0xDF}, body, octs(h.signWith(signer, body)))
	}
	if tp.policy != 0 {
		out := &general{hdr: [5][]byte{tp.cipherTx, h.SystemTitle, h.ThirdPartyST, cosemNow(), nil}}
		if tp.scheme == 1 {
			e, _ := ecdsa.GenerateKey(h.KAKey.Curve, rand.Reader)
			pub := pointOf(&e.PublicKey)
			out.key = h.derive(ecdhWith(e, h.ThirdPartyKAKey), out.hdr[1], out.hdr[2])
			out.ki = &keyInfo{choice: 2, params: []byte{1}, data: cat(pub, h.signWith(h.SigningKey, pub))}
		} else {
			out.key = h.derive(ecdhWith(h.KAKey, h.ThirdPartyKAKey), cat(out.hdr[1], []byte{byte(len(out.hdr[0]))}, out.hdr[0]), out.hdr[2])
			out.ki = &keyInfo{choice: 2, params: []byte{2}}
		}
		k := sessionKeys{policy: tp.policy, suite: h.Suite, ak: h.ThirdPartyAuthKey}
		if c, ok := h.compress(resp); ok {
			resp, k.flags = c, 0x80
			h.tpCompressedOut++
		}
		out.content = k.seal(out.key, h.SystemTitle, 0, resp, out.header())
		resp = out.encode()
	}
	return resp
}

// nextIC is the meter's next global frame counter (callers hold m.mu).
func (m *Meter) nextIC() uint32 {
	m.serverIC++
	return m.serverIC
}

// Protected request tags and the plain service they carry.
var securedRequests = map[byte]struct {
	plain byte
	ded   bool
}{0xC8: {0xC0, false}, 0xC9: {0xC1, false}, 0xCB: {0xC3, false}, 0xD0: {0xC0, true}, 0xD1: {0xC1, true}, 0xD3: {0xC3, true}}

// secured removes the protection from a request (service-specific,
// general-glo, general-ded or general ciphering), handles it and protects
// the answer in the same form.
func (m *Meter) secured(s *session, apdu []byte) []byte {
	h := m.hlsOf(s)
	if s.hls == nil {
		return []byte{0xD8, 0x01, 0x01}
	}
	k := s.hls.keys
	m.mu.Lock()
	if m.forms == nil {
		m.forms = map[byte]int{}
	}
	m.forms[apdu[0]]++
	m.mu.Unlock()
	var (
		plain []byte
		ic    uint32
		ok    bool
		ded   bool
		want  byte // the plain tag a service-specific APDU must carry
		gen   *general
	)
	switch apdu[0] {
	case 0xDB, 0xDC:
		ded = apdu[0] == 0xDC
		st, content, good := decodeGloDed(apdu)
		if !good || string(st) != string(s.hls.clientST) {
			return []byte{0xD8, 0x01, 0x02}
		}
		if !ded && len(content) > 0 && content[0]&0x40 != 0 {
			return m.broadcastRequest(s, k, content, nil, 0)
		}
		key := k.key
		if ded {
			key = s.hls.dedKey
		}
		plain, ic, ok = k.openCompressed(key, st, content, nil)
		if len(content) > 0 {
			plain, ok = m.inflate(h, content[0], plain, ok)
		}
	case 0xDD:
		g, good := decodeGeneral(apdu)
		// Broadcast: the recipient-system-title is empty and key-info
		// names the global broadcast key (IEC 62056-5-3:2023 6.x, 5.5.3).
		if good && len(g.hdr[2]) == 0 && string(g.hdr[1]) == string(s.hls.clientST) && g.ki != nil && g.ki.choice == 0 && g.ki.id == 1 {
			if len(g.content) > 0 && g.content[0]&0x40 != 0 {
				m.mu.Lock()
				m.badBroadcasts++
				m.mu.Unlock()
				return nil // the key-set bit must be 0 in general-ciphering
			}
			return m.broadcastRequest(s, k, g.content, g.header(), 0)
		}
		if !good || string(g.hdr[1]) != string(s.hls.clientST) || string(g.hdr[2]) != string(h.SystemTitle) {
			return []byte{0xD8, 0x01, 0x02}
		}
		m.mu.Lock()
		key := m.contentKey(s, g)
		m.mu.Unlock()
		plain, ic, ok = k.openCompressed(key, g.hdr[1], g.content, g.header())
		if len(g.content) > 0 {
			plain, ok = m.inflate(h, g.content[0], plain, ok)
		}
		g.key = key
		gen = g
	default:
		req := securedRequests[apdu[0]]
		ded, want = req.ded, req.plain
		n, sz := readLen(apdu[1:])
		if n < 0 || 1+sz+n > len(apdu) {
			return []byte{0xD8, 0x01, 0x02}
		}
		key := k.key
		if ded {
			key = s.hls.dedKey
		}
		payload := apdu[1+sz : 1+sz+n]
		if !ded && len(payload) > 0 && payload[0]&0x40 != 0 {
			return m.broadcastRequest(s, k, payload, nil, want)
		}
		plain, ic, ok = k.open(key, s.hls.clientST, payload, nil)
		// Service-specific ciphering carries no compression (5.3.6).
		if ok && (len(plain) == 0 || plain[0] != want || payload[0]&0x80 != 0) {
			ok = false
		}
	}
	if ded && s.hls.dedKey == nil {
		return []byte{0xD8, 0x01, 0x01}
	}
	// A request a third party signed inside the client's ciphering.
	var tp *tpLayers
	if ok && apdu[0] >= 0xDB && len(plain) > 0 && (plain[0] == 0xDF || plain[0] == 0xDD) && h.ThirdPartyST != nil {
		inner, layers, good := m.thirdPartyRequest(s, plain)
		if !good {
			return []byte{0xD8, 0x01, 0x02}
		}
		plain, tp = inner, layers
	}
	if !ok || len(plain) == 0 || (plain[0] != 0xC0 && plain[0] != 0xC1 && plain[0] != 0xC3) {
		return []byte{0xD8, 0x01, 0x02}
	}
	if last, seen := s.hls.lastIC[ded]; seen && ic <= last {
		return []byte{0xD8, 0x01, 0x02} // replayed counter
	}
	s.hls.lastIC[ded] = ic
	s.unwrapped = true
	resp := m.handle(s, plain)
	s.unwrapped = false
	if s.hls.unconfirmed {
		return nil // nothing is answered in an unconfirmed AA
	}
	if len(resp) == 0 || resp[0] == 0xD8 {
		return resp
	}
	if tp != nil {
		resp = m.thirdPartyAnswer(s, tp, resp)
	}
	nextIC := func() uint32 {
		if ded {
			s.hls.dedIC++
			return s.hls.dedIC
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		return m.nextIC()
	}
	switch apdu[0] {
	case 0xDB, 0xDC:
		key := k.key
		if ded {
			key = s.hls.dedKey
		}
		resp = m.deflate(h, &k, resp)
		return encodeGloDed(apdu[0], h.SystemTitle, k.seal(key, h.SystemTitle, nextIC(), resp, nil))
	case 0xDD:
		m.mu.Lock()
		out := m.answerGeneral(s, gen)
		m.mu.Unlock()
		resp = m.deflate(h, &k, resp)
		out.content = k.seal(out.key, h.SystemTitle, nextIC(), resp, out.header())
		return out.encode()
	}
	tag := resp[0] + 8 // C4→CC, C5→CD, C7→CF
	key := k.key
	if ded {
		tag = resp[0] + 0x10 // C4→D4, C5→D5, C7→D7
		key = s.hls.dedKey
	} else {
		m.mu.Lock()
		if h.BroadcastAnswers {
			key, k.flags = clone(h.BroadcastKey), k.flags|0x40
		}
		if h.CompressedAnswers {
			k.flags |= 0x80
		}
		m.mu.Unlock()
	}
	out := k.seal(key, h.SystemTitle, nextIC(), resp, nil)
	return cat([]byte{tag}, berLen(len(out)), out)
}

// broadcastRequest handles a request protected with the global broadcast
// key: only unconfirmed services, never answered; one that does not
// verify, is confirmed or repeats a counter is dropped silently. want is
// the plain tag a service-specific APDU must carry (0: any request).
func (m *Meter) broadcastRequest(s *session, k sessionKeys, content, extra []byte, want byte) []byte {
	h := m.hlsOf(s)
	m.mu.Lock()
	key := clone(h.BroadcastKey)
	m.mu.Unlock()
	plain, ic, ok := k.open(key, s.hls.clientST, content, extra)
	if len(content) > 0 && content[0]&0x80 != 0 {
		ok = false // broadcasts are not compressed here
	}
	if ok && want == 0 && len(plain) > 0 && plain[0] != 0xC1 && plain[0] != 0xC3 && plain[0] != 0xC0 {
		ok = false
	}
	if !ok || len(plain) < 3 || (want != 0 && plain[0] != want) || plain[2]&0x40 != 0 || ic <= max(s.hls.bcastIC, m.bcastLast.Load()) {
		m.mu.Lock()
		m.badBroadcasts++
		m.mu.Unlock()
		return nil
	}
	s.hls.bcastIC = ic
	m.bcastSeen(ic)
	s.unwrapped = true
	m.handle(s, plain)
	s.unwrapped = false
	m.mu.Lock()
	m.broadcasts++
	m.mu.Unlock()
	return nil
}

// replyToHLS is pass 3 on the meter: check f(StoC), answer f(CtoS).
func (m *Meter) replyToHLS(s *session, invoke byte, param []byte) []byte {
	h, sess := m.hlsOf(s), s.hls
	sess.pending = false
	if !h.verify(sess, param) {
		m.mu.Lock()
		m.refused++
		m.mu.Unlock()
		return []byte{0xC7, 0x01, invoke, 0xFA, 0x00} // other-reason
	}
	m.mu.Lock()
	m.assocs++
	ic := m.nextIC()
	m.mu.Unlock()
	s.associated = true
	back := h.f(sess.keys, h.SystemTitle, sess.clientST, sess.ctos, sess.stoc, ic)
	return cat([]byte{0xC7, 0x01, invoke, 0x00, 0x01, 0x00, 0x09}, berLen(len(back)), back)
}

// bcastSeen records the highest invocation counter taken under the
// broadcast key. A meter keeps it across associations and from every
// source (a group's unconfirmed association, a broadcast request on its
// own association): a counter not above it is a replay.
func (m *Meter) bcastSeen(ic uint32) {
	for {
		old := m.bcastLast.Load()
		if ic <= old || m.bcastLast.CompareAndSwap(old, ic) {
			return
		}
	}
}

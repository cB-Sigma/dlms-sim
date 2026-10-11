package cosemtest

// Key rotation (cosem.KeyRotation) against the simulated meter's security
// setup object: key_transfer and key_agreement, a crash between the meter's
// answer and the store, and a meter that does not take the keys.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/cB-Sigma/iotsec"

	. "github.com/cB-Sigma/dlms/cosem"
)

// memStore is an iotsec.Store in memory.
type memStore struct {
	mu sync.Mutex
	b  []byte
}

func (s *memStore) Load(_ context.Context, v any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.b == nil {
		return iotsec.ErrNotStored
	}
	return json.Unmarshal(s.b, v)
}

func (s *memStore) Save(_ context.Context, v any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := json.Marshal(v)
	s.b = b
	return err
}

// stoppingLink is a link whose process stops right after the meter
// answered key_transfer or key_agreement (crash), or whose key_transfer
// never reaches the meter but is reported done (lie).
type stoppingLink struct {
	*ClientRotationLink
	crash, lie bool
}

type stopped struct{}

func (l *stoppingLink) Transfer(master []byte, keys KeySet) error {
	if l.lie {
		return nil
	}
	err := l.ClientRotationLink.Transfer(master, keys)
	if l.crash {
		panic(stopped{})
	}
	return err
}

func (l *stoppingLink) Agree(ids []byte) (KeySet, error) {
	ks, err := l.ClientRotationLink.Agree(ids)
	if l.crash {
		panic(stopped{})
	}
	return ks, err
}

func rigKeys(r *secRig) KeySet {
	sec := r.m.hls.Security
	ks := KeySet{KeyGlobalUnicast: sec.Key, KeyAuthentication: sec.AuthKey, KeyMaster: sec.MasterKey}
	if sec.BroadcastKey != nil {
		ks[KeyGlobalBroadcast] = sec.BroadcastKey
	}
	return ks.Clone()
}

func rotationFor(r *secRig, link RotationLink, st *memStore) *KeyRotation {
	return &KeyRotation{Link: link, Store: st, StorageKey: bytes.Repeat([]byte{0x6B}, 16)}
}

// key_transfer of the unicast, broadcast, authentication and master keys:
// the meter holds the new keys afterwards, the client reads with them, and
// the master key was proved by a second transfer under it.
//
// Covers: SIG-IPE-069
func TestKeyRotationTransferSim(t *testing.T) {
	r := newRig(t, 0, 0x30, nil)
	if err := r.read(t); err != nil {
		t.Fatal(err)
	}
	r.mt.close()
	old := rigKeys(r)
	rot := rotationFor(r, &ClientRotationLink{Client: r.mt.client()}, &memStore{})
	ks, err := rot.Rotate(context.Background(), old, []byte{KeyGlobalUnicast, KeyGlobalBroadcast, KeyAuthentication, KeyMaster})
	if err != nil {
		t.Fatal(err)
	}
	u, b, a := r.sim.Keys()
	if !bytes.Equal(u, ks[KeyGlobalUnicast]) || !bytes.Equal(b, ks[KeyGlobalBroadcast]) || !bytes.Equal(a, ks[KeyAuthentication]) ||
		!bytes.Equal(r.sim.MasterKey(), ks[KeyMaster]) || bytes.Equal(u, old[KeyGlobalUnicast]) || bytes.Equal(r.sim.MasterKey(), old[KeyMaster]) {
		t.Fatal("the meter does not hold the rotated keys")
	}
	if n := r.sim.KeyChanges(); n != 5 {
		t.Errorf("%d key changes, want 4 and the master key proof", n)
	}
	if rot.Status().State != RotationDone {
		t.Errorf("status %+v", rot.Status())
	}
	if err := r.read(t); err != nil {
		t.Fatalf("reading with the new keys: %v", err)
	}
}

// The process stops after the meter took the keys and before the state was
// stored: a new KeyRotation on the same store resumes and finds the new keys
// active. A key_transfer reported done that never reached the meter is
// rolled back, and the old keys keep working.
//
// Covers: SIG-IPE-069
func TestKeyRotationResumeSim(t *testing.T) {
	r := newRig(t, 0, 0x30, nil)
	old := rigKeys(r)
	st := &memStore{}
	link := &stoppingLink{ClientRotationLink: &ClientRotationLink{Client: r.mt.client()}, crash: true}
	func() {
		defer func() {
			if p := recover(); p == nil {
				t.Fatal("no stop")
			} else if _, ok := p.(stopped); !ok {
				panic(p)
			}
		}()
		_, _ = rotationFor(r, link, st).Rotate(context.Background(), old, []byte{KeyGlobalUnicast, KeyAuthentication})
	}()
	r.mt.client().Close()
	link.crash = false
	ks, s, err := rotationFor(r, link, st).Resume(context.Background())
	if err != nil || s.State != RotationDone {
		t.Fatalf("resume: %v %+v", err, s)
	}
	if u, _, a := r.sim.Keys(); !bytes.Equal(u, ks[KeyGlobalUnicast]) || !bytes.Equal(a, ks[KeyAuthentication]) || bytes.Equal(u, old[KeyGlobalUnicast]) {
		t.Fatal("the resumed keys are not the meter's")
	}
	if err := r.read(t); err != nil {
		t.Fatalf("reading after the resume: %v", err)
	}
	r.mt.close()

	link.lie = true
	before := r.sim.KeyChanges()
	kept, err := rotationFor(r, link, st).Rotate(context.Background(), ks, []byte{KeyGlobalUnicast})
	if !errors.Is(err, ErrRotationRolledBack) || !bytes.Equal(kept[KeyGlobalUnicast], ks[KeyGlobalUnicast]) || r.sim.KeyChanges() != before {
		t.Fatalf("a transfer that did not reach the meter: %v", err)
	}
	if err := r.read(t); err != nil {
		t.Fatalf("reading with the kept keys: %v", err)
	}
}

// key_agreement (suite 1) of the unicast and authentication keys: the meter
// and the client derive the same keys and the client reads with them.
//
// Covers: SIG-IPE-070
func TestKeyRotationAgreementSim(t *testing.T) {
	r := newRig(t, 1, 0x30, nil)
	old := rigKeys(r)
	rot := rotationFor(r, &ClientRotationLink{Client: r.mt.client()}, &memStore{})
	rot.Method = RotateByAgreement
	ks, err := rot.Rotate(context.Background(), old, []byte{KeyGlobalUnicast, KeyAuthentication})
	if err != nil {
		t.Fatal(err)
	}
	if u, _, a := r.sim.Keys(); !bytes.Equal(u, ks[KeyGlobalUnicast]) || !bytes.Equal(a, ks[KeyAuthentication]) || bytes.Equal(u, old[KeyGlobalUnicast]) {
		t.Fatal("the meter and the client did not agree the same keys")
	}
	if err := r.read(t); err != nil {
		t.Fatalf("reading with the agreed keys: %v", err)
	}
}

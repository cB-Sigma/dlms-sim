package cosemtest

import (
	"strings"
	"testing"

	dlmssim "github.com/cB-Sigma/dlms-sim/sim"
	"github.com/cB-Sigma/dlms/cosem"
)

// gbtRun drives an exchange over a request/answer link with general block
// transfer (size, 0 off) and the keys' compression, against the simulated
// meter behind its own GBT link (meterSize) with its own keys.
func gbtRun(t *testing.T, m *listMeter, meterKeys *cosem.Keys, meterSize, size int, b cosem.CommandRequest) (*cosem.Exchange, *cosem.BlockTransfer, *dlmssim.GBTLink, []int) {
	t.Helper()
	req, err := b.Request()
	if err != nil {
		t.Fatal(err)
	}
	req.Invoke = 0xC1
	x, apdu, err := req.Start(0) // whole xDLMS APDUs: GBT carries them
	if err != nil {
		t.Fatal(err)
	}
	st := []byte("SIGMA001")
	mg := &dlmssim.GBTLink{Size: meterSize}
	serve := func(w []byte) []byte {
		plain, _, _, err := cosem.Open(w, meterKeys)
		if err != nil {
			t.Fatalf("meter: %v", err)
		}
		resp := m.sim.HandleAPDU(m.sess, plain)
		m.ic++
		out, err := cosem.Seal(meterKeys, []byte("MTR00001"), m.ic, resp)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	bt := &cosem.BlockTransfer{Size: size}
	var sealedSizes []int
	seal := func(a []byte) []byte {
		m.ic++
		w, err := cosem.Seal(m.keys, st, m.ic, a)
		if err != nil {
			t.Fatal(err)
		}
		sealedSizes = append(sealedSizes, len(w))
		return bt.Send(w)
	}
	wire := seal(apdu)
	for round := 0; round < 500; round++ {
		next, ans, err := bt.Receive(mg.Handle(wire, serve))
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		if ans == nil {
			wire = next
			continue
		}
		plain, _, _, err := cosem.Open(ans, m.keys)
		if err != nil {
			t.Fatalf("opening the answer: %v", err)
		}
		n, err := x.Step(plain)
		if err != nil {
			t.Fatal(err)
		}
		if x.Done() {
			return x, bt, mg, sealedSizes
		}
		wire = seal(n)
	}
	t.Fatal("the exchange did not end")
	return nil, nil, nil, nil
}

func suite1Keys(t *testing.T, comp *cosem.Compression) *cosem.Keys {
	k, err := cosem.ParseKeys(1, strings.Repeat("11", 16), strings.Repeat("22", 16))
	if err != nil {
		t.Fatal(err)
	}
	if err := k.SetCompression(comp); err != nil {
		t.Fatal(err)
	}
	return k
}

// General block transfer over a request/answer link: a SET whose ciphered
// APDU is longer than the block size goes as acknowledged blocks, and a
// GET answer longer than the meter's block size comes back as blocks we
// acknowledge, each side numbering every GBT APDU it sends
// (IEC 62056-5-3:2023 7.3.13).
//
// Covers: SIG-IPE-2989
func TestMBusGeneralBlockTransfer(t *testing.T) {
	keys := suite1Keys(t, nil)
	m := newListMeter(t, 4000, keys)
	long := "09" + "820190" + strings.Repeat("5a", 400)
	x, bt, mg, _ := gbtRun(t, m, keys, 64, 64, listCmd(t, `{"op": "set", "class": 1, "obis": "0.0.96.50.1.255", "value": "`+long+`"}`))
	if r := x.Result(); r.Result != 0 {
		t.Fatalf("set %+v", r)
	}
	if sent, _ := bt.Blocks(); sent < 6 || mg.Received != sent {
		t.Errorf("SET in %d blocks, meter joined %d", sent, mg.Received)
	}
	if sets := m.sim.Sets(); len(sets) != 1 {
		t.Fatalf("meter sets %+v", sets)
	}
	x, bt, mg, _ = gbtRun(t, m, keys, 64, 64, listCmd(t, `{"class": 1, "obis": "0.0.96.50.1.255"}`))
	if d := x.Result().Data; d == nil || len(d.Value.(string)) != 800 {
		t.Fatalf("get %+v", x.Result())
	}
	if _, recv := bt.Blocks(); recv < 6 || recv != mg.Sent {
		t.Errorf("answer in %d blocks, meter sent %d", recv, mg.Sent)
	}
	// Without GBT on our side the meter's blocks are still joined.
	x, _, _, _ = gbtRun(t, m, keys, 100, 0, listCmd(t, `{"class": 1, "obis": "0.0.96.50.1.255"}`))
	if x.Result().Data == nil {
		t.Fatal("answer in blocks to a whole request not joined")
	}
	// Faults: an acknowledgement of the wrong block, and streaming.
	var b cosem.BlockTransfer
	b.Size = 4
	b.Send([]byte("0123456789"))
	if _, _, err := b.Receive([]byte{0xE0, 0x01, 0, 1, 0, 7, 0}); err == nil {
		t.Error("acknowledgement of block 7 accepted")
	}
	b.Send([]byte("xy"))
	if _, _, err := b.Receive([]byte{0xE0, 0x41, 0, 1, 0, 0, 1, 'a'}); err == nil {
		t.Error("a streamed block accepted")
	}
}

// V.44 compression under general-glo-ciphering on M-Bus (IEC 62056-5-3:2023
// 5.3.6, Table 27 bit 7): with compressRequests our requests are
// compressed before ciphering when that makes them smaller, the meter's
// compressed answers are deciphered then decompressed, together with
// general block transfer; a compressed answer without the setting is
// refused naming it, and suite 0 has no compression.
//
// Covers: SIG-IPE-2990
func TestMBusCompression(t *testing.T) {
	comp := &cosem.Compression{Enabled: true, CompressRequests: true}
	keys := suite1Keys(t, comp)
	meterKeys := suite1Keys(t, comp)
	m := newListMeter(t, 4000, keys)
	long := "09" + "820190" + strings.Repeat("5a", 400)
	x, _, _, sizes := gbtRun(t, m, meterKeys, 64, 64, listCmd(t, `{"op": "set", "class": 1, "obis": "0.0.96.50.1.255", "value": "`+long+`"}`))
	if x.Result().Result != 0 {
		t.Fatalf("set %+v", x.Result())
	}
	if sizes[0] > 200 {
		t.Errorf("the 400-octet SET was sealed in %d octets: not compressed", sizes[0])
	}
	x, _, _, _ = gbtRun(t, m, meterKeys, 64, 64, listCmd(t, `{"class": 1, "obis": "0.0.96.50.1.255"}`))
	if d := x.Result().Data; d == nil || !strings.HasPrefix(d.Value.(string), "5a5a") {
		t.Fatalf("get %+v", x.Result())
	}
	// Our side without compression: the meter's compressed answer is
	// refused with a message naming the setting.
	plainKeys := suite1Keys(t, nil)
	sealed, err := cosem.Seal(meterKeys, []byte("MTR00001"), 900, append([]byte{0xC4, 0x01, 0xC1, 0x00, 0x09, 0x82, 0x01, 0x90}, []byte(strings.Repeat("Z", 400))...))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := cosem.Open(sealed, plainKeys); err == nil || !strings.Contains(err.Error(), "compression") {
		t.Errorf("compressed answer without the setting: %v", err)
	}
	k0, _ := cosem.ParseKeys(0, strings.Repeat("11", 16), "")
	if err := k0.SetCompression(comp); err == nil {
		t.Error("compression accepted with suite 0")
	}
}

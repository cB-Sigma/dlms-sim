package cosemtest

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"gitlab.com/circutor-library/gosem/pkg/axdr"

	dlmssim "github.com/cB-Sigma/dlms-sim/sim"
	"github.com/cB-Sigma/dlms/cosem"
	"github.com/cB-Sigma/dlms/is15959"
)

// listMeter is the DLMS simulator on a pre-established association, as an
// M-Bus meter has it, with its APDUs sealed under keys when given.
type listMeter struct {
	sim  *dlmssim.Meter
	sess *dlmssim.Session
	keys *cosem.Keys
	ic   uint32
}

func newListMeter(t *testing.T, block int, keys *cosem.Keys) *listMeter {
	t.Helper()
	sp, _ := is15959.Get("part2-3ph")
	sim := dlmssim.NewIS15959(sp, dlmssim.IS15959Options{})
	sim.BlockSize = block
	sim.Loc = time.UTC
	sim.Set(1, "0.0.96.50.1.255", 2, axdr.CreateAxdrOctetString(strings.Repeat("ab", 300)))
	sim.Set(1, "0.0.96.50.3.255", 2, axdr.CreateAxdrDoubleLongUnsigned(7))
	sim.ActionHandler = func(class uint16, obis string, method int8, p *axdr.DlmsData) (byte, *axdr.DlmsData, bool) {
		switch obis {
		case "0.0.96.50.2.255": // returns its parameter
			return 0, p, true
		case "0.0.96.50.4.255": // takes no parameter, returns nothing
			return 0, nil, true
		}
		return 0, nil, false
	}
	return &listMeter{sim: sim, sess: sim.PreEstablished(16), keys: keys}
}

// run drives an exchange to its end against the meter.
func (m *listMeter) run(t *testing.T, b cosem.CommandRequest, block int) *cosem.Exchange {
	t.Helper()
	req, err := b.Request()
	if err != nil {
		t.Fatal(err)
	}
	req.Invoke = 0xC3
	x, apdu, err := req.Start(block)
	if err != nil {
		t.Fatal(err)
	}
	st := []byte("SIGMA001")
	for round := 0; round < 100; round++ {
		wire := apdu
		if m.keys != nil {
			m.ic++
			if wire, err = cosem.Seal(m.keys, st, m.ic, apdu); err != nil {
				t.Fatal(err)
			}
		}
		plain, _, _, err := cosem.Open(wire, m.keys)
		if err != nil {
			t.Fatal(err)
		}
		resp := m.sim.HandleAPDU(m.sess, plain)
		if m.keys != nil {
			m.ic++
			if resp, err = cosem.Seal(m.keys, []byte("MTR00001"), m.ic, resp); err != nil {
				t.Fatal(err)
			}
			if resp, _, _, err = cosem.Open(resp, m.keys); err != nil {
				t.Fatal(err)
			}
		}
		next, err := x.Step(resp)
		if err != nil {
			t.Fatalf("step %d: %v (answer % X)", round, err, resp)
		}
		if x.Done() {
			return x
		}
		apdu = next
	}
	t.Fatal("the exchange did not end")
	return nil
}

func listCmd(t *testing.T, s string) cosem.CommandRequest {
	t.Helper()
	var b cosem.CommandRequest
	if err := json.Unmarshal([]byte(s), &b); err != nil {
		t.Fatal(err)
	}
	return b
}

// GET, SET and ACTION with list against the simulated meter, short and
// long enough for blocks both ways, in the clear and under
// general-glo-ciphering.
//
// Covers: SIG-IPE-2975
func TestExchangeWithList(t *testing.T) {
	keys, _ := cosem.ParseKeys(0, strings.Repeat("11", 16), strings.Repeat("22", 16))
	for _, k := range []*cosem.Keys{nil, keys} {
		name := "clear"
		if k != nil {
			name = "ciphered"
		}
		t.Run(name, func(t *testing.T) {
			// GET with list: two attributes and one the meter lacks; the
			// long octet string makes the answer go in blocks.
			for _, block := range []int{1000, 120} {
				m := newListMeter(t, block, k)
				x := m.run(t, listCmd(t, `{"class": 1, "obis": "0.0.96.50.3.255",
					"list": [{"class": 1, "obis": "0.0.96.50.1.255"}, {"class": 1, "obis": "0.0.96.50.9.255"}]}`), 0)
				r := x.Result()
				if len(r.Items) != 3 || r.Items[0].Data == nil || r.Items[0].Data.Value != uint32(7) ||
					r.Items[1].Data == nil || r.Items[2].Result == 0 || r.Result != r.Items[2].Result {
					t.Fatalf("block %d: items %+v", block, r.Items)
				}
				if (block == 120) != (r.Blocks > 1) {
					t.Errorf("block %d: %d blocks received", block, r.Blocks)
				}
				_, _, rec := x.Outcome(time.UTC)
				items, _ := rec["items"].([]any)
				if len(items) != 3 || items[0].(map[string]any)["point"] == nil {
					t.Errorf("outcome %v", rec)
				}
			}
			// SET with list, the values fitting one APDU and then in blocks.
			for _, block := range []int{0, 16} {
				m := newListMeter(t, 120, k)
				long := "09" + "40" + strings.Repeat("cd", 64)
				x := m.run(t, listCmd(t, `{"op": "set", "class": 1, "obis": "0.0.96.50.3.255", "value": "0600000009",
					"list": [{"class": 1, "obis": "0.0.96.50.1.255", "value": "`+long+`"}]}`), block)
				r := x.Result()
				if len(r.Items) != 2 || r.Items[0].Result != 0 || r.Items[1].Result != 0 || r.Result != 0 {
					t.Fatalf("set block %d: %+v", block, r)
				}
				if (block == 16) != (r.Sent > 1) {
					t.Errorf("set block %d: %d blocks sent", block, r.Sent)
				}
				sets := m.sim.Sets()
				if len(sets) != 2 || sets[0].OBIS != "0.0.96.50.3.255" || sets[1].OBIS != "0.0.96.50.1.255" {
					t.Errorf("meter saw sets %+v", sets)
				}
			}
			// ACTION with list: one method returns its parameter (long
			// enough for parameter blocks and answer blocks), one takes none.
			for _, block := range []int{0, 32} {
				m := newListMeter(t, 60, k)
				param := "09" + "50" + strings.Repeat("ef", 80)
				x := m.run(t, listCmd(t, `{"op": "action", "class": 1, "obis": "0.0.96.50.2.255", "method": 1, "value": "`+param+`",
					"list": [{"class": 1, "obis": "0.0.96.50.4.255", "method": 1}]}`), block)
				r := x.Result()
				if len(r.Items) != 2 || r.Items[0].Data == nil || r.Items[1].Data != nil || r.Result != 0 {
					t.Fatalf("action block %d: %+v", block, r)
				}
				if r.Blocks < 2 {
					t.Errorf("action block %d: answer in %d blocks", block, r.Blocks)
				}
				if acts := m.sim.Actions(); len(acts) != 2 || acts[1].Value != nil {
					t.Errorf("meter saw actions %+v", acts)
				}
				if m.sim.Lists() != 1 {
					t.Errorf("lists served %d", m.sim.Lists())
				}
			}
		})
	}
}

// Covers: SIG-IPE-2975
func TestWithListCommandChecks(t *testing.T) {
	for name, s := range map[string]string{
		"mixed ops":     `{"class": 1, "obis": "0.0.96.50.3.255", "list": [{"op": "set", "class": 1, "obis": "0.0.96.50.1.255", "value": "0F01"}]}`,
		"nested list":   `{"class": 1, "obis": "0.0.96.50.3.255", "list": [{"class": 1, "obis": "0.0.96.50.1.255", "list": [{"class": 1, "obis": "0.0.96.50.1.255"}]}]}`,
		"item no value": `{"op": "set", "class": 1, "obis": "0.0.96.50.3.255", "value": "0F01", "list": [{"class": 1, "obis": "0.0.96.50.1.255"}]}`,
		"bad obis":      `{"class": 1, "obis": "0.0.96.50.3.255", "list": [{"class": 1, "obis": "x"}]}`,
		"too many":      `{"class": 1, "obis": "0.0.96.50.3.255", "list": [` + strings.TrimSuffix(strings.Repeat(`{"class": 1, "obis": "0.0.96.50.1.255"},`, cosem.MaxListItems), ",") + `]}`,
	} {
		if _, err := listCmd(t, s).Request(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A GET with list with selective access on one item encodes and is
	// answered item by item.
	m := newListMeter(t, 1000, nil)
	x := m.run(t, listCmd(t, `{"class": 1, "obis": "0.0.96.50.3.255", "list": [{"class": 7, "obis": "1.0.99.1.0.255", "access": {"selector": "entry", "fromEntry": 1, "toEntry": 1}}]}`), 0)
	if r := x.Result(); len(r.Items) != 2 {
		t.Fatalf("%+v", r)
	}
	// An answer with the wrong number of results is refused.
	req, _ := listCmd(t, `{"op": "set", "class": 1, "obis": "0.0.96.50.3.255", "value": "0F01", "list": [{"class": 1, "obis": "0.0.96.50.1.255", "value": "0F02"}]}`).Request()
	req.Invoke = 0xC1
	x2, _, _ := req.Start(0)
	if _, err := x2.Step([]byte{0xC5, 0x05, 0xC1, 0x01, 0x00}); err == nil {
		t.Error("one result for two items accepted")
	}
}

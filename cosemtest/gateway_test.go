// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package cosemtest

import (
	"sync"
	"testing"
	"time"

	. "github.com/cB-Sigma/dlms/cosem"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"

	dlmssim "github.com/cB-Sigma/dlms-sim/sim"
)

// Two meters behind one DCU, one in gateway mode (prefix with network and
// physical address) and one served as the DCU's logical device 17, are
// read over the DCU's one connection.
func TestGatewayModes(t *testing.T) {
	a, b := &dlmssim.Meter{}, &dlmssim.Meter{}
	a.Register("1.0.32.7.0.255", axdr.CreateAxdrLongUnsigned(23000), -2, 35)
	b.Register("1.0.32.7.0.255", axdr.CreateAxdrLongUnsigned(24000), -2, 35)
	dcu := &dlmssim.DCU{Meters: []*dlmssim.DCUMeter{{Network: 2, Address: []byte{0x0A, 0x0B}, Meter: a}},
		Logical: map[uint16]*dlmssim.Meter{17: b}}
	addr, err := dcu.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dcu.Close() })
	var mu sync.Mutex
	var health []int8
	g := NewGateway(GatewayConfig{ID: "DCU-1", Address: addr, Timeout: 3 * time.Second,
		HasMeter: func(network byte, address []byte) bool { return network == 2 && string(address) == "\x0A\x0B" },
		Health:   func(was int8, err error) { mu.Lock(); health = append(health, was); mu.Unlock() },
	})
	t.Cleanup(g.Close)
	read := func(d GatewayDest) uint16 {
		t.Helper()
		c := NewClient(ClientConfig{Transport: func(client int) (gdlms.Transport, error) {
			d.Client = uint16(client)
			return g.Transport(d), nil
		}, ClientAddress: 16, Name: d.Name, Where: "DCU-1"})
		if err := c.Connect(); err != nil {
			t.Fatalf("%s: %v", d.Name, err)
		}
		defer c.Close()
		v, err := c.Get(3, "1.0.32.7.0.255", 2)
		if err != nil {
			t.Fatalf("%s: %v", d.Name, err)
		}
		return v.Value.(uint16)
	}
	for i := 0; i < 2; i++ {
		if v := read(GatewayDest{Network: 2, Address: []byte{0x0A, 0x0B}, Server: 1, Name: "A", Timeout: 3 * time.Second}); v != 23000 {
			t.Errorf("meter A read %d", v)
		}
		if v := read(GatewayDest{Logical: true, Server: 17, Name: "B", Timeout: 3 * time.Second}); v != 24000 {
			t.Errorf("meter B read %d", v)
		}
	}
	if n := dcu.Accepts(); n != 1 || g.Dials() != 1 {
		t.Errorf("the DCU saw %d connections, the gateway dialled %d; want 1 shared", n, g.Dials())
	}
	if h := g.Health(); h.Online != 1 || h.LastOK.IsZero() {
		t.Errorf("health %+v", h)
	}
	mu.Lock()
	if len(health) != 1 || health[0] != -1 {
		t.Errorf("health callbacks %v, want one from unknown", health)
	}
	mu.Unlock()
}

// An unreachable DCU fails at once within its timeout after a failed
// attempt, with an error IsGatewayDown recognises.
func TestGatewayDown(t *testing.T) {
	g := NewGateway(GatewayConfig{ID: "DCU-9", Address: "127.0.0.1:1", Timeout: time.Second})
	err := g.Ensure()
	if !IsGatewayDown(err) || !g.Unreachable() {
		t.Fatalf("err %v, unreachable %v", err, g.Unreachable())
	}
	start := time.Now()
	if err := g.Ensure(); !IsGatewayDown(err) || time.Since(start) > 100*time.Millisecond {
		t.Errorf("the second attempt within the timeout dialled again or did not fail: %v", err)
	}
}

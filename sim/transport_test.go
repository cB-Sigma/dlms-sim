// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package sim_test

import (
	"testing"

	"github.com/cB-Sigma/dlms-sim/sim"
	"github.com/cB-Sigma/dlms/is15959"
)

// A caller carrying APDUs itself gets the push as an APDU addressed to
// the profile's push client, and an error for a setup the profile lacks;
// a session it opens is not associated until an AARQ comes.
func TestCallerTransport(t *testing.T) {
	sp, _ := is15959.Get("part2-1ph")
	m := sim.NewIS15959(sp, sim.IS15959Options{})
	m.Prepare()
	client, apdu, err := m.PushNotification(is15959.PushPeriodic)
	if err != nil {
		t.Fatal(err)
	}
	if a, _ := sp.Association(is15959.Push); client != a.Client {
		t.Errorf("push client %d, want %d", client, a.Client)
	}
	if len(apdu) == 0 {
		t.Error("empty push")
	}
	if _, _, err := m.PushNotification("0.0.25.9.0.254"); err == nil {
		t.Error("an unknown push setup gave a push")
	}
	// An exception-response (service not allowed) before the AARQ.
	if resp := m.HandleAPDU(m.NewSession(16), []byte{0xC0, 0x01, 0xC1, 0x00, 0x01, 0x00, 0x00, 0x60, 0x01, 0x00, 0xFF, 0x02, 0x00}); len(resp) == 0 || resp[0] != 0xD8 {
		t.Errorf("a GET without an association was answered %X", resp)
	}
	if !m.ServesWPort(m.ServerAddress) || m.ServesWPort(m.ServerAddress+1) {
		t.Error("ServesWPort")
	}
}

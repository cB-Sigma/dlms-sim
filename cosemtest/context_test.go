// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package cosemtest

import (
	"bytes"
	"encoding/hex"
	"testing"

	"gitlab.com/circutor-library/gosem/pkg/axdr"

	dlmssim "github.com/cB-Sigma/dlms-sim/sim"
	. "github.com/cB-Sigma/dlms/cosem"
)

// A meter that accepts only logical name referencing without ciphering
// for HLS-GMAC with unprotected APDUs (Gurux's default) refuses the
// ciphering context the client proposes by default, and associates and
// reads with applicationContext "ln"; a meter that wants the ciphering
// context refuses "ln".
//
// Covers: SIG-IPE-046
func TestApplicationContextAgainstMeter(t *testing.T) {
	key, ak := bytes.Repeat([]byte{0x11}, 16), bytes.Repeat([]byte{0x22}, 16)
	start := func(ctx byte) (*dlmssim.Meter, string) {
		sim := &dlmssim.Meter{HLS: &dlmssim.HLS{Context: ctx, SystemTitle: meterST, Key: key, AuthKey: ak}}
		sim.Register("1.0.12.7.0.255", axdr.CreateAxdrLongUnsigned(23050), -2, 35)
		addr, err := sim.Listen("127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = sim.Close() })
		return sim, addr
	}
	try := func(addr, context string) error {
		m := &testMeter{ID: "M", Address: addr, Authentication: "hls-gmac", Security: "none",
			BlockCipherKey: hex.EncodeToString(key), AuthenticationKey: hex.EncodeToString(ak)}
		if err := m.validate(); err != nil {
			t.Fatal(err)
		}
		if context != "" {
			c := SecurityConfig{Name: "M", Authentication: "hls-gmac", Security: "none", ApplicationContext: context,
				BlockCipherKey: hex.EncodeToString(key), AuthenticationKey: hex.EncodeToString(ak)}
			h, _, err := c.Build()
			if err != nil {
				t.Fatal(err)
			}
			m.hls = h
		}
		mt := &testConn{m: m}
		defer mt.close()
		if err := mt.connect(); err != nil {
			return err
		}
		v, err := mt.get(3, "1.0.12.7.0.255", 2)
		if err == nil && v.Value != uint16(23050) {
			t.Errorf("read %v", v.Value)
		}
		return err
	}

	sim, addr := start(ContextLN)
	if err := try(addr, ""); err == nil {
		t.Error("the ciphering context was accepted by a meter that does not support it")
	}
	if sim.ContextRefusals() != 1 {
		t.Errorf("%d refusals for the context, want 1", sim.ContextRefusals())
	}
	if err := try(addr, "ln"); err != nil {
		t.Errorf("applicationContext ln: %v", err)
	}
	if acc, _ := sim.Associations(); acc != 1 {
		t.Errorf("%d associations, want 1", acc)
	}

	sim, addr = start(ContextLNCiphering)
	if err := try(addr, "ln"); err == nil || sim.ContextRefusals() != 1 {
		t.Errorf("a meter wanting the ciphering context accepted ln: %v", err)
	}
	if err := try(addr, "ln-ciphering"); err != nil {
		t.Errorf("applicationContext ln-ciphering: %v", err)
	}
}

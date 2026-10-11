// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package iec6205621sim_test

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/cB-Sigma/dlms-sim/iec6205621sim"
	"github.com/cB-Sigma/dlms/iec6205621"
)

func registers() map[string]string {
	return map[string]string{
		"0.0.0": "12345678", "1.8.0": "001234.5*kWh", "32.7.0": "231.4*V", "C.1.0": "12345678",
	}
}

func start(t testing.TB, m *iec6205621sim.Meter) *iec6205621sim.Meter {
	t.Helper()
	if err := m.Listen(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Stop)
	return m
}

func config(addr string) *iec6205621.SessionConfig {
	return &iec6205621.SessionConfig{Line: iec6205621.Line{TCP: true, Address: addr, Emulate7E1: true},
		MaxBaud: 19200, Timeout: time.Second, ReadCommand: "R1", WriteCommand: "W1"}
}

// A mode C readout over a converter with the parity emulated: sign-on,
// identification, option select for a readout at 300 baud (the converter's
// rate is its own), and the data message's data sets.
func TestReadout(t *testing.T) {
	m := start(t, &iec6205621sim.Meter{Manufacturer: "ISk", BaudChar: '5', Model: "MT174", Registers: registers()})
	var id iec6205621.Identification
	cfg := config(m.Addr())
	cfg.Identified = func(i iec6205621.Identification) { id = i }
	s, _, err := iec6205621.OpenSession(context.Background(), cfg, '0', false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.CloseLine()
	ds, err := s.ReadData()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, d := range ds {
		got[d.Address] = d.Value + "*" + d.Unit
	}
	if got["1.8.0"] != "001234.5*kWh" || got["32.7.0"] != "231.4*V" || id.Mode != iec6205621.ModeC || id.Manufacturer != "ISk" {
		t.Errorf("data sets %v, identification %+v", got, id)
	}
	if err := s.EndReadout(); err != nil {
		t.Error(err)
	}
	if _, _, parity := m.Counts(); parity != 0 {
		t.Errorf("the meter saw %d parity errors", parity)
	}
}

// Programming mode: the password in P1, a read with R1 and a write with W1;
// a wrong password is refused.
func TestProgramming(t *testing.T) {
	m := start(t, &iec6205621sim.Meter{Manufacturer: "ISk", BaudChar: '5', Model: "MT174", Password: "00000000", Registers: registers()})
	s, err := iec6205621.OpenProgramming(context.Background(), config(m.Addr()), "00000000")
	if err != nil {
		t.Fatal(err)
	}
	ds, err := s.Read("1.8.0()")
	if err != nil || len(ds) != 1 || ds[0].Value != "001234.5" {
		t.Fatalf("read 1.8.0: %v %v", ds, err)
	}
	if err := s.WriteValue("C.1.0", "87654321"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if w := m.Writes(); !slices.Contains(w, "C.1.0(87654321)") {
		t.Errorf("the meter took writes %v", w)
	}
	if _, err := iec6205621.OpenProgramming(context.Background(), config(m.Addr()), "11111111"); err == nil {
		t.Error("a wrong password opened programming mode")
	}
}

// A data readout of the simulated mode C meter through a converter, with
// the iec6205621 package of the dlms module.
func Example_readout() {
	m := &iec6205621sim.Meter{Manufacturer: "ISk", BaudChar: '5', Model: "MT174",
		Registers: map[string]string{"1.8.0": "001234.5*kWh", "32.7.0": "231.4*V"}}
	if err := m.Listen(); err != nil {
		panic(err)
	}
	defer m.Stop()
	cfg := &iec6205621.SessionConfig{Line: iec6205621.Line{TCP: true, Address: m.Addr(), Emulate7E1: true}, Timeout: time.Second}
	s, _, err := iec6205621.OpenSession(context.Background(), cfg, '0', false)
	if err != nil {
		panic(err)
	}
	defer s.CloseLine()
	ds, err := s.ReadData()
	if err != nil {
		panic(err)
	}
	for _, d := range ds {
		fmt.Println(iec6205621.PointName(d.Address), d.Value, d.Unit)
	}
	// Output:
	// activeEnergyImport 001234.5 kWh
	// voltageL1 231.4 V
}

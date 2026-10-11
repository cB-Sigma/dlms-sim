// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/dlms/iec6205621"
)

// The runner's meter answers a readout.
func TestRunnerReadout(t *testing.T) {
	var out bytes.Buffer
	m, err := start(config{manufacturer: "ISk", model: "SIM21", baud: "5"}, &out)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()
	if !strings.Contains(out.String(), m.Addr()) {
		t.Errorf("printed %q", out.String())
	}
	cfg := &iec6205621.SessionConfig{Line: iec6205621.Line{TCP: true, Address: m.Addr(), Emulate7E1: true}, Timeout: time.Second}
	s, _, err := iec6205621.OpenSession(context.Background(), cfg, '0', false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.CloseLine()
	ds, err := s.ReadData()
	if err != nil || len(ds) < 5 {
		t.Fatalf("readout %v %v", ds, err)
	}
	if _, err := start(config{baud: "55"}, &out); err == nil {
		t.Error("a two-character -baud was taken")
	}
}

// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Command iec6205621sim serves a simulated IEC 62056-21 meter on TCP, as
// an optical probe behind a transparent serial-to-IP converter would be
// reached (7E1 carried in 8-bit bytes, the parity in bit 7), so a client
// can be tried without hardware.
//
//	iec6205621sim -baud 5 -password 00000000
//
// The meter is a mode C meter (baud character 0 to 6) or, with -baud A to
// F, mode B, with -baud M mode A. It answers a readout with a few
// registers and programming mode with the password given. It listens on
// a free port of 127.0.0.1 (it is a test tool) and prints the address.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/cB-Sigma/dlms-sim/iec6205621sim"
)

// config is what the flags set.
type config struct {
	manufacturer, model, password, address string
	baud                                   string
}

func main() {
	var c config
	flag.StringVar(&c.manufacturer, "manufacturer", "ISk", "manufacturer code (a lower-case third letter: 20 ms reaction)")
	flag.StringVar(&c.model, "model", "SIM21", "identification")
	flag.StringVar(&c.baud, "baud", "5", "baud character: 0 to 6 mode C, A to F mode B, M mode A")
	flag.StringVar(&c.password, "password", "", "programming mode P1 password (empty: access level 1)")
	flag.StringVar(&c.address, "address", "", "device address the meter answers (empty: any)")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	m, err := start(c, os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "iec6205621sim:", err)
		os.Exit(2)
	}
	<-ctx.Done()
	m.Stop()
}

// start builds the meter from the flags and starts it.
func start(c config, out io.Writer) (*iec6205621sim.Meter, error) {
	if len(c.baud) != 1 {
		return nil, errors.New("-baud is one character")
	}
	m := &iec6205621sim.Meter{Manufacturer: c.manufacturer, BaudChar: c.baud[0], Model: c.model,
		Password: c.password, Address: c.address, Serial: "00000001",
		Registers: map[string]string{"0.0.0": "00000001", "1.8.0": "001234.5*kWh", "2.8.0": "0000.0*kWh",
			"32.7.0": "231.4*V", "31.7.0": "4.52*A", "14.7.0": "49.98", "C.1.0": "00000001", "F.F": "00000000"}}
	if err := m.Listen(); err != nil {
		return nil, err
	}
	fmt.Fprintln(out, "IEC 62056-21 meter on", m.Addr())
	return m, nil
}

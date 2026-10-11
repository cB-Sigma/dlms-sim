// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Command dlmssim serves a simulated IS 15959 DLMS/COSEM meter, so a head
// end or a DLMS client can be tried without hardware: the IEC 62056-4-7
// wrapper on TCP (and optionally UDP), and optionally HDLC over TCP as a
// serial-to-Ethernet converter would carry it.
//
//	dlmssim -profile part2-1ph -listen 127.0.0.1:4059 -hdlc 127.0.0.1:4060
//
// The meter answers the associations of its profile: the public client
// (16) without authentication, the meter reader (32) with the password
// -password (in the Part 2 and 3 profiles also with APDUs ciphered under
// the global key), the utility settings and firmware clients with HLS,
// as the profile's association table says. It prints
// the secrets and global keys it uses, which are test values. Its
// instantaneous values are counters, and its profiles and event logs hold
// -rows entries.
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"

	"github.com/cB-Sigma/dlms-sim/sim"
	"github.com/cB-Sigma/dlms/is15959"
)

// config is what the flags set.
type config struct {
	profile, serial, password string
	listen, udp, hdlc         string
	rows                      int
}

func main() {
	var c config
	flag.StringVar(&c.profile, "profile", "part2-1ph", "IS 15959 profile: "+strings.Join(is15959.IDs(), ", "))
	flag.StringVar(&c.serial, "serial", "00000001", "meter serial number")
	flag.StringVar(&c.password, "password", "ABCDEFGH", "meter reader (client 32) low-level security secret")
	flag.StringVar(&c.listen, "listen", "127.0.0.1:4059", "TCP address of the wrapper (empty: none)")
	flag.StringVar(&c.udp, "udp", "", "UDP address of the wrapper (empty: none)")
	flag.StringVar(&c.hdlc, "hdlc", "", "TCP address of HDLC, as through a serial converter (empty: none)")
	flag.IntVar(&c.rows, "rows", 48, "entries in each profile and event log")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	m, err := start(c, os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dlmssim:", err)
		os.Exit(2)
	}
	<-ctx.Done()
	_ = m.Close()
}

// start builds the meter and opens its listeners, describing them on w.
func start(c config, w io.Writer) (*sim.Meter, error) {
	if !slices.Contains(is15959.IDs(), c.profile) {
		return nil, fmt.Errorf("profile %q is not one of %s", c.profile, strings.Join(is15959.IDs(), ", "))
	}
	if c.listen == "" && c.udp == "" && c.hdlc == "" {
		return nil, fmt.Errorf("nothing to serve: give -listen, -udp or -hdlc")
	}
	sp, _ := is15959.Get(c.profile)
	o := sim.IS15959Options{Serial: c.serial, Password: c.password, Rows: c.rows}
	m := sim.NewIS15959(sp, o)
	fmt.Fprintf(w, "meter %s, IS 15959 profile %s (%s)\n", c.serial, sp.ID, sp.Title)
	open := func(what string, listen func(string) (string, error), addr string) error {
		if addr == "" {
			return nil
		}
		a, err := listen(addr)
		if err != nil {
			_ = m.Close()
			return fmt.Errorf("%s: %w", what, err)
		}
		fmt.Fprintf(w, "%s on %s\n", what, a)
		return nil
	}
	if err := open("wrapper over TCP", m.Listen, c.listen); err != nil {
		return nil, err
	}
	if err := open("wrapper over UDP", m.ListenUDP, c.udp); err != nil {
		return nil, err
	}
	if err := open("HDLC over TCP", m.ListenHDLC, c.hdlc); err != nil {
		return nil, err
	}
	for _, a := range sp.Associations {
		fmt.Fprintf(w, "client %d (%s): authentication %s\n", a.Client, a.Role, a.Auth)
	}
	unicast, _, auth := m.Keys()
	fmt.Fprintf(w, "test secrets: meter reader password %q; global key %s, authentication key %s\n",
		c.password, hex.EncodeToString(unicast), hex.EncodeToString(auth))
	return m, nil
}

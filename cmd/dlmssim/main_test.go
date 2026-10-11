// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"

	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"

	"github.com/cB-Sigma/dlms/wrapper"
)

// The runner serves the profile's meter on each transport asked for: a
// client associates over the TCP wrapper with the meter reader's password
// and is refused with a wrong one; the UDP and HDLC listeners open. A
// profile that does not exist and a runner with nothing to serve fail.
func TestStart(t *testing.T) {
	var out bytes.Buffer
	m, err := start(config{profile: "part1-category-C", serial: "00000042", password: "SECRET12",
		listen: "127.0.0.1:0", udp: "127.0.0.1:0", hdlc: "127.0.0.1:0", rows: 4}, &out)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	text := out.String()
	for _, want := range []string{"meter 00000042", "part1-category-C", "wrapper over TCP on 127.0.0.1:", "wrapper over UDP on 127.0.0.1:",
		"HDLC over TCP on 127.0.0.1:", "client 32 (MR): authentication low", `password "SECRET12"`} {
		if !strings.Contains(text, want) {
			t.Errorf("output lacks %q:\n%s", want, text)
		}
	}
	addr := regexp.MustCompile(`wrapper over TCP on (\S+)`).FindStringSubmatch(text)[1]
	associate := func(password string) gdlms.AssociationResult {
		t.Helper()
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		settings, _ := gdlms.NewSettingsWithLowAuthentication([]byte(password))
		aarq, _ := gdlms.EncodeAARQ(&settings)
		w, _ := wrapper.Encode(32, 1, aarq)
		if _, err := c.Write(w); err != nil {
			t.Fatal(err)
		}
		_, aare, err := wrapper.ReadWPDU(c)
		if err != nil {
			t.Fatal(err)
		}
		res, err := gdlms.DecodeAARE(&settings, &aare)
		if err != nil {
			t.Fatal(err)
		}
		return res.AssociationResult
	}
	if r := associate("SECRET12"); r != gdlms.AssociationResultAccepted {
		t.Errorf("meter reader with the password: result %v", r)
	}
	if r := associate("WRONG123"); r == gdlms.AssociationResultAccepted {
		t.Error("meter reader with a wrong password was accepted")
	}
	if _, err := start(config{profile: "part9", listen: "127.0.0.1:0"}, &out); err == nil {
		t.Error("an unknown profile started")
	}
	if _, err := start(config{profile: "part2-1ph"}, &out); err == nil {
		t.Error("a runner with nothing to serve started")
	}
}

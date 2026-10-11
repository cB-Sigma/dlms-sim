// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/cB-Sigma/dlms-sim/sim"
	"github.com/cB-Sigma/dlms/is15959"
)

// The peer: the gurux-dlms package for Python at this version, in this
// image.
const (
	image        = "python:3.12.10-slim"
	guruxPackage = "gurux-dlms==1.0.203"
)

var (
	peerOnce sync.Once
	peerName string
	peerOwn  bool
	peerErr  error
)

func TestMain(m *testing.M) {
	code := m.Run()
	if peerOwn {
		_ = exec.Command("docker", "container", "rm", "-f", peerName).Run()
	}
	os.Exit(code)
}

// needPeer starts the Python container once and installs Gurux in it (or
// uses the running container named by SIGMA_DLMS_GURUX_CONTAINER, which
// must already have it).
func needPeer(t *testing.T) string {
	t.Helper()
	if os.Getenv("SIGMA_DLMS_INTEROP") != "1" {
		t.Skip("runs Gurux's DLMS client in Docker; set SIGMA_DLMS_INTEROP=1 to run")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not on PATH")
	}
	peerOnce.Do(func() {
		if peerName = os.Getenv("SIGMA_DLMS_GURUX_CONTAINER"); peerName != "" {
			return
		}
		td, err := filepath.Abs("testdata")
		if err != nil {
			peerErr = err
			return
		}
		peerName = fmt.Sprintf("sigma-dlms-gurux-client-%d", os.Getpid())
		out, err := exec.Command("docker", "run", "-d", "--name", peerName,
			"--add-host", "host.docker.internal:host-gateway",
			"-v", td+":/sigma:ro", image, "sleep", "3600").CombinedOutput()
		if err != nil {
			peerErr = fmt.Errorf("docker run: %v: %s", err, out)
			return
		}
		peerOwn = true
		out, err = exec.Command("docker", "exec", peerName, "pip", "install", "--no-cache-dir",
			"--disable-pip-version-check", "--root-user-action=ignore", guruxPackage).CombinedOutput()
		if err != nil {
			peerErr = fmt.Errorf("pip install %s: %v: %s", guruxPackage, err, out)
		}
	})
	if peerErr != nil {
		t.Fatal(peerErr)
	}
	return peerName
}

// listenAddr is where the meter listens so that the container reaches it
// at host.docker.internal (see doc.go).
func listenAddr() string {
	if runtime.GOOS == "darwin" {
		return "127.0.0.1:0"
	}
	return "0.0.0.0:0"
}

type check struct {
	Check  string `json:"check"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// gurux runs the client script against the meter at addr and returns its
// checks, failing the test for each one that failed.
func gurux(t *testing.T, addr string, args ...string) map[string]check {
	t.Helper()
	name := needPeer(t)
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	cmd := append([]string{"exec", name, "python", "-I", "/sigma/gurux_client.py",
		"--host", "host.docker.internal", "--port", port}, args...)
	var stdout, stderr bytes.Buffer
	c := exec.Command("docker", cmd...)
	c.Stdout, c.Stderr = &stdout, &stderr
	runErr := c.Run()
	got := map[string]check{}
	sc := bufio.NewScanner(&stdout)
	for sc.Scan() {
		var ck check
		if json.Unmarshal(sc.Bytes(), &ck) != nil {
			continue // Gurux's own prints ("Encryption is applied.")
		}
		got[ck.Check] = ck
		if ck.OK {
			t.Logf("PASS %s: %s", ck.Check, ck.Detail)
		} else {
			t.Errorf("FAIL %s: %s", ck.Check, ck.Detail)
		}
	}
	if runErr != nil {
		t.Errorf("gurux client: %v\n%s", runErr, stderr.String())
	}
	if _, ok := got["associate"]; !ok {
		t.Fatalf("the gurux client reported nothing\n%s", stderr.String())
	}
	return got
}

// meter starts an IS 15959 meter of the profile, listening on the wrapper
// and on HDLC; its profiles hold rows entries, so a whole buffer needs
// blocks (the meter sends at most 180 octets of data per response).
func meter(t *testing.T, profile string, rows int, o sim.IS15959Options) (*sim.Meter, string, string) {
	t.Helper()
	sp, ok := is15959.Get(profile)
	if !ok {
		t.Fatalf("no profile %s", profile)
	}
	o.Rows = rows
	m := sim.NewIS15959(sp, o)
	w, err := m.Listen(listenAddr())
	if err != nil {
		t.Fatal(err)
	}
	h, err := m.ListenHDLC(listenAddr())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m, w, h
}

const (
	clock  = "8:0.0.1.0.0.255:2"
	serial = "1:0.0.96.1.0.255:2"
	// The voltage register: of the single phase (Part 2 single-phase
	// meters) and of L1 (Part 1 meters, three-phase).
	voltage     = "3:1.0.12.7.0.255:2"
	voltSU      = "3:1.0.12.7.0.255:3"
	voltageL1   = "3:1.0.32.7.0.255:2"
	voltageL1SU = "3:1.0.32.7.0.255:3"
	blockLP     = "1.0.99.1.0.255"
	readerPW    = "ABCDEFGH"
)

func hexKey(b byte) string { return strings.Repeat(fmt.Sprintf("%02X", b), 16) }

func both(t *testing.T, f func(t *testing.T, iface string)) {
	for _, iface := range []string{"wrapper", "hdlc"} {
		t.Run(iface, func(t *testing.T) { f(t, iface) })
	}
}

func addrFor(iface, w, h string) string {
	if iface == "hdlc" {
		return h
	}
	return w
}

// Public client (16), no security, on an IS 15959 Part 1 meter.
func TestNoSecurity(t *testing.T) {
	_, w, h := meter(t, "part1-category-C", 4, sim.IS15959Options{})
	both(t, func(t *testing.T, iface string) {
		gurux(t, addrFor(iface, w, h), "--iface", iface, "--client", "16", "--get", clock, "--get", serial)
	})
}

// Meter reader (32), low-level security, Part 1 (no APDU protection):
// clock, a register with scaler and unit, a data object, the block load
// profile whole (in blocks), by entry and by range.
func TestLowLevelSecurity(t *testing.T) {
	m, w, h := meter(t, "part1-category-C", 400, sim.IS15959Options{})
	both(t, func(t *testing.T, iface string) {
		before := m.Blocks()
		gurux(t, addrFor(iface, w, h), "--iface", iface, "--client", "32", "--auth", "low", "--password", readerPW,
			"--get", clock, "--get", voltageL1, "--get", voltageL1SU, "--get", serial, "--profile", blockLP, "--range-hours", "6")
		if n := m.Blocks() - before; n < 2 {
			t.Errorf("the meter sent %d data blocks", n)
		} else {
			t.Logf("the meter sent %d data blocks", n)
		}
	})
}

// Utility settings client (48), HLS mechanism 2, Part 1.
func TestHLSMechanism2(t *testing.T) {
	_, w, h := meter(t, "part1-category-C", 4, sim.IS15959Options{})
	both(t, func(t *testing.T, iface string) {
		gurux(t, addrFor(iface, w, h), "--iface", iface, "--client", "48", "--auth", "hls", "--password", "UTILITYSECRET016",
			"--get", clock, "--get", voltageL1)
	})
}

// Meter reader (32) of a Part 2 meter: low-level security with encrypted
// APDUs under the global key (suite 0).
func TestLowLevelSecurityEncrypted(t *testing.T) {
	_, w, h := meter(t, "part2-1ph", 4, sim.IS15959Options{})
	both(t, func(t *testing.T, iface string) {
		gurux(t, addrFor(iface, w, h), "--iface", iface, "--client", "32", "--auth", "low", "--password", readerPW,
			"--security", "enc", "--block-key", hexKey(0x30), "--auth-key", hexKey(0x31),
			"--get", clock, "--get", voltage)
	})
}

// Utility settings client (48) of a Part 2 meter switched to HLS-GMAC
// (mechanism 5), security suite 0, authenticated and encrypted APDUs: the
// clock, a register, the block load profile in blocks.
func TestHLSGMAC(t *testing.T) {
	m, w, h := meter(t, "part2-1ph", 300, sim.IS15959Options{})
	m.Lock()
	m.HLS.Mechanism, m.HLS.Secret = 5, nil
	m.Unlock()
	both(t, func(t *testing.T, iface string) {
		before := m.Blocks()
		gurux(t, addrFor(iface, w, h), "--iface", iface, "--client", "48", "--auth", "gmac",
			"--security", "authenc", "--block-key", hexKey(0x30), "--auth-key", hexKey(0x31),
			"--get", clock, "--get", voltage, "--get", voltSU, "--profile", blockLP, "--range-hours", "6")
		if n := m.Blocks() - before; n < 2 {
			t.Errorf("the meter sent %d data blocks", n)
		} else {
			t.Logf("the meter sent %d data blocks", n)
		}
	})
}

// A wrong low-level password is refused.
func TestLowLevelSecurityWrongPassword(t *testing.T) {
	_, w, _ := meter(t, "part1-category-C", 4, sim.IS15959Options{})
	name := needPeer(t)
	_, port, _ := net.SplitHostPort(w)
	out, err := exec.Command("docker", "exec", name, "python", "-I", "/sigma/gurux_client.py",
		"--host", "host.docker.internal", "--port", port, "--client", "32", "--auth", "low", "--password", "WRONGPW1").Output()
	if err == nil || !strings.Contains(string(out), `"check": "associate", "ok": false`) {
		t.Fatalf("association with a wrong password was not refused: %v %s", err, out)
	}
	t.Logf("refused as expected: %s", strings.TrimSpace(string(out)))
}

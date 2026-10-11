package lpwantest

import (
	"context"
	"encoding/binary"
	"sync"
	"testing"
	"time"

	dlmssim "github.com/cB-Sigma/dlms-sim/sim"
	"github.com/cB-Sigma/dlms/lpwan"
	"github.com/cB-Sigma/dlms/wrapper"
	"github.com/cB-Sigma/schc"
)

func frame(src, dst uint16, apdu []byte) []byte {
	f := make([]byte, 8, 8+len(apdu))
	binary.BigEndian.PutUint16(f[0:], 1)
	binary.BigEndian.PutUint16(f[2:], src)
	binary.BigEndian.PutUint16(f[4:], dst)
	binary.BigEndian.PutUint16(f[6:], uint16(len(apdu)))
	return append(f, apdu...)
}

func loraSettings(t *testing.T, mut func(*lpwan.BridgeSettings)) lpwan.BridgeSettings {
	t.Helper()
	s := lpwan.BridgeSettings{}
	if mut != nil {
		mut(&s)
	}
	if err := s.Check(); err != nil {
		t.Fatal(err)
	}
	return s
}

// A request goes down to the simulated class A meter and its answer comes
// back, through SCHC compression and, where the payload limit needs it,
// downlink ACK-Always and uplink ACK-on-Error fragmentation, for each
// header choice; downlinks leave only in receive windows after uplinks.
// Covers: SIG-IPE-3774
func TestBridgeWithSimulatedMeter(t *testing.T) {
	for _, c := range []struct {
		name        string
		header      string
		maxPayload  int
		upPayload   int
		wantFragDn  bool
		wantFragUp  bool
		requestSize int
	}{
		{"wrapper small", "wrapper", 51, 51, false, false, 20},
		{"wrapper fragmented both ways", "wrapper", 11, 11, true, true, 120},
		{"bare APDU", "none", 51, 11, false, true, 20},
		{"ipv6 udp wrapper", "ipv6/udp/wrapper", 51, 51, false, false, 20},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := loraSettings(t, func(s *lpwan.BridgeSettings) { s.Header = c.header; s.MaxPayload = c.maxPayload })
			ns := lpwan.NewMemNS()
			b, err := lpwan.NewBridge(s, ns, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			conn, err := b.Add(lpwan.DeviceOptions{Meter: lpwan.MeterLoRaWAN{DevEUI: "70b3d57ed005a1b2"}})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() { _ = b.Run(ctx) }()
			<-ns.Ready()
			sim := &dlmssim.LoRaWANMeter{Meter: &dlmssim.Meter{}, DevEUI: "70b3d57ed005a1b2", NS: ns, Settings: s,
				UplinkPayload: c.upPayload, Poll: 20 * time.Millisecond}
			if err := sim.Start(); err != nil {
				t.Fatal(err)
			}
			defer sim.Stop()
			aarq := make([]byte, c.requestSize)
			aarq[0], aarq[1] = 0x60, byte(c.requestSize-2)
			if _, err := conn.Write(frame(48, 1, aarq)); err != nil {
				t.Fatal(err)
			}
			_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			h, apdu, err := wrapper.ReadWPDU(conn)
			if err != nil {
				t.Fatal(err)
			}
			if apdu[0] != 0x61 || h.Dst != 48 || h.Src != 1 {
				t.Fatalf("answer %+v % x", h, apdu)
			}
			li, _ := b.Link("70b3d57ed005a1b2")
			if li.RSSI == nil || *li.RSSI != -97 || li.DR == nil || *li.DR != 5 || li.Uplinks == 0 || li.Downlinks == 0 {
				t.Fatalf("link %+v", li)
			}
			if c.wantFragDn && li.Downlinks < 3 {
				t.Fatalf("%d downlinks for a fragmented request", li.Downlinks)
			}
			if c.wantFragUp && sim.Uplinks() < 3 {
				t.Fatalf("%d uplinks for a fragmented answer", sim.Uplinks())
			}
		})
	}
}

// Lost radio frames are recovered by SCHC retransmission.
// Covers: SIG-IPE-3774
func TestBridgeRecoversLostFrames(t *testing.T) {
	s := loraSettings(t, func(s *lpwan.BridgeSettings) {
		s.MaxPayload = 11
		s.InactivityTimer = lpwan.Duration(2 * time.Second) // the uplink rule's timers, short for the test
		s.RetransmissionTimer = lpwan.Duration(time.Second)
		s.Class = "C"
	})
	ns := lpwan.NewMemNS()
	var mu sync.Mutex
	ns.DropDown = func(n int, d lpwan.Downlink) bool { mu.Lock(); defer mu.Unlock(); return n == 2 }
	ns.DropUp = func(n int, u lpwan.Uplink) bool {
		mu.Lock()
		defer mu.Unlock()
		return u.FPort == schc.FPortUp && n%5 == 3
	}
	b, err := lpwan.NewBridge(s, ns, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	conn, _ := b.Add(lpwan.DeviceOptions{Meter: lpwan.MeterLoRaWAN{DevEUI: "70b3d57ed005a1b3"}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = b.Run(ctx) }()
	<-ns.Ready()
	sim := &dlmssim.LoRaWANMeter{Meter: &dlmssim.Meter{}, DevEUI: "70b3d57ed005a1b3", NS: ns, Settings: s, UplinkPayload: 11, Poll: 20 * time.Millisecond}
	if err := sim.Start(); err != nil {
		t.Fatal(err)
	}
	defer sim.Stop()
	aarq := make([]byte, 60)
	aarq[0], aarq[1] = 0x60, 58
	if _, err := conn.Write(frame(48, 1, aarq)); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(20 * time.Second))
	if _, apdu, err := wrapper.ReadWPDU(conn); err != nil || apdu[0] != 0x61 {
		t.Fatalf("% x %v", apdu, err)
	}
}

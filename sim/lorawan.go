package sim

// The meter end of the DLMS/COSEM LoRaWAN link (package lpwan) for
// tests: a simulated meter behind a LoRaWAN radio on an lpwan.MemNS
// network server.

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cB-Sigma/dlms/lpwan"
	"github.com/cB-Sigma/schc"
)

// LoRaWANMeter is the meter behind a LoRaWAN radio: the device end of SCHC
// (RFC 8724, RFC 9011) on an lpwan.MemNS network server. Its uplinks
// fragment with ACK-on-Error, it reassembles ACK-Always downlinks and
// answers them with SCHC ACKs, and as a class A device it can only be
// reached in the receive window after one of its uplinks, so it sends an
// empty frame every Poll. The SCHC settings must be the head end's.
type LoRaWANMeter struct {
	Meter    *Meter
	DevEUI   string
	NS       *lpwan.MemNS
	Settings lpwan.BridgeSettings // fPorts, header, rules: the head end's
	// UplinkPayload is the largest uplink FRMPayload in bytes (default 51,
	// DR0–DR2 in IN865).
	UplinkPayload int
	// Poll is how often the meter sends an empty uplink to open a receive
	// window (default 200 ms; 0 after Start disables nothing: use Stop).
	Poll time.Duration
	// NoneClient is the client address taken for requests when the header
	// is none (no wPorts on the air; default 48).
	NoneClient uint16

	mu       sync.Mutex
	rules    *schc.RuleSet
	stack    schc.Stack
	ctxt     schc.Context
	recv     *schc.Receiver
	send     *schc.Sender
	pending  []schc.Bits
	sessions map[uint16]*Session
	lastRecv *schc.Receiver
	uplinks  int
	served   int
	cancel   context.CancelFunc
}

// Start attaches the meter to the network server and runs it.
func (lm *LoRaWANMeter) Start() error {
	lm.Meter.Prepare()
	if err := lm.Settings.Check(); err != nil {
		return err
	}
	rs, err := lm.Settings.RuleSet()
	if err != nil {
		return err
	}
	lm.rules = rs
	lm.stack, _ = schc.ParseStack(lm.Settings.Header)
	if lm.UplinkPayload == 0 {
		lm.UplinkPayload = 51
	}
	if lm.Poll == 0 {
		lm.Poll = 200 * time.Millisecond
	}
	lm.sessions = map[uint16]*Session{}
	if lm.NoneClient == 0 {
		lm.NoneClient = 48
	}
	if lm.ctxt.DevIID == nil {
		// The head end's defaults: the modified EUI-64 and ::1.
		e, err := hex.DecodeString(lm.DevEUI)
		if err != nil || len(e) != 8 {
			return fmt.Errorf("devEUI %q is not 8 bytes of hex", lm.DevEUI)
		}
		e[0] ^= 0x02
		app := make([]byte, 8)
		app[7] = 1
		lm.ctxt = schc.Context{DevIID: e, AppIID: app}
	}
	rx := lm.NS.Attach(lm.DevEUI, lm.Settings.Class)
	ctx, cancel := context.WithCancel(context.Background())
	lm.cancel = cancel
	go func() {
		t := time.NewTicker(lm.Poll)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case dl := <-rx:
				lm.downlink(dl)
			case <-t.C:
				lm.mu.Lock()
				out := lm.tick()
				lm.mu.Unlock()
				lm.up(out)
				lm.NS.Uplink(lm.DevEUI, 0, nil) // an empty frame opens a receive window
			}
		}
	}()
	return nil
}

// Stop stops the meter.
func (lm *LoRaWANMeter) Stop() {
	if lm.cancel != nil {
		lm.cancel()
	}
}

// Served is how many requests the meter answered.
func (lm *LoRaWANMeter) Served() int { lm.mu.Lock(); defer lm.mu.Unlock(); return lm.served }

// Uplinks is how many SCHC messages the meter sent.
func (lm *LoRaWANMeter) Uplinks() int { lm.mu.Lock(); defer lm.mu.Unlock(); return lm.uplinks }

func (lm *LoRaWANMeter) tick() []schc.Bits {
	now := time.Now()
	var out []schc.Bits
	if lm.send != nil && !lm.send.Done() {
		m, _ := lm.send.Tick(now)
		out = append(out, m...)
	}
	if lm.recv != nil {
		out = append(out, lm.recv.Tick(now)...)
	}
	return out
}

// up sends SCHC messages as uplinks.
func (lm *LoRaWANMeter) up(msgs []schc.Bits) {
	for _, m := range msgs {
		f, err := schc.ToLoRaWAN(m)
		if err != nil {
			continue
		}
		lm.mu.Lock()
		lm.uplinks++
		lm.mu.Unlock()
		lm.NS.Uplink(lm.DevEUI, int(f.FPort), f.Payload)
	}
}

func (lm *LoRaWANMeter) downlink(dl lpwan.Downlink) {
	lm.mu.Lock()
	now := time.Now()
	msg := schc.FromLoRaWAN(uint8(dl.FPort), dl.Data)
	var out []schc.Bits
	var packets []schc.Bits
	switch dl.FPort {
	case lm.Settings.FPortDown:
		r := lm.rules.ByID(uint32(dl.FPort))
		if lm.recv == nil || lm.recv.Err() != nil || lm.recv.Done() {
			if m, err := schc.DecodeAtReceiver(r, msg, 8); lm.recv == nil || lm.recv.Err() != nil || (err == nil && m.Kind == schc.MsgFragment && m.W == 0) {
				lm.recv = schc.NewReceiver(r, 8, 0, 0, now)
			}
		}
		acks, _ := lm.recv.Receive(now, msg)
		out = append(out, acks...)
		if p, ok := lm.recv.Packet(); ok && lm.lastRecv != lm.recv {
			lm.lastRecv = lm.recv
			packets = append(packets, p)
		}
	case lm.Settings.FPortUp:
		if lm.send != nil {
			more, _ := lm.send.Receive(now, msg, 8+8*lm.UplinkPayload)
			out = append(out, more...)
			if lm.send.Done() && len(lm.pending) > 0 {
				next := lm.pending[0]
				lm.pending = lm.pending[1:]
				out = append(out, lm.fragment(next)...)
			}
		}
	default:
		packets = append(packets, msg)
	}
	var replies [][]byte
	for _, p := range packets {
		pkt, _, err := lm.rules.Decompress(lm.stack, p, schc.Down, lm.ctxt)
		if err != nil {
			continue
		}
		if r := lm.serve(pkt); r != nil {
			replies = append(replies, r)
		}
	}
	for _, r := range replies {
		out = append(out, lm.encode(r)...)
	}
	lm.mu.Unlock()
	lm.up(out)
}

// serve answers one decompressed packet (lm.mu held).
func (lm *LoRaWANMeter) serve(pkt []byte) []byte {
	var src, dst uint16
	var apdu []byte
	switch lm.stack.String() {
	case "none":
		// Without the wrapper the client is not named: NoneClient.
		src, dst, apdu = lm.NoneClient, lm.Meter.ServerAddress, pkt
	default:
		if lm.stack.String() != "wrapper" {
			if len(pkt) < 48 {
				return nil
			}
			pkt = pkt[48:]
		}
		if len(pkt) < 8 {
			return nil
		}
		src, dst, apdu = binary.BigEndian.Uint16(pkt[2:]), binary.BigEndian.Uint16(pkt[4:]), pkt[8:]
	}
	if !lm.Meter.ServesWPort(dst) {
		return nil
	}
	s := lm.sessions[src]
	if s == nil {
		s = lm.Meter.NewSession(src)
		lm.sessions[src] = s
	}
	resp := lm.Meter.HandleAPDU(s, apdu)
	if resp == nil {
		return nil
	}
	lm.served++
	return lm.frame(src, resp)
}

// Push sends the data-notification of a push setup as uplinks.
func (lm *LoRaWANMeter) Push(setupOBIS string) error {
	client, apdu, err := lm.Meter.PushNotification(setupOBIS)
	if err != nil {
		return err
	}
	lm.mu.Lock()
	out := lm.encode(lm.frame(client, apdu))
	lm.mu.Unlock()
	if len(out) == 0 {
		return errors.New("the push could not be compressed")
	}
	lm.up(out)
	return nil
}

// frame is a wrapper frame from the meter to a client wPort.
func (lm *LoRaWANMeter) frame(client uint16, apdu []byte) []byte {
	f := make([]byte, 8, 8+len(apdu))
	binary.BigEndian.PutUint16(f[0:], 1)
	binary.BigEndian.PutUint16(f[2:], lm.Meter.ServerAddress)
	binary.BigEndian.PutUint16(f[4:], client)
	binary.BigEndian.PutUint16(f[6:], uint16(len(apdu)))
	return append(f, apdu...)
}

// encode compresses a wrapper frame from the meter and fragments it if it
// does not fit one uplink (lm.mu held).
func (lm *LoRaWANMeter) encode(frame []byte) []schc.Bits {
	pkt := frame
	switch lm.stack.String() {
	case "none":
		pkt = frame[8:]
	case "wrapper":
	default:
		ip := lm.Settings.IPv6
		v := lpwan.IPv6Settings{DevPrefix: "fe80::/64", AppPrefix: "fe80::/64", AppIID: "::1", Port: 4059, HopLimit: 255}
		if ip != nil {
			v = *ip
		}
		vals := map[string]schc.Bits{
			schc.FIPv6Version: schc.Uint(6, 4), schc.FIPv6TrafficClass: schc.Uint(0, 8), schc.FIPv6FlowLabel: schc.Uint(0, 20),
			schc.FIPv6NextHeader: schc.Uint(17, 8), schc.FIPv6HopLimit: schc.Uint(uint64(v.HopLimit), 8),
			schc.FUDPDevPort: schc.Uint(uint64(v.Port), 16), schc.FUDPAppPort: schc.Uint(uint64(v.Port), 16),
			schc.FIPv6DevIID: schc.BytesOf(lm.ctxt.DevIID), schc.FIPv6AppIID: schc.BytesOf(lm.ctxt.AppIID),
		}
		vals[schc.FIPv6DevPrefix], _ = schc.IPv6Value(v.DevPrefix)
		vals[schc.FIPv6AppPrefix], _ = schc.IPv6Value(v.AppPrefix)
		b, err := schc.Stack{"ipv6", "udp"}.Build(vals, frame, schc.Up)
		if err != nil {
			return nil
		}
		pkt = b
	}
	msg, _, err := lm.rules.Compress(lm.stack, pkt, schc.Up, lm.ctxt)
	if err != nil {
		return nil
	}
	padded := msg.Clone()
	padded.Pad(8)
	if padded.Len() <= 8+8*lm.UplinkPayload {
		return []schc.Bits{padded}
	}
	if lm.send != nil && !lm.send.Done() {
		lm.pending = append(lm.pending, msg)
		return nil
	}
	return lm.fragment(msg)
}

func (lm *LoRaWANMeter) fragment(msg schc.Bits) []schc.Bits {
	r := lm.rules.ByID(uint32(lm.Settings.FPortUp))
	s, err := schc.NewSender(r, 8, 0, msg)
	if err != nil {
		return nil
	}
	lm.send = s
	out, _ := s.Start(time.Now(), 8+8*lm.UplinkPayload)
	return out
}

// SetIIDs sets the IPv6 interface identifiers the meter uses with header
// ipv6/udp/wrapper (the head end's defaults: EUI-64 based and ::1).
func (lm *LoRaWANMeter) SetIIDs(dev, app []byte) { lm.ctxt = schc.Context{DevIID: dev, AppIID: app} }

package sim

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/cB-Sigma/dlms/wrapper"
)

// NBIoTMeter is a meter on NB-IoT (or LTE-M) behind carrier NAT that
// sleeps in PSM: it wakes, sends one push over UDP with the wrapper to the
// head end from a fresh source port (as a NAT rebinding would show it),
// answers requests arriving from the head end for ActiveTime after its
// last datagram, then sleeps again and cannot be reached.
type NBIoTMeter struct {
	Meter  *Meter
	Server string // head end host:port
	// ActiveTime is how long it listens after its last datagram (T3324;
	// default 2 s).
	ActiveTime time.Duration

	mu      sync.Mutex
	calls   int
	served  int
	awake   bool
	lastSrc string
}

// Call wakes the meter: it pushes setupOBIS's data-notification and
// serves the head end until it has been idle for ActiveTime; Call returns
// when the meter sleeps again.
func (n *NBIoTMeter) Call(setupOBIS string) error {
	done, err := n.CallAsync(setupOBIS)
	if err != nil {
		return err
	}
	<-done
	return nil
}

// CallAsync is Call returning at once; the channel closes when the meter
// sleeps.
func (n *NBIoTMeter) CallAsync(setupOBIS string) (<-chan struct{}, error) {
	n.Meter.prepare()
	if n.ActiveTime == 0 {
		n.ActiveTime = 2 * time.Second
	}
	apdu, err := n.Meter.pushAPDU(setupOBIS)
	if err != nil {
		return nil, err
	}
	srv, err := net.ResolveUDPAddr("udp", n.Server)
	if err != nil {
		return nil, err
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	if _, err := pc.WriteTo(wrapperFrame(n.Meter.pushClient(), apdu), srv); err != nil {
		_ = pc.Close()
		return nil, err
	}
	n.mu.Lock()
	n.calls++
	n.awake = true
	n.lastSrc = pc.LocalAddr().String()
	n.mu.Unlock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer pc.Close()
		defer func() { n.mu.Lock(); n.awake = false; n.mu.Unlock() }()
		sessions := map[uint16]*session{}
		buf := make([]byte, 65536)
		for {
			_ = pc.SetReadDeadline(time.Now().Add(n.ActiveTime))
			k, from, err := pc.ReadFrom(buf)
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return // asleep
			}
			if err != nil {
				return
			}
			if from.String() != srv.String() {
				continue
			}
			h, req, err := wrapper.ParseDatagram(buf[:k])
			if err != nil || !n.Meter.boundWPort(h.Dst) {
				n.Meter.discard()
				continue
			}
			s := sessions[h.Src]
			if s == nil {
				s = &session{client: h.Src}
				sessions[h.Src] = s
			}
			resp := n.Meter.handle(s, append([]byte(nil), req...))
			if resp == nil || h.Dst == wrapper.AllStation {
				continue
			}
			out, err := wrapper.Encode(n.Meter.ServerAddress, h.Src, resp)
			if err != nil {
				continue
			}
			n.mu.Lock()
			n.served++
			n.mu.Unlock()
			_, _ = pc.WriteTo(out, srv)
		}
	}()
	return done, nil
}

// Calls is how many times the meter woke.
func (n *NBIoTMeter) Calls() int { n.mu.Lock(); defer n.mu.Unlock(); return n.calls }

// Served is how many requests it answered.
func (n *NBIoTMeter) Served() int { n.mu.Lock(); defer n.mu.Unlock(); return n.served }

// Awake reports whether it is listening now.
func (n *NBIoTMeter) Awake() bool { n.mu.Lock(); defer n.mu.Unlock(); return n.awake }

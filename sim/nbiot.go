package sim

import (
	"errors"
	"sync"
	"time"

	"github.com/cB-Sigma/dlms/lpwan/enddevice"
)

var errStopped = errors.New("the meter is not started")

// NBIoTMeter is a meter on NB-IoT (or LTE-M) behind carrier NAT that
// sleeps in PSM: it wakes, sends one push over UDP with the wrapper to the
// head end from a fresh source port (as a NAT rebinding would show it),
// answers requests arriving from the head end for ActiveTime after its
// last datagram, then sleeps again and cannot be reached. The dlms
// library's end device (package lpwan/enddevice) runs it.
type NBIoTMeter struct {
	Meter  *Meter
	Server string // head end host:port
	// ActiveTime is how long it listens after its last datagram (T3324;
	// default 2 s).
	ActiveTime time.Duration

	once sync.Once
	dev  *enddevice.NBIoT
}

func (n *NBIoTMeter) device() *enddevice.NBIoT {
	n.once.Do(func() {
		n.dev = &enddevice.NBIoT{Handler: &handler{m: n.Meter}}
	})
	return n.dev
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
	d := n.device()
	d.ServerAddress, d.Server, d.ActiveTime = n.Meter.ServerAddress, n.Server, n.ActiveTime
	// Each wake is a new session, as a meter coming out of PSM.
	d.Handler = &handler{m: n.Meter}
	return d.CallAsync(n.Meter.pushClient(), apdu)
}

// Calls is how many times the meter woke.
func (n *NBIoTMeter) Calls() int { return n.device().Calls() }

// Served is how many requests it answered.
func (n *NBIoTMeter) Served() int { return n.device().Served() }

// Awake reports whether it is listening now.
func (n *NBIoTMeter) Awake() bool { return n.device().Awake() }

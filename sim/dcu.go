package sim

import (
	"errors"
	"fmt"
	"sync"

	"github.com/cB-Sigma/dlms/concentrator"
	"github.com/cB-Sigma/dlms/gateway"
)

// DCU is a simulated data concentrator unit: the data concentrator of the
// dlms library (package concentrator) in front of simulated meters. It
// routes requests carrying the gateway prefix of IEC 62056-5-3:2023 annex
// C to the meters behind it by network ID and physical device address, and
// answers for them with the prefix (header E7, the meter's network and
// address). Plain requests go to the meters it serves as its own logical
// devices, by server wPort. A meter marked unreachable never answers, as a
// meter the DCU's local network cannot reach.
type DCU struct {
	// Meters behind the DCU's gateway.
	Meters []*DCUMeter
	// Logical are meters the DCU serves as its logical devices, by server
	// SAP (wPort).
	Logical map[uint16]*Meter
	// AnswerAddress, when set, is put in every answer's prefix instead of
	// the meter's address (a DCU that names itself, for tests).
	AnswerAddress []byte
	// PushHeader is the header of pushes the DCU forwards: gateway.Request
	// (E6, default, as C.2 says) or gateway.Response (E7, as some DCUs do).
	PushHeader byte
	// DropAfterAction, while above 0, makes the DCU go away (close every
	// connection and stop listening) after a meter executed an
	// action-request, before the answer is sent: the request ran, its
	// answer is lost. Each such drop counts it down. Set under Lock.
	DropAfterAction int

	mu     sync.Mutex
	c      *concentrator.Concentrator
	routed map[string]int
}

// DCUMeter is a meter behind the DCU's gateway.
type DCUMeter struct {
	Network     byte
	Address     []byte
	Meter       *Meter
	Unreachable bool
}

// device is a simulated meter as the concentrator's downstream device;
// dm is nil for a logical device.
func (d *DCU) device(m *Meter, dm *DCUMeter) concentrator.Downstream {
	return concentrator.Func(func(client, server uint16) (concentrator.Session, error) {
		s := &session{client: client}
		return concentrator.SessionFunc(func(apdu []byte) ([]byte, error) {
			if dm != nil {
				d.mu.Lock()
				down := dm.Unreachable
				if !down {
					d.routed[gateway.FormatAddress(dm.Address)]++
				}
				d.mu.Unlock()
				if down {
					return nil, concentrator.ErrUnreachable
				}
				if !m.boundWPort(server) {
					return nil, nil
				}
			}
			s.client = client
			resp := m.handle(s, apdu)
			if len(apdu) > 0 && apdu[0] == 0xC3 {
				d.mu.Lock()
				drop := d.DropAfterAction > 0
				if drop {
					d.DropAfterAction--
				}
				d.mu.Unlock()
				if drop {
					go func() { _ = d.Close() }()
					return nil, concentrator.ErrUnreachable
				}
			}
			return resp, nil
		}), nil
	})
}

// Listen serves on addr ("127.0.0.1:0") until Close.
func (d *DCU) Listen(addr string) (string, error) {
	for _, m := range d.Meters {
		m.Meter.prepare()
	}
	for sap, m := range d.Logical {
		m.ServerAddress = sap
		m.prepare()
	}
	c := &concentrator.Concentrator{PushHeader: d.PushHeader, Logical: map[uint16]concentrator.Downstream{}}
	for _, dm := range d.Meters {
		c.Meters = append(c.Meters, concentrator.Meter{Network: dm.Network, Address: dm.Address, Device: d.device(dm.Meter, dm)})
	}
	for sap, m := range d.Logical {
		c.Logical[sap] = d.device(m, nil)
	}
	if d.AnswerAddress != nil {
		a := d.AnswerAddress
		c.ResponsePrefix = func(p gateway.Prefix) gateway.Prefix {
			return gateway.Prefix{Header: gateway.Response, Network: p.Network, Address: a}
		}
	}
	d.mu.Lock()
	d.c = c
	if d.routed == nil {
		d.routed = map[string]int{}
	}
	d.mu.Unlock()
	return c.Listen(addr)
}

func (d *DCU) conc() *concentrator.Concentrator {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.c
}

// Close stops listening and drops the head end's connections.
func (d *DCU) Close() error {
	if c := d.conc(); c != nil {
		return c.Close()
	}
	return nil
}

// Lock takes the lock that guards the behaviour switches (DropAfterAction).
func (d *DCU) Lock() { d.mu.Lock() }

// Unlock releases the lock Lock took.
func (d *DCU) Unlock() { d.mu.Unlock() }

// Accepts counts the connections the head end opened.
func (d *DCU) Accepts() int {
	if c := d.conc(); c != nil {
		return c.Stats().Accepts
	}
	return 0
}

// Unknown counts prefixed requests for an address no meter has (dropped).
func (d *DCU) Unknown() int {
	if c := d.conc(); c != nil {
		return c.Stats().Unknown
	}
	return 0
}

// Routed counts the requests passed to the meter at an address (hex).
func (d *DCU) Routed(address []byte) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.routed[gateway.FormatAddress(address)]
}

// SetUnreachable makes the meter at an address stop or start answering.
func (d *DCU) SetUnreachable(address []byte, down bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if dm := d.at(0, address, true); dm != nil {
		dm.Unreachable = down
	}
}

// at finds a meter by network and address (anyNet: by address alone).
func (d *DCU) at(network byte, address []byte, anyNet bool) *DCUMeter {
	for _, dm := range d.Meters {
		if (anyNet || dm.Network == network) && string(dm.Address) == string(address) {
			return dm
		}
	}
	return nil
}

// push is a meter's push from a push setup of its profile, and the client
// it goes to.
func (d *DCU) push(network byte, address []byte, setupOBIS string) ([]byte, uint16, error) {
	d.mu.Lock()
	dm := d.at(network, address, false)
	d.mu.Unlock()
	m := (*Meter)(nil)
	switch {
	case dm != nil:
		m = dm.Meter
	case len(d.Meters) > 0:
		// An address the DCU has no meter at: the first meter's push,
		// forwarded as if from that address (tests of unknown addresses).
		m = d.Meters[0].Meter
	default:
		return nil, 0, fmt.Errorf("no meter at network %d address %X", network, address)
	}
	apdu, err := m.pushAPDU(setupOBIS)
	if err != nil {
		return nil, 0, err
	}
	return apdu, m.pushClient(), nil
}

// header keeps the concentrator's push header in step with PushHeader,
// which tests change while serving.
func (d *DCU) header() *concentrator.Concentrator {
	c := d.conc()
	if c == nil {
		c = &concentrator.Concentrator{}
	}
	d.mu.Lock()
	c.PushHeader = d.PushHeader
	d.mu.Unlock()
	return c
}

// Push forwards a meter's push on the head end's open connections (the
// DCU has no other way to it).
func (d *DCU) Push(network byte, address []byte, setupOBIS string) error {
	apdu, client, err := d.push(network, address, setupOBIS)
	if err != nil {
		return err
	}
	if d.conc() == nil {
		return errors.New("the head end has no connection open to the DCU")
	}
	return d.header().Forward(network, address, client, apdu)
}

// PushTo forwards a meter's push to the head end's push listener at addr
// over TCP, as a DCU that knows the head end's address does (C.4.2).
func (d *DCU) PushTo(addr string, network byte, address []byte, setupOBIS string) error {
	apdu, client, err := d.push(network, address, setupOBIS)
	if err != nil {
		return err
	}
	return d.header().ForwardTo(addr, network, address, client, apdu)
}

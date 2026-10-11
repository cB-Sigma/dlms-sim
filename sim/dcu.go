package sim

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/cB-Sigma/dlms/gateway"
	"github.com/cB-Sigma/dlms/wrapper"
)

// DCU is a simulated data concentrator unit: a wrapper server over TCP
// that routes requests carrying the gateway prefix of IEC 62056-5-3:2023
// annex C to the simulated meters behind it by network ID and physical
// device address, and answers for them with the prefix (header E7, the
// meter's network and address). Plain requests go to the meters it serves
// as its own logical devices, by server wPort. A meter marked unreachable
// never answers, as a meter the DCU's local network cannot reach.
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

	mu      sync.Mutex
	ln      net.Listener
	conns   []net.Conn
	accepts int
	unknown int
	routed  map[string]int
}

// DCUMeter is a meter behind the DCU's gateway.
type DCUMeter struct {
	Network     byte
	Address     []byte
	Meter       *Meter
	Unreachable bool
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
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", err
	}
	d.mu.Lock()
	d.ln = ln
	if d.routed == nil {
		d.routed = map[string]int{}
	}
	d.mu.Unlock()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			d.mu.Lock()
			d.accepts++
			d.conns = append(d.conns, c)
			d.mu.Unlock()
			go d.serve(c)
		}
	}()
	return ln.Addr().String(), nil
}

// Close stops listening and drops the head end's connections.
func (d *DCU) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, c := range d.conns {
		_ = c.Close()
	}
	d.conns = nil
	if d.ln == nil {
		return nil
	}
	return d.ln.Close()
}

// Lock takes the lock that guards the behaviour switches (DropAfterAction).
func (d *DCU) Lock() { d.mu.Lock() }

// Unlock releases the lock Lock took.
func (d *DCU) Unlock() { d.mu.Unlock() }

// Accepts counts the connections the head end opened.
func (d *DCU) Accepts() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.accepts
}

// Unknown counts prefixed requests for an address no meter has (dropped).
func (d *DCU) Unknown() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.unknown
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

type dcuSessionKey struct {
	logical bool
	network byte
	address string
	client  uint16
	server  uint16
}

func (d *DCU) serve(c net.Conn) {
	defer c.Close()
	sessions := map[dcuSessionKey]*session{}
	var wmu sync.Mutex
	for {
		h, apdu, err := wrapper.ReadWPDU(c)
		if errors.Is(err, wrapper.ErrVersion) {
			continue
		}
		if err != nil {
			return
		}
		pre, inner, prefixed, err := gateway.Parse(apdu)
		if err != nil {
			continue
		}
		var m *Meter
		k := dcuSessionKey{client: h.Src, server: h.Dst}
		if prefixed {
			d.mu.Lock()
			dm := d.at(pre.Network, pre.Address, false)
			switch {
			case dm == nil:
				d.unknown++
			case !dm.Unreachable:
				m = dm.Meter
				d.routed[gateway.FormatAddress(pre.Address)]++
			}
			d.mu.Unlock()
			if m == nil || !m.boundWPort(h.Dst) {
				continue
			}
			k.network, k.address = pre.Network, string(pre.Address)
		} else {
			k.logical = true
			if m = d.Logical[h.Dst]; m == nil {
				continue
			}
			inner = apdu
		}
		s := sessions[k]
		if s == nil {
			s = &session{}
			sessions[k] = s
		}
		s.client = h.Src
		// Each meter answers in its own time, as on a real local network;
		// the head end tells the answers apart by their prefix.
		resp := m.handle(s, inner)
		if len(inner) > 0 && inner[0] == 0xC3 {
			d.mu.Lock()
			drop := d.DropAfterAction > 0
			if drop {
				d.DropAfterAction--
			}
			d.mu.Unlock()
			if drop {
				go func() { _ = d.Close() }()
				return
			}
		}
		if resp == nil || h.Dst == wrapper.AllStation {
			continue
		}
		if prefixed {
			addr := pre.Address
			if d.AnswerAddress != nil {
				addr = d.AnswerAddress
			}
			if resp, err = gateway.Encode(gateway.Prefix{Header: gateway.Response, Network: pre.Network, Address: addr}, resp); err != nil {
				return
			}
		}
		out, err := wrapper.Encode(h.Dst, h.Src, resp)
		if err != nil {
			return
		}
		wmu.Lock()
		_, err = c.Write(out)
		wmu.Unlock()
		if err != nil {
			return
		}
	}
}

// pushFrame is a meter's push from a push setup of its profile as the DCU
// forwards it: prefixed with the header, the network and the address.
func (d *DCU) pushFrame(network byte, address []byte, setupOBIS string) ([]byte, error) {
	d.mu.Lock()
	dm := d.at(network, address, false)
	d.mu.Unlock()
	var apdu []byte
	var client uint16 = 1
	var err error
	if dm != nil {
		if apdu, err = dm.Meter.pushAPDU(setupOBIS); err != nil {
			return nil, err
		}
		client = dm.Meter.pushClient()
	} else if len(d.Meters) > 0 {
		// An address the DCU has no meter at: the first meter's push,
		// forwarded as if from that address (tests of unknown addresses).
		if apdu, err = d.Meters[0].Meter.pushAPDU(setupOBIS); err != nil {
			return nil, err
		}
		client = d.Meters[0].Meter.pushClient()
	} else {
		return nil, fmt.Errorf("no meter at network %d address %X", network, address)
	}
	h := d.PushHeader
	if h == 0 {
		h = gateway.Request
	}
	b, err := gateway.Encode(gateway.Prefix{Header: h, Network: network, Address: address}, apdu)
	if err != nil {
		return nil, err
	}
	return wrapper.Encode(wrapper.ManagementDevice, client, b)
}

// Push forwards a meter's push on the head end's open connections (the
// DCU has no other way to it).
func (d *DCU) Push(network byte, address []byte, setupOBIS string) error {
	out, err := d.pushFrame(network, address, setupOBIS)
	if err != nil {
		return err
	}
	d.mu.Lock()
	conns := append([]net.Conn(nil), d.conns...)
	d.mu.Unlock()
	if len(conns) == 0 {
		return errors.New("the head end has no connection open to the DCU")
	}
	for _, c := range conns {
		_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Write(out); err != nil {
			return err
		}
	}
	return nil
}

// PushTo forwards a meter's push to the head end's push listener at addr
// over TCP, as a DCU that knows the head end's address does (C.4.2).
func (d *DCU) PushTo(addr string, network byte, address []byte, setupOBIS string) error {
	out, err := d.pushFrame(network, address, setupOBIS)
	if err != nil {
		return err
	}
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = c.Write(out)
	return err
}

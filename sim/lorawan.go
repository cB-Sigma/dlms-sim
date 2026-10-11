package sim

// The meter end of the DLMS/COSEM LoRaWAN link (package lpwan) for
// tests: a simulated meter behind a LoRaWAN radio on an lpwan.MemNS
// network server, run by the dlms library's end device (package
// lpwan/enddevice).

import (
	"sync"
	"time"

	"github.com/cB-Sigma/dlms/lpwan"
	"github.com/cB-Sigma/dlms/lpwan/enddevice"
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

	mu   sync.Mutex
	dev  *enddevice.LoRaWAN
	iids [2][]byte
}

// handler serves the simulated meter to the library's end devices.
type handler struct {
	m        *Meter
	mu       sync.Mutex
	sessions map[uint16]*Session
}

func (h *handler) Serves(sap uint16) bool { return h.m.ServesWPort(sap) }

func (h *handler) Drop() { h.m.discard() }

func (h *handler) Handle(client uint16, apdu []byte) []byte {
	h.mu.Lock()
	if h.sessions == nil {
		h.sessions = map[uint16]*Session{}
	}
	s := h.sessions[client]
	if s == nil {
		s = h.m.NewSession(client)
		h.sessions[client] = s
	}
	h.mu.Unlock()
	return h.m.HandleAPDU(s, apdu)
}

// Start attaches the meter to the network server and runs it.
func (lm *LoRaWANMeter) Start() error {
	lm.Meter.Prepare()
	d := &enddevice.LoRaWAN{Handler: &handler{m: lm.Meter}, ServerAddress: lm.Meter.ServerAddress, DevEUI: lm.DevEUI,
		Settings: lm.Settings, UplinkPayload: lm.UplinkPayload, Poll: lm.Poll, NoneClient: lm.NoneClient}
	lm.mu.Lock()
	if lm.iids[0] != nil {
		d.SetIIDs(lm.iids[0], lm.iids[1])
	}
	lm.mu.Unlock()
	if err := lm.Settings.Check(); err != nil {
		return err
	}
	d.Radio = enddevice.MemRadio(lm.NS, lm.DevEUI, lm.Settings.Class)
	if err := d.Start(); err != nil {
		return err
	}
	lm.mu.Lock()
	lm.dev = d
	lm.mu.Unlock()
	return nil
}

func (lm *LoRaWANMeter) device() *enddevice.LoRaWAN {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	return lm.dev
}

// Stop stops the meter.
func (lm *LoRaWANMeter) Stop() {
	if d := lm.device(); d != nil {
		d.Stop()
	}
}

// Served is how many requests the meter answered.
func (lm *LoRaWANMeter) Served() int {
	if d := lm.device(); d != nil {
		return d.Served()
	}
	return 0
}

// Uplinks is how many SCHC messages the meter sent.
func (lm *LoRaWANMeter) Uplinks() int {
	if d := lm.device(); d != nil {
		return d.Uplinks()
	}
	return 0
}

// Push sends the data-notification of a push setup as uplinks.
func (lm *LoRaWANMeter) Push(setupOBIS string) error {
	client, apdu, err := lm.Meter.PushNotification(setupOBIS)
	if err != nil {
		return err
	}
	d := lm.device()
	if d == nil {
		return errStopped
	}
	return d.Push(client, apdu)
}

// SetIIDs sets the IPv6 interface identifiers the meter uses with header
// ipv6/udp/wrapper (the head end's defaults: EUI-64 based and ::1).
func (lm *LoRaWANMeter) SetIIDs(dev, app []byte) {
	lm.mu.Lock()
	lm.iids = [2][]byte{dev, app}
	lm.mu.Unlock()
}

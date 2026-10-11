// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package sim

// Serving the meter over a transport of the caller's own (a LoRaWAN or
// other LPWAN radio, a test harness): the caller carries the APDUs and
// the meter answers them. Listen, ListenUDP, ServeHDLC and the other
// listeners do the same for the transports this package provides.

// Prepare fills in the meter's defaults (block size, addresses, time
// zone, empty object tables). The listeners call it; a caller that
// carries APDUs itself calls it before NewSession.
func (m *Meter) Prepare() { m.prepare() }

// NewSession returns a client's session that is not yet associated: the
// client opens it with an AARQ through HandleAPDU, as over the wrapper.
// PreEstablished returns one that is open without an AARQ.
func (m *Meter) NewSession(client uint16) *Session {
	return &Session{s: session{client: client}}
}

// ServesWPort reports whether the meter answers a destination wPort: its
// logical device (ServerAddress) or the all-station address, which it
// accepts and never answers.
func (m *Meter) ServesWPort(p uint16) bool { return m.boundWPort(p) }

// PushNotification returns the data-notification APDU of a push setup
// (protected as the meter's security policy requires) and the client
// address it goes to, for a caller that delivers it itself.
func (m *Meter) PushNotification(setupOBIS string) (client uint16, apdu []byte, err error) {
	apdu, err = m.pushAPDU(setupOBIS)
	if err != nil {
		return 0, nil, err
	}
	return m.pushClient(), apdu, nil
}

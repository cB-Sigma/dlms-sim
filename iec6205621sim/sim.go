// Package iec6205621sim is an in-process IEC 62056-21 meter for tests:
// the meter of the dlms library (package iec6205621/meter), reached over
// TCP as through a transparent converter with 7E1 emulated, with its
// fault switches for tests. Its DLMS field takes a simulated meter of
// package sim (or a server of package server) for mode E.
package iec6205621sim

import (
	"github.com/cB-Sigma/dlms/iec6205621/meter"
)

// Meter is the simulated meter.
type Meter = meter.Meter

// Line is several meters on one serial line behind one converter.
type Line = meter.Line

// ModeE serves the HDLC phase of mode E.
type ModeE = meter.ModeE

// NewLine puts meters on one line.
func NewLine(meters ...*Meter) *Line { return meter.NewLine(meters...) }

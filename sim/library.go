// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package sim

// The meter on the dlms module's server package: Server builds a
// server.Server holding the meter's objects, profiles, associations and
// access rights as they are now, so the same simulated IS 15959 meter can
// be served by the library's meter side instead of the simulator's own
// (which keeps the fault injection, the data concentrator, LoRaWAN and
// the test counters).

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"gitlab.com/circutor-library/gosem/pkg/axdr"

	"github.com/cB-Sigma/dlms/classes"
	"github.com/cB-Sigma/dlms/is15959"
	"github.com/cB-Sigma/dlms/server"
)

// Server returns a server of package server with the meter's objects
// (each as a classes.Generic with every attribute the meter holds,
// writable, except the clock, profiles and disconnect control, which get
// their typed classes), its profiles with their rows, an association per
// client of its IS 15959 profile (or, without one, the public client and
// the HLS settings for client 48) and, with a profile, its access rights.
func (m *Meter) Server() (*server.Server, error) {
	m.prepare()
	m.mu.Lock()
	defer m.mu.Unlock()
	s := &server.Server{Address: m.ServerAddress, HDLCAddress: m.HDLCAddress, HDLCAddressSize: m.HDLCAddressSize,
		HDLCParams: m.HDLCParams, HDLCInactivity: m.HDLCInactivity}
	if m.BlockSize > 0 {
		s.BlockSize = m.BlockSize
	}
	generic := map[string]*classes.Generic{}
	var order []string
	for k, v := range m.objects {
		parts := strings.Split(k, "/")
		if len(parts) != 3 {
			continue
		}
		class, _ := strconv.Atoi(parts[0])
		attr, _ := strconv.Atoi(parts[2])
		obis := parts[1]
		if class == 8 && obis == "0.0.1.0.0.255" && attr == 2 {
			continue // the clock runs
		}
		gk := parts[0] + "/" + obis
		g := generic[gk]
		if g == nil {
			g = &classes.Generic{Class: uint16(class), LN: obis, Attrs: map[int8]*axdr.DlmsData{}, Writable: map[int8]bool{}}
			generic[gk] = g
			order = append(order, gk)
		}
		val := v
		g.Attrs[int8(attr)] = &val
		g.Writable[int8(attr)] = true
	}
	for _, gk := range order {
		g := generic[gk]
		switch {
		case g.Class == 8 && g.LN == "0.0.1.0.0.255":
			s.Add(&classes.Clock{LN: g.LN, Location: m.Loc})
		case g.Class == is15959.ClassDisconnect:
			d := &classes.DisconnectControl{LN: g.LN, OutputState: true, ControlState: 1, ControlMode: 4}
			if v, ok := g.Attrs[2]; ok {
				d.OutputState, _ = v.Value.(bool)
			}
			if v, ok := g.Attrs[3]; ok {
				st, _ := v.Value.(uint8)
				d.ControlState = st
			}
			if v, ok := g.Attrs[4]; ok {
				mode, _ := v.Value.(uint8)
				d.ControlMode = mode
			}
			s.Add(d)
		case g.Class == is15959.ClassProfileGeneric:
			if _, isProfile := m.profiles[g.LN]; isProfile {
				continue
			}
			s.Add(g)
		default:
			s.Add(g)
		}
	}
	if _, ok := generic["8/0.0.1.0.0.255"]; !ok {
		s.Add(&classes.Clock{LN: "0.0.1.0.0.255", Location: m.Loc})
	}
	for obis, p := range m.profiles {
		pg := &classes.ProfileGeneric{LN: obis, Location: m.Loc}
		for _, c := range p.Columns {
			pg.CaptureObjects = append(pg.CaptureObjects, classes.CaptureObject{Class: c.Class, LN: c.OBIS, Attr: c.Attr})
		}
		for _, r := range p.Rows {
			pg.Buffer = append(pg.Buffer, append([]*axdr.DlmsData(nil), r...))
		}
		if v, ok := m.objects[key(7, obis, 4)]; ok {
			if n, ok := v.Value.(uint32); ok {
				pg.CapturePeriod = n
			}
		}
		s.Add(pg)
	}
	assoc := func(client uint16, h *HLS) *server.Association {
		a := &server.Association{ClientAddress: client}
		if h == nil {
			return a
		}
		if len(h.SystemTitle) == 8 {
			s.SystemTitle = append([]byte(nil), h.SystemTitle...)
		}
		a.Mechanism, a.Secret, a.Policy, a.Suite = h.mechanism(), clone(h.Secret), h.Policy, h.Suite
		if h.Unauthenticated {
			a.Mechanism, a.Secret = 0, nil
		}
		a.Key, a.AuthKey, a.BroadcastKey = clone(h.Key), clone(h.AuthKey), clone(h.BroadcastKey)
		a.SigningKey, a.ClientKey, a.Context = h.SigningKey, h.ClientKey, h.Context
		return a
	}
	seen := map[uint16]bool{}
	add := func(a *server.Association) {
		if !seen[a.ClientAddress] {
			seen[a.ClientAddress] = true
			s.Associations = append(s.Associations, a)
		}
	}
	if m.Spec != nil {
		for _, sa := range m.Spec.Associations {
			if sa.Role == is15959.Push {
				continue
			}
			h, ok := m.ClientHLS[sa.Client]
			if !ok && sa.Client != 16 {
				h = m.HLS
			}
			if sa.Client == 16 {
				h = nil
			}
			add(assoc(sa.Client, h))
		}
		spec := m.Spec
		s.Associations = withRights(s.Associations, spec)
	} else {
		add(assoc(16, nil))
		for c, h := range m.ClientHLS {
			add(assoc(c, h))
		}
		if m.HLS != nil {
			add(assoc(48, m.HLS))
		}
		if m.Password != "" {
			add(&server.Association{ClientAddress: 32, Mechanism: 1, Secret: []byte(m.Password)})
		}
	}
	if len(s.Associations) == 0 {
		return nil, errors.New("the meter has no association to serve")
	}
	for _, a := range s.Associations {
		if (a.Policy != 0 || a.Mechanism >= 5) && len(s.SystemTitle) != 8 {
			return nil, fmt.Errorf("client %d needs the meter's system title", a.ClientAddress)
		}
	}
	return s, nil
}

// withRights gives each association the IS 15959 rights of its role.
func withRights(as []*server.Association, spec *is15959.Spec) []*server.Association {
	for _, a := range as {
		role, ok := spec.RoleOf(a.ClientAddress)
		if !ok {
			continue
		}
		a.Allow = func(class uint16, ln string, id int8, op server.Op) bool {
			want := map[server.Op]is15959.Right{server.OpRead: is15959.Read, server.OpWrite: is15959.Write, server.OpExecute: is15959.Exec}[op]
			rights, listed := spec.Access(class, ln, id, op == server.OpExecute)
			return !listed || rights.Of(role)&want != 0
		}
	}
	return as
}

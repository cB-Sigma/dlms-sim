package iec6205621sim

// Annex C formatted codes in the simulator: R2/R4 reads, W2/W4 writes
// and erases, and E2 executes over the Formatted records.

import (
	"sort"
	"strings"

	p "github.com/cB-Sigma/dlms/iec6205621"
)

// seasonMatch reports whether a season record key (code and data field,
// eight digits) is selected by a season read or erase (C.4.2.1).
func seasonMatch(key string, c p.Code, tariff, season, access int) bool {
	kc, err := p.ParseCode(key[:4])
	if err != nil || kc.Category != p.CatSeason {
		return false
	}
	kt, ks, _, err := p.ParseSeasonData(key[4:])
	if err != nil {
		return false
	}
	switch access {
	case p.AccessSingle:
		return kc.Raw == c.Raw && kt == tariff && ks == season
	case p.AccessSeasons:
		return kc.Raw == c.Raw && kt == tariff
	case p.AccessTariffs:
		return kc.Raw == c.Raw
	case p.AccessRegisters:
		return kc.Channel == c.Channel && kc.Type == c.Type
	case p.AccessTypes:
		return kc.Channel == c.Channel
	case p.AccessChannels:
		return true
	}
	return false
}

// groupMatch reports whether a register record code is selected by a
// group code's wild card bits and the data field's register code.
func groupMatch(code string, wild int, d p.Code) bool {
	kc, err := p.ParseCode(code)
	if err != nil || kc.Category != p.CatRegister {
		return false
	}
	return (wild&p.WildChannel != 0 || kc.Channel == d.Channel) && (wild&p.WildType != 0 || kc.Type == d.Type) &&
		(wild&p.WildRegister != 0 || kc.Register == d.Register) && (wild&p.WildTariff != 0 || kc.Tariff == d.Tariff)
}

// selected returns the keys of the Formatted records a code and data
// field select, sorted, and whether the code is one the meter serves.
// Under m.mu.
func (m *Meter) selected(code, data string) ([]string, bool) {
	c, err := p.ParseCode(code)
	if err != nil || !c.Readable() {
		return nil, false
	}
	var keys []string
	switch c.Category {
	case p.CatSeason:
		t, s, a, err := p.ParseSeasonData(data)
		if err != nil {
			return nil, false
		}
		for k := range m.Formatted {
			if len(k) == 8 && seasonMatch(k, c, t, s, a) {
				keys = append(keys, k)
			}
		}
	case p.CatGroup:
		d, err := p.ParseCode(data)
		if c.Access != p.GroupWildcards || err != nil {
			return nil, false
		}
		for k := range m.Formatted {
			if len(k) == 4 && groupMatch(k, c.Wild, d) {
				keys = append(keys, k)
			}
		}
	default:
		if _, ok := m.Formatted[code]; ok {
			keys = append(keys, code)
		}
	}
	sort.Strings(keys)
	return keys, true
}

// formattedAnswer builds the data lines answering R2/R4 code(data): a
// season record's ID is its code and data field (the command's access
// nibble kept), and only the first record of each code carries the code
// (C.4.2.1). errCode is set when there is no answer.
func (m *Meter) formattedAnswer(code, data string) (lines []string, errCode string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	keys, ok := m.selected(code, data)
	if !ok {
		return nil, "(ER06)"
	}
	if len(keys) == 0 {
		return nil, "(ER03)"
	}
	c, _ := p.ParseCode(code)
	if c.Category == p.CatLoadProfile {
		m.profiles = append(m.profiles, code+"("+data+")")
		return strings.Split(m.Formatted[code], "\r\n"), ""
	}
	_, _, access, _ := p.ParseSeasonData(data)
	last := ""
	for _, k := range keys {
		id := k
		if len(k) == 8 {
			t, s, _, _ := p.ParseSeasonData(k[4:])
			d := p.SeasonData(t, s, access)
			id = k[:4] + d
			if k[:4] == last {
				id = d
			}
			last = k[:4]
		}
		lines = append(lines, id+"("+m.Formatted[k]+")")
	}
	return lines, ""
}

// formattedWrite applies W2/W4 code(value): a register, variable,
// parameter or manufacturer record is set (an empty value resets it to
// 0); in the season, group and load profile categories the write erases
// what a read would select (C.3).
func (m *Meter) formattedWrite(code, value string) (errCode string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, err := p.ParseCode(code)
	if err != nil || !c.Writable() {
		return "(ER06)"
	}
	if m.RefuseWrites {
		return "(ER04)"
	}
	if c.Erases() {
		keys, ok := m.selected(code, value)
		if !ok {
			return "(ER02)"
		}
		for _, k := range keys {
			delete(m.Formatted, k)
		}
		m.writes = append(m.writes, "erase "+code+"("+value+")")
		return ""
	}
	if value == "" {
		value = "0"
	}
	m.Formatted[code] = value
	m.writes = append(m.writes, code+"("+value+")")
	return ""
}

// executeReadouts maps the E2 0000 data field to the categories of each
// readout (C.5.1).
var executeReadouts = map[string][]p.Category{
	"0000": {p.CatRegister, p.CatSeason, p.CatLoadProfile},
	"0001": {p.CatRegister, p.CatSeason},
	"0002": {p.CatRegister},
	"0003": {p.CatSeason},
	"0004": {p.CatLoadProfile},
	"0005": {p.CatVariable},
	"0006": {p.CatParameter},
}

// execute answers E2 code(data): the readouts of code 0000 give a data
// message; other execute and manufacturer-specific codes are carried out
// (recorded) and acknowledged.
func (m *Meter) execute(code, data string) (lines []string, ack bool, errCode string) {
	if !p.ValidExecute(code) {
		return nil, false, "(ER07)"
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.executes = append(m.executes, code+"("+data+")")
	if code != "0000" {
		return nil, true, ""
	}
	cats, ok := executeReadouts[data]
	if !ok {
		return nil, false, "(ER08)"
	}
	want := map[p.Category]bool{}
	for _, c := range cats {
		want[c] = true
	}
	var keys []string
	for k := range m.Formatted {
		if c, err := p.ParseCode(k[:4]); err == nil && want[c.Category] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		lines = append(lines, k+"("+m.Formatted[k]+")")
	}
	return lines, false, ""
}

package sim

// Load profile values of the simulated IS 15959 meter that agree with its
// instantaneous registers, as a real meter's do: a block's average
// voltage and current are what the meter measures, a block's energy is
// what the measured power gives over the block, and a daily row's
// cumulative energy runs up to the register's present value. Each value
// is converted between the registers' own scaler_units, so a register
// reported with another scaler than its instantaneous counterpart still
// reads the same quantity.

import (
	"math"
	"strconv"
	"strings"
	"time"

	"gitlab.com/circutor-library/gosem/pkg/axdr"

	"github.com/cB-Sigma/dlms/is15959"
)

// Recapture rebuilds the meter's periodic load profiles and its scaler
// profiles from the present register values, as if the load had been
// steady, with the newest entry the last whole period before now. A
// simulation whose instantaneous values move calls it so the profiles
// follow them, and so new entries appear as time passes.
func (m *Meter) Recapture(now time.Time) {
	if m.Spec == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	rows := m.profileRows
	if rows == 0 {
		rows = 4
	}
	if m.profiles == nil {
		m.profiles = map[string]*Profile{}
	}
	// Scaler profiles first: they hold the registers' scaler_units the
	// profiles below are converted with.
	for _, p := range m.Spec.Profiles {
		if scalerBuffer(p) {
			m.profiles[p.OBIS] = m.buildProfile(p, now, rows)
		}
	}
	for _, p := range m.Spec.Profiles {
		if p.Period > 0 {
			m.profiles[p.OBIS] = m.buildProfile(p, now, rows)
		}
	}
}

// obisCD is an OBIS code's value groups C (quantity) and D (processing).
func obisCD(obis string) (c, d int, ok bool) {
	f := strings.Split(obis, ".")
	if len(f) != 6 || f[0] != "1" {
		return 0, 0, false
	}
	c, err1 := strconv.Atoi(f[2])
	d, err2 := strconv.Atoi(f[3])
	return c, d, err1 == nil && err2 == nil
}

// withD is obis with value group D replaced.
func withD(obis string, d int) string {
	f := strings.Split(obis, ".")
	f[3] = strconv.Itoa(d)
	return strings.Join(f, ".")
}

// scalerOf is a register's scaler (0 when it has none).
func (m *Meter) scalerOf(obis string) int {
	v, ok := m.objects[key(is15959.ClassRegister, obis, is15959.ScalerAttr(is15959.ClassRegister))]
	if !ok {
		return 0
	}
	f, _ := v.Value.([]*axdr.DlmsData)
	if len(f) == 0 {
		return 0
	}
	s, _ := f[0].Value.(int8)
	return int(s)
}

// quantity is a register's value times 10^scaler.
func (m *Meter) quantity(obis string) (float64, bool) {
	v, ok := m.objects[key(is15959.ClassRegister, obis, 2)]
	if !ok {
		return 0, false
	}
	n, ok := numeric(v)
	if !ok {
		return 0, false
	}
	return n * math.Pow10(m.scalerOf(obis)), true
}

// power is the measured power that feeds an energy quantity C (active
// import 1 from 1.7, apparent import 9 from 9.7, net 16 from 1.7); 0 for
// export and reactive energy, which a household meter does not see here.
func (m *Meter) power(c int) float64 {
	src := map[int]string{1: "1.0.1.7.0.255", 9: "1.0.9.7.0.255", 16: "1.0.1.7.0.255"}[c]
	if src == "" {
		return 0
	}
	p, _ := m.quantity(src)
	return math.Max(p, 0)
}

// periodCell is the value of a register column of a periodic profile at
// entry time at (entry k, counted from 1), derived from the instantaneous
// registers; nil for columns it does not derive.
func (m *Meter) periodCell(col is15959.Column, at, now time.Time, period time.Duration, k int) *axdr.DlmsData {
	if col.Class != is15959.ClassRegister || col.Attr != 2 {
		return nil
	}
	c, d, ok := obisCD(col.OBIS)
	if !ok {
		return nil
	}
	wave := math.Sin(float64(k) * 0.7)
	var q float64
	switch d {
	case 27: // the average over the period of what C.7 measures
		inst, ok := m.quantity(withD(col.OBIS, 7))
		if !ok {
			return nil
		}
		amp := 0.08 // currents and powers move with the load
		switch c {
		case 12, 32, 52, 72, 14: // voltages and frequency hardly do
			amp = 0.003
		}
		q = inst * (1 + amp*wave)
	case 29: // the energy of one period
		q = m.power(c) * period.Hours() * (1 + 0.08*wave)
	case 8: // cumulative energy at the entry's time
		reg, ok := m.quantity(col.OBIS)
		if !ok {
			return nil
		}
		q = math.Max(reg-m.power(c)*now.Sub(at).Hours(), 0)
	default:
		return nil
	}
	return m.registerValue(col.OBIS, q)
}

// registerValue is quantity q as a raw value of the register's type and
// scaler.
func (m *Meter) registerValue(obis string, q float64) *axdr.DlmsData {
	raw := math.Round(q / math.Pow10(m.scalerOf(obis)))
	clamp := func(lo, hi float64) float64 { return math.Min(math.Max(raw, lo), hi) }
	tmpl, ok := m.objects[key(is15959.ClassRegister, obis, 2)]
	if !ok {
		return axdr.CreateAxdrDoubleLongUnsigned(uint32(clamp(0, math.MaxUint32)))
	}
	switch tmpl.Value.(type) {
	case uint8:
		return axdr.CreateAxdrUnsigned(uint8(clamp(0, math.MaxUint8)))
	case int8:
		return axdr.CreateAxdrInteger(int8(clamp(math.MinInt8, math.MaxInt8)))
	case uint16:
		return axdr.CreateAxdrLongUnsigned(uint16(clamp(0, math.MaxUint16)))
	case int16:
		return axdr.CreateAxdrLong(int16(clamp(math.MinInt16, math.MaxInt16)))
	case int32:
		return axdr.CreateAxdrDoubleLong(int32(clamp(math.MinInt32, math.MaxInt32)))
	case uint64:
		return axdr.CreateAxdrLong64Unsigned(uint64(clamp(0, math.MaxUint32)))
	case int64:
		return axdr.CreateAxdrLong64(int64(clamp(math.MinInt32, math.MaxInt32)))
	}
	return axdr.CreateAxdrDoubleLongUnsigned(uint32(clamp(0, math.MaxUint32)))
}

// keepLastAverages sets each average register (D = 27) a profile captures
// to its newest entry, as a meter's register holds the last period's
// average.
func (m *Meter) keepLastAverages(p is15959.Profile, pr *Profile) {
	if len(pr.Rows) == 0 {
		return
	}
	last := pr.Rows[len(pr.Rows)-1]
	for j, c := range p.Capture {
		if _, d, ok := obisCD(c.OBIS); ok && d == 27 && c.Class == is15959.ClassRegister && c.Attr == 2 && last[j] != nil {
			if m.objects == nil {
				m.objects = map[string]axdr.DlmsData{}
			}
			m.objects[key(c.Class, c.OBIS, 2)] = *last[j]
		}
	}
}

// numeric is a number's value.
func numeric(d axdr.DlmsData) (float64, bool) {
	switch v := d.Value.(type) {
	case uint8:
		return float64(v), true
	case int8:
		return float64(v), true
	case uint16:
		return float64(v), true
	case int16:
		return float64(v), true
	case uint32:
		return float64(v), true
	case int32:
		return float64(v), true
	case uint64:
		return float64(v), true
	case int64:
		return float64(v), true
	case float32:
		return float64(v), true
	case float64:
		return v, true
	}
	return 0, false
}

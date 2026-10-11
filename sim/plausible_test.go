package sim

import (
	"testing"

	"gitlab.com/circutor-library/gosem/pkg/axdr"

	"github.com/cB-Sigma/dlms/is15959"
)

// The simulated meter's registers read like a household meter's (demand
// within its 10-60 A rating, a dozen billings, a month's energy), not
// stepped placeholder counters.
//
// Covers: SIG-WEB-3319
func TestPlausibleRegisterValues(t *testing.T) {
	num := func(d *axdr.DlmsData) float64 {
		switch v := d.Value.(type) {
		case uint32:
			return float64(v)
		case uint16:
			return float64(v)
		case uint8:
			return float64(v)
		case int32:
			return float64(v)
		case uint64:
			return float64(v)
		}
		t.Fatalf("value %T", d.Value)
		return 0
	}
	cases := []struct {
		name, typ string
		lo, hi    float64
	}{
		{"maxDemandActive", "double-long-unsigned", 1000, 13800}, // W: up to 60 A at 230 V
		{"maxDemandActiveT3", "double-long-unsigned", 1000, 13800},
		{"billingCount", "double-long-unsigned", 1, 120},
		{"powerOnDurationTotal", "double-long-unsigned", 1, 10 * 525600},
		{"activeEnergyImportPeriod", "double-long-unsigned", 1000, 2000000},
		{"loadLimit", "long-unsigned", 1000, 13800},
	}
	for _, c := range cases {
		v := plausible(is15959.Object{Name: c.name, Type: c.typ})
		if v == nil {
			t.Errorf("%s: no value", c.name)
			continue
		}
		if n := num(v); n < c.lo || n > c.hi {
			t.Errorf("%s = %v, want %v to %v", c.name, n, c.lo, c.hi)
		}
	}
	if plausible(is15959.Object{Name: "voltage", Type: "long-unsigned"}) != nil {
		t.Error("a live value is left to the meter's own simulation")
	}
}

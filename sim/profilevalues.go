package sim

// Load profile values of the simulated IS 15959 meter that agree with its
// instantaneous registers, as a real meter's do (the dlms library's IS
// 15959 meter builder computes them).

import (
	"time"

	ismeter "github.com/cB-Sigma/dlms/is15959/meter"
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
	if m.profiles == nil {
		m.profiles = map[string]*Profile{}
	}
	ismeter.Recapture(store{m}, m.Spec, m.profileRows, now, m.Loc)
}

package network

import (
	"encoding/json"

	"netmon/internal/observation"
)

// The existing small per-IP evidence object also stores traffic-class totals.
// Old evidence has no traffic member and is explicitly attributed to UNKNOWN.
type ipState struct {
	observation.Evidence
	Traffic     *observation.Traffic     `json:"traffic,omitempty"`
	Correlation *observation.Correlation `json:"correlation,omitempty"`
}

func marshalIPState(e observation.Evidence, t observation.Traffic, correlation ...*observation.Correlation) []byte {
	var c *observation.Correlation
	if len(correlation) > 0 {
		c = correlation[0]
	}
	raw, _ := json.Marshal(ipState{Evidence: e, Traffic: &t, Correlation: c})
	return raw
}

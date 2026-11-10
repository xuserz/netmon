package observation

import (
	"math"
	"time"
)

type Correlation struct {
	ID     string `json:"incident_id"`
	Score  int    `json:"severity"`
	At     int64  `json:"at"`
	Reason string `json:"reason"`
}

func (c *Correlation) Priority(p Policy) float64 {
	if c == nil || c.Score <= 0 {
		return -1e30
	}
	return math.Log(float64(c.Score)) + math.Ln2*float64(c.At)/float64(p.HalfLifeSeconds)
}
func (c *Correlation) Decay(p Policy, now time.Time) int {
	if c == nil {
		return 0
	}
	age := max(int64(0), now.Unix()-c.At)
	return max(0, min(100, int(math.Round(float64(c.Score)*math.Exp(-math.Ln2*float64(age)/float64(p.HalfLifeSeconds))))))
}

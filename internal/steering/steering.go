// Package steering decides how hard each node should lean away from traffic.
//
// Capacity already weights the fabric: a node half the size of the largest
// announces with one more AS-path prepend. That is static. This package adds
// the part that reacts to what is actually happening — a node measured near
// its packet-rate ceiling is padded further so the next-closest node takes
// the overflow, and is unpadded again once it recovers.
//
// Two things keep that from becoming a liability. The watermarks leave a wide
// band in the middle where nothing moves, so a node hovering at its threshold
// does not oscillate. And a level holds for MinDwell whatever the load does,
// because BGP punishes churn: upstreams damp a route that flaps, and a damped
// route is worse than a saturated node.
package steering

import (
	"fmt"
	"sync"
	"time"
)

const (
	// HighWatermark is the share of a node's packet-rate ceiling at which it
	// starts shedding traffic to its neighbours.
	HighWatermark = 0.80
	// LowWatermark is where it starts taking traffic back. The gap up to
	// HighWatermark is the hysteresis band: inside it nothing moves.
	LowWatermark = 0.50
	// MinDwell is the shortest time between two changes to one node's
	// padding, so load that crosses a watermark repeatedly cannot turn into
	// a stream of BGP updates.
	MinDwell = 30 * time.Second
	// MaxEscalation bounds how far load alone can pad a node, on top of
	// whatever its capacity already earns it.
	MaxEscalation = 3
	// ReportFreshness is how recent a node's counters must be to steer on.
	// Older than this and the node's level is held where it is: acting on a
	// stale measurement is worse than not acting.
	ReportFreshness = 15 * time.Second
)

// Sample is one node's measured load for one round of the control loop.
type Sample struct {
	NodeID string
	// OfferedPPS is the node's measured packet rate, averaged over its own
	// load window. A total would be useless here: the question is what the
	// node is carrying now, not since it started.
	OfferedPPS uint64
	// CapacityPPS is the ceiling to compare against. Zero means unknown, and
	// a node with an unknown ceiling is never padded for load.
	CapacityPPS int64
	// Fresh is whether the measurement is recent enough to act on.
	Fresh bool
}

// Level is one node's current load-driven padding and why it holds.
type Level struct {
	Prepends  int       `json:"prepends"`
	Ratio     float64   `json:"ratio"`
	Reason    string    `json:"reason"`
	ChangedAt time.Time `json:"changed_at"`
}

// Controller tracks each node's padding across rounds. The levels are derived
// state: losing them on a restart costs one control loop, not correctness.
type Controller struct {
	mu     sync.Mutex
	levels map[string]*Level
	now    func() time.Time
}

func New() *Controller {
	return &Controller{levels: map[string]*Level{}, now: time.Now}
}

// SetClock replaces the time source, so tests can step past MinDwell without
// sleeping.
func (c *Controller) SetClock(now func() time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = now
}

func (c *Controller) clock() time.Time {
	if c.now == nil {
		return time.Now()
	}
	return c.now()
}

// Observe folds one round of measurements in and returns the extra prepends
// each node should carry. Nodes absent from samples are forgotten, so the
// table stays bounded by the fleet.
func (c *Controller) Observe(samples []Sample) map[string]int {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.clock()

	next := make(map[string]*Level, len(samples))
	out := make(map[string]int, len(samples))
	for _, s := range samples {
		level := c.levels[s.NodeID]
		if level == nil {
			// ChangedAt stays zero: dwell exists to stop a level churning, not
			// to delay the first move, so a node that shows up already
			// saturated can shed on its first round.
			level = &Level{Reason: "no load measured yet"}
		}
		cp := *level
		next[s.NodeID] = &cp
		apply(&cp, s, now)
		out[s.NodeID] = cp.Prepends
	}
	c.levels = next
	return out
}

// apply moves one node's level at most one step, and only when it has held
// long enough.
func apply(level *Level, s Sample, now time.Time) {
	if !s.Fresh {
		level.Reason = "holding: no recent counters from this node"
		return
	}
	if s.CapacityPPS <= 0 {
		level.Ratio = 0
		level.Reason = "holding: node reports no packet-rate capacity to measure against"
		return
	}

	level.Ratio = float64(s.OfferedPPS) / float64(s.CapacityPPS)
	want := level.Prepends
	switch {
	case level.Ratio >= HighWatermark:
		want++
	case level.Ratio <= LowWatermark:
		want--
	}
	if want > MaxEscalation {
		want = MaxEscalation
	}
	if want < 0 {
		want = 0
	}

	if want == level.Prepends {
		level.Reason = holdReason(level.Ratio, level.Prepends)
		return
	}
	// BGP churn is expensive, so a level that changed recently stays put even
	// though the load says otherwise.
	if now.Sub(level.ChangedAt) < MinDwell {
		level.Reason = fmt.Sprintf("holding %d: load is %.0f%% but the level changed less than %s ago",
			level.Prepends, level.Ratio*100, MinDwell)
		return
	}
	if want > level.Prepends {
		level.Reason = fmt.Sprintf("shedding: load is %.0f%% of capacity, above the %.0f%% mark",
			level.Ratio*100, HighWatermark*100)
	} else {
		level.Reason = fmt.Sprintf("recovering: load is %.0f%% of capacity, below the %.0f%% mark",
			level.Ratio*100, LowWatermark*100)
	}
	level.Prepends = want
	level.ChangedAt = now
}

func holdReason(ratio float64, prepends int) string {
	if prepends == 0 {
		return fmt.Sprintf("load is %.0f%% of capacity, inside the band", ratio*100)
	}
	return fmt.Sprintf("holding %d: load is %.0f%% of capacity", prepends, ratio*100)
}

// Levels copies the current table out for metrics and for the operator.
func (c *Controller) Levels() map[string]Level {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]Level, len(c.levels))
	for id, l := range c.levels {
		out[id] = *l
	}
	return out
}

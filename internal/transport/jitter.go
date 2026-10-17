package transport

import (
	"crypto/rand"
	"math/big"
	"time"
)

// JitterFraction is how far a cadence is spread either side of its nominal
// interval. Enough that an attacker cannot phase-lock to it; not so much
// that the interval stops meaning anything.
const JitterFraction = 0.2

// Jitter spreads an interval randomly within ±JitterFraction.
//
// Every repeating cadence in a scrubbing fabric is a schedule an attacker
// can learn. A burst timed to land in the gap between two samples, and to
// stop before the next one, is measured as nothing at all — and a fleet
// that polls in lockstep hands out that schedule for free, identically on
// every node. Spreading each cadence means a burst train tuned to one
// interval drifts into the next sample instead of hiding between them, and
// no two nodes are blind at the same moment.
//
// The spread is drawn from the system's source rather than a seeded
// generator: a deterministic schedule is the thing being avoided, and one
// recovered from a node's start time would be no better than a fixed one.
func Jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	span := int64(float64(d) * JitterFraction)
	if span <= 0 {
		return d
	}
	// A value in [-span, +span].
	offset, err := rand.Int(rand.Reader, big.NewInt(2*span+1))
	if err != nil {
		// The system's entropy source failing is not a reason to stop
		// polling; it is a reason to lose the jitter.
		return d
	}
	out := d + time.Duration(offset.Int64()-span)
	if out <= 0 {
		return d
	}
	return out
}

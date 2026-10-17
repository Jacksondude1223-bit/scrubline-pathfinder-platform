package transport

import (
	"testing"
	"time"
)

// A fixed cadence is a schedule an attacker can learn.
func TestJitterSpreadsWithinBounds(t *testing.T) {
	const nominal = 2 * time.Second
	span := time.Duration(float64(nominal) * JitterFraction)
	seen := map[time.Duration]bool{}
	for i := 0; i < 500; i++ {
		got := Jitter(nominal)
		if got < nominal-span || got > nominal+span {
			t.Fatalf("jittered interval %v is outside ±%v of %v", got, span, nominal)
		}
		if got <= 0 {
			t.Fatalf("jitter produced a non-positive interval %v", got)
		}
		seen[got] = true
	}
	// It has to actually vary, or it is a fixed cadence with extra steps.
	if len(seen) < 50 {
		t.Fatalf("jitter produced only %d distinct intervals across 500 draws", len(seen))
	}
}

// Two nodes must not be blind at the same moment.
func TestJitterDiffersBetweenCallers(t *testing.T) {
	const nominal = 5 * time.Second
	var matches int
	for i := 0; i < 200; i++ {
		if Jitter(nominal) == Jitter(nominal) {
			matches++
		}
	}
	if matches > 20 {
		t.Fatalf("two draws agreed %d times in 200; the cadence is not being spread", matches)
	}
}

func TestJitterLeavesDegenerateIntervalsAlone(t *testing.T) {
	for _, d := range []time.Duration{0, -time.Second, time.Nanosecond} {
		if got := Jitter(d); got != d {
			t.Fatalf("Jitter(%v) = %v, expected it left alone", d, got)
		}
	}
}

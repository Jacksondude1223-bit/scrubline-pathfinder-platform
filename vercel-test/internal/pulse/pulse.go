// Package pulse recognises burst attacks, and keeps mitigation engaged
// through the gaps between bursts.
//
// A pulse attack sends short, heavy bursts on a repeating interval instead
// of a steady flood. It beats a volumetric threshold twice over. The average
// stays low, so a mean-based measurement never crosses a watermark: one
// second at five times capacity every twenty seconds averages to a quarter
// of capacity. And the burst is over before mitigation engages, so a
// defence that reacts to load and then relaxes when load falls spends the
// attack chasing its own tail — which is the behaviour the attacker is
// actually paying for.
//
// Two things here answer that. Traffic is measured at a resolution short
// enough to see a burst, and judged on its shape — peak against mean, and
// how much of the time the line is quiet — rather than its average. And a
// recognised pulse train latches: once a prefix is known to be under one,
// it stays flagged across the quiet stretches, so nothing disengages
// between bursts and the attacker's interval buys them nothing.
package pulse

import (
	"sync"
	"time"
)

const (
	// Resolution is how finely traffic is bucketed. A pulse attack's bursts
	// are commonly well under a second, and a measurement coarser than the
	// burst averages it away — which is the blindness being fixed.
	Resolution = 250 * time.Millisecond
	// Horizon is how far back the shape is judged over. It has to span
	// several inter-burst gaps for a train to be distinguishable from one
	// busy moment.
	Horizon = 60 * time.Second
	// buckets covers Horizon at Resolution.
	buckets = int(Horizon / Resolution)

	// MinBursts is how many distinct bursts make a train. One burst is
	// ordinary: a game server has busy moments, a map change, a wave of
	// joins. A run of them separated by quiet is not.
	MinBursts = 3
	// MinCrest is the peak-to-mean ratio a pulse train shows. Steady traffic
	// sits near one however heavy it is.
	MinCrest = 4.0
	// MaxDutyCycle is the share of the horizon a pulse train is active for.
	// Above this it is simply busy traffic, not a pulse.
	MaxDutyCycle = 0.5
	// Hold is how long a recognised pulse train stays flagged after its last
	// burst. It has to outlast the gaps, or the attacker's interval is just
	// tuned to it.
	Hold = 5 * time.Minute
	// DefaultFloorPPS is how loud a burst must be to count.
	//
	// Shape alone cannot decide this. A handful of packets scattered across
	// a minute has exactly the crest factor and duty cycle of an attack —
	// sparse is sparse — so without a floor every quiet trickle reads as a
	// pulse train. The floor is what separates a burst from a lull, and it
	// belongs to the deployment: set it from what the protected service
	// actually carries.
	DefaultFloorPPS = 10_000

	// maxSeries bounds the table. Keys are protected prefixes, so this is
	// generous, but an unbounded map reachable from traffic is a
	// memory-exhaustion vector whatever its keys.
	maxSeries = 4096
)

// Assessment is what the shape of a key's traffic looks like.
type Assessment struct {
	// Pulsing is true while a burst train is recognised, including through
	// the quiet stretches between bursts.
	Pulsing bool `json:"pulsing"`
	// PeakPPS is the heaviest Resolution-length burst in the horizon,
	// expressed as a per-second rate. This is the number a mean hides.
	PeakPPS uint64 `json:"peak_pps"`
	// MeanPPS is the average across the horizon.
	MeanPPS uint64 `json:"mean_pps"`
	// Crest is PeakPPS over MeanPPS. Steady traffic sits near one.
	Crest float64 `json:"crest"`
	// DutyCycle is the share of the horizon with any traffic at all.
	DutyCycle float64 `json:"duty_cycle"`
	// Bursts is how many distinct bursts were counted in the horizon.
	Bursts int `json:"bursts"`
	// HeldFor is how much longer the flag stands without another burst.
	HeldFor time.Duration `json:"held_for"`
}

type series struct {
	// counts is a ring of Resolution-length buckets. slot holds the bucket
	// index each count belongs to, so a bucket left behind by a quiet
	// stretch is recognised as stale rather than counted again.
	counts [buckets]uint64
	slot   [buckets]int64
	// latched is when the current flag lapses, zero when nothing is flagged.
	latched time.Time
	// cached is the last assessment, recomputed at most once per bucket:
	// walking the ring per packet would cost more than the attack.
	cached    Assessment
	cachedAt  int64
	lastWrite int64
}

// Detector tracks the shape of traffic per key. A key is whatever the
// caller wants judged as one thing; the datapath keys it by protected
// prefix, because a pulse aimed at a customer is the unit that matters and
// keying by source would miss a spoofed one entirely.
type Detector struct {
	mu     sync.Mutex
	series map[string]*series
	now    func() time.Time
	// floor is how loud a burst must be to count. Zero takes the default.
	floor uint64
	// lastSweep throttles reclaiming the table to once per horizon.
	lastSweep time.Time
}

func New() *Detector {
	return &Detector{series: map[string]*series{}, now: time.Now}
}

// SetFloor sets how loud a burst must be to count. Zero restores the
// default.
func (d *Detector) SetFloor(pps uint64) {
	d.mu.Lock()
	d.floor = pps
	d.mu.Unlock()
}

func (d *Detector) burstFloor() uint64 {
	if d.floor == 0 {
		return DefaultFloorPPS
	}
	return d.floor
}

// SetClock replaces the time source, for tests.
func (d *Detector) SetClock(now func() time.Time) {
	d.mu.Lock()
	d.now = now
	d.mu.Unlock()
}

func (d *Detector) clock() time.Time {
	if d.now == nil {
		return time.Now()
	}
	return d.now()
}

// slotOf is the bucket index a moment falls in. It counts Resolution-length
// steps since the epoch, so it is monotonic and comparable across buckets.
func slotOf(t time.Time) int64 {
	return t.UnixNano() / int64(Resolution)
}

// Observe folds one packet's reported rate into a key's shape.
func (d *Detector) Observe(key string, pps uint64) {
	if key == "" {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.clock()
	s := d.seriesFor(key, now)
	if s == nil {
		return
	}
	slot := slotOf(now)
	idx := int(((slot % int64(buckets)) + int64(buckets)) % int64(buckets))
	if s.slot[idx] != slot {
		s.slot[idx] = slot
		s.counts[idx] = 0
	}
	s.counts[idx] += pps
	s.lastWrite = slot
}

// Assess reports the shape of a key's traffic. The walk over the ring runs
// at most once per bucket; between those it serves the last answer.
func (d *Detector) Assess(key string) Assessment {
	d.mu.Lock()
	defer d.mu.Unlock()
	s := d.series[key]
	if s == nil {
		return Assessment{}
	}
	return d.assess(s, d.clock())
}

func (d *Detector) assess(s *series, now time.Time) Assessment {
	slot := slotOf(now)
	if s.cachedAt == slot {
		return d.withLatch(s, now, s.cached)
	}

	oldest := slot - int64(buckets) + 1
	var peak, total uint64
	active, bursts := 0, 0
	// A burst is a run of loud buckets; the run is counted once, however
	// many buckets it spans, so one long burst is not mistaken for a train.
	inBurst := false

	// First pass for the peak, because loudness is relative to it.
	for i := 0; i < buckets; i++ {
		if s.slot[i] < oldest || s.slot[i] > slot {
			continue
		}
		if s.counts[i] > peak {
			peak = s.counts[i]
		}
	}
	// A bucket is loud if it stands out against the peak *and* clears the
	// floor. The floor is what keeps a sparse trickle, which has the same
	// shape as an attack, from reading as one.
	floor := d.burstFloor()
	loud := peak / 2
	if loud < floor {
		loud = floor
	}
	// Walk in time order so runs are contiguous.
	for step := int64(0); step < int64(buckets); step++ {
		at := oldest + step
		i := int(((at % int64(buckets)) + int64(buckets)) % int64(buckets))
		var count uint64
		if s.slot[i] == at {
			count = s.counts[i]
		}
		total += count
		if count > 0 {
			active++
		}
		switch {
		case count > 0 && count >= loud && loud > 0:
			if !inBurst {
				bursts++
				inBurst = true
			}
		default:
			inBurst = false
		}
	}

	// Both numbers are sums of the per-flow rates reported in a bucket, so
	// they are comparable with each other and with the rest of the
	// platform's pps series. Crest is a ratio, so the unit cancels.
	a := Assessment{
		PeakPPS:   peak,
		MeanPPS:   total / uint64(buckets),
		Bursts:    bursts,
		DutyCycle: float64(active) / float64(buckets),
	}
	if a.MeanPPS > 0 {
		a.Crest = float64(peak) / float64(a.MeanPPS)
	}
	shaped := a.Crest >= MinCrest && a.DutyCycle <= MaxDutyCycle && peak >= floor
	a.Pulsing = shaped && bursts >= MinBursts

	switch {
	case a.Pulsing:
		// Latch. The flag now outlasts the gaps, so nothing downstream
		// disengages between bursts.
		s.latched = now.Add(Hold)
	case shaped && bursts >= 1 && !s.latched.IsZero() && now.Before(s.latched):
		// Already flagged and still bursting, just with fewer bursts in
		// view. Staying flagged asks less than becoming flagged did, so an
		// attacker cannot stretch their interval until the hold lapses and
		// then resume for free.
		s.latched = now.Add(Hold)
	}
	s.cached = a
	s.cachedAt = slot
	return d.withLatch(s, now, a)
}

// withLatch keeps the flag up through a quiet stretch.
func (d *Detector) withLatch(s *series, now time.Time, a Assessment) Assessment {
	if s.latched.IsZero() || !now.Before(s.latched) {
		return a
	}
	a.Pulsing = true
	a.HeldFor = s.latched.Sub(now)
	return a
}

// Pulsing is the question the datapath and the steering loop actually ask.
func (d *Detector) Pulsing(key string) bool {
	return d.Assess(key).Pulsing
}

// Keys lists the tracked keys, for metrics.
func (d *Detector) Keys() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]string, 0, len(d.series))
	for k := range d.series {
		out = append(out, k)
	}
	return out
}

// Tracked reports how many keys are tracked, and the bound.
func (d *Detector) Tracked() (int, int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.series), maxSeries
}

// Forget drops keys that are no longer in the policy.
func (d *Detector) Forget(live map[string]struct{}) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for k := range d.series {
		if _, ok := live[k]; !ok {
			delete(d.series, k)
		}
	}
}

// seriesFor returns a key's series, creating it if there is room. Callers
// hold d.mu.
func (d *Detector) seriesFor(key string, now time.Time) *series {
	if d.series == nil {
		d.series = map[string]*series{}
	}
	if s, ok := d.series[key]; ok {
		return s
	}
	if len(d.series) >= maxSeries && !d.reclaim(now) {
		return nil
	}
	s := &series{}
	d.series[key] = s
	return s
}

// reclaim drops series that have seen nothing for a horizon, at most once
// per horizon: with the table full, scanning per packet would be its own
// denial of service. Callers hold d.mu.
func (d *Detector) reclaim(now time.Time) bool {
	if !d.lastSweep.IsZero() && now.Sub(d.lastSweep) < Horizon {
		return false
	}
	d.lastSweep = now
	cutoff := slotOf(now) - int64(buckets)
	for k, s := range d.series {
		if s.lastWrite < cutoff && (s.latched.IsZero() || now.After(s.latched)) {
			delete(d.series, k)
		}
	}
	return len(d.series) < maxSeries
}

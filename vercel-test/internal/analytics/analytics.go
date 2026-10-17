// Package analytics turns the datapath counters the fleet reports into the
// view a protected customer asks for: how much traffic arrived for their
// prefix, how much of it was scrubbed, when they were attacked, and what the
// attack was made of.
//
// It is a different question from the one the metrics endpoint answers.
// Metrics describe the fleet to the people running it — this node, that rule,
// this scrubber's load. A customer does not have a node; they have a prefix,
// and it is carried by every scrubber in the fabric at once. So everything
// here is keyed by prefix and summed across the fleet, and nothing in a
// customer's view names a node they do not own.
//
// The fleet reports cumulative counters, which is deliberate: a counter that
// only counts up can survive a report being missed, where a rate cannot. The
// collector deltas them into its own history, and treats a counter that went
// backwards as a node that restarted rather than as negative traffic.
//
// History is kept in memory and is not durable. It is derived from reports
// that keep arriving, so a control plane that restarts rebuilds it within a
// couple of heartbeats rather than carrying stale numbers across the gap.
package analytics

import (
	"sort"
	"sync"
	"time"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/telemetry"
)

const (
	// Resolution is how finely history is bucketed. A minute is short enough
	// to show the shape of an attack over a day and coarse enough that a
	// day's history for a prefix is kilobytes rather than megabytes.
	Resolution = time.Minute
	// Horizon is how far back history is kept.
	Horizon = 24 * time.Hour
	// buckets covers Horizon at Resolution.
	buckets = int(Horizon / Resolution)

	// MaxPrefixes bounds the number of prefixes history is kept for. Keys are
	// protected prefixes rather than anything a packet can influence, so this
	// is generous — but the table is reachable from node reports, and an
	// unbounded one is a memory-exhaustion vector whatever its keys.
	MaxPrefixes = 256
	// MaxEvents is how many attack events are kept per prefix. Past that the
	// oldest is dropped.
	MaxEvents = 128
	// MaxVectors bounds the distinct rules and filters tracked within one
	// event. An attack that trips more than this many is already described
	// well enough by the heaviest of them.
	MaxVectors = 32

	// NodeFreshness is how long a node's reported rates stand before they
	// stop counting toward the fleet total. A node that has gone quiet is
	// not still scrubbing at the rate it last reported, and leaving its
	// number in would show a customer an attack that ended.
	NodeFreshness = 30 * time.Second

	// AttackFloorPPS is how much has to be scrubbed before an event is
	// opened. Shape alone cannot decide it: a handful of dropped packets has
	// the same drop share as a flood, so without a floor every stray packet
	// against a quiet prefix would be billed to a customer as an attack.
	AttackFloorPPS = 5_000
	// AttackDropShare is how much of a prefix's traffic has to be getting
	// scrubbed for it to count as under attack, on top of the floor.
	AttackDropShare = 0.25
	// AttackSettle is how long both signals have to stay clear before an
	// event is closed. A pulse train is quiet between bursts by design, so
	// closing on the first quiet moment would record one attack as fifty.
	AttackSettle = 2 * time.Minute
)

// Scope is the protected prefixes one rule or game filter guards.
type Scope struct {
	// Prefixes the rule or filter is attributed to.
	Prefixes []string
	// Stage the rule runs at, for a customer-readable description of how the
	// traffic was stopped.
	Stage string
	// Shared marks a rule that names no destination and so guards everything
	// the policy protects. Its volume is attributed to every prefix in the
	// policy and flagged, because the alternative — attributing it to none —
	// hides the rule that is doing the work.
	Shared bool
}

// Attribution maps a node's rule and filter IDs onto what they guard. The
// control plane builds it from the compiled program, which is the only place
// that knows both the rule and the prefix list it was compiled against.
type Attribution struct {
	Rules   map[string]Scope
	Filters map[string]Scope
}

// Vector is one way traffic was stopped during an attack.
type Vector struct {
	// RuleID or FilterID, whichever stopped it.
	RuleID   string `json:"rule_id,omitempty"`
	FilterID string `json:"filter_id,omitempty"`
	Stage    string `json:"stage,omitempty"`
	// Shared is true when this rule guards the whole policy rather than this
	// prefix specifically, so its volume is not necessarily this customer's.
	Shared bool `json:"shared,omitempty"`
	// Flows dropped and the volume those flows carried.
	Flows   uint64 `json:"flows"`
	Dropped uint64 `json:"dropped"`
}

// Event is one attack against one prefix.
type Event struct {
	Prefix    string    `json:"prefix"`
	StartedAt time.Time `json:"started_at"`
	// EndedAt is absent while the attack is still running. A pointer rather
	// than a zero time: a zero time.Time serialises as year 1, and a
	// customer's dashboard should not have to know that means "ongoing".
	EndedAt *time.Time `json:"ended_at,omitempty"`
	Ongoing bool       `json:"ongoing"`
	Seconds float64    `json:"seconds"`
	// PeakPPS is the heaviest rate measured against the prefix during the
	// event, summed across the fleet. PeakDroppedPPS is how much of that was
	// being scrubbed at the worst moment.
	PeakPPS        uint64 `json:"peak_pps"`
	PeakDroppedPPS uint64 `json:"peak_dropped_pps"`
	// Dropped is the volume scrubbed over the whole event, weighted by the
	// rate each flow reported, and Flows is the count behind it.
	//
	// Both are the sum over Vectors, which is not always the same number as
	// the prefix's own dropped total: a rule that guards several prefixes at
	// once has its volume attributed to each of them. Those vectors are
	// marked Shared, and the prefix total in the summary is the figure to
	// read when the two disagree.
	Dropped uint64 `json:"dropped"`
	Flows   uint64 `json:"flows"`
	// Pulse records that the burst detector recognised a pulse train, which
	// is why mitigation stayed engaged through the quiet stretches.
	Pulse bool `json:"pulse"`
	// Vectors are the rules and filters that did the stopping, heaviest
	// first.
	Vectors []Vector `json:"vectors,omitempty"`
}

// Point is one interval of a prefix's history.
type Point struct {
	At           time.Time `json:"at"`
	Flows        uint64    `json:"flows"`
	FlowsDropped uint64    `json:"flows_dropped"`
	Offered      uint64    `json:"offered"`
	Dropped      uint64    `json:"dropped"`
	Delivered    uint64    `json:"delivered"`
	Challenged   uint64    `json:"challenged"`
	// PeakPPS, OfferedPPS and DroppedPPS are the heaviest fleet-wide rates
	// seen inside the interval, not averages over it: an average is exactly
	// what a burst attack is shaped to hide.
	PeakPPS    uint64 `json:"peak_pps"`
	OfferedPPS uint64 `json:"offered_pps"`
	DroppedPPS uint64 `json:"dropped_pps"`
	Pulsing    bool   `json:"pulsing"`
}

// Summary is a prefix's traffic over a window, and where it stands now.
type Summary struct {
	Prefix string    `json:"prefix"`
	From   time.Time `json:"from"`
	To     time.Time `json:"to"`
	// Totals over the window.
	Flows        uint64 `json:"flows"`
	FlowsDropped uint64 `json:"flows_dropped"`
	Offered      uint64 `json:"offered"`
	Dropped      uint64 `json:"dropped"`
	Delivered    uint64 `json:"delivered"`
	Challenged   uint64 `json:"challenged"`
	// MitigatedPct is the share of the offered volume that was scrubbed.
	MitigatedPct float64 `json:"mitigated_pct"`
	// PeakPPS and PeakDroppedPPS are the worst moments in the window.
	PeakPPS        uint64 `json:"peak_pps"`
	PeakDroppedPPS uint64 `json:"peak_dropped_pps"`
	// OfferedPPS and DroppedPPS are where the prefix stands right now, summed
	// across the nodes currently reporting.
	OfferedPPS uint64 `json:"offered_pps"`
	DroppedPPS uint64 `json:"dropped_pps"`
	// Nodes is how many scrubbers are currently carrying traffic for this
	// prefix. Under anycast this is the fabric absorbing the attack, so a
	// customer seeing one node during a flood is seeing a problem.
	Nodes int `json:"nodes"`
	// UnderAttack is whether an event is open right now, Attacks is how many
	// started inside the window, and AttackSeconds is how long they ran.
	UnderAttack   bool    `json:"under_attack"`
	Pulsing       bool    `json:"pulsing"`
	Attacks       int     `json:"attacks"`
	AttackSeconds float64 `json:"attack_seconds"`
}

// bucket is one Resolution-length interval of a prefix's history. minute
// records which interval it holds, so a bucket left behind by a quiet stretch
// is recognised as stale rather than counted again when the ring wraps onto
// it.
type bucket struct {
	minute       int64
	flows        uint64
	flowsDropped uint64
	offered      uint64
	dropped      uint64
	challenged   uint64
	offeredPPS   uint64
	droppedPPS   uint64
	peakPPS      uint64
	pulsing      bool
}

// gauge is one node's current reading for one prefix.
type gauge struct {
	offeredPPS uint64
	droppedPPS uint64
	peakPPS    uint64
	pulsing    bool
	at         time.Time
}

// counter is the last cumulative value seen for one node's counter, so the
// next report can be turned into a delta.
type counter struct {
	flows        uint64
	flowsDropped uint64
	offered      uint64
	dropped      uint64
	challenged   uint64
}

// delta reports how much a counter moved, treating a value that went
// backwards as a node that restarted its counters rather than as negative
// traffic.
func delta(previous, current uint64) uint64 {
	if current < previous {
		return current
	}
	return current - previous
}

type series struct {
	ring [buckets]bucket
	// gauges is the latest reading from each node carrying this prefix.
	gauges map[string]gauge
	// open is the attack currently running, or nil.
	open *Event
	// vectors accumulates the open event's attribution.
	vectors map[vectorKey]*Vector
	// clearSince is when both attack signals last went quiet, used to close
	// an event only after it has settled.
	clearSince time.Time
	// past is the closed events, oldest first.
	past []Event
}

type vectorKey struct {
	rule   string
	filter string
}

// Collector holds the fleet's reported counters as per-prefix history.
type Collector struct {
	mu     sync.Mutex
	series map[string]*series
	// prefixCounters and ruleCounters hold the last cumulative value seen
	// from each node, which is what the deltas are measured against.
	prefixCounters map[nodePrefix]counter
	ruleCounters   map[nodeRule]counter
	// nodeSeen is when each node last reported, so state for a node that has
	// gone away can be reclaimed.
	nodeSeen map[string]time.Time
	now      func() time.Time
}

type nodePrefix struct{ node, prefix string }

type nodeRule struct {
	node string
	// id is the rule or filter ID; filter marks which of the two it is, so a
	// rule and a filter sharing a name cannot collide.
	id     string
	filter bool
}

func New() *Collector {
	return &Collector{
		series:         map[string]*series{},
		prefixCounters: map[nodePrefix]counter{},
		ruleCounters:   map[nodeRule]counter{},
		nodeSeen:       map[string]time.Time{},
		now:            func() time.Time { return time.Now().UTC() },
	}
}

// SetClock replaces the time source. Tests use it to walk a day of history
// without waiting for one.
func (c *Collector) SetClock(now func() time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = now
}

func (c *Collector) clock() time.Time {
	if c.now == nil {
		return time.Now().UTC()
	}
	return c.now()
}

// minuteOf is the interval a moment falls in, counted from the epoch so it is
// monotonic and comparable across series.
func minuteOf(t time.Time) int64 {
	return t.UnixNano() / int64(Resolution)
}

// Observe folds one node's report into the history.
//
// The report is timestamped here rather than taken from the node: the fleet's
// clocks are not synchronised, and a node whose clock is wrong would otherwise
// write into the wrong hour of a customer's history.
func (c *Collector) Observe(r telemetry.Report, attr Attribution) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.clock()
	c.nodeSeen[r.NodeID] = now
	c.reclaimLocked(now)

	touched := make(map[string]bool, len(r.Stats.Prefixes))
	for _, row := range r.Stats.Prefixes {
		s := c.seriesLocked(row.Prefix)
		if s == nil {
			// At the bound. Dropping the row keeps the prefixes already
			// being tracked intact, which beats evicting a customer's
			// history to make room for one more.
			continue
		}
		touched[row.Prefix] = true

		key := nodePrefix{node: r.NodeID, prefix: row.Prefix}
		previous := c.prefixCounters[key]
		current := counter{
			flows:        row.Flows,
			flowsDropped: row.FlowsDropped,
			offered:      row.Offered,
			dropped:      row.Dropped,
		}
		c.prefixCounters[key] = current

		b := s.bucketLocked(now)
		b.flows += delta(previous.flows, current.flows)
		b.flowsDropped += delta(previous.flowsDropped, current.flowsDropped)
		b.offered += delta(previous.offered, current.offered)
		b.dropped += delta(previous.dropped, current.dropped)

		s.gauges[r.NodeID] = gauge{
			offeredPPS: row.OfferedPPS,
			droppedPPS: row.DroppedPPS,
			peakPPS:    row.PeakPPS,
			pulsing:    row.Pulsing,
			at:         now,
		}
	}

	// Challenges are counted by the game filters, not by the prefix rows, so
	// they are attributed the same way the vectors are.
	drops := c.vectorDeltasLocked(r, attr)
	for _, d := range drops {
		for _, prefix := range d.scope.Prefixes {
			s := c.series[prefix]
			if s == nil {
				continue
			}
			touched[prefix] = true
			s.bucketLocked(now).challenged += d.counts.challenged
		}
	}

	// Attack state is judged after the gauges are in, so an event opening now
	// sees this report's numbers.
	for prefix := range touched {
		c.series[prefix].judgeLocked(prefix, now)
	}
	for _, d := range drops {
		for _, prefix := range d.scope.Prefixes {
			s := c.series[prefix]
			if s == nil || s.open == nil {
				continue
			}
			s.addVector(d)
		}
	}
}

// vectorDelta is one rule's or filter's movement since the last report, with
// the prefixes it is attributed to.
type vectorDelta struct {
	key    vectorKey
	scope  Scope
	counts counter
}

// vectorDeltasLocked turns a report's rule and filter counters into deltas.
// Callers hold c.mu.
func (c *Collector) vectorDeltasLocked(r telemetry.Report, attr Attribution) []vectorDelta {
	out := make([]vectorDelta, 0, len(r.Stats.Rules)+len(r.Stats.Games))
	for _, rule := range r.Stats.Rules {
		scope, known := attr.Rules[rule.RuleID]
		if !known || len(scope.Prefixes) == 0 {
			continue
		}
		key := nodeRule{node: r.NodeID, id: rule.RuleID}
		previous := c.ruleCounters[key]
		current := counter{flowsDropped: rule.Drops, dropped: rule.PPSDropped}
		c.ruleCounters[key] = current
		moved := counter{
			flowsDropped: delta(previous.flowsDropped, current.flowsDropped),
			dropped:      delta(previous.dropped, current.dropped),
		}
		if moved.flowsDropped == 0 && moved.dropped == 0 {
			continue
		}
		if scope.Stage == "" {
			scope.Stage = string(rule.Stage)
		}
		out = append(out, vectorDelta{key: vectorKey{rule: rule.RuleID}, scope: scope, counts: moved})
	}
	for _, g := range r.Stats.Games {
		scope, known := attr.Filters[g.FilterID]
		if !known || len(scope.Prefixes) == 0 {
			continue
		}
		key := nodeRule{node: r.NodeID, id: g.FilterID, filter: true}
		previous := c.ruleCounters[key]
		current := counter{flowsDropped: g.Dropped, dropped: g.PPSDropped, challenged: g.Challenged}
		c.ruleCounters[key] = current
		moved := counter{
			flowsDropped: delta(previous.flowsDropped, current.flowsDropped),
			dropped:      delta(previous.dropped, current.dropped),
			challenged:   delta(previous.challenged, current.challenged),
		}
		if moved.flowsDropped == 0 && moved.dropped == 0 && moved.challenged == 0 {
			continue
		}
		if scope.Stage == "" {
			scope.Stage = "zc"
		}
		out = append(out, vectorDelta{key: vectorKey{filter: g.FilterID}, scope: scope, counts: moved})
	}
	return out
}

// seriesLocked returns a prefix's history, creating it if there is room.
// Callers hold c.mu.
func (c *Collector) seriesLocked(prefix string) *series {
	if prefix == "" {
		return nil
	}
	if s, ok := c.series[prefix]; ok {
		return s
	}
	if len(c.series) >= MaxPrefixes {
		return nil
	}
	s := &series{gauges: map[string]gauge{}}
	c.series[prefix] = s
	return s
}

// bucketLocked returns the interval a moment falls in, clearing it first if
// the ring has wrapped onto a stale one. Callers hold c.mu.
func (s *series) bucketLocked(now time.Time) *bucket {
	minute := minuteOf(now)
	idx := int(((minute % int64(buckets)) + int64(buckets)) % int64(buckets))
	b := &s.ring[idx]
	if b.minute != minute {
		*b = bucket{minute: minute}
	}
	return b
}

// fleet sums the current rates across the nodes still reporting. A node whose
// report has gone stale is left out: it is not still scrubbing at the rate it
// last claimed.
func (s *series) fleet(now time.Time) (offeredPPS, droppedPPS, peakPPS uint64, pulsing bool, nodes int) {
	for _, g := range s.gauges {
		if now.Sub(g.at) > NodeFreshness {
			continue
		}
		nodes++
		offeredPPS += g.offeredPPS
		droppedPPS += g.droppedPPS
		// Peaks are summed rather than maxed because under anycast a
		// distributed attack lands on every node at once. The bursts need not
		// be simultaneous, so this is an upper bound on the instantaneous
		// fabric peak rather than a measurement of it.
		peakPPS += g.peakPPS
		if g.pulsing {
			pulsing = true
		}
	}
	return offeredPPS, droppedPPS, peakPPS, pulsing, nodes
}

// judgeLocked records the fleet's current reading into the open interval and
// decides whether an attack is running. Callers hold c.mu.
func (s *series) judgeLocked(prefix string, now time.Time) {
	offeredPPS, droppedPPS, peakPPS, pulsing, _ := s.fleet(now)

	b := s.bucketLocked(now)
	// The heaviest reading inside the interval, not the latest: an attack
	// that peaks between two polls must not be averaged away.
	if offeredPPS > b.offeredPPS {
		b.offeredPPS = offeredPPS
	}
	if droppedPPS > b.droppedPPS {
		b.droppedPPS = droppedPPS
	}
	if peakPPS > b.peakPPS {
		b.peakPPS = peakPPS
	}
	if pulsing {
		b.pulsing = true
	}

	// Either signal opens an event. The drop share catches a flood being
	// scrubbed steadily; the pulse flag catches a burst train, whose average
	// is under every watermark by design.
	heavy := droppedPPS >= AttackFloorPPS && float64(droppedPPS) >= AttackDropShare*float64(offeredPPS)
	under := pulsing || heavy

	if under {
		s.clearSince = time.Time{}
		if s.open == nil {
			s.open = &Event{Prefix: prefix, StartedAt: now, Ongoing: true}
			s.vectors = map[vectorKey]*Vector{}
		}
		e := s.open
		if peakPPS > e.PeakPPS {
			e.PeakPPS = peakPPS
		}
		if droppedPPS > e.PeakDroppedPPS {
			e.PeakDroppedPPS = droppedPPS
		}
		if pulsing {
			e.Pulse = true
		}
		e.Seconds = now.Sub(e.StartedAt).Seconds()
		return
	}

	if s.open == nil {
		return
	}
	if s.clearSince.IsZero() {
		s.clearSince = now
	}
	if now.Sub(s.clearSince) < AttackSettle {
		// Still inside the settle window. A pulse train is quiet between
		// bursts, so closing here would record one attack as fifty.
		s.open.Seconds = now.Sub(s.open.StartedAt).Seconds()
		return
	}
	s.closeLocked(s.clearSince)
}

// closeLocked ends the open event at the moment the attack actually stopped,
// not at the end of the settle window. Callers hold c.mu.
func (s *series) closeLocked(at time.Time) {
	e := *s.open
	e.Ongoing = false
	ended := at
	e.EndedAt = &ended
	e.Seconds = at.Sub(e.StartedAt).Seconds()
	if e.Seconds < 0 {
		e.Seconds = 0
	}
	e.Vectors = renderVectors(s.vectors)
	s.past = append(s.past, e)
	if len(s.past) > MaxEvents {
		s.past = s.past[len(s.past)-MaxEvents:]
	}
	s.open = nil
	s.vectors = nil
	s.clearSince = time.Time{}
}

// addVector folds one rule's or filter's movement into the open event.
func (s *series) addVector(d vectorDelta) {
	v, ok := s.vectors[d.key]
	if !ok {
		if len(s.vectors) >= MaxVectors {
			return
		}
		v = &Vector{
			RuleID:   d.key.rule,
			FilterID: d.key.filter,
			Stage:    d.scope.Stage,
			Shared:   d.scope.Shared,
		}
		s.vectors[d.key] = v
	}
	v.Flows += d.counts.flowsDropped
	v.Dropped += d.counts.dropped
	s.open.Flows += d.counts.flowsDropped
	s.open.Dropped += d.counts.dropped
}

// renderVectors orders an event's attribution, heaviest first.
func renderVectors(in map[vectorKey]*Vector) []Vector {
	out := make([]Vector, 0, len(in))
	for _, v := range in {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Dropped != out[j].Dropped {
			return out[i].Dropped > out[j].Dropped
		}
		if out[i].RuleID != out[j].RuleID {
			return out[i].RuleID < out[j].RuleID
		}
		return out[i].FilterID < out[j].FilterID
	})
	return out
}

// reclaimLocked drops per-node state for nodes that have stopped reporting,
// so the delta bookkeeping stays bounded by the live fleet rather than by
// every node that ever existed. Callers hold c.mu.
func (c *Collector) reclaimLocked(now time.Time) {
	for node, seen := range c.nodeSeen {
		// Well past freshness: the node is not coming back with counters that
		// continue from where these left off.
		if now.Sub(seen) <= 10*NodeFreshness {
			continue
		}
		delete(c.nodeSeen, node)
		for key := range c.prefixCounters {
			if key.node == node {
				delete(c.prefixCounters, key)
			}
		}
		for key := range c.ruleCounters {
			if key.node == node {
				delete(c.ruleCounters, key)
			}
		}
		for _, s := range c.series {
			delete(s.gauges, node)
		}
	}
}

// Forget drops history for prefixes the fabric no longer protects. A customer
// whose policy was withdrawn stops being accounted rather than sitting at the
// numbers they had when it was.
func (c *Collector) Forget(live map[string]struct{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for prefix := range c.series {
		if _, still := live[prefix]; still {
			continue
		}
		delete(c.series, prefix)
		for key := range c.prefixCounters {
			if key.prefix == prefix {
				delete(c.prefixCounters, key)
			}
		}
	}
}

// Prefixes lists the prefixes history is held for.
func (c *Collector) Prefixes() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, 0, len(c.series))
	for prefix := range c.series {
		out = append(out, prefix)
	}
	sort.Strings(out)
	return out
}

// window clamps a requested span to what is actually kept.
func window(d time.Duration) time.Duration {
	if d <= 0 {
		return Horizon
	}
	if d > Horizon {
		return Horizon
	}
	return d
}

// Summary reports a prefix's traffic over the window, and where it stands now.
func (c *Collector) Summary(prefix string, span time.Duration) Summary {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.summaryLocked(prefix, span)
}

func (c *Collector) summaryLocked(prefix string, span time.Duration) Summary {
	now := c.clock()
	span = window(span)
	out := Summary{Prefix: prefix, From: now.Add(-span).Truncate(Resolution), To: now}
	s := c.series[prefix]
	if s == nil {
		return out
	}

	first := minuteOf(now) - int64(span/Resolution) + 1
	for i := range s.ring {
		b := &s.ring[i]
		if b.minute < first || b.minute > minuteOf(now) {
			continue
		}
		out.Flows += b.flows
		out.FlowsDropped += b.flowsDropped
		out.Offered += b.offered
		out.Dropped += b.dropped
		out.Challenged += b.challenged
		if b.peakPPS > out.PeakPPS {
			out.PeakPPS = b.peakPPS
		}
		if b.droppedPPS > out.PeakDroppedPPS {
			out.PeakDroppedPPS = b.droppedPPS
		}
		if b.pulsing {
			out.Pulsing = true
		}
	}
	// Delivered is what reached the customer. It is a subtraction rather than
	// its own counter because the datapath only knows what it stopped.
	if out.Offered > out.Dropped {
		out.Delivered = out.Offered - out.Dropped
	}
	if out.Offered > 0 {
		out.MitigatedPct = 100 * float64(out.Dropped) / float64(out.Offered)
	}

	out.OfferedPPS, out.DroppedPPS, _, _, out.Nodes = s.fleet(now)
	out.UnderAttack = s.open != nil
	for _, e := range c.eventsLocked(prefix, span) {
		out.Attacks++
		out.AttackSeconds += e.Seconds
	}
	return out
}

// Series reports a prefix's history as points of the requested step. A step
// shorter than Resolution is rounded up to it, because nothing finer is kept.
func (c *Collector) Series(prefix string, span, step time.Duration) []Point {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.clock()
	span = window(span)
	if step < Resolution {
		step = Resolution
	}
	// Whole intervals only, so a point never covers part of a bucket.
	per := int64(step / Resolution)
	if per < 1 {
		per = 1
	}

	s := c.series[prefix]
	last := minuteOf(now)
	first := last - int64(span/Resolution) + 1
	// Align to the step so the same moment always lands in the same point,
	// which is what makes two consecutive reads of a dashboard comparable.
	first -= ((first % per) + per) % per

	out := make([]Point, 0, (last-first)/per+1)
	for start := first; start <= last; start += per {
		p := Point{At: time.Unix(0, start*int64(Resolution)).UTC()}
		if s != nil {
			for minute := start; minute < start+per && minute <= last; minute++ {
				idx := int(((minute % int64(buckets)) + int64(buckets)) % int64(buckets))
				b := &s.ring[idx]
				if b.minute != minute {
					continue
				}
				p.Flows += b.flows
				p.FlowsDropped += b.flowsDropped
				p.Offered += b.offered
				p.Dropped += b.dropped
				p.Challenged += b.challenged
				if b.peakPPS > p.PeakPPS {
					p.PeakPPS = b.peakPPS
				}
				if b.offeredPPS > p.OfferedPPS {
					p.OfferedPPS = b.offeredPPS
				}
				if b.droppedPPS > p.DroppedPPS {
					p.DroppedPPS = b.droppedPPS
				}
				if b.pulsing {
					p.Pulsing = true
				}
			}
		}
		if p.Offered > p.Dropped {
			p.Delivered = p.Offered - p.Dropped
		}
		out = append(out, p)
	}
	return out
}

// Events lists the attacks against a prefix that overlap the window, newest
// first. An attack still running is included, with Ongoing set.
func (c *Collector) Events(prefix string, span time.Duration) []Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.eventsLocked(prefix, window(span))
}

func (c *Collector) eventsLocked(prefix string, span time.Duration) []Event {
	s := c.series[prefix]
	if s == nil {
		return nil
	}
	now := c.clock()
	cutoff := now.Add(-span)
	out := make([]Event, 0, len(s.past)+1)
	if s.open != nil {
		e := *s.open
		e.Seconds = now.Sub(e.StartedAt).Seconds()
		e.Vectors = renderVectors(s.vectors)
		out = append(out, e)
	}
	for i := len(s.past) - 1; i >= 0; i-- {
		// Overlap, not containment: an attack that started before the window
		// and ran into it is one the customer was under during the window.
		if s.past[i].EndedAt != nil && s.past[i].EndedAt.Before(cutoff) {
			continue
		}
		out = append(out, s.past[i])
	}
	return out
}

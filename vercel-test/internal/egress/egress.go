// Package egress confirms a client by watching what the protected service
// sends back to it.
//
// Every other gate in this fabric reasons about the packets arriving. That is
// the hard direction: a source address on an inbound packet is written by
// whoever sent it, so proving anything about it needs a round trip the
// attacker cannot fake — a challenge the client has to echo, which only works
// for protocols that define one.
//
// Return traffic is different evidence, and it needs no protocol knowledge at
// all. If the origin is sending a stream of packets to an address, the origin
// has decided that address is a peer worth answering. Whatever the protocol
// is, whatever its handshake looks like, the service itself has vouched for
// the client. That is available for a game nobody has written a dissector
// for, and for a protocol that has no challenge to issue.
//
// # What it is not
//
// It is weaker than a challenge, and the hierarchy matters. A challenge
// proves the address can receive, because the client echoed something only a
// reply to that address could have taught it. Return traffic proves the
// origin is talking to the address — which an attacker can arrange by
// spoofing a victim's address into the service and letting it answer. So this
// confirms "the service considers this a client", not "this address is real".
//
// # Asymmetric paths
//
// Some deployments never route the return path through the scrubber at all:
// with direct server return the origin answers the client straight out, and
// there is nothing here to see. A prefix that has shown ingress and no egress
// is assumed to be one of those, and everything that depends on return
// traffic quietly stops applying to it. Inferring "no client is confirmed"
// from "we cannot see the replies" would cap every real player on the
// service.
package egress

import (
	"sort"
	"time"
)

const (
	// Tick is the resolution return traffic is counted at. Confirmation asks
	// for packets in several distinct ticks rather than a count, because a
	// single burst of replies is what an origin sends when it is bouncing
	// errors at a flood; a conversation is spread out.
	Tick = 250 * time.Millisecond
	// MinPackets is how many packets back a client needs before it counts.
	MinPackets = 10
	// MinTicks is how many distinct ticks those packets must span.
	MinTicks = 3
	// ConfirmWindow is how far back the ticks are counted over. Wide enough
	// for a quiet client, short enough that confirmation describes now.
	ConfirmWindow = 10 * time.Second
	// ConfirmTTL is how long a confirmation stands once the return traffic
	// stops. A paused client is still a client; an address that has been
	// silent for longer has probably changed hands.
	ConfirmTTL = 2 * time.Minute

	// DefaultGrace is how long a source the node has not seen before is left
	// alone under lockdown.
	//
	// Lockdown without it is a trap with no exit: a new client is
	// unconfirmed, so it is held back, so its packets never reach the
	// origin, so the origin never answers, so it is never confirmed. The
	// grace is the window in which the origin gets a chance to vouch.
	DefaultGrace = 500 * time.Millisecond
	// DefaultLockdownPPS is what an unconfirmed source is held to while a
	// prefix is under attack, when the policy names no figure.
	DefaultLockdownPPS = 500

	// VisibilityWindow is how recently a prefix must have shown any return
	// traffic at all for this to be believed as a signal about it.
	VisibilityWindow = 30 * time.Second

	// MaxPrefixes and MaxClients bound the tables. Clients are keyed by
	// address, which is the field an attacker varies without limit, so the
	// bound is what keeps this from becoming the exhaustion vector it is
	// meant to help against.
	MaxPrefixes = 256
	MaxClients  = 1 << 16

	// sweepInterval throttles reclaiming. With the table full, scanning per
	// packet would be its own denial of service.
	sweepInterval = 5 * time.Second
)

// Visibility is what is known about whether a prefix's return path is
// observable here.
type Visibility uint8

const (
	// Unknown means nothing has been seen for this prefix yet, in either
	// direction.
	Unknown Visibility = iota
	// Visible means return traffic has been observed recently, so an absence
	// of it for a given client is informative.
	Visible
	// Asymmetric means the prefix carries ingress but no return traffic has
	// been seen. Either the origin answers directly, or this node is not on
	// the return path. Either way, nothing here can say anything about a
	// client, and nothing that depends on it should fire.
	Asymmetric
)

func (v Visibility) String() string {
	switch v {
	case Visible:
		return "visible"
	case Asymmetric:
		return "asymmetric"
	default:
		return "unknown"
	}
}

// client is one address's return-traffic record for one prefix.
type client struct {
	// packets and ticks accumulate inside the confirmation window; windowEnds
	// is when they lapse.
	packets    int
	ticks      int
	lastTick   int64
	windowEnds time.Time
	// confirmedUntil stands after the traffic stops.
	confirmedUntil time.Time
	lastSeen       time.Time
	// firstIngress is when this node first saw the source sending, which is
	// what the grace window is measured from.
	firstIngress time.Time
}

type series struct {
	clients map[string]*client
	// lastEgress and lastIngress drive the visibility judgement.
	lastEgress  time.Time
	lastIngress time.Time
}

// Stats is what the tracker is holding.
type Stats struct {
	Prefixes   int `json:"prefixes"`
	Clients    int `json:"clients"`
	ClientsMax int `json:"clients_max"`
	Confirmed  int `json:"confirmed"`
	// Promotions counts clients that reached confirmation.
	Promotions uint64 `json:"promotions"`
	// Full counts clients there was no room to track. They are simply not
	// confirmed, which costs them the fast path and nothing else.
	Full uint64 `json:"full"`
	// Asymmetric is how many prefixes look like direct server return.
	Asymmetric int `json:"asymmetric"`
}

// Tracker watches return traffic per protected prefix.
//
// It is not safe for concurrent use. The pipeline owns one and holds its own
// lock across a decision, which is where every call comes from.
type Tracker struct {
	series    map[string]*series
	clients   int
	lastSweep time.Time
	stats     Stats
	now       func() time.Time
}

func New() *Tracker {
	return &Tracker{series: map[string]*series{}, now: time.Now}
}

// SetClock replaces the time source, so tests can age a confirmation out
// without waiting for it.
func (t *Tracker) SetClock(now func() time.Time) {
	if t == nil {
		return
	}
	t.now = now
}

func (t *Tracker) clock() time.Time {
	if t == nil || t.now == nil {
		return time.Now()
	}
	return t.now()
}

func tickOf(at time.Time) int64 { return at.UnixNano() / int64(Tick) }

// Ingress records that a prefix is carrying inbound traffic. It is what makes
// an absence of return traffic meaningful: a prefix nobody is sending to is
// not asymmetric, it is idle.
func (t *Tracker) Ingress(prefix string, now time.Time) {
	if t == nil || prefix == "" {
		return
	}
	s := t.seriesFor(prefix)
	if s == nil {
		return
	}
	s.lastIngress = now
}

// InGrace reports whether a source is new enough to be left alone under
// lockdown, recording it on first sight.
//
// With the table full it reports false — the source is held back. During the
// flood that filled it, being strict is the posture lockdown exists for, and
// the default mode caps rather than drops, so a real client still passes at
// a reduced rate.
func (t *Tracker) InGrace(prefix, clientAddr string, grace time.Duration, now time.Time) bool {
	if t == nil || prefix == "" || clientAddr == "" {
		return false
	}
	s := t.seriesFor(prefix)
	if s == nil {
		return false
	}
	c, ok := s.clients[clientAddr]
	if !ok {
		if t.clients >= MaxClients {
			t.stats.Full++
			return false
		}
		c = &client{firstIngress: now}
		s.clients[clientAddr] = c
		t.clients++
	}
	if c.firstIngress.IsZero() {
		c.firstIngress = now
	}
	c.lastSeen = now
	return now.Sub(c.firstIngress) < grace
}

// Return records packets the origin sent back to a client, and reports
// whether that client has just become confirmed.
func (t *Tracker) Return(prefix, clientAddr string, packets int, now time.Time) bool {
	if t == nil || prefix == "" || clientAddr == "" || packets <= 0 {
		return false
	}
	s := t.seriesFor(prefix)
	if s == nil {
		return false
	}
	s.lastEgress = now
	t.reclaim(now)

	c, ok := s.clients[clientAddr]
	if !ok {
		if t.clients >= MaxClients {
			t.stats.Full++
			return false
		}
		c = &client{}
		s.clients[clientAddr] = c
		t.clients++
	}
	c.lastSeen = now

	// A fresh window whenever the last one lapsed: confirmation describes a
	// conversation happening now, not one that happened at some point.
	if now.After(c.windowEnds) {
		c.packets, c.ticks, c.lastTick = 0, 0, 0
		c.windowEnds = now.Add(ConfirmWindow)
	}
	c.packets += packets
	// Distinct ticks, not a count: ten packets in one instant is a burst,
	// which is what an origin emits when it is bouncing errors at a flood.
	// Ten spread across three ticks is a conversation.
	if tick := tickOf(now); tick != c.lastTick {
		c.lastTick = tick
		c.ticks++
	}

	if c.packets < MinPackets || c.ticks < MinTicks {
		return false
	}
	fresh := !now.Before(c.confirmedUntil)
	c.confirmedUntil = now.Add(ConfirmTTL)
	if fresh {
		t.stats.Promotions++
	}
	return fresh
}

// Confirmed reports whether the origin has been talking to this client.
func (t *Tracker) Confirmed(prefix, clientAddr string, now time.Time) bool {
	if t == nil {
		return false
	}
	s := t.series[prefix]
	if s == nil {
		return false
	}
	c := s.clients[clientAddr]
	return c != nil && now.Before(c.confirmedUntil)
}

// Visibility reports whether this node can see the prefix's return path.
func (t *Tracker) Visibility(prefix string, now time.Time) Visibility {
	if t == nil {
		return Unknown
	}
	s := t.series[prefix]
	if s == nil {
		return Unknown
	}
	if !s.lastEgress.IsZero() && now.Sub(s.lastEgress) <= VisibilityWindow {
		return Visible
	}
	// Ingress and no egress is the direct-server-return shape. With neither,
	// the prefix is simply idle and nothing can be said.
	if !s.lastIngress.IsZero() && now.Sub(s.lastIngress) <= VisibilityWindow {
		return Asymmetric
	}
	return Unknown
}

// Forget drops prefixes the node no longer carries.
func (t *Tracker) Forget(live map[string]struct{}) {
	if t == nil {
		return
	}
	for prefix, s := range t.series {
		if _, ok := live[prefix]; ok {
			continue
		}
		t.clients -= len(s.clients)
		delete(t.series, prefix)
	}
	if t.clients < 0 {
		t.clients = 0
	}
}

func (t *Tracker) seriesFor(prefix string) *series {
	if s, ok := t.series[prefix]; ok {
		return s
	}
	if len(t.series) >= MaxPrefixes {
		return nil
	}
	s := &series{clients: map[string]*client{}}
	t.series[prefix] = s
	return s
}

// reclaim drops clients with nothing left to say. It scans at most once per
// interval, for the same reason the rate table does.
func (t *Tracker) reclaim(now time.Time) {
	if !t.lastSweep.IsZero() && now.Sub(t.lastSweep) < sweepInterval {
		return
	}
	t.lastSweep = now
	for _, s := range t.series {
		for addr, c := range s.clients {
			if now.Before(c.confirmedUntil) || now.Before(c.windowEnds) {
				continue
			}
			if now.Sub(c.lastSeen) < ConfirmTTL {
				continue
			}
			if !c.firstIngress.IsZero() && now.Sub(c.firstIngress) < ConfirmTTL {
				// Still inside anything the grace could be set to.
				continue
			}
			delete(s.clients, addr)
			t.clients--
		}
	}
	if t.clients < 0 {
		t.clients = 0
	}
}

// Stats copies the counters out, with the live totals counted fresh.
func (t *Tracker) Stats() Stats {
	if t == nil {
		return Stats{}
	}
	now := t.clock()
	out := t.stats
	out.ClientsMax = MaxClients
	out.Prefixes = len(t.series)
	for prefix, s := range t.series {
		out.Clients += len(s.clients)
		for _, c := range s.clients {
			if now.Before(c.confirmedUntil) {
				out.Confirmed++
			}
		}
		if t.Visibility(prefix, now) == Asymmetric {
			out.Asymmetric++
		}
	}
	return out
}

// PrefixState is one prefix's return-path picture, for an operator.
type PrefixState struct {
	Prefix     string `json:"prefix"`
	Visibility string `json:"visibility"`
	Clients    int    `json:"clients"`
	Confirmed  int    `json:"confirmed"`
}

// Prefixes lists what the tracker knows, by prefix.
func (t *Tracker) Prefixes() []PrefixState {
	if t == nil {
		return nil
	}
	now := t.clock()
	out := make([]PrefixState, 0, len(t.series))
	for prefix, s := range t.series {
		row := PrefixState{
			Prefix:     prefix,
			Visibility: t.Visibility(prefix, now).String(),
			Clients:    len(s.clients),
		}
		for _, c := range s.clients {
			if now.Before(c.confirmedUntil) {
				row.Confirmed++
			}
		}
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Prefix < out[j].Prefix })
	return out
}

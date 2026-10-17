package model

import "time"

type Action string

const (
	ActionDrop    Action = "drop"
	ActionPermit  Action = "permit"
	ActionLimit   Action = "rate_limit"
	ActionInspect Action = "inspect"
	ActionCount   Action = "count"
	// ActionChallenge drops this packet and emits the protocol's own
	// challenge back to the source. The source is admitted once it answers.
	ActionChallenge Action = "challenge"
)

type Stage string

const (
	StageASIC Stage = "asic"
	StageFPGA Stage = "fpga"
	StageZC   Stage = "zc"
)

type Match struct {
	SrcCIDR  string `json:"src_cidr,omitempty"`
	DstCIDR  string `json:"dst_cidr,omitempty"`
	Proto    string `json:"proto,omitempty"`
	DPort    int    `json:"dport,omitempty"`
	SPort    int    `json:"sport,omitempty"`
	TCPFlags string `json:"tcp_flags,omitempty"`
}

type Rule struct {
	ID       string `json:"id"`
	Stage    Stage  `json:"stage"`
	Action   Action `json:"action"`
	Match    Match  `json:"match"`
	PPS      int    `json:"pps,omitempty"`
	Priority int    `json:"priority,omitempty"`
	Comment  string `json:"comment,omitempty"`
}

type Policy struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Protected []string   `json:"protected"`
	Rules     []Rule     `json:"rules"`
	Steering  []Steering `json:"steering,omitempty"`
	// Games binds protocol filters to ports on protected addresses.
	Games []GameFilter `json:"games,omitempty"`
	// PulseFloorPPS is how loud a burst must be before it counts toward a
	// burst train. Shape alone cannot decide it: a sparse trickle has the
	// same crest factor and duty cycle as an attack, so this belongs to the
	// deployment — set it from what the protected service actually carries.
	// Zero takes the platform default.
	PulseFloorPPS int `json:"pulse_floor_pps,omitempty"`
	// ChallengeSecret keys the cookies the challenge gate mints. The control
	// plane generates it and ships it to every node, because under anycast a
	// cookie minted by one scrubber has to verify on another.
	ChallengeSecret string    `json:"challenge_secret,omitempty"`
	UpdatedAt       time.Time `json:"updated_at"`
	Version         int       `json:"version"`
}

// Steering overrides the default anycast posture for one protected prefix.
// Regions is a hard boundary: a node outside them neither announces the prefix
// nor enforces policy on it, which is how a prefix is kept inside a
// jurisdiction. Communities ride along on the announcement for upstreams that
// act on them.
type Steering struct {
	Prefix      string   `json:"prefix"`
	Regions     []string `json:"regions,omitempty"`
	Communities []string `json:"communities,omitempty"`
}

// Node liveness states reported by the control plane.
const (
	NodeReady = "ready"
	NodeStale = "stale"
)

type Node struct {
	ID           string  `json:"id"`
	Name         string  `json:"name"`
	Region       string  `json:"region"`
	CapacityGbps float64 `json:"capacity_gbps"`
	// CapacityPPS is the packet rate this node can scrub. It is separate from
	// CapacityGbps because the ZC inspect path runs out of packets per second
	// long before it runs out of bits, and load-driven steering compares a
	// measured packet rate against it. Zero means unknown, which leaves this
	// node out of load-driven padding entirely.
	CapacityPPS int64     `json:"capacity_pps,omitempty"`
	Backends    []Stage   `json:"backends"`
	LastSeen    time.Time `json:"last_seen"`
	Status      string    `json:"status"`
	Advertise   string    `json:"advertise,omitempty"`
}

// Tenant is a customer of the scrubbing service.
//
// It exists so a customer can be given a credential that reads their own
// traffic and nothing else. Without it the only way to show someone their
// analytics is to hand them an operator token, which also reads every other
// customer's prefixes, the fleet's topology and the policy behind it.
//
// Prefixes are what the tenant may see. A prefix here covers anything inside
// it, so a customer who brings a /22 and has it protected as four /24s is
// given the /22 once rather than having to be re-entitled on every split.
type Tenant struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Prefixes []string `json:"prefixes"`
	// Contact is free text for whoever runs the platform: who to call. It is
	// never matched on.
	Contact   string    `json:"contact,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Flow struct {
	SrcIP string `json:"src_ip"`
	DstIP string `json:"dst_ip"`
	Proto string `json:"proto"`
	SPort int    `json:"sport"`
	DPort int    `json:"dport"`
	Flags string `json:"flags,omitempty"`
	PPS   int    `json:"pps"`
	// Payload is the packet bytes, base64 in JSON. Only the ZC stage sees
	// it: neither the TCAM nor the FPGA matches on payload. A record without
	// one is still decided, just not by the game filter, which refuses to
	// judge what it was not given.
	Payload []byte `json:"payload,omitempty"`
}

type Decision struct {
	Action Action  `json:"action"`
	Stage  Stage   `json:"stage"`
	RuleID string  `json:"rule_id,omitempty"`
	Reason string  `json:"reason"`
	NodeID string  `json:"node_id,omitempty"`
	Score  float64 `json:"score,omitempty"`
	// Filter names the game filter that decided, when one did.
	Filter string `json:"filter,omitempty"`
	// Reply is what the datapath should send back to the source. It is set
	// only on a challenge.
	Reply []byte `json:"reply,omitempty"`
}

type ACLEntry struct {
	Priority int    `json:"priority"`
	Action   Action `json:"action"`
	Match    Match  `json:"match"`
	RuleID   string `json:"rule_id"`
	TCAMKey  string `json:"tcam_key"`
}

type FPGAEntry struct {
	Table    string `json:"table"`
	Priority int    `json:"priority"`
	Match    Match  `json:"match"`
	Meter    int    `json:"meter_pps,omitempty"`
	Action   Action `json:"action"`
	RuleID   string `json:"rule_id"`
}

type ZCEntry struct {
	Cluster  string `json:"cluster"`
	Priority int    `json:"priority"`
	Match    Match  `json:"match"`
	Action   Action `json:"action"`
	PPS      int    `json:"pps,omitempty"`
	RuleID   string `json:"rule_id"`
}

type Program struct {
	NodeID   string      `json:"node_id"`
	PolicyID string      `json:"policy_id"`
	Version  int         `json:"version"`
	Prefixes []string    `json:"prefixes"`
	ASIC     []ACLEntry  `json:"asic"`
	FPGA     []FPGAEntry `json:"fpga"`
	ZC       []ZCEntry   `json:"zc"`
	// Announcements is this node's share of the fabric's BGP plan: what it
	// advertises, and how hard it leans away from traffic it should not take.
	Announcements []Announcement `json:"announcements"`
	// Games are the protocol filters this node applies on its ZC stage, and
	// the secret their challenge cookies are keyed with.
	Games           []GameFilter `json:"games,omitempty"`
	ChallengeSecret string       `json:"challenge_secret,omitempty"`
	// PulseFloorPPS is how loud a burst must be before it counts toward a
	// pulse train. Zero takes the platform default.
	PulseFloorPPS int       `json:"pulse_floor_pps,omitempty"`
	CompiledAt    time.Time `json:"compiled_at"`
}

// GameFilter admits traffic to a game port only if it looks like that game.
//
// It is bound to a port on a protected address rather than to a game the
// platform knows about: an operator says what runs where, and a protocol the
// platform has never heard of is described in Custom rather than waiting for
// a release.
type GameFilter struct {
	ID      string `json:"id"`
	DstCIDR string `json:"dst_cidr,omitempty"`
	Proto   string `json:"proto,omitempty"`
	DPort   int    `json:"dport,omitempty"`
	// Profile names a built-in protocol, or is empty when Custom describes
	// one inline.
	Profile string         `json:"profile,omitempty"`
	Custom  *GameSignature `json:"custom,omitempty"`
	// Observe records what the filter would have done without acting on it,
	// which is how a binding is rolled out.
	Observe bool   `json:"observe,omitempty"`
	Comment string `json:"comment,omitempty"`
}

// GameSignature describes a protocol in the policy, for a game the platform
// does not ship a profile for.
//
// It can validate framing and gate on the protocol's own opening sequence.
// It cannot configure a challenge gate: answering a challenge means emitting
// protocol-correct bytes, and a wrong guess at that framing breaks every
// client rather than failing closed.
type GameSignature struct {
	MinLen    int         `json:"min_len,omitempty"`
	MaxLen    int         `json:"max_len,omitempty"`
	PacketIDs []int       `json:"packet_ids,omitempty"`
	Magic     []GameMagic `json:"magic,omitempty"`
	// Gate is "none" or "handshake".
	Gate        string `json:"gate,omitempty"`
	OpenerIDs   []int  `json:"opener_ids,omitempty"`
	CompleteIDs []int  `json:"complete_ids,omitempty"`
}

// GameMagic is a byte sequence that must appear at a fixed offset, written
// as hex in the policy.
type GameMagic struct {
	Offset int    `json:"offset"`
	Hex    string `json:"hex"`
}

// AnnounceState is whether a node offers a prefix to its upstreams.
type AnnounceState string

const (
	// StateAnnounce means the node advertises the prefix and so attracts
	// traffic for it.
	StateAnnounce AnnounceState = "announce"
	// StateWithdraw means the node does not advertise the prefix, so traffic
	// falls through to the next-closest node announcing it.
	StateWithdraw AnnounceState = "withdraw"
)

// Announcement is one node's BGP posture for one protected prefix.
//
// The fabric is anycast: every eligible node announces every protected prefix,
// and traffic lands wherever BGP decides is closest. Nothing is exclusively
// owned, so an attack on a single prefix is absorbed by the whole fabric
// rather than by one scrubber. How much traffic a node attracts is tuned with
// AS-path prepends, and a node that stops answering is withdrawn so its share
// moves to the nodes that are still up.
type Announcement struct {
	Prefix   string        `json:"prefix"`
	NodeID   string        `json:"node_id"`
	NodeName string        `json:"node_name,omitempty"`
	Region   string        `json:"region,omitempty"`
	State    AnnounceState `json:"state"`
	// Prepends is how many extra copies of the local AS pad the AS path. Each
	// one makes this node a less attractive path for sources that have a
	// choice, which is how capacity is weighted without exclusive ownership.
	Prepends    int      `json:"prepends"`
	Communities []string `json:"communities,omitempty"`
	NextHop     string   `json:"next_hop,omitempty"`
	Reason      string   `json:"reason"`
}

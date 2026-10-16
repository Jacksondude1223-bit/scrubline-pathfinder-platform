package model

import "time"

type Action string

const (
	ActionDrop    Action = "drop"
	ActionPermit  Action = "permit"
	ActionLimit   Action = "rate_limit"
	ActionInspect Action = "inspect"
	ActionCount   Action = "count"
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
	UpdatedAt time.Time  `json:"updated_at"`
	Version   int        `json:"version"`
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
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Region       string    `json:"region"`
	CapacityGbps float64   `json:"capacity_gbps"`
	Backends     []Stage   `json:"backends"`
	LastSeen     time.Time `json:"last_seen"`
	Status       string    `json:"status"`
	Advertise    string    `json:"advertise,omitempty"`
}

type Flow struct {
	SrcIP string `json:"src_ip"`
	DstIP string `json:"dst_ip"`
	Proto string `json:"proto"`
	SPort int    `json:"sport"`
	DPort int    `json:"dport"`
	Flags string `json:"flags,omitempty"`
	PPS   int    `json:"pps"`
}

type Decision struct {
	Action Action  `json:"action"`
	Stage  Stage   `json:"stage"`
	RuleID string  `json:"rule_id,omitempty"`
	Reason string  `json:"reason"`
	NodeID string  `json:"node_id,omitempty"`
	Score  float64 `json:"score,omitempty"`
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
	CompiledAt    time.Time      `json:"compiled_at"`
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

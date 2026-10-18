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
	// Tunnels say where scrubbed traffic goes. Attracting a prefix without
	// one means a scrubber pulls the customer's traffic in and has nowhere
	// to send it, so a policy that protects a prefix it cannot deliver is
	// worse than no policy at all.
	Tunnels []Tunnel `json:"tunnels,omitempty"`
	// Sessions are BGP peerings with the customer, for prefixes they
	// announce to the fabric rather than ones the operator types in.
	Sessions []Session `json:"sessions,omitempty"`
	// PulseFloorPPS is how loud a burst must be before it counts toward a
	// burst train. Shape alone cannot decide it: a sparse trickle has the
	// same crest factor and duty cycle as an attack, so this belongs to the
	// deployment — set it from what the protected service actually carries.
	// Zero takes the platform default.
	PulseFloorPPS int `json:"pulse_floor_pps,omitempty"`
	// Reputation tunes the two-tier source cache: who gets the short path,
	// and whether repeat offenders are dropped at the top of the pipeline.
	Reputation *ReputationPolicy `json:"reputation,omitempty"`
	// ChallengeSecret keys the cookies the challenge gate mints. The control
	// plane generates it and ships it to every node, because under anycast a
	// cookie minted by one scrubber has to verify on another.
	ChallengeSecret string    `json:"challenge_secret,omitempty"`
	UpdatedAt       time.Time `json:"updated_at"`
	Version         int       `json:"version"`
}

// ReputationPolicy tunes what the datapath remembers about a source.
type ReputationPolicy struct {
	// FastPass is the weakest proof that earns the short path: "challenge",
	// "handshake", or "off".
	//
	// It defaults to "challenge", the stricter reading. Answering a
	// challenge means echoing a value that could only have come from a
	// reply to that address, so the address answers for itself; completing
	// a handshake can be done blind, which means a spoofer can clear it for
	// any address. Widening this to "handshake" is reasonable for a
	// protocol that defines no challenge, and it is a deliberate decision
	// rather than a default.
	FastPass string `json:"fast_pass,omitempty"`
	// PenaltyBox drops sources that keep failing, at the top of the
	// pipeline, instead of letting them walk every stage to the same
	// verdict. Off by default: it is an escalation of consequence beyond
	// what one packet earned, so it is rolled out deliberately. With it
	// off, strikes and would-be demotions are still counted and exposed.
	PenaltyBox bool `json:"penalty_box,omitempty"`
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
	// TunnelSrc is the local address this node builds return tunnels from.
	// It is per node rather than per tunnel because the fabric is anycast:
	// every node carrying a prefix needs its own tunnel to the one customer
	// endpoint, and they cannot all share a source address.
	//
	// A node without one cannot carry a tunnelled prefix, and the compiler
	// withdraws it from those prefixes rather than announcing traffic it
	// could not deliver.
	TunnelSrc string `json:"tunnel_src,omitempty"`
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
	PulseFloorPPS int               `json:"pulse_floor_pps,omitempty"`
	Reputation    *ReputationPolicy `json:"reputation,omitempty"`
	// Tunnels are this node's own return paths: one per customer endpoint
	// whose prefixes this node carries, sourced from this node's address.
	Tunnels []NodeTunnel `json:"tunnels,omitempty"`
	// Sessions are the customer peerings this node terminates.
	Sessions   []Session `json:"sessions,omitempty"`
	CompiledAt time.Time `json:"compiled_at"`
}

// NodeTunnel is one node's instance of a policy Tunnel, with the local end
// filled in and the derived values resolved, so the agent renders config
// rather than recomputing policy.
type NodeTunnel struct {
	ID       string   `json:"id"`
	Type     string   `json:"type"`
	Local    string   `json:"local"`
	Remote   string   `json:"remote"`
	Prefixes []string `json:"prefixes"`
	MTU      int      `json:"mtu"`
	MSSClamp int      `json:"mss_clamp"`
	Key      uint32   `json:"key,omitempty"`
	Required bool     `json:"required,omitempty"`
	// Interface is the link name the agent renders, derived from the ID and
	// kept inside the kernel's limit.
	Interface string `json:"interface"`
	Comment   string `json:"comment,omitempty"`
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

// Tunnel types the fabric can build a return path with.
const (
	TunnelGRE  = "gre"
	TunnelIPIP = "ipip"
)

// Tunnel is the return path for a set of protected prefixes: where scrubbed
// traffic goes once it is clean.
//
// It is the half of a scrubbing service that BGP cannot do. Announcing a
// customer's prefix pulls their traffic to the scrubbers, and the traffic
// then cannot be routed back the ordinary way, because the scrubbers are
// what the internet now believes that prefix to be. It is encapsulated to
// the customer's own edge instead.
//
// One Tunnel describes one customer endpoint. The fabric is anycast, so it
// compiles to one tunnel per node carrying the prefixes, all to the same
// remote.
type Tunnel struct {
	ID string `json:"id"`
	// Prefixes this tunnel delivers. Each must be one the policy protects.
	Prefixes []string `json:"prefixes"`
	// Type is "gre" or "ipip". GRE unless the customer's edge cannot do it:
	// ipip is lighter but carries no key, so it cannot demultiplex several
	// tunnels between the same pair of addresses.
	Type string `json:"type,omitempty"`
	// Remote is the customer's tunnel endpoint. The local end is each node's
	// own TunnelSrc.
	Remote string `json:"remote"`
	// MTU of the tunnel. Zero derives it from a 1500-byte path less this
	// encapsulation's overhead, which is the value that stops large packets
	// being silently dropped inside the tunnel.
	MTU int `json:"mtu,omitempty"`
	// MSSClamp is the TCP MSS to clamp to on the way in. Zero derives it
	// from the MTU. Without clamping, a customer whose path does not honour
	// path-MTU discovery sees TCP hang on anything larger than a handshake
	// — the classic way a working tunnel still looks broken.
	MSSClamp int `json:"mss_clamp,omitempty"`
	// Key demultiplexes several GRE tunnels between the same two addresses.
	// Zero means none. Not available on ipip.
	Key uint32 `json:"key,omitempty"`
	// Required makes a confirmed-up tunnel a precondition for announcing
	// these prefixes from a node. Off by default, because a fabric whose
	// provisioner reports nothing would otherwise announce nothing at all
	// and give no hint why; on, for operators whose tunnels report reliably
	// and who would rather drop traffic than black-hole it.
	Required bool   `json:"required,omitempty"`
	Comment  string `json:"comment,omitempty"`
}

// Session is a BGP peering with a customer, for customers who announce their
// own prefixes to the fabric instead of having them typed into a policy.
//
// What the session may carry is still declared here. A route learned from a
// customer does not add itself to the protected set: a peer that leaked a
// supernet would otherwise have the fabric announcing address space it was
// never asked to protect.
type Session struct {
	ID string `json:"id"`
	// PeerIP and PeerAS identify the customer's router.
	PeerIP string `json:"peer_ip"`
	PeerAS int    `json:"peer_as"`
	// LocalAS is the AS the fabric peers from. Zero takes the node's own.
	LocalAS int `json:"local_as,omitempty"`
	// Prefixes the session accepts. Each must be one the policy protects,
	// and anything else the peer sends is refused by the filter.
	Prefixes []string `json:"prefixes"`
	// MaxPrefixes tears the session down if the peer announces more than
	// this. Zero derives a limit from the filter, because a peer with no
	// limit at all is how one customer's route leak becomes everyone's
	// outage.
	MaxPrefixes int `json:"max_prefixes,omitempty"`
	// Password is the TCP-MD5 secret, if the customer uses one. It is
	// shipped only to the nodes that terminate this session.
	Password string `json:"password,omitempty"`
	// Multihop is the TTL for a peer that is not directly attached. Zero
	// means directly connected.
	Multihop int `json:"multihop,omitempty"`
	// Passive waits for the customer to connect rather than dialling them.
	Passive bool `json:"passive,omitempty"`
	// Nodes and Regions scope where this session terminates. Empty means
	// every node, which is rarely what anyone wants: a customer peers at the
	// handful of places they have a path to, not with the whole fabric.
	Nodes   []string `json:"nodes,omitempty"`
	Regions []string `json:"regions,omitempty"`
	Comment string   `json:"comment,omitempty"`
}

// TunnelState is what a node's provisioner reports back about a return path.
const (
	// TunnelUp means the node confirmed the tunnel carries traffic.
	TunnelUp = "up"
	// TunnelDown means it confirmed it does not. This withdraws the
	// tunnel's prefixes from that node.
	TunnelDown = "down"
	// TunnelUnknown is the absence of a report. It does not withdraw on its
	// own: no news is not the same as bad news, and treating it that way
	// would blank a fabric whose provisioner simply does not report.
	TunnelUnknown = "unknown"
)

// TunnelStatus is one node's view of one of its return tunnels. Nodes attach
// these to the heartbeat they already send.
type TunnelStatus struct {
	TunnelID string `json:"tunnel_id"`
	State    string `json:"state"`
	// Detail is free text from whatever provisioned the tunnel, carried
	// through to the operator unchanged.
	Detail     string    `json:"detail,omitempty"`
	ReportedAt time.Time `json:"reported_at,omitempty"`
}

// SourceReputation is what the datapath remembers about one source address.
// It is a debugging view for an operator asking who is in the penalty box,
// not something the hot path reads.
type SourceReputation struct {
	Source string `json:"source"`
	// State is "trusted", "penalised", or "tracked" for a source that is
	// neither but has history worth keeping.
	State string `json:"state"`
	// Proof is what the source demonstrated: "challenge" is an echoed cookie
	// and so proves the address answers for itself; "handshake" only proves
	// the source speaks the protocol, since an opening sequence can be sent
	// blind.
	Proof     string  `json:"proof"`
	ExpiresIn float64 `json:"expires_in_seconds,omitempty"`
	// Level is how far up the penalty ladder this source has climbed.
	Level   int `json:"level,omitempty"`
	Strikes int `json:"strikes,omitempty"`
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

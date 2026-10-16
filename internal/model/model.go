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
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Protected []string  `json:"protected"`
	Rules     []Rule    `json:"rules"`
	UpdatedAt time.Time `json:"updated_at"`
	Version   int       `json:"version"`
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
	NodeID     string      `json:"node_id"`
	PolicyID   string      `json:"policy_id"`
	Version    int         `json:"version"`
	Prefixes   []string    `json:"prefixes"`
	ASIC       []ACLEntry  `json:"asic"`
	FPGA       []FPGAEntry `json:"fpga"`
	ZC         []ZCEntry   `json:"zc"`
	CompiledAt time.Time   `json:"compiled_at"`
}

type Assignment struct {
	Prefix string  `json:"prefix"`
	NodeID string  `json:"node_id"`
	Weight float64 `json:"weight"`
}

//! Typed heartbeat wire contract.
use crate::model::null_default;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
/// A node's last heartbeat as the control plane keeps it. The counters stay typed: as JSON values
/// a fabric's worth of them would cost several times what the counters themselves do.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub node_id: String,
    pub name: String,
    pub region: String,
    pub stats: Stats,
    pub reported_at: DateTime<Utc>,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ReputationStats {
    #[serde(deserialize_with = "null_default")]
    pub tracked: i64,
    #[serde(deserialize_with = "null_default")]
    pub max: i64,
    #[serde(deserialize_with = "null_default")]
    pub trusted: i64,
    #[serde(deserialize_with = "null_default")]
    pub penalised: i64,
    #[serde(deserialize_with = "null_default")]
    pub fast_passed: u64,
    #[serde(deserialize_with = "null_default")]
    pub boxed: u64,
    #[serde(deserialize_with = "null_default")]
    pub promotions: u64,
    #[serde(deserialize_with = "null_default")]
    pub demotions: u64,
    #[serde(deserialize_with = "null_default")]
    pub strikes: u64,
    #[serde(deserialize_with = "null_default")]
    pub shielded: u64,
    #[serde(deserialize_with = "null_default")]
    pub full: u64,
    #[serde(deserialize_with = "null_default")]
    pub freed: u64,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct EgressTrackerStats {
    #[serde(deserialize_with = "null_default")]
    pub prefixes: i64,
    #[serde(deserialize_with = "null_default")]
    pub clients: i64,
    #[serde(deserialize_with = "null_default")]
    pub clients_max: i64,
    #[serde(deserialize_with = "null_default")]
    pub confirmed: i64,
    #[serde(deserialize_with = "null_default")]
    pub promotions: u64,
    #[serde(deserialize_with = "null_default")]
    pub full: u64,
    #[serde(deserialize_with = "null_default")]
    pub asymmetric: i64,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PrefixState {
    #[serde(deserialize_with = "null_default")]
    pub prefix: String,
    #[serde(deserialize_with = "null_default")]
    pub visibility: String,
    #[serde(deserialize_with = "null_default")]
    pub clients: i64,
    #[serde(deserialize_with = "null_default")]
    pub confirmed: i64,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Stats {
    #[serde(deserialize_with = "null_default")]
    pub decisions: u64,
    #[serde(deserialize_with = "null_default")]
    pub unowned: u64,
    #[serde(deserialize_with = "null_default")]
    pub stages: Vec<StageStats>,
    #[serde(deserialize_with = "null_default")]
    pub rules: Vec<RuleStats>,
    #[serde(deserialize_with = "null_default")]
    pub games: Vec<GameStats>,
    #[serde(deserialize_with = "null_default")]
    pub prefixes: Vec<PrefixStats>,
    #[serde(deserialize_with = "null_default")]
    pub ml: MLStats,
    #[serde(deserialize_with = "null_default")]
    pub pulsing: bool,
    #[serde(deserialize_with = "null_default")]
    pub pulse_peak_pps: u64,
    #[serde(deserialize_with = "null_default")]
    pub game_sessions: i64,
    #[serde(deserialize_with = "null_default")]
    pub game_sessions_max: i64,
    #[serde(deserialize_with = "null_default")]
    pub game_http_windows: i64,
    #[serde(deserialize_with = "null_default")]
    pub game_http_windows_max: i64,
    #[serde(deserialize_with = "null_default")]
    pub reputation: ReputationStats,
    #[serde(deserialize_with = "null_default")]
    pub egress: EgressStats,
    #[serde(deserialize_with = "null_default")]
    pub rate_buckets: i64,
    #[serde(deserialize_with = "null_default")]
    pub rate_buckets_max: i64,
    #[serde(deserialize_with = "null_default")]
    pub offered_pps: u64,
    #[serde(deserialize_with = "null_default")]
    pub dropped_pps: u64,
    #[serde(deserialize_with = "null_default")]
    pub surge_pps: u64,
    #[serde(deserialize_with = "null_default")]
    pub load_window_seconds: i64,
    #[serde(deserialize_with = "null_default")]
    pub crafted: CraftedStats,
    /// What the agent's process holds in memory, as the kernel counts it.
    #[serde(deserialize_with = "null_default")]
    pub resident_bytes: u64,
    #[serde(
        deserialize_with = "null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub mitigation: Vec<MitigationStats>,
}
impl Stats {
    /// The node as a whole: everything but its rows for each prefix, rule, filter and on-demand
    /// tunnel, and which prefixes' return paths it sees. Every field is named, so one added to
    /// Stats is not left out of the summary without a decision.
    pub fn summary(&self) -> Self {
        let Self {
            decisions,
            unowned,
            stages,
            rules: _,
            games: _,
            prefixes: _,
            ml,
            pulsing,
            pulse_peak_pps,
            game_sessions,
            game_sessions_max,
            game_http_windows,
            game_http_windows_max,
            reputation,
            egress,
            rate_buckets,
            rate_buckets_max,
            offered_pps,
            dropped_pps,
            surge_pps,
            load_window_seconds,
            crafted,
            resident_bytes,
            mitigation: _,
        } = self;
        let EgressStats {
            tracker,
            seen,
            promoted,
            locked_down,
            lockdown,
            prefix_states: _,
        } = egress;
        Self {
            decisions: *decisions,
            unowned: *unowned,
            stages: stages.clone(),
            rules: Vec::new(),
            games: Vec::new(),
            prefixes: Vec::new(),
            ml: ml.clone(),
            pulsing: *pulsing,
            pulse_peak_pps: *pulse_peak_pps,
            game_sessions: *game_sessions,
            game_sessions_max: *game_sessions_max,
            game_http_windows: *game_http_windows,
            game_http_windows_max: *game_http_windows_max,
            reputation: reputation.clone(),
            egress: EgressStats {
                tracker: tracker.clone(),
                seen: *seen,
                promoted: *promoted,
                locked_down: *locked_down,
                lockdown: lockdown.clone(),
                prefix_states: Vec::new(),
            },
            rate_buckets: *rate_buckets,
            rate_buckets_max: *rate_buckets_max,
            offered_pps: *offered_pps,
            dropped_pps: *dropped_pps,
            surge_pps: *surge_pps,
            load_window_seconds: *load_window_seconds,
            crafted: crafted.clone(),
            resident_bytes: *resident_bytes,
            mitigation: Vec::new(),
        }
    }
}
/// What the crafted-packet checks did: in which mode, in all and per check, and how full the
/// table of fragments in reassembly is.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CraftedStats {
    #[serde(deserialize_with = "null_default")]
    pub mode: String,
    #[serde(deserialize_with = "null_default")]
    pub dropped: u64,
    #[serde(deserialize_with = "null_default")]
    pub observed: u64,
    #[serde(deserialize_with = "null_default")]
    pub fragments: i64,
    #[serde(deserialize_with = "null_default")]
    pub fragments_max: i64,
    #[serde(deserialize_with = "null_default")]
    pub fragments_untracked: u64,
    #[serde(deserialize_with = "null_default")]
    pub checks: Vec<CheckStats>,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CheckStats {
    #[serde(deserialize_with = "null_default")]
    pub check: String,
    #[serde(deserialize_with = "null_default")]
    pub class: String,
    #[serde(deserialize_with = "null_default")]
    pub dropped: u64,
    #[serde(deserialize_with = "null_default")]
    pub observed: u64,
}
/// What the crafted-packet checks dropped of one class for a prefix: flows, and their packets.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PrefixCrafted {
    #[serde(deserialize_with = "null_default")]
    pub class: String,
    #[serde(deserialize_with = "null_default")]
    pub flows: u64,
    #[serde(deserialize_with = "null_default")]
    pub dropped: u64,
}
/// An on-demand tunnel as the node holding it sees it: whether it is being mitigated, what
/// reaches it over the last second, the thresholds that start its mitigation, and which wave of
/// an attack the last mitigation was, with how long it holds.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct MitigationStats {
    #[serde(deserialize_with = "null_default")]
    pub tunnel_id: String,
    #[serde(deserialize_with = "null_default")]
    pub active: bool,
    #[serde(
        deserialize_with = "null_default",
        skip_serializing_if = "Option::is_none"
    )]
    pub since: Option<String>,
    #[serde(deserialize_with = "null_default")]
    pub pps: u64,
    #[serde(deserialize_with = "null_default")]
    pub bps: u64,
    #[serde(deserialize_with = "null_default")]
    pub attack_pps: u64,
    #[serde(deserialize_with = "null_default")]
    pub attack_bps: u64,
    #[serde(deserialize_with = "null_default")]
    pub wave: u32,
    #[serde(deserialize_with = "null_default")]
    pub hold_seconds: i64,
    #[serde(deserialize_with = "null_default")]
    pub mitigations: u64,
    #[serde(deserialize_with = "null_default")]
    pub unfiltered: u64,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct EgressStats {
    #[serde(flatten)]
    pub tracker: EgressTrackerStats,
    #[serde(deserialize_with = "null_default")]
    pub seen: u64,
    #[serde(deserialize_with = "null_default")]
    pub promoted: u64,
    #[serde(deserialize_with = "null_default")]
    pub locked_down: u64,
    #[serde(deserialize_with = "null_default")]
    pub lockdown: String,
    #[serde(deserialize_with = "null_default")]
    pub prefix_states: Vec<PrefixState>,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct StageStats {
    #[serde(deserialize_with = "null_default")]
    pub stage: String,
    #[serde(deserialize_with = "null_default")]
    pub dropped: u64,
    #[serde(deserialize_with = "null_default")]
    pub permitted: u64,
    #[serde(deserialize_with = "null_default")]
    pub pps_dropped: u64,
    #[serde(deserialize_with = "null_default")]
    pub pps_permitted: u64,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RuleStats {
    #[serde(deserialize_with = "null_default")]
    pub rule_id: String,
    #[serde(deserialize_with = "null_default")]
    pub stage: String,
    #[serde(deserialize_with = "null_default")]
    pub matches: u64,
    #[serde(deserialize_with = "null_default")]
    pub drops: u64,
    #[serde(deserialize_with = "null_default")]
    pub pps_seen: u64,
    #[serde(deserialize_with = "null_default")]
    pub pps_dropped: u64,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PrefixStats {
    #[serde(deserialize_with = "null_default")]
    pub prefix: String,
    #[serde(deserialize_with = "null_default")]
    pub flows: u64,
    #[serde(deserialize_with = "null_default")]
    pub flows_dropped: u64,
    #[serde(deserialize_with = "null_default")]
    pub offered: u64,
    #[serde(deserialize_with = "null_default")]
    pub dropped: u64,
    #[serde(deserialize_with = "null_default")]
    pub offered_pps: u64,
    #[serde(deserialize_with = "null_default")]
    pub dropped_pps: u64,
    #[serde(deserialize_with = "null_default")]
    pub pulsing: bool,
    #[serde(deserialize_with = "null_default")]
    pub peak_pps: u64,
    #[serde(deserialize_with = "null_default")]
    pub mean_pps: u64,
    #[serde(deserialize_with = "null_default")]
    pub crest: f64,
    #[serde(deserialize_with = "null_default")]
    pub duty_cycle: f64,
    #[serde(deserialize_with = "null_default")]
    pub bursts: i64,
    #[serde(deserialize_with = "null_default")]
    pub held_for_seconds: f64,
    /// How far under their thresholds the classifiers drop for this prefix while it is being
    /// probed.
    #[serde(deserialize_with = "null_default")]
    pub ml_cut: f64,
    #[serde(
        deserialize_with = "null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub crafted: Vec<PrefixCrafted>,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct GameStats {
    #[serde(deserialize_with = "null_default")]
    pub filter_id: String,
    #[serde(deserialize_with = "null_default")]
    pub profile: String,
    #[serde(deserialize_with = "null_default")]
    pub inspected: u64,
    #[serde(deserialize_with = "null_default")]
    pub dropped: u64,
    #[serde(deserialize_with = "null_default")]
    pub challenged: u64,
    #[serde(deserialize_with = "null_default")]
    pub uninspectable: u64,
    #[serde(deserialize_with = "null_default")]
    pub pps_dropped: u64,
    #[serde(deserialize_with = "null_default")]
    pub http_requests: u64,
    #[serde(deserialize_with = "null_default")]
    pub http_dropped: u64,
    #[serde(deserialize_with = "null_default")]
    pub http_rate_limited: u64,
    #[serde(deserialize_with = "null_default")]
    pub http_other: u64,
    #[serde(deserialize_with = "null_default")]
    pub http_budget_dropped: u64,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct MLStats {
    #[serde(deserialize_with = "null_default")]
    pub ready: bool,
    #[serde(deserialize_with = "null_default")]
    pub scored: u64,
    #[serde(deserialize_with = "null_default")]
    pub drops: u64,
    #[serde(deserialize_with = "null_default")]
    pub passes: u64,
    #[serde(deserialize_with = "null_default")]
    pub observed: u64,
    #[serde(deserialize_with = "null_default")]
    pub http_ready: bool,
    #[serde(deserialize_with = "null_default")]
    pub http_scored: u64,
    #[serde(deserialize_with = "null_default")]
    pub http_drops: u64,
    #[serde(deserialize_with = "null_default")]
    pub http_observed: u64,
    #[serde(deserialize_with = "null_default")]
    pub scope: String,
    #[serde(deserialize_with = "null_default")]
    pub mode: String,
    #[serde(deserialize_with = "null_default")]
    pub probing: String,
    #[serde(deserialize_with = "null_default")]
    pub near_misses: u64,
    #[serde(deserialize_with = "null_default")]
    pub tightened: u64,
}

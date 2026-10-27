//! Typed heartbeat wire contract.
use crate::model::null_default;
use serde::{Deserialize, Serialize};
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
    #[serde(
        deserialize_with = "null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub mitigation: Vec<MitigationStats>,
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

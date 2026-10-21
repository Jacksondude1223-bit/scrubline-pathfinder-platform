//! Wire-compatible policy and program types shared by the Rust components.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
pub type Action = String;
pub type Stage = String;
pub type AnnounceState = String;
fn is_zero<T: Default + PartialEq>(v: &T) -> bool {
    *v == T::default()
}
pub fn null_default<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}
pub fn zero_time() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("0001-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc)
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Match {
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub src_cidr: String,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub dst_cidr: String,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub proto: String,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub dport: i64,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub sport: i64,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub tcp_flags: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Rule {
    #[serde(deserialize_with = "null_default")]
    pub id: String,
    #[serde(deserialize_with = "null_default")]
    pub stage: Stage,
    #[serde(deserialize_with = "null_default")]
    pub action: Action,
    pub r#match: Match,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub pps: i64,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub priority: i64,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub comment: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Policy {
    #[serde(deserialize_with = "null_default")]
    pub id: String,
    #[serde(deserialize_with = "null_default")]
    pub name: String,
    #[serde(deserialize_with = "null_default")]
    pub protected: Vec<String>,
    #[serde(deserialize_with = "null_default")]
    pub rules: Vec<Rule>,
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub steering: Vec<Steering>,
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub games: Vec<GameFilter>,
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub tunnels: Vec<Tunnel>,
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub sessions: Vec<Session>,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub pulse_floor_pps: i64,
    #[serde(skip_serializing_if = "is_zero")]
    pub reputation: Option<ReputationPolicy>,
    #[serde(skip_serializing_if = "is_zero")]
    pub egress: Option<EgressPolicy>,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub challenge_secret: String,
    #[serde(deserialize_with = "null_time")]
    pub updated_at: DateTime<Utc>,
    #[serde(deserialize_with = "null_default")]
    pub version: i64,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            id: Default::default(),
            name: Default::default(),
            protected: Vec::new(),
            rules: Vec::new(),
            steering: Vec::new(),
            games: Vec::new(),
            tunnels: Vec::new(),
            sessions: Vec::new(),
            pulse_floor_pps: Default::default(),
            reputation: None,
            egress: None,
            challenge_secret: Default::default(),
            updated_at: zero_time(),
            version: Default::default(),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ReputationPolicy {
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub fast_pass: String,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub penalty_box: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct EgressPolicy {
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub lockdown: String,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub lockdown_pps: i64,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub grace_millis: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Steering {
    #[serde(deserialize_with = "null_default")]
    pub prefix: String,
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub regions: Vec<String>,
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub communities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Node {
    #[serde(deserialize_with = "null_default")]
    pub id: String,
    #[serde(deserialize_with = "null_default")]
    pub name: String,
    #[serde(deserialize_with = "null_default")]
    pub region: String,
    #[serde(deserialize_with = "null_default")]
    pub capacity_gbps: f64,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub capacity_pps: i64,
    #[serde(deserialize_with = "null_default")]
    pub backends: Vec<Stage>,
    #[serde(deserialize_with = "null_time")]
    pub last_seen: DateTime<Utc>,
    #[serde(deserialize_with = "null_default")]
    pub status: String,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub advertise: String,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub tunnel_src: String,
}
impl Default for Node {
    fn default() -> Self {
        Self {
            id: Default::default(),
            name: Default::default(),
            region: Default::default(),
            capacity_gbps: Default::default(),
            capacity_pps: Default::default(),
            backends: Vec::new(),
            last_seen: zero_time(),
            status: Default::default(),
            advertise: Default::default(),
            tunnel_src: Default::default(),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Tenant {
    #[serde(deserialize_with = "null_default")]
    pub id: String,
    #[serde(deserialize_with = "null_default")]
    pub name: String,
    #[serde(deserialize_with = "null_default")]
    pub prefixes: Vec<String>,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub contact: String,
    #[serde(deserialize_with = "null_time")]
    pub created_at: DateTime<Utc>,
    #[serde(deserialize_with = "null_time")]
    pub updated_at: DateTime<Utc>,
}
impl Default for Tenant {
    fn default() -> Self {
        Self {
            id: Default::default(),
            name: Default::default(),
            prefixes: Vec::new(),
            contact: Default::default(),
            created_at: zero_time(),
            updated_at: zero_time(),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Serialize, Default)]
#[serde(default)]
pub struct Flow {
    pub src_ip: String,
    pub dst_ip: String,
    pub proto: String,
    pub sport: i64,
    pub dport: i64,
    #[serde(skip_serializing_if = "is_zero")]
    pub flags: String,
    pub pps: i64,
    #[serde(with = "base64_bytes", skip_serializing_if = "is_zero")]
    pub payload: Vec<u8>,
    #[serde(skip)]
    pub has_payload: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Decision {
    #[serde(deserialize_with = "null_default")]
    pub action: Action,
    #[serde(deserialize_with = "null_default")]
    pub stage: Stage,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub rule_id: String,
    #[serde(deserialize_with = "null_default")]
    pub reason: String,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub node_id: String,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub score: f64,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub filter: String,
    #[serde(with = "base64_bytes", skip_serializing_if = "is_zero")]
    pub reply: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ACLEntry {
    #[serde(deserialize_with = "null_default")]
    pub priority: i64,
    #[serde(deserialize_with = "null_default")]
    pub action: Action,
    pub r#match: Match,
    #[serde(deserialize_with = "null_default")]
    pub rule_id: String,
    #[serde(deserialize_with = "null_default")]
    pub tcam_key: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct FPGAEntry {
    #[serde(deserialize_with = "null_default")]
    pub table: String,
    #[serde(deserialize_with = "null_default")]
    pub priority: i64,
    pub r#match: Match,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub meter_pps: i64,
    #[serde(deserialize_with = "null_default")]
    pub action: Action,
    #[serde(deserialize_with = "null_default")]
    pub rule_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ZCEntry {
    #[serde(deserialize_with = "null_default")]
    pub cluster: String,
    #[serde(deserialize_with = "null_default")]
    pub priority: i64,
    pub r#match: Match,
    #[serde(deserialize_with = "null_default")]
    pub action: Action,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub pps: i64,
    #[serde(deserialize_with = "null_default")]
    pub rule_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Program {
    #[serde(deserialize_with = "null_default")]
    pub node_id: String,
    #[serde(deserialize_with = "null_default")]
    pub policy_id: String,
    #[serde(deserialize_with = "null_default")]
    pub version: i64,
    #[serde(deserialize_with = "null_default")]
    pub prefixes: Vec<String>,
    #[serde(deserialize_with = "null_default")]
    pub asic: Vec<ACLEntry>,
    #[serde(deserialize_with = "null_default")]
    pub fpga: Vec<FPGAEntry>,
    #[serde(deserialize_with = "null_default")]
    pub zc: Vec<ZCEntry>,
    #[serde(deserialize_with = "null_default")]
    pub announcements: Vec<Announcement>,
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub games: Vec<GameFilter>,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub challenge_secret: String,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub pulse_floor_pps: i64,
    #[serde(skip_serializing_if = "is_zero")]
    pub reputation: Option<ReputationPolicy>,
    #[serde(skip_serializing_if = "is_zero")]
    pub egress: Option<EgressPolicy>,
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub tunnels: Vec<NodeTunnel>,
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub sessions: Vec<Session>,
    /// The node's own address for tunnels and customer peering, as the control plane holds it.
    /// An operator can reassign it at any time, so the agent takes it from here rather than from
    /// what it registered with.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub tunnel_src: String,
    #[serde(deserialize_with = "null_time")]
    pub compiled_at: DateTime<Utc>,
}
impl Default for Program {
    fn default() -> Self {
        Self {
            node_id: Default::default(),
            policy_id: Default::default(),
            version: Default::default(),
            prefixes: Vec::new(),
            asic: Vec::new(),
            fpga: Vec::new(),
            zc: Vec::new(),
            announcements: Vec::new(),
            games: Vec::new(),
            challenge_secret: Default::default(),
            pulse_floor_pps: Default::default(),
            reputation: None,
            egress: None,
            tunnels: Vec::new(),
            sessions: Vec::new(),
            tunnel_src: Default::default(),
            compiled_at: zero_time(),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct NodeTunnel {
    #[serde(deserialize_with = "null_default")]
    pub id: String,
    #[serde(deserialize_with = "null_default")]
    pub r#type: String,
    #[serde(deserialize_with = "null_default")]
    pub local: String,
    #[serde(deserialize_with = "null_default")]
    pub remote: String,
    #[serde(deserialize_with = "null_default")]
    pub prefixes: Vec<String>,
    #[serde(deserialize_with = "null_default")]
    pub mtu: i64,
    #[serde(deserialize_with = "null_default")]
    pub mss_clamp: i64,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub key: u32,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub required: bool,
    #[serde(deserialize_with = "null_default")]
    pub interface: String,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub comment: String,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub direction: String,
    /// This node's share of the tunnel's clean-traffic allowance, in kbit/s.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub rate_kbps: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct GameFilter {
    #[serde(deserialize_with = "null_default")]
    pub id: String,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub dst_cidr: String,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub proto: String,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub dport: i64,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub profile: String,
    #[serde(skip_serializing_if = "is_zero")]
    pub custom: Option<GameSignature>,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub observe: bool,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub comment: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct GameSignature {
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub min_len: i64,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub max_len: i64,
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub packet_ids: Vec<i64>,
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub magic: Vec<GameMagic>,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub gate: String,
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub opener_ids: Vec<i64>,
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub complete_ids: Vec<i64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct GameMagic {
    #[serde(deserialize_with = "null_default")]
    pub offset: i64,
    #[serde(deserialize_with = "null_default")]
    pub hex: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Tunnel {
    #[serde(deserialize_with = "null_default")]
    pub id: String,
    #[serde(deserialize_with = "null_default")]
    pub prefixes: Vec<String>,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub r#type: String,
    #[serde(deserialize_with = "null_default")]
    pub remote: String,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub mtu: i64,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub mss_clamp: i64,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub key: u32,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub required: bool,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub comment: String,
    /// "both" (the default when empty): clean traffic goes to the customer through the tunnel
    /// and the customer's replies come back up it to the node. "return": the tunnel only
    /// carries clean traffic out, and replies leave the customer directly.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub direction: String,
    /// Node ids that must not build this tunnel; they withdraw its prefixes instead.
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub disabled: Vec<String>,
    /// The customer (tenant id) this tunnel is allocated to. Its prefixes must be the tenant's.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub tenant: String,
    /// Clean traffic allowed down this tunnel in Mbit/s, summed across every node sending it.
    /// Zero takes the maximum, tunnel::MAX_RATE_MBPS.
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub rate_mbps: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Session {
    #[serde(deserialize_with = "null_default")]
    pub id: String,
    #[serde(deserialize_with = "null_default")]
    pub peer_ip: String,
    #[serde(deserialize_with = "null_default")]
    pub peer_as: i64,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub local_as: i64,
    #[serde(deserialize_with = "null_default")]
    pub prefixes: Vec<String>,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub max_prefixes: i64,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub password: String,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub multihop: i64,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub passive: bool,
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub nodes: Vec<String>,
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub regions: Vec<String>,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub comment: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct TunnelStatus {
    #[serde(deserialize_with = "null_default")]
    pub tunnel_id: String,
    #[serde(deserialize_with = "null_default")]
    pub state: String,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub detail: String,
    #[serde(default = "zero_time")]
    #[serde(deserialize_with = "null_time")]
    pub reported_at: DateTime<Utc>,
}
impl Default for TunnelStatus {
    fn default() -> Self {
        Self {
            tunnel_id: Default::default(),
            state: Default::default(),
            detail: Default::default(),
            reported_at: zero_time(),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct SourceReputation {
    #[serde(deserialize_with = "null_default")]
    pub source: String,
    #[serde(deserialize_with = "null_default")]
    pub state: String,
    #[serde(deserialize_with = "null_default")]
    pub proof: String,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub expires_in_seconds: f64,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub level: i64,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub strikes: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Announcement {
    #[serde(deserialize_with = "null_default")]
    pub prefix: String,
    #[serde(deserialize_with = "null_default")]
    pub node_id: String,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub node_name: String,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub region: String,
    #[serde(deserialize_with = "null_default")]
    pub state: AnnounceState,
    #[serde(deserialize_with = "null_default")]
    pub prepends: i64,
    #[serde(deserialize_with = "null_default", skip_serializing_if = "is_zero")]
    pub communities: Vec<String>,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(deserialize_with = "null_default")]
    pub next_hop: String,
    #[serde(deserialize_with = "null_default")]
    pub reason: String,
}

mod base64_bytes {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let v = Option::<String>::deserialize(d)?;
        v.map(|v| STANDARD.decode(v).map_err(serde::de::Error::custom))
            .unwrap_or_else(|| Ok(Vec::new()))
    }
}

fn null_time<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<DateTime<Utc>, D::Error> {
    Ok(Option::<DateTime<Utc>>::deserialize(d)?.unwrap_or_else(zero_time))
}

impl<'de> Deserialize<'de> for Flow {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Wire {
            #[serde(deserialize_with = "null_default")]
            src_ip: String,
            #[serde(deserialize_with = "null_default")]
            dst_ip: String,
            #[serde(deserialize_with = "null_default")]
            proto: String,
            #[serde(deserialize_with = "null_default")]
            sport: i64,
            #[serde(deserialize_with = "null_default")]
            dport: i64,
            #[serde(deserialize_with = "null_default")]
            flags: String,
            #[serde(deserialize_with = "null_default")]
            pps: i64,
            payload: Option<String>,
        }
        use base64::Engine;
        let w = Wire::deserialize(d)?;
        let has_payload = w.payload.is_some();
        let payload = w
            .payload
            .map(|p| {
                base64::engine::general_purpose::STANDARD
                    .decode(p)
                    .map_err(serde::de::Error::custom)
            })
            .transpose()?
            .unwrap_or_default();
        Ok(Self {
            src_ip: w.src_ip,
            dst_ip: w.dst_ip,
            proto: w.proto,
            sport: w.sport,
            dport: w.dport,
            flags: w.flags,
            pps: w.pps,
            payload,
            has_payload,
        })
    }
}

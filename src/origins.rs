use crate::{model::Program, Result};
use maxminddb::Reader;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs::File,
    io::Read,
    net::IpAddr,
};

pub const PREFIXES_MAX: usize = 128;
pub const COUNTRIES_MAX: usize = 64;
pub const LOOKUPS_PER_SECOND: u32 = 2000;
pub const SAMPLE_EVERY: u32 = 128;
const SAFE: u64 = 9_007_199_254_740_991;
const DB_MAX: u64 = 64 * 1024 * 1024;
fn add(a: u64, b: u64) -> u64 {
    a.saturating_add(b).min(SAFE)
}
fn generation() -> String {
    format!("{:032x}", rand::random::<u128>())
}
fn valid_generation(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|c| c.is_ascii_hexdigit())
}
fn country(value: &str) -> bool {
    value.len() == 2
        && value.bytes().all(|c| c.is_ascii_uppercase())
        && !matches!(value, "XX" | "ZZ")
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Location {
    pub longitude: f64,
    pub latitude: f64,
    pub label: String,
}
impl Location {
    pub fn parse(longitude: &str, latitude: &str, label: &str) -> Result<Option<Self>> {
        if longitude.is_empty() && latitude.is_empty() && label.is_empty() {
            return Ok(None);
        }
        let value = Self {
            longitude: longitude
                .parse()
                .map_err(|_| "origin longitude must be a number")?,
            latitude: latitude
                .parse()
                .map_err(|_| "origin latitude must be a number")?,
            label: label.into(),
        };
        if !value.valid() {
            return Err(
                "origin location requires valid longitude, latitude and a label of 1..80 bytes"
                    .into(),
            );
        }
        Ok(Some(value))
    }
    fn valid(&self) -> bool {
        self.longitude.is_finite()
            && self.latitude.is_finite()
            && (-180.0..=180.0).contains(&self.longitude)
            && (-90.0..=90.0).contains(&self.latitude)
            && !self.label.trim().is_empty()
            && self.label.len() <= 80
            && !self.label.chars().any(char::is_control)
    }
}
#[derive(Deserialize)]
struct GeoRecord {
    country: Option<GeoCountry>,
}
#[derive(Deserialize)]
struct GeoCountry {
    iso_code: Option<String>,
}
pub struct CountryDb(Reader<Vec<u8>>);
impl CountryDb {
    pub fn open(path: &str) -> Result<Self> {
        let file = File::open(path)
            .map_err(|error| format!("opening origin country database: {error}"))?;
        let mut bytes = Vec::new();
        file.take(DB_MAX + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("reading origin country database: {error}"))?;
        if bytes.len() as u64 > DB_MAX {
            return Err("origin country database exceeds 64 MiB".into());
        }
        Reader::from_source(bytes)
            .map(Self)
            .map_err(|error| format!("invalid origin country database: {error}"))
    }
    pub fn lookup(&self, ip: IpAddr) -> Option<String> {
        self.0
            .lookup::<GeoRecord>(ip)
            .ok()
            .flatten()?
            .country?
            .iso_code
            .filter(|value| country(value))
    }
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PrefixCounts {
    pub prefix: String,
    pub generation: String,
    pub countries: BTreeMap<String, u64>,
    pub unknown: u64,
}
impl PrefixCounts {
    fn record(&mut self, code: Option<String>) {
        if let Some(code) = code.filter(|value| country(value)) {
            if self.countries.contains_key(&code) || self.countries.len() < COUNTRIES_MAX {
                let value = self.countries.entry(code).or_default();
                *value = add(*value, 1);
                return;
            }
        }
        self.unknown = add(self.unknown, 1);
    }
    fn valid(&self) -> bool {
        self.prefix.len() <= 49
            && self.prefix.parse::<ipnet::IpNet>().is_ok()
            && valid_generation(&self.generation)
            && self.countries.len() <= COUNTRIES_MAX
            && self.unknown <= SAFE
            && self
                .countries
                .values()
                .try_fold(self.unknown, |total, value| total.checked_add(*value))
                .is_some_and(|total| total <= SAFE)
            && self
                .countries
                .iter()
                .all(|(code, count)| country(code) && *count <= SAFE)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub epoch: String,
    pub provider: String,
    pub destination: Option<Location>,
    pub prefixes: Vec<PrefixCounts>,
    pub limited: u64,
}
impl Report {
    fn valid(&self) -> bool {
        valid_generation(&self.epoch)
            && matches!(self.provider.as_str(), "dbip" | "maxmind" | "custom")
            && self.destination.as_ref().is_none_or(Location::valid)
            && self.prefixes.len() <= PREFIXES_MAX
            && self.prefixes.iter().all(PrefixCounts::valid)
            && self
                .prefixes
                .iter()
                .map(|row| &row.prefix)
                .collect::<HashSet<_>>()
                .len()
                == self.prefixes.len()
    }
}
pub struct Sampler {
    db: CountryDb,
    report: Report,
    counts: BTreeMap<String, PrefixCounts>,
    second: i64,
    lookups: u32,
    rng: rand::rngs::StdRng,
}
impl Sampler {
    pub fn open(path: &str, provider: &str, destination: Option<Location>) -> Result<Self> {
        if !matches!(provider, "dbip" | "maxmind" | "custom") {
            return Err("origin-country-provider must be dbip, maxmind or custom".into());
        }
        Ok(Self {
            db: CountryDb::open(path)?,
            report: Report {
                epoch: generation(),
                provider: provider.into(),
                destination,
                prefixes: vec![],
                limited: 0,
            },
            counts: BTreeMap::new(),
            second: 0,
            lookups: 0,
            rng: rand::rngs::StdRng::from_entropy(),
        })
    }
    #[cfg(test)]
    pub(crate) fn test_seed(&mut self, seed: u64) {
        self.rng = rand::rngs::StdRng::seed_from_u64(seed);
    }
    pub fn retain(&mut self, program: &Program) {
        self.counts
            .retain(|prefix, _| program.prefixes.contains(prefix));
    }
    pub fn select(&mut self, now: i64) -> bool {
        if self.second != now / 1000 {
            self.second = now / 1000;
            self.lookups = 0;
        }
        if self.lookups >= LOOKUPS_PER_SECOND {
            self.report.limited = add(self.report.limited, 1);
            return false;
        }
        if !self.rng.gen_ratio(1, SAMPLE_EVERY) {
            return false;
        }
        self.lookups += 1;
        true
    }
    pub fn observe_drop(&mut self, prefix: &str, source: &str) {
        if !self.counts.contains_key(prefix) && self.counts.len() >= PREFIXES_MAX {
            self.report.limited = add(self.report.limited, 1);
            return;
        }
        let code = source.parse().ok().and_then(|ip| self.db.lookup(ip));
        self.counts
            .entry(prefix.into())
            .or_insert_with(|| PrefixCounts {
                prefix: prefix.into(),
                generation: generation(),
                ..Default::default()
            })
            .record(code);
    }
    pub fn report(&self) -> Report {
        Report {
            prefixes: self.counts.values().cloned().collect(),
            ..self.report.clone()
        }
    }
}
#[derive(Clone)]
struct Baseline {
    at: i64,
    counts: PrefixCounts,
}
#[derive(Default)]
pub struct Baselines {
    nodes: HashMap<String, (Report, HashMap<String, Baseline>)>,
}
pub struct Delta {
    pub prefix: String,
    pub since: i64,
    pub counts: PrefixCounts,
    pub provider: String,
    pub destination: Option<Location>,
}
impl Baselines {
    pub fn forget(&mut self, live: &HashSet<String>) {
        for (_, rows) in self.nodes.values_mut() {
            rows.retain(|prefix, _| live.contains(prefix));
        }
    }
    pub fn forget_node(&mut self, node: &str) {
        self.nodes.remove(node);
    }
    pub fn observe(
        &mut self,
        node: &str,
        report: Option<&Report>,
        allowed: &HashSet<String>,
        now: i64,
    ) -> Vec<Delta> {
        let Some(report) = report.filter(|report| report.valid()) else {
            self.nodes.remove(node);
            return vec![];
        };
        let (prior, mut before) = self
            .nodes
            .remove(node)
            .unwrap_or_else(|| (report.clone(), HashMap::new()));
        if before.values().any(|row| row.at >= now) {
            self.nodes.insert(node.into(), (prior, before));
            return vec![];
        }
        if prior.epoch != report.epoch
            || prior.provider != report.provider
            || prior.destination != report.destination
        {
            before.clear();
        }
        let mut next = HashMap::new();
        let mut deltas = Vec::new();
        for row in report
            .prefixes
            .iter()
            .filter(|row| allowed.contains(&row.prefix))
        {
            if let Some(old) = before.remove(&row.prefix).filter(|old| {
                old.counts.generation == row.generation
                    && now - old.at <= 30000
                    && row.unknown >= old.counts.unknown
                    && old.counts.countries.iter().all(|(code, count)| {
                        row.countries.get(code).is_some_and(|value| value >= count)
                    })
            }) {
                let countries = row
                    .countries
                    .iter()
                    .map(|(code, count)| {
                        (
                            code.clone(),
                            count.saturating_sub(
                                old.counts.countries.get(code).copied().unwrap_or(0),
                            ),
                        )
                    })
                    .collect();
                deltas.push(Delta {
                    prefix: row.prefix.clone(),
                    since: old.at,
                    counts: PrefixCounts {
                        prefix: row.prefix.clone(),
                        generation: row.generation.clone(),
                        countries,
                        unknown: row.unknown - old.counts.unknown,
                    },
                    provider: report.provider.clone(),
                    destination: report.destination.clone(),
                });
            }
            next.insert(
                row.prefix.clone(),
                Baseline {
                    at: now,
                    counts: row.clone(),
                },
            );
        }
        self.nodes.insert(
            node.into(),
            (
                Report {
                    prefixes: vec![],
                    ..report.clone()
                },
                next,
            ),
        );
        deltas
    }
}
#[derive(Default, Clone)]
pub struct EventOrigins {
    countries: BTreeMap<String, u64>,
    unknown: u64,
    samples: u64,
    providers: HashSet<String>,
    destination: Option<Location>,
    location_seen: bool,
    location_conflict: bool,
}
impl EventOrigins {
    pub fn merge(&mut self, delta: Delta) {
        let total = delta
            .counts
            .countries
            .values()
            .copied()
            .fold(delta.counts.unknown, add);
        if total == 0 || total > SAFE.saturating_sub(self.samples) {
            return;
        }
        self.samples = add(self.samples, total);
        self.unknown = add(self.unknown, delta.counts.unknown);
        for (code, count) in delta.counts.countries {
            if self.countries.contains_key(&code) || self.countries.len() < COUNTRIES_MAX {
                let value = self.countries.entry(code).or_default();
                *value = add(*value, count);
            } else {
                self.unknown = add(self.unknown, count);
            }
        }
        self.providers.insert(delta.provider);
        if self.location_seen && self.destination != delta.destination {
            self.location_conflict = true;
        }
        if !self.location_seen {
            self.destination = delta.destination;
            self.location_seen = true;
        }
    }
    pub fn render(&self) -> Option<serde_json::Value> {
        if self.samples == 0 {
            return None;
        }
        let countries: Vec<_> = self
            .countries
            .iter()
            .filter(|(_, count)| **count > 0)
            .map(|(code, count)| serde_json::json!({"code":code,"packets":count,"sourceIps":null}))
            .collect();
        let mut providers: Vec<_> = self.providers.iter().collect();
        providers.sort();
        Some(
            serde_json::json!({"basis":"sampled_packets","scope":"inline_game_drop_decisions","providers":providers,"countries":countries,"unknownPackets":self.unknown,"destination":if self.location_conflict {None} else {self.destination.as_ref()}}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> String {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let path = root.join("tests/data/GeoIP2-Country-Test.mmdb");
        if path.exists() {
            path
        } else {
            root.join("../tests/data/GeoIP2-Country-Test.mmdb")
        }
        .to_string_lossy()
        .into_owned()
    }
    fn report(count: u64) -> Report {
        Report {
            epoch: "a".repeat(32),
            provider: "dbip".into(),
            destination: None,
            limited: 0,
            prefixes: vec![PrefixCounts {
                prefix: "203.0.113.0/24".into(),
                generation: "b".repeat(32),
                countries: [("GB".into(), count)].into(),
                unknown: count / 2,
            }],
        }
    }
    fn allowed() -> HashSet<String> {
        ["203.0.113.0/24".into()].into()
    }
    #[test]
    fn actual_mmdb_lookup_handles_v4_v6_and_missing_addresses() {
        let db = CountryDb::open(&fixture()).unwrap();
        assert_eq!(
            db.lookup("81.2.69.160".parse().unwrap()).as_deref(),
            Some("GB")
        );
        assert_eq!(
            db.lookup("2001:218::".parse().unwrap()).as_deref(),
            Some("JP")
        );
        assert_eq!(db.lookup("10.0.0.1".parse().unwrap()), None);
        assert!(CountryDb::open("/nonexistent/pathfinder-country.mmdb").is_err());
    }
    #[test]
    fn location_and_provider_configuration_are_explicit() {
        assert_eq!(Location::parse("", "", "").unwrap(), None);
        assert!(Location::parse("-78.87", "42.89", "Buffalo")
            .unwrap()
            .is_some());
        assert!(Location::parse("NaN", "42", "Buffalo").is_err());
        assert!(Location::parse("181", "42", "Buffalo").is_err());
        assert!(Location::parse("1", "", "").is_err());
        assert!(Sampler::open(&fixture(), "unverified", None).is_err());
    }
    #[test]
    fn sampling_is_bounded_and_keeps_unknown_countries() {
        let mut sampler = Sampler::open(&fixture(), "maxmind", None).unwrap();
        sampler.rng = rand::rngs::StdRng::seed_from_u64(71);
        let selected = (0..12800).filter(|_| sampler.select(1000)).count();
        assert!((50..150).contains(&selected));
        sampler.lookups = LOOKUPS_PER_SECOND;
        for _ in 0..100 {
            assert!(!sampler.select(1000));
        }
        assert_eq!(sampler.report().limited, 100);
        sampler.observe_drop("203.0.113.0/24", "81.2.69.160");
        sampler.observe_drop("203.0.113.0/24", "10.0.0.1");
        let report = sampler.report();
        assert_eq!(report.prefixes[0].countries["GB"], 1);
        assert_eq!(report.prefixes[0].unknown, 1);
        assert!(!serde_json::to_string(&report)
            .unwrap()
            .contains("81.2.69.160"));
        sampler.retain(&Program::default());
        assert!(sampler.report().prefixes.is_empty());
    }
    #[test]
    fn country_overflow_becomes_unknown_instead_of_growing_without_bound() {
        let mut counts = PrefixCounts::default();
        for a in b'A'..=b'Z' {
            for b in b'A'..=b'Z' {
                counts.record(Some(String::from_utf8(vec![a, b]).unwrap()));
            }
        }
        assert_eq!(counts.countries.len(), COUNTRIES_MAX);
        assert_eq!(counts.countries.values().sum::<u64>() + counts.unknown, 676);
    }
    #[test]
    fn repeated_heartbeats_and_counter_resets_do_not_double_count() {
        let mut baselines = Baselines::default();
        assert!(baselines
            .observe("n", Some(&report(10)), &allowed(), 1000)
            .is_empty());
        let delta = baselines
            .observe("n", Some(&report(20)), &allowed(), 2000)
            .pop()
            .unwrap();
        assert_eq!(delta.counts.countries["GB"], 10);
        assert_eq!(delta.counts.unknown, 5);
        assert_eq!(
            baselines.observe("n", Some(&report(20)), &allowed(), 3000)[0]
                .counts
                .countries["GB"],
            0
        );
        assert!(baselines
            .observe("n", Some(&report(2)), &allowed(), 4000)
            .is_empty());
        assert_eq!(
            baselines.observe("n", Some(&report(4)), &allowed(), 5000)[0]
                .counts
                .countries["GB"],
            2
        );
        let mut restarted = report(1000);
        restarted.epoch = "c".repeat(32);
        assert!(baselines
            .observe("n", Some(&restarted), &allowed(), 6000)
            .is_empty());
    }
    #[test]
    fn stale_intervals_unowned_prefixes_and_invalid_reports_are_excluded() {
        let mut baselines = Baselines::default();
        baselines.observe("n", Some(&report(10)), &allowed(), 1000);
        assert!(baselines
            .observe("n", Some(&report(100)), &allowed(), 40000)
            .is_empty());
        assert!(baselines
            .observe("n", Some(&report(200)), &HashSet::new(), 41000)
            .is_empty());
        let mut invalid = report(300);
        invalid.prefixes.push(invalid.prefixes[0].clone());
        assert!(baselines
            .observe("n", Some(&invalid), &allowed(), 42000)
            .is_empty());
        assert!(baselines.nodes.is_empty());
    }
    #[test]
    fn out_of_order_reports_cannot_roll_back_a_baseline() {
        let mut baselines = Baselines::default();
        baselines.observe("n", Some(&report(10)), &allowed(), 1000);
        baselines.observe("n", Some(&report(20)), &allowed(), 3000);
        assert!(baselines
            .observe("n", Some(&report(15)), &allowed(), 2000)
            .is_empty());
        assert_eq!(
            baselines.observe("n", Some(&report(30)), &allowed(), 4000)[0]
                .counts
                .countries["GB"],
            10
        );
    }
    #[test]
    fn mixed_destination_samples_do_not_claim_a_single_location() {
        let mut baselines = Baselines::default();
        baselines.observe("n", Some(&report(0)), &allowed(), 1000);
        let delta = baselines
            .observe("n", Some(&report(10)), &allowed(), 2000)
            .pop()
            .unwrap();
        let mut event = EventOrigins::default();
        event.merge(delta);
        let mut delta = baselines
            .observe("n", Some(&report(20)), &allowed(), 3000)
            .pop()
            .unwrap();
        delta.destination = Location::parse("-78.87", "42.89", "Buffalo").unwrap();
        event.merge(delta);
        let rendered = event.render().unwrap();
        assert_eq!(rendered["destination"], serde_json::Value::Null);
        assert_eq!(
            rendered["countries"][0]["sourceIps"],
            serde_json::Value::Null
        );
        assert_eq!(rendered["scope"], "inline_game_drop_decisions");
        assert_eq!(rendered["providers"], serde_json::json!(["dbip"]));
    }
}

//! Load-driven AS-path padding, with hysteresis and minimum dwell.
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
pub const HIGH_WATERMARK: f64 = 0.80;
pub const LOW_WATERMARK: f64 = 0.50;
pub const MIN_DWELL: Duration = Duration::seconds(30);
pub const MAX_ESCALATION: i64 = 3;
pub const REPORT_FRESHNESS: Duration = Duration::seconds(15);
#[derive(Debug, Clone, Default)]
pub struct Sample {
    pub node_id: String,
    pub offered_pps: u64,
    pub capacity_pps: i64,
    pub fresh: bool,
    pub pulsing: bool,
    pub peak_pps: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Level {
    pub prepends: i64,
    pub ratio: f64,
    pub reason: String,
    pub changed_at: DateTime<Utc>,
}
impl Default for Level {
    fn default() -> Self {
        Self {
            prepends: 0,
            ratio: 0.0,
            reason: "no load measured yet".into(),
            changed_at: crate::model::zero_time(),
        }
    }
}
#[derive(Default)]
pub struct Controller {
    levels: HashMap<String, Level>,
}
impl Controller {
    pub fn levels(&self) -> HashMap<String, Level> {
        self.levels.clone()
    }
    pub fn observe(&mut self, samples: &[Sample]) -> HashMap<String, i64> {
        self.observe_at(samples, Utc::now())
    }
    pub fn observe_at(&mut self, samples: &[Sample], now: DateTime<Utc>) -> HashMap<String, i64> {
        let mut next = HashMap::new();
        let mut out = HashMap::new();
        for s in samples {
            let mut level = self.levels.get(&s.node_id).cloned().unwrap_or_default();
            apply(&mut level, s, now);
            out.insert(s.node_id.clone(), level.prepends);
            next.insert(s.node_id.clone(), level);
        }
        self.levels = next;
        out
    }
}
fn apply(l: &mut Level, s: &Sample, now: DateTime<Utc>) {
    if !s.fresh {
        l.reason = "holding: no recent counters from this node".into();
        return;
    }
    if s.capacity_pps <= 0 {
        l.ratio = 0.0;
        l.reason = "holding: node reports no packet-rate capacity to measure against".into();
        return;
    }
    let measured = if s.pulsing {
        s.offered_pps.max(s.peak_pps)
    } else {
        s.offered_pps
    };
    l.ratio = measured as f64 / s.capacity_pps as f64;
    let mut want = l.prepends;
    if l.ratio >= HIGH_WATERMARK {
        want += 1;
    } else if l.ratio <= LOW_WATERMARK {
        if s.pulsing {
            l.reason = format!(
                "holding {}: under a burst train, peak {} of {} pps",
                l.prepends, s.peak_pps, s.capacity_pps
            );
            return;
        }
        want -= 1;
    }
    want = want.clamp(0, MAX_ESCALATION);
    if want == l.prepends {
        let what = if s.pulsing { "burst peak" } else { "load" };
        l.reason = if want == 0 {
            format!(
                "{what} is {:.0}% of capacity, inside the band",
                l.ratio * 100.0
            )
        } else {
            format!(
                "holding {}: {what} is {:.0}% of capacity",
                l.prepends,
                l.ratio * 100.0
            )
        };
        return;
    }
    if now.signed_duration_since(l.changed_at) < MIN_DWELL {
        l.reason = format!(
            "holding {}: load is {:.0}% but the level changed less than 30s ago",
            l.prepends,
            l.ratio * 100.0
        );
        return;
    }
    l.reason = if want > l.prepends {
        if s.pulsing {
            format!(
                "shedding: burst train peaking at {:.0}% of capacity, above the 80% mark",
                l.ratio * 100.0
            )
        } else {
            format!(
                "shedding: load is {:.0}% of capacity, above the 80% mark",
                l.ratio * 100.0
            )
        }
    } else {
        format!(
            "recovering: load is {:.0}% of capacity, below the 50% mark",
            l.ratio * 100.0
        )
    };
    l.prepends = want;
    l.changed_at = now;
}

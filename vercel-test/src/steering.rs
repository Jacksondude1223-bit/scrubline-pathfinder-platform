//! Load-driven AS-path padding, with hysteresis and minimum dwell.
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
pub const HIGH_WATERMARK: f64 = 0.80;
pub const LOW_WATERMARK: f64 = 0.50;
pub const MIN_DWELL: Duration = Duration::seconds(30);
/// Load at which a node is losing more traffic than waiting out the dwell is worth: at twice its
/// capacity or more, it pads again EXTREME_DWELL after the last change instead of MIN_DWELL.
pub const EXTREME_LOAD: f64 = 2.0;
pub const EXTREME_DWELL: Duration = Duration::seconds(5);
pub const MAX_ESCALATION: i64 = 3;
pub const REPORT_FRESHNESS: Duration = Duration::seconds(15);
/// How long the fabric keeps helping a node with its pinned customers after it was last measured
/// overloaded. Help moves traffic off it, which brings its load down; ending help the moment it
/// recovers would put the traffic straight back and flap the routes with every swing.
pub const OVERFLOW_HOLD: Duration = Duration::minutes(5);
#[derive(Debug, Clone, Default)]
pub struct Sample {
    pub node_id: String,
    pub offered_pps: u64,
    /// The rate over the last second, which reaches a flood's level within a second where the
    /// ten-second mean in offered_pps takes ten.
    pub surge_pps: u64,
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
        // A node that declares no ceiling is never padded for load, including padding it earned
        // before it stopped declaring one.
        l.ratio = 0.0;
        if l.prepends != 0 {
            l.prepends = 0;
            l.changed_at = now;
        }
        l.reason = "not padded for load: node reports no packet-rate capacity".into();
        return;
    }
    let steady = if s.pulsing {
        s.offered_pps.max(s.peak_pps)
    } else {
        s.offered_pps
    };
    // Shedding goes by the higher of the two rates, so it starts on the last second's, and
    // recovery waits for both to fall, so it ends on the ten-second mean.
    let surging = s.surge_pps > steady;
    l.ratio = steady.max(s.surge_pps) as f64 / s.capacity_pps as f64;
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
        let what = if surging {
            "the last second's load"
        } else if s.pulsing {
            "burst peak"
        } else {
            "load"
        };
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
    let dwell = if want > l.prepends && l.ratio >= EXTREME_LOAD {
        EXTREME_DWELL
    } else {
        MIN_DWELL
    };
    if now.signed_duration_since(l.changed_at) < dwell {
        l.reason = format!(
            "holding {}: load is {:.0}% but the level changed less than {}s ago",
            l.prepends,
            l.ratio * 100.0,
            dwell.num_seconds()
        );
        return;
    }
    l.reason = if want > l.prepends {
        if surging {
            format!(
                "shedding: the last second's load is {:.0}% of capacity, above the 80% mark",
                l.ratio * 100.0
            )
        } else if s.pulsing {
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
#[cfg(test)]
mod tests {
    use super::*;
    fn at(seconds: i64) -> DateTime<Utc> {
        "2026-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap() + Duration::seconds(seconds)
    }
    /// One round for a node that takes 1,000 pps.
    fn step(c: &mut Controller, seconds: i64, offered_pps: u64, surge_pps: u64) -> Level {
        let s = Sample {
            node_id: "n".into(),
            offered_pps,
            surge_pps,
            capacity_pps: 1000,
            fresh: true,
            ..Default::default()
        };
        c.observe_at(&[s], at(seconds));
        c.levels()["n"].clone()
    }
    #[test]
    fn a_surge_sheds_before_the_mean_shows_it_and_recovery_waits_for_both() {
        let mut c = Controller::default();
        // A second into a flood at 1.5 times capacity, the mean has a tenth of it.
        let l = step(&mut c, 0, 150, 1500);
        assert_eq!(
            (l.prepends, l.reason.as_str()),
            (
                1,
                "shedding: the last second's load is 150% of capacity, above the 80% mark"
            )
        );
        // Below twice capacity the next step waits out the usual dwell.
        let l = step(&mut c, 10, 1500, 1500);
        assert_eq!(l.prepends, 1);
        assert!(l.reason.ends_with("less than 30s ago"), "{}", l.reason);
        // The flood is over within the last second, but the mean still carries it.
        let l = step(&mut c, 40, 600, 0);
        assert_eq!(
            (l.prepends, l.reason.as_str()),
            (1, "holding 1: load is 60% of capacity")
        );
        // The mean has come down, but the last second has not.
        let l = step(&mut c, 50, 400, 600);
        assert_eq!(
            (l.prepends, l.reason.as_str()),
            (1, "holding 1: the last second's load is 60% of capacity")
        );
        let l = step(&mut c, 60, 400, 300);
        assert_eq!(
            (l.prepends, l.reason.as_str()),
            (0, "recovering: load is 40% of capacity, below the 50% mark")
        );
    }
    #[test]
    fn at_twice_capacity_or_more_each_step_waits_only_the_short_dwell() {
        let mut c = Controller::default();
        assert_eq!(step(&mut c, 0, 300, 3000).prepends, 1);
        let l = step(&mut c, 3, 1200, 3000);
        assert_eq!(
            (l.prepends, l.reason.as_str()),
            (
                1,
                "holding 1: load is 300% but the level changed less than 5s ago"
            )
        );
        assert_eq!(step(&mut c, 5, 1500, 3000).prepends, 2);
        assert_eq!(step(&mut c, 10, 2000, 3000).prepends, MAX_ESCALATION);
        assert_eq!(step(&mut c, 15, 3000, 3000).prepends, MAX_ESCALATION);
        // Recovery keeps the long dwell whatever the load was.
        let l = step(&mut c, 20, 100, 100);
        assert_eq!(l.prepends, MAX_ESCALATION);
        assert!(l.reason.ends_with("less than 30s ago"), "{}", l.reason);
        assert_eq!(step(&mut c, 40, 100, 100).prepends, MAX_ESCALATION - 1);
    }
}

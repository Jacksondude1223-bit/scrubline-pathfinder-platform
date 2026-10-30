//! Prometheus text exposition with stable series ordering and escaped labels.
use crate::Result;
use std::{
    collections::{BTreeMap, HashSet},
    fmt::Write,
};
pub const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";
#[derive(Debug, Clone, Default)]
pub struct Label {
    pub name: String,
    pub value: String,
}
#[derive(Debug, Clone, Default)]
pub struct Sample {
    pub labels: Vec<Label>,
    pub value: f64,
}
#[derive(Debug, Clone, Default)]
pub struct Family {
    pub name: String,
    pub help: String,
    pub kind: String,
    pub samples: Vec<Sample>,
}
fn valid_name(s: &str, colon: bool) -> bool {
    !s.is_empty()
        && s.bytes().enumerate().all(|(i, c)| {
            c.is_ascii_alphabetic()
                || c == b'_'
                || (colon && c == b':')
                || (i > 0 && c.is_ascii_digit())
        })
}
fn escape(s: &str, quote: bool) -> String {
    let s = s.replace('\\', "\\\\").replace('\n', "\\n");
    if quote {
        s.replace('"', "\\\"")
    } else {
        s
    }
}
fn label_key(s: &Sample) -> String {
    s.labels
        .iter()
        .map(|l| format!("{}\0{}\0", l.name, l.value))
        .collect()
}
pub fn render(families: &[Family]) -> Result<String> {
    let mut out = String::new();
    let mut seen = HashSet::new();
    for f in families {
        if f.samples.is_empty() {
            continue;
        }
        if !valid_name(&f.name, true) {
            return Err(format!("metrics: invalid metric name {:?}", f.name));
        }
        if !seen.insert(&f.name) {
            return Err(format!("metrics: duplicate metric family {:?}", f.name));
        }
        if !f.help.is_empty() {
            writeln!(out, "# HELP {} {}", f.name, escape(&f.help, false)).unwrap();
        }
        if !f.kind.is_empty() {
            writeln!(out, "# TYPE {} {}", f.name, f.kind).unwrap();
        }
        let mut samples: Vec<_> = f.samples.iter().collect();
        samples.sort_by_cached_key(|s| label_key(s));
        for s in samples {
            let mut labels = Vec::new();
            for l in &s.labels {
                if !valid_name(&l.name, false) {
                    return Err(format!(
                        "metrics: {}: invalid label name {:?}",
                        f.name, l.name
                    ));
                }
                labels.push(format!("{}=\"{}\"", l.name, escape(&l.value, true)));
            }
            let labels = if labels.is_empty() {
                String::new()
            } else {
                format!("{{{}}}", labels.join(","))
            };
            writeln!(out, "{}{labels} {}", f.name, value_text(s.value)).unwrap();
        }
    }
    Ok(out)
}

/// A family whose samples carry their labels already written out, `name="value",…`, for rendering
/// a fabric's worth of nodes at once. A sample's labels are the ones it shares with the rest of
/// what one source reported (which node it is), written once in a list kept beside the families,
/// and its own, written into one string the family keeps for all of them: one string a sample,
/// or a list of labels, would hold each node's labels again for every sample it reported.
#[derive(Debug, Clone, Default)]
pub struct Written {
    pub help: String,
    pub kind: String,
    own: String,
    samples: Vec<Entry>,
}
/// A sample: where its own labels are in its family's string, which shared labels it carries
/// (UNSHARED for none), and its value.
#[derive(Debug, Clone, Copy)]
struct Entry {
    start: usize,
    len: u32,
    shared: u32,
    value: f64,
}
/// What a sample sharing no labels gives as its shared ones.
pub const UNSHARED: u32 = u32::MAX;
impl Written {
    pub fn new(help: String, kind: String) -> Self {
        Self {
            help,
            kind,
            ..Default::default()
        }
    }
    /// Adds a sample carrying the shared labels at `shared` and `own`, written out.
    pub fn push(&mut self, shared: u32, own: &str, value: f64) {
        let start = self.own.len();
        self.own.push_str(own);
        self.samples.push(Entry {
            start,
            len: own.len() as u32,
            shared,
            value,
        });
    }
}
/// Appends a label to a sample's written labels, refusing a name Prometheus would.
pub fn write_label(out: &mut String, name: &str, value: &str) -> Result<()> {
    if !valid_name(name, false) {
        return Err(format!("metrics: invalid label name {name:?}"));
    }
    if !out.is_empty() {
        out.push(',');
    }
    write!(out, "{name}=\"{}\"", escape(value, true)).unwrap();
    Ok(())
}
/// Renders written families in name order, as render does a list of them, each sample's labels
/// the shared ones it carries then its own. Samples sort by their labels written out whole, a
/// stable an order as render keeps.
pub fn render_written(families: BTreeMap<String, Written>, shared: &[String]) -> Result<String> {
    // Room for all of it at once: a scrape of a whole fabric grown a line at a time would be
    // copied each time it doubled.
    let room: usize = families
        .iter()
        .filter(|(_, f)| !f.samples.is_empty())
        .map(|(name, f)| {
            let head = 2 * name.len() + 2 * f.help.len() + f.kind.len() + 20;
            let lines: usize = f
                .samples
                .iter()
                .map(|e| {
                    let common = shared.get(e.shared as usize).map_or(0, String::len);
                    name.len() + 3 + common + 1 + e.len as usize + 2 + value_room(e.value)
                })
                .sum();
            head + lines
        })
        .sum();
    let mut out = String::with_capacity(room);
    for (name, mut f) in families {
        if f.samples.is_empty() {
            continue;
        }
        if !valid_name(&name, true) {
            return Err(format!("metrics: invalid metric name {name:?}"));
        }
        if !f.help.is_empty() {
            writeln!(out, "# HELP {name} {}", escape(&f.help, false)).unwrap();
        }
        if !f.kind.is_empty() {
            writeln!(out, "# TYPE {name} {}", f.kind).unwrap();
        }
        let own = &f.own;
        let parts = |e: &Entry| {
            let common = shared.get(e.shared as usize).map_or("", String::as_str);
            let own = &own[e.start..e.start + e.len as usize];
            let comma = if common.is_empty() || own.is_empty() {
                ""
            } else {
                ","
            };
            (common, comma, own)
        };
        let whole = |e: &Entry| {
            let (common, comma, own) = parts(e);
            common.bytes().chain(comma.bytes()).chain(own.bytes())
        };
        f.samples.sort_by(|a, b| whole(a).cmp(whole(b)));
        for e in &f.samples {
            let value = value_text(e.value);
            match parts(e) {
                ("", _, "") => writeln!(out, "{name} {value}"),
                (common, comma, own) => writeln!(out, "{name}{{{common}{comma}{own}}} {value}"),
            }
            .unwrap();
        }
    }
    Ok(out)
}
/// At least as long as value_text(v): exact, but for a sign, for the small whole numbers most
/// samples are, and the longest a value is written for the rest.
fn value_room(v: f64) -> usize {
    if v.fract() == 0.0 && v.abs() < 1e6 {
        (v.abs() as u64)
            .checked_ilog10()
            .map_or(1, |d| d as usize + 1)
            + 1
    } else {
        24
    }
}
fn value_text(v: f64) -> String {
    if v.is_nan() {
        "NaN".into()
    } else if v == f64::INFINITY {
        "+Inf".into()
    } else if v == f64::NEG_INFINITY {
        "-Inf".into()
    } else {
        format_value(v)
    }
}
fn format_value(v: f64) -> String {
    let scientific = format!("{v:e}");
    let (mantissa, exponent) = scientific.split_once('e').unwrap();
    let exponent: i32 = exponent.parse().unwrap();
    if !(-4..6).contains(&exponent) {
        format!("{mantissa}e{exponent:+03}")
    } else {
        v.to_string()
    }
}

//! Prometheus text exposition with stable series ordering and escaped labels.
use crate::Result;
use std::{collections::HashSet, fmt::Write};
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
            let v = if s.value.is_nan() {
                "NaN".into()
            } else if s.value == f64::INFINITY {
                "+Inf".into()
            } else if s.value == f64::NEG_INFINITY {
                "-Inf".into()
            } else {
                format_value(s.value)
            };
            writeln!(out, "{}{labels} {v}", f.name).unwrap();
        }
    }
    Ok(out)
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

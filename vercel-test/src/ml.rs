//! Seven-feature logistic classifier with deterministic holdout evaluation.
use crate::{model::Flow, Result};
use serde::{Deserialize, Serialize};
pub const FEATURE_COUNT: usize = 7;
pub const MAX_PORT: i64 = 65535;
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Sample {
    pub flow: Flow,
    pub label: i64,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Model {
    #[serde(deserialize_with = "crate::model::null_default")]
    pub weights: Vec<f64>,
    pub bias: f64,
    pub threshold: f64,
    pub epochs: i64,
    pub loss: f64,
    pub accuracy: f64,
    pub precision: f64,
    pub recall: f64,
    pub validation: usize,
    pub samples: usize,
    pub ready: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub withdrawn: bool,
}
pub fn validate_flow(f: &Flow) -> Result<()> {
    if f.pps < 0 {
        return Err(format!("pps must not be negative, got {}", f.pps));
    }
    for (name, port) in [("dport", f.dport), ("sport", f.sport)] {
        if !(0..=MAX_PORT).contains(&port) {
            return Err(format!("{name} must be within 0..{MAX_PORT}, got {port}"));
        }
    }
    Ok(())
}
pub fn validate_sample(s: &Sample) -> Result<()> {
    if s.label != 0 && s.label != 1 {
        return Err(format!(
            "label must be 0 (clean) or 1 (attack), got {}",
            s.label
        ));
    }
    validate_flow(&s.flow)
}
pub fn features(f: &Flow) -> [f64; FEATURE_COUNT] {
    let proto = f.proto.to_ascii_lowercase();
    [
        (f.pps.clamp(0, i32::MAX as i64) as f64).ln_1p() / 12.0,
        if proto == "tcp" { 1.0 } else { 0.0 },
        if proto == "udp" { 1.0 } else { 0.0 },
        if proto == "icmp" { 1.0 } else { 0.0 },
        if f.flags.eq_ignore_ascii_case("syn") {
            1.0
        } else {
            0.0
        },
        f.dport.clamp(0, MAX_PORT) as f64 / MAX_PORT as f64,
        f.sport.clamp(0, MAX_PORT) as f64 / MAX_PORT as f64,
    ]
}
fn sigmoid(z: f64) -> f64 {
    if z > 30.0 {
        1.0
    } else if z < -30.0 {
        0.0
    } else {
        1.0 / (1.0 + (-z).exp())
    }
}
fn dot(w: &[f64], x: &[f64]) -> f64 {
    w.iter().zip(x).map(|(w, x)| w * x).sum()
}
pub fn score(m: &Model, f: &Flow) -> f64 {
    if !m.ready || m.weights.len() != FEATURE_COUNT {
        return 0.0;
    }
    let s = sigmoid(dot(&m.weights, &features(f)) + m.bias);
    if s.is_nan() {
        0.0
    } else {
        s
    }
}
pub fn predict(m: &Model, f: &Flow) -> i64 {
    i64::from(m.ready && score(m, f) >= m.threshold)
}
pub fn train(samples: &[Sample], epochs: i64, lr: f64, threshold: f64) -> Result<Model> {
    if samples.is_empty() {
        return Err("no samples to train on".into());
    }
    for (i, s) in samples.iter().enumerate() {
        validate_sample(s).map_err(|e| format!("sample {i}: {e}"))?;
    }
    let epochs = if epochs <= 0 { 200 } else { epochs };
    let lr = if lr <= 0.0 { 0.15 } else { lr };
    let threshold = if threshold <= 0.0 { 0.7 } else { threshold };
    let (fit, holdout): (Vec<_>, Vec<_>) = samples
        .iter()
        .enumerate()
        .partition(|(i, _)| samples.len() < 10 || i % 5 != 4);
    let mut weights = vec![0.0; FEATURE_COUNT];
    let mut bias = 0.0;
    let mut loss = 0.0;
    for _ in 0..epochs {
        loss = 0.0;
        for (_, s) in &fit {
            let x = features(&s.flow);
            let p = sigmoid(dot(&weights, &x) + bias);
            let y = s.label as f64;
            let err = p - y;
            loss += -(y * p.clamp(1e-9, 1.0 - 1e-9).ln()
                + (1.0 - y) * (1.0 - p).clamp(1e-9, 1.0 - 1e-9).ln());
            for (w, x) in weights.iter_mut().zip(x) {
                *w -= lr * err * x;
            }
            bias -= lr * err;
        }
        loss /= fit.len() as f64;
    }
    if weights.iter().chain([&bias, &loss]).any(|v| !v.is_finite()) {
        return Err("training diverged (try a smaller lr)".into());
    }
    let mut model = Model {
        weights,
        bias,
        threshold,
        epochs,
        loss,
        samples: samples.len(),
        validation: holdout.len(),
        ready: true,
        ..Default::default()
    };
    let scored = if holdout.is_empty() { &fit } else { &holdout };
    let (mut correct, mut tp, mut fp, mut fn_) = (0, 0, 0, 0);
    for (_, s) in scored {
        let p = predict(&model, &s.flow);
        if p == s.label {
            correct += 1;
        }
        match (p, s.label) {
            (1, 1) => tp += 1,
            (1, 0) => fp += 1,
            (0, 1) => fn_ += 1,
            _ => {}
        }
    }
    model.accuracy = correct as f64 / scored.len() as f64;
    if tp + fp > 0 {
        model.precision = tp as f64 / (tp + fp) as f64;
    }
    if tp + fn_ > 0 {
        model.recall = tp as f64 / (tp + fn_) as f64;
    }
    Ok(model)
}

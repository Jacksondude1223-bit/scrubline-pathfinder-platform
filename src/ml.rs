//! Logistic classifiers with deterministic holdout evaluation: a seven-feature model of flows, and
//! one of the HTTP requests the layer-7 rules let through.
//!
//! A false positive is a customer's traffic dropped, so a fit is held to what it would drop of the
//! clean samples before it is published, at its threshold and at every one a node may lower it to.
use crate::{httpfilter, model::Flow, Result};
use serde::{Deserialize, Serialize};
pub const FEATURE_COUNT: usize = 7;
pub const REQUEST_FEATURES: usize = 17;
pub const MAX_PORT: i64 = 65535;
/// The share of the clean samples it is measured on that a model may drop and still be published,
/// unless a training request sets its own.
pub const FALSE_POSITIVE_LIMIT: f64 = 0.01;
/// How far each step of tightening lowers a model's threshold for a target being probed, and how
/// many steps there are.
pub const PROBE_MARGIN: f64 = 0.1;
pub const PROBE_STEPS: u8 = 2;
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Sample {
    pub flow: Flow,
    pub label: i64,
    /// A clean sample the models must never drop: a false positive that was reported, or traffic
    /// known to be legitimate. A fit that would drop one is not published.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub known_good: bool,
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
    /// Of the clean samples it was measured on, the holdout's, the share it would drop.
    pub false_positive_rate: f64,
    /// How far under its threshold it may drop for a target being probed: as far as it stays
    /// within the false-positive limit on those clean samples, and drops no known-good one. Zero
    /// for a model fitted before this was measured, which therefore never tightens.
    pub max_cut: f64,
    pub validation: usize,
    pub samples: usize,
    pub ready: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub withdrawn: bool,
    /// The request model, fitted to the samples whose payload is an HTTP request. Its `samples`
    /// and `validation` count requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http: Option<Box<Model>>,
}
impl Model {
    /// Whether either model is fitted, so there is something for a node to install.
    pub fn usable(&self) -> bool {
        self.ready || self.http.as_ref().is_some_and(|h| h.ready)
    }
}
/// What the request model sees of one HTTP request: its head as far as the segment carrying it
/// holds it, and where it falls among the requests pipelined into that segment.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Request {
    /// GET or HEAD.
    pub get: bool,
    pub post: bool,
    pub http10: bool,
    /// Bytes of the target before any query, and its '/'-separated segments.
    pub path: usize,
    pub depth: usize,
    /// Bytes of the query.
    pub query: usize,
    pub headers: usize,
    pub user_agent: bool,
    pub accept: bool,
    pub accept_language: bool,
    pub accept_encoding: bool,
    pub cookie: bool,
    pub referer: bool,
    /// The body length it declares, or whether it sends one chunked.
    pub body: u64,
    pub chunked: bool,
    /// Whether the head ends inside the segment, so what it lacks is not merely cut off.
    pub complete: bool,
    /// 1 for the first request in the segment, 2 for one pipelined after it, and so on.
    pub position: u64,
}
pub fn validate_flow(f: &Flow) -> Result<()> {
    if f.pps < 0 {
        return Err(format!("pps must not be negative, got {}", f.pps));
    }
    if f.bps < 0 {
        return Err(format!("bps must not be negative, got {}", f.bps));
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
    if s.known_good && s.label != 0 {
        return Err("a known_good sample must be labelled 0 (clean)".into());
    }
    validate_flow(&s.flow)
}
// Scored per flow on the ZC stage and per sample per epoch in training, so it must not allocate.
pub fn features(f: &Flow) -> [f64; FEATURE_COUNT] {
    let proto = |name: &str| {
        if f.proto.eq_ignore_ascii_case(name) {
            1.0
        } else {
            0.0
        }
    };
    [
        (f.pps.clamp(0, i32::MAX as i64) as f64).ln_1p() / 12.0,
        proto("tcp"),
        proto("udp"),
        proto("icmp"),
        if crate::packet::tcp_flags(&f.flags).map_or_else(
            || f.flags.eq_ignore_ascii_case("syn"),
            |b| crate::packet::flags_meet(crate::packet::SYN, b),
        ) {
            1.0
        } else {
            0.0
        },
        f.dport.clamp(0, MAX_PORT) as f64 / MAX_PORT as f64,
        f.sport.clamp(0, MAX_PORT) as f64 / MAX_PORT as f64,
    ]
}
// Scored per request the layer-7 rules allow, so it must not allocate either.
pub fn request_features(r: &Request, pps: i64) -> [f64; REQUEST_FEATURES] {
    let bit = |b: bool| if b { 1.0 } else { 0.0 };
    let size = |n: usize| (n.min(1 << 16) as f64).ln_1p() / 8.0;
    [
        (pps.clamp(0, i32::MAX as i64) as f64).ln_1p() / 12.0,
        bit(r.get),
        bit(r.post),
        bit(r.http10),
        size(r.path),
        r.depth.min(16) as f64 / 16.0,
        size(r.query),
        r.headers.min(32) as f64 / 32.0,
        bit(r.user_agent),
        bit(r.accept),
        bit(r.accept_language),
        bit(r.accept_encoding),
        bit(r.cookie),
        bit(r.referer),
        if r.chunked {
            1.0
        } else {
            (r.body.min(1 << 32) as f64).ln_1p() / 23.0
        },
        bit(r.complete),
        (r.position.clamp(1, 64) as f64).ln_1p() / 65f64.ln(),
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
/// The request model's score for one request in a flow arriving at `pps`.
pub fn score_request(m: &Model, r: &Request, pps: i64) -> f64 {
    if !m.ready || m.weights.len() != REQUEST_FEATURES {
        return 0.0;
    }
    let s = sigmoid(dot(&m.weights, &request_features(r, pps)) + m.bias);
    if s.is_nan() {
        0.0
    } else {
        s
    }
}
/// Every fifth sample is held out of the fit, once there are ten or more.
fn held_out(count: usize, i: usize) -> bool {
    count >= 10 && i % 5 == 4
}
/// Fits a logistic model to `fit` and measures it on `holdout`, or on `fit` when nothing is held
/// out: how well it separates attacks from clean traffic at its threshold, how much of the clean
/// traffic it drops there, and how far under the threshold it can go while what it drops of the
/// clean traffic stays within `limit`.
fn fit<const N: usize>(
    fit: &[([f64; N], i64)],
    holdout: &[([f64; N], i64)],
    epochs: i64,
    lr: f64,
    threshold: f64,
    limit: f64,
) -> Result<Model> {
    let mut weights = vec![0.0; N];
    let mut bias = 0.0;
    let mut loss = 0.0;
    for _ in 0..epochs {
        loss = 0.0;
        for (x, label) in fit {
            let p = sigmoid(dot(&weights, x) + bias);
            let y = *label as f64;
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
        samples: fit.len() + holdout.len(),
        validation: holdout.len(),
        ready: true,
        ..Default::default()
    };
    let scored = if holdout.is_empty() { fit } else { holdout };
    let (mut correct, mut tp, mut fp, mut fn_) = (0, 0, 0, 0);
    for (x, label) in scored {
        let p = i64::from(sigmoid(dot(&model.weights, x) + model.bias) >= threshold);
        if p == *label {
            correct += 1;
        }
        match (p, *label) {
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
    // What it drops of the clean traffic at a threshold. Nothing measured, nothing vouched for:
    // a model shown no clean traffic is never tightened.
    let clean: Vec<f64> = scored
        .iter()
        .filter(|(_, label)| *label == 0)
        .map(|(x, _)| sigmoid(dot(&model.weights, x) + model.bias))
        .collect();
    let dropped = |at: f64| clean.iter().filter(|s| **s >= at).count() as f64 / clean.len() as f64;
    if !clean.is_empty() {
        model.false_positive_rate = dropped(threshold);
        for step in 1..=PROBE_STEPS {
            let cut = f64::from(step) * PROBE_MARGIN;
            if dropped(threshold - cut) > limit {
                break;
            }
            model.max_cut = cut;
        }
    }
    Ok(model)
}
/// Holds a fitted model to what it must not drop before it is published: no more than `limit`
/// of the clean samples it was measured on, and none of the known-good ones, at its threshold.
/// A known-good sample is held to every model that may judge it on a node: the flow model, which
/// can have the last word on any flow, and the request model on the requests it carries. Lowers
/// how far a node may tighten each to keep every known-good sample under it. Err says what it
/// would drop.
pub fn vet(m: &mut Model, samples: &[Sample], limit: f64) -> Result<()> {
    let mut problems = Vec::new();
    let percent = |v: f64| format!("{:.1}%", v * 100.0);
    if m.ready && m.false_positive_rate > limit {
        problems.push(format!(
            "the flow model drops {} of the clean samples it was measured on, over the {} limit",
            percent(m.false_positive_rate),
            percent(limit)
        ));
    }
    if let Some(h) = m.http.as_deref().filter(|h| h.ready) {
        if h.false_positive_rate > limit {
            problems.push(format!(
                "the request model drops {} of the clean requests it was measured on, over the {} limit",
                percent(h.false_positive_rate),
                percent(limit)
            ));
        }
    }
    let mut hold = |i: usize, which: &str, model: &mut Model, score: f64| {
        if score >= model.threshold {
            problems.push(format!(
                "known-good sample {i} scores {score:.2} by the {which} model, over its {:.2} threshold",
                model.threshold
            ));
        }
        let mut steps = (model.max_cut / PROBE_MARGIN).round() as u8;
        while steps > 0 && score >= model.threshold - f64::from(steps) * PROBE_MARGIN {
            steps -= 1;
        }
        model.max_cut = f64::from(steps) * PROBE_MARGIN;
    };
    for (i, s) in samples.iter().enumerate().filter(|(_, s)| s.known_good) {
        if m.ready {
            let flow = score(m, &s.flow);
            hold(i, "flow", m, flow);
        }
        let carried = httpfilter::requests(&s.flow);
        if let Some(h) = m
            .http
            .as_deref_mut()
            .filter(|h| h.ready && !carried.is_empty())
        {
            let request = carried
                .iter()
                .map(|r| score_request(h, r, s.flow.pps))
                .fold(0.0, f64::max);
            hold(i, "request", h, request);
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("; "))
    }
}
/// Fits the flow model to the samples that carry no HTTP request, and the request model to the
/// requests in those that do. A sample whose payload is an HTTP request trains the request model
/// alone: what makes it an attack may be in the request, which the flow model cannot see. The
/// request model needs clean and attack requests both, or it is left out. `limit` is the share of
/// clean holdout traffic either may drop at a threshold a node tightens it to; see vet() for
/// holding them to it at their own.
pub fn train(
    samples: &[Sample],
    epochs: i64,
    lr: f64,
    threshold: f64,
    limit: f64,
) -> Result<Model> {
    if samples.is_empty() {
        return Err("no samples to train on".into());
    }
    for (i, s) in samples.iter().enumerate() {
        validate_sample(s).map_err(|e| format!("sample {i}: {e}"))?;
    }
    let epochs = if epochs <= 0 { 200 } else { epochs };
    let lr = if lr <= 0.0 { 0.15 } else { lr };
    let threshold = if threshold <= 0.0 { 0.7 } else { threshold };
    let mut flows = Vec::new();
    let mut requests = Vec::new();
    for s in samples {
        let carried = httpfilter::requests(&s.flow);
        if carried.is_empty() {
            flows.push(s);
        } else {
            requests.push((s, carried));
        }
    }
    let (mut rows, mut holdout) = (Vec::new(), Vec::new());
    for (i, s) in flows.iter().enumerate() {
        let row = (features(&s.flow), s.label);
        if held_out(flows.len(), i) {
            holdout.push(row);
        } else {
            rows.push(row);
        }
    }
    let mut model = if rows.is_empty() {
        Model {
            threshold,
            epochs,
            ..Default::default()
        }
    } else {
        fit(&rows, &holdout, epochs, lr, threshold, limit)?
    };
    let labelled = |label| requests.iter().any(|(s, _)| s.label == label);
    if labelled(0) && labelled(1) {
        let (mut rows, mut holdout) = (Vec::new(), Vec::new());
        for (i, (s, carried)) in requests.iter().enumerate() {
            let into = if held_out(requests.len(), i) {
                &mut holdout
            } else {
                &mut rows
            };
            into.extend(
                carried
                    .iter()
                    .map(|r| (request_features(r, s.flow.pps), s.label)),
            );
        }
        model.http = Some(Box::new(fit(
            &rows, &holdout, epochs, lr, threshold, limit,
        )?));
    } else if !model.ready {
        return Err(
            "every sample is an HTTP request, and the request model needs both clean and attack ones"
                .into(),
        );
    }
    Ok(model)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn flow(proto: &str, dport: i64, pps: i64, label: i64) -> Sample {
        Sample {
            flow: Flow {
                proto: proto.into(),
                dport,
                sport: 40000,
                pps,
                ..Default::default()
            },
            label,
            ..Default::default()
        }
    }
    fn request(payload: &str, pps: i64, label: i64) -> Sample {
        Sample {
            flow: Flow {
                proto: "tcp".into(),
                dport: 30120,
                sport: 50000,
                pps,
                payload: payload.as_bytes().to_vec(),
                has_payload: true,
                ..Default::default()
            },
            label,
            ..Default::default()
        }
    }
    fn flows() -> Vec<Sample> {
        vec![
            flow("tcp", 443, 40, 0),
            flow("udp", 19132, 80, 0),
            flow("udp", 27015, 120000, 1),
            flow("tcp", 80, 90000, 1),
        ]
    }
    const CLIENT: &str = "GET /players.json HTTP/1.1\r\nHost: s\r\nUser-Agent: CitizenFX/1\r\nAccept: */*\r\nAccept-Encoding: gzip\r\n\r\n";
    const FLOOD: &str = "GET /players.json?x=81d3 HTTP/1.0\r\n\r\n";
    #[test]
    fn http_samples_train_the_request_model_and_leave_the_flow_model_alone() {
        let alone = train(&flows(), 100, 0.2, 0.6, FALSE_POSITIVE_LIMIT).unwrap();
        let mut set = flows();
        set.push(request(CLIENT, 2, 0));
        set.push(request(FLOOD, 400, 1));
        // Two requests pipelined into one sample are two rows.
        set.push(request(&format!("{FLOOD}{FLOOD}"), 800, 1));
        let both = train(&set, 100, 0.2, 0.6, FALSE_POSITIVE_LIMIT).unwrap();
        assert_eq!(both.weights, alone.weights);
        assert_eq!((both.bias, both.samples), (alone.bias, alone.samples));
        let http = both.http.as_deref().unwrap();
        assert!(http.ready);
        assert_eq!(http.weights.len(), REQUEST_FEATURES);
        assert_eq!((http.samples, http.validation), (4, 0));
        let flagged = |payload: &str, pps| {
            let carried = httpfilter::requests(&request(payload, pps, 0).flow);
            score_request(http, &carried[0], pps) >= http.threshold
        };
        assert!(!flagged(CLIENT, 2));
        assert!(flagged(FLOOD, 400));
        // The flow model is not consulted on what only the request model knows of.
        assert_eq!(
            score(&both, &request(FLOOD, 400, 1).flow),
            score(&alone, &request(FLOOD, 400, 1).flow)
        );
    }
    #[test]
    fn the_request_model_needs_clean_and_attack_requests() {
        let mut set = flows();
        set.push(request(FLOOD, 400, 1));
        let m = train(&set, 50, 0.2, 0.6, FALSE_POSITIVE_LIMIT).unwrap();
        assert!(m.ready && m.http.is_none());
        let only = [request(FLOOD, 400, 1), request(FLOOD, 900, 1)];
        assert!(train(&only, 50, 0.2, 0.6, FALSE_POSITIVE_LIMIT)
            .unwrap_err()
            .contains("both clean and attack"));
        let m = train(
            &[request(CLIENT, 2, 0), request(FLOOD, 400, 1)],
            50,
            0.2,
            0.6,
            FALSE_POSITIVE_LIMIT,
        )
        .unwrap();
        assert!(!m.ready && m.weights.is_empty());
        assert!(m.usable() && m.http.unwrap().ready);
        assert!(!Model::default().usable());
    }
    #[test]
    fn a_fit_reports_the_clean_traffic_it_drops_and_how_far_it_can_tighten() {
        // Clean traffic far from the attacks: none of it dropped, even two steps down.
        let m = train(&flows(), 100, 0.2, 0.6, FALSE_POSITIVE_LIMIT).unwrap();
        assert_eq!((m.false_positive_rate, m.max_cut), (0.0, 0.2));
        // A clean sample that looks exactly like the attacks outnumbering it is dropped with them,
        // and a model that drops clean traffic at its threshold may not tighten at all.
        let mut set = flows();
        set.extend([flow("udp", 27015, 120000, 1), flow("udp", 27015, 120000, 1)]);
        set.push(flow("udp", 27015, 120000, 0));
        let mut m = train(&set, 300, 0.2, 0.6, FALSE_POSITIVE_LIMIT).unwrap();
        assert!((m.false_positive_rate - 1.0 / 3.0).abs() < 1e-9, "{m:?}");
        assert_eq!(m.max_cut, 0.0);
        assert_eq!(
            vet(&mut m, &set, FALSE_POSITIVE_LIMIT).unwrap_err(),
            "the flow model drops 33.3% of the clean samples it was measured on, over the 1.0% limit"
        );
        // A limit that allows a third of them passes it.
        assert!(vet(&mut m, &set, 0.34).is_ok());
    }
    /// A model that goes by rate alone: 1,000 pps scores 0.5, its threshold.
    fn by_rate() -> Model {
        let mut weights = vec![0.0; FEATURE_COUNT];
        weights[0] = 12.0;
        Model {
            weights,
            bias: -(1001f64).ln(),
            threshold: 0.5,
            max_cut: 0.2,
            ready: true,
            ..Default::default()
        }
    }
    #[test]
    fn known_good_samples_are_never_dropped_and_bound_how_far_a_model_tightens() {
        let known = |pps| Sample {
            known_good: true,
            ..flow("udp", 27015, pps, 0)
        };
        // 500 pps scores 0.33: clear of the threshold and of the first step under it, at 0.4,
        // but not of the second, at 0.3.
        let mut m = by_rate();
        vet(&mut m, &[flow("udp", 27015, 900, 0), known(500)], 1.0).unwrap();
        assert_eq!(m.max_cut, 0.1);
        // 700 pps scores 0.41, so the model may not tighten at all.
        vet(&mut m, &[known(700)], 1.0).unwrap();
        assert_eq!(m.max_cut, 0.0);
        // 2,000 pps scores 0.67, which it drops: not published, whatever the limit.
        let mut m = by_rate();
        assert_eq!(
            vet(&mut m, &[known(10), known(2000)], 1.0).unwrap_err(),
            "known-good sample 1 scores 0.67 by the flow model, over its 0.50 threshold"
        );
        // A request is held to the flow model too, which can have the last word on any flow.
        let page = Sample {
            known_good: true,
            ..request(CLIENT, 2000, 0)
        };
        assert_eq!(
            vet(&mut by_rate(), &[page], 1.0).unwrap_err(),
            "known-good sample 0 scores 0.67 by the flow model, over its 0.50 threshold"
        );
        // Only a clean sample can be known good.
        let wrong = Sample {
            label: 1,
            ..known(10)
        };
        assert!(validate_sample(&wrong).unwrap_err().contains("labelled 0"));
    }
    #[test]
    fn every_fifth_http_sample_is_held_out_with_all_its_requests() {
        let mut set = Vec::new();
        for i in 0..10 {
            let pipelined = if i == 4 { 3 } else { 1 };
            let label = i % 2;
            let one = if label == 0 { CLIENT } else { FLOOD };
            set.push(request(&one.repeat(pipelined), 10 + i, label));
        }
        let m = train(&set, 20, 0.2, 0.6, FALSE_POSITIVE_LIMIT).unwrap();
        let http = m.http.unwrap();
        assert_eq!((http.samples, http.validation), (12, 4));
    }
}

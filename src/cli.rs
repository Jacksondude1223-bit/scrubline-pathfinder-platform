//! scrubctl command routing and human-readable operator reports.
use crate::Result;
use serde_json::{json, Value};
use std::{fs, path::Path};
#[derive(Debug, PartialEq)]
pub struct Request {
    pub method: &'static str,
    pub path: String,
    pub body: Option<Vec<u8>>,
    pub view: View,
}
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum View {
    Json,
    Plan,
    Overview,
    Attacks,
    Credential,
}
fn file(path: &str) -> Result<Vec<u8>> {
    let raw = fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    serde_json::from_slice::<Value>(&raw)
        .map_err(|e| format!("{path} does not contain valid JSON: {e}"))?;
    Ok(raw)
}
pub fn request(args: &[String]) -> Result<Request> {
    let arg = |n: usize, usage: &str| {
        args.get(n)
            .map(String::as_str)
            .ok_or_else(|| usage.to_string())
    };
    let command=arg(0,"usage: scrubctl [-api URL] [-ca PEM] nodes | policies | apply <file> | deploy <id> | fabric | bgp | decide <node> <flow.json> | ml-load <file> | ml-train [file] | ml-model | analytics [window] | attacks [window] | tenants | tenant-add <file> | tenant-token <id> | tenant-rm <id>")?;
    let window = args.get(1).map(String::as_str).unwrap_or("24h");
    let mut r = Request {
        method: "GET",
        path: String::new(),
        body: None,
        view: View::Json,
    };
    match command {
        "nodes" | "policies" | "fabric" | "tenants" => r.path = format!("/v1/{command}"),
        "bgp" => {
            r.path = "/v1/fabric".into();
            r.view = View::Plan;
        }
        "apply" | "ml-load" | "tenant-add" => {
            r.method = "POST";
            r.path = match command {
                "apply" => "/v1/policies",
                "ml-load" => "/v1/ml/samples",
                _ => "/v1/tenants",
            }
            .into();
            r.body = Some(file(arg(1, &format!("{command} <file>"))?)?);
        }
        "deploy" | "tenant-token" => {
            let id = arg(1, &format!("{command} <id>"))?;
            safe_id(id)?;
            r.method = "POST";
            r.path = if command == "deploy" {
                format!("/v1/policies/{id}/deploy")
            } else {
                r.view = View::Credential;
                format!("/v1/tenants/{id}/token")
            };
            r.body = Some(b"{}".to_vec());
        }
        "tenant-rm" => {
            let id = arg(1, "tenant-rm <tenant-id>")?;
            safe_id(id)?;
            r.method = "DELETE";
            r.path = format!("/v1/tenants/{id}");
        }
        "decide" => {
            let id = arg(1, "decide <node-id> <flow.json>")?;
            let flow: Value =
                serde_json::from_slice(&file(arg(2, "decide <node-id> <flow.json>")?)?)
                    .map_err(|e| e.to_string())?;
            r.method = "POST";
            r.path = "/v1/decide".into();
            r.body = Some(
                serde_json::to_vec(&json!({"node_id":id,"flow":flow}))
                    .map_err(|e| e.to_string())?,
            );
        }
        "ml-train" => {
            r.method = "POST";
            r.path = "/v1/ml/train".into();
            r.body = Some(if let Some(path) = args.get(1) {
                file(path)?
            } else {
                br#"{"epochs":300,"lr":0.2,"threshold":0.65}"#.to_vec()
            });
        }
        "ml-model" => r.path = "/v1/ml/model".into(),
        "analytics" | "attacks" => {
            // Encode the query value rather than interpreting it as URL syntax.
            let mut url = reqwest::Url::parse("http://localhost/").unwrap();
            url.query_pairs_mut().append_pair("window", window);
            r.path = format!(
                "/v1/analytics/{}?{}",
                if command == "analytics" {
                    "overview"
                } else {
                    "events"
                },
                url.query().unwrap()
            );
            r.view = if command == "analytics" {
                View::Overview
            } else {
                View::Attacks
            };
        }
        _ => return Err("unknown command".into()),
    }
    Ok(r)
}
fn safe_id(id: &str) -> Result<()> {
    if id.is_empty() || id.contains(['/', '?', '#', '%']) || id == "." || id == ".." {
        Err("id must be a single URL path component".into())
    } else {
        Ok(())
    }
}
pub fn call(
    client: &reqwest::blocking::Client,
    base: &str,
    token: &str,
    r: &Request,
) -> Result<Vec<u8>> {
    let method = reqwest::Method::from_bytes(r.method.as_bytes()).map_err(|e| e.to_string())?;
    let url = format!("{}{}", base.trim_end_matches('/'), r.path);
    let mut req = client
        .request(method, &url)
        .bearer_auth(token)
        .header("Content-Type", "application/json");
    if let Some(body) = &r.body {
        req = req.body(body.clone());
    }
    let resp = req.send().map_err(|e| format!("{} {url}: {e}", r.method))?;
    let status = resp.status();
    let raw = resp
        .bytes()
        .map_err(|e| format!("reading {} {url}: {e}", r.method))?;
    if status.as_u16() >= 300 {
        return Err(format!(
            "{} {url}: {status}: {}",
            r.method,
            String::from_utf8_lossy(&raw).trim()
        ));
    }
    Ok(raw.to_vec())
}
fn text(v: &Value, k: &str) -> String {
    v[k].as_str().unwrap_or("").into()
}
fn number(v: &Value, k: &str) -> String {
    v[k].as_u64().unwrap_or(0).to_string()
}
fn dash(s: String) -> String {
    if s.is_empty() {
        "-".into()
    } else {
        s
    }
}
fn table(rows: Vec<Vec<String>>) -> String {
    let columns = rows.iter().map(Vec::len).max().unwrap_or(0);
    let mut widths = vec![0; columns];
    for row in &rows {
        for (i, cell) in row.iter().enumerate().take(columns.saturating_sub(1)) {
            widths[i] = widths[i].max(cell.chars().count() + 2);
        }
    }
    let mut out = String::new();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            out.push_str(cell);
            if i + 1 < row.len() {
                out.push_str(&" ".repeat(widths[i].saturating_sub(cell.chars().count())));
            }
        }
        out.push('\n');
    }
    out
}
fn header(cols: &[&str]) -> Vec<String> {
    cols.iter().map(|s| (*s).into()).collect()
}
fn duration(seconds: i64) -> String {
    let sign = if seconds < 0 { "-" } else { "" };
    let seconds = seconds.unsigned_abs();
    if seconds >= 3600 {
        format!(
            "{sign}{}h{}m{}s",
            seconds / 3600,
            seconds % 3600 / 60,
            seconds % 60
        )
    } else if seconds >= 60 {
        format!("{sign}{}m{}s", seconds / 60, seconds % 60)
    } else {
        format!("{sign}{seconds}s")
    }
}
pub fn render(raw: &[u8], view: View) -> Result<String> {
    if matches!(view, View::Json | View::Credential) {
        return Ok(format!("{}\n", String::from_utf8_lossy(raw)));
    }
    let v: Value = serde_json::from_slice(raw).map_err(|e| e.to_string())?;
    let key = match view {
        View::Plan => "announcements",
        View::Overview => "prefixes",
        _ => "events",
    };
    let empty = Vec::new();
    let entries = v[key].as_array().unwrap_or(&empty);
    if entries.is_empty() {
        return Ok(match view {
            View::Plan => "no announcements; deploy a policy first\n".into(),
            View::Overview => "no protected prefixes are being reported on yet\n".into(),
            _ => format!("no attacks in the last {}\n", text(&v, "window")),
        });
    }
    let mut rows = vec![match view {
        View::Plan => header(&[
            "PREFIX", "NODE", "REGION", "STATE", "PREPENDS", "NEXT HOP", "WHY",
        ]),
        View::Overview => header(&[
            "PREFIX",
            "OFFERED",
            "SCRUBBED",
            "MITIGATED",
            "PEAK PPS",
            "NOW PPS",
            "NODES",
            "ATTACKS",
            "STATE",
        ]),
        _ => header(&[
            "STARTED",
            "PREFIX",
            "FOR",
            "PEAK PPS",
            "SCRUBBED PPS",
            "SHAPE",
            "STOPPED BY",
        ]),
    }];
    for e in entries {
        rows.push(match view {
            View::Plan => vec![
                text(e, "prefix"),
                text(e, "node_name"),
                text(e, "region"),
                text(e, "state"),
                if e["state"] == "announce" {
                    number(e, "prepends")
                } else {
                    "-".into()
                },
                dash(text(e, "next_hop")),
                text(e, "reason"),
            ],
            View::Overview => vec![
                text(e, "prefix"),
                number(e, "offered"),
                number(e, "dropped"),
                format!("{:.1}%", e["mitigated_pct"].as_f64().unwrap_or(0.0)),
                number(e, "peak_pps"),
                number(e, "offered_pps"),
                number(e, "nodes"),
                number(e, "attacks"),
                if e["under_attack"].as_bool().unwrap_or(false) {
                    "UNDER ATTACK".into()
                } else {
                    "clear".into()
                },
            ],
            _ => {
                let vectors: Vec<_> = e["vectors"]
                    .as_array()
                    .unwrap_or(&empty)
                    .iter()
                    .map(|v| {
                        let mut name = text(v, "rule_id");
                        if name.is_empty() {
                            name = text(v, "filter_id");
                        }
                        format!("{name}({})", text(v, "stage"))
                    })
                    .collect();
                let mut took = duration(e["seconds"].as_f64().unwrap_or(0.0) as i64);
                if e["ongoing"].as_bool().unwrap_or(false) {
                    took += " (ongoing)";
                }
                let started = chrono::DateTime::parse_from_rfc3339(&text(e, "started_at"))
                    .map_err(|e| e.to_string())?
                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                vec![
                    started,
                    text(e, "prefix"),
                    took,
                    number(e, "peak_pps"),
                    number(e, "peak_dropped_pps"),
                    if e["pulse"].as_bool().unwrap_or(false) {
                        "burst train".into()
                    } else {
                        "flood".into()
                    },
                    dash(vectors.join(" ")),
                ]
            }
        });
    }
    let mut out = table(rows);
    if view == View::Overview {
        out += &format!("\nover the last {}\n", text(&v, "window"));
    }
    Ok(out)
}
pub fn run(args: impl IntoIterator<Item = String>) -> Result<()> {
    let args: Vec<_> = args.into_iter().collect();
    let mut pos = 0;
    let mut api = "http://127.0.0.1:8080".to_string();
    let mut ca = None;
    while let Some(flag) = args.get(pos) {
        if flag == "--" {
            pos += 1;
            break;
        }
        if !flag.starts_with('-') {
            break;
        }
        let (name, inline) = flag
            .split_once('=')
            .map(|(a, b)| (a, Some(b)))
            .unwrap_or((flag, None));
        if name == "-h" || name == "--help" || name == "-help" {
            println!("scrubctl [-api URL] [-ca PEM] <command>\nCommands: nodes policies apply deploy fabric bgp decide ml-load ml-train ml-model analytics attacks tenants tenant-add tenant-token tenant-rm");
            return Ok(());
        }
        let value = if let Some(v) = inline {
            v.to_string()
        } else {
            pos += 1;
            args.get(pos)
                .ok_or_else(|| format!("{name} needs a value"))?
                .clone()
        };
        match name {
            "-api" | "--api" => api = value,
            "-ca" | "--ca" => ca = Some(value),
            _ => return Err(format!("unknown flag {name}")),
        }
        pos += 1;
    }
    let client = crate::transport::client(
        ca.as_deref().map(Path::new),
        std::time::Duration::from_secs(30),
    )?;
    let token = std::env::var("SCRUBLINE_API_TOKEN")
        .ok()
        .filter(|v| !v.is_empty())
        .ok_or("SCRUBLINE_API_TOKEN is required (the operator credential)")?;
    let req = request(&args[pos..])?;
    let raw = call(&client, &api, &token, &req)?;
    print!("{}", render(&raw, req.view)?);
    if req.view == View::Credential {
        eprintln!("this credential is shown once; only its hash is kept");
    }
    Ok(())
}

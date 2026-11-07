use pathfinder::{
    cli::{self, View},
    transport,
};
use serde_json::json;
use std::{
    io::{Read, Write},
    net::TcpListener,
    time::Duration,
};
fn args(s: &[&str]) -> Vec<String> {
    s.iter().map(|s| (*s).into()).collect()
}
#[test]
fn routes_all_read_and_id_commands() {
    for (cmd, method, path) in [
        (vec!["nodes"], "GET", "/v1/nodes"),
        (vec!["policies"], "GET", "/v1/policies"),
        (vec!["fabric"], "GET", "/v1/fabric"),
        (vec!["bgp"], "GET", "/v1/fabric"),
        (vec!["tenants"], "GET", "/v1/tenants"),
        (vec!["ml-model"], "GET", "/v1/ml/model"),
        (vec!["deploy", "pol-1"], "POST", "/v1/policies/pol-1/deploy"),
        (
            vec!["tenant-token", "ten-1"],
            "POST",
            "/v1/tenants/ten-1/token",
        ),
        (vec!["tenant-rm", "ten-1"], "DELETE", "/v1/tenants/ten-1"),
        (vec!["settings"], "GET", "/v1/settings"),
        (
            vec!["settings", "pol-1"],
            "GET",
            "/v1/policies/pol-1/settings",
        ),
    ] {
        let r = cli::request(&args(&cmd)).unwrap();
        assert_eq!(r.method, method);
        assert_eq!(r.path, path);
        if method == "POST" {
            assert_eq!(r.body.unwrap(), b"{}");
        }
    }
    let r = cli::request(&args(&["ml-train"])).unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&r.body.unwrap()).unwrap(),
        json!({"epochs":300,"lr":0.2,"threshold":0.65})
    );
    assert_eq!(
        cli::request(&args(&["analytics"])).unwrap().path,
        "/v1/analytics/overview?window=24h"
    );
    assert_eq!(
        cli::request(&args(&["attacks", "1h&secret=foo"]))
            .unwrap()
            .path,
        "/v1/analytics/events?window=1h%26secret%3Dfoo"
    );
    for cmd in [
        &["unknown"][..],
        &["deploy"],
        &["decide", "n"],
        &["tenant-token", "../x"],
        &["tenant-rm", "id?other=1"],
        &["settings", "../x"],
    ] {
        assert!(cli::request(&args(cmd)).is_err());
    }
}
#[test]
fn file_commands_validate_json_and_build_decide_body() {
    let dir = std::env::temp_dir().join(format!("pathfinder-cli-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("data.json");
    std::fs::write(&file, br#"{"proto":"udp","pps":100}"#).unwrap();
    let file = file.to_str().unwrap();
    for (cmd, path) in [
        ("apply", "/v1/policies"),
        ("ml-load", "/v1/ml/samples"),
        ("tenant-add", "/v1/tenants"),
        ("ml-train", "/v1/ml/train"),
    ] {
        let r = cli::request(&args(&[cmd, file])).unwrap();
        assert_eq!(r.path, path);
        assert_eq!(r.method, "POST");
    }
    let r = cli::request(&args(&["decide", "node-\"1", file])).unwrap();
    let body: serde_json::Value = serde_json::from_slice(&r.body.unwrap()).unwrap();
    assert_eq!(
        body,
        json!({"node_id":"node-\"1","flow":{"proto":"udp","pps":100}})
    );
    std::fs::write(file, b"broken JSON").unwrap();
    assert!(cli::request(&args(&["apply", file])).is_err());
    std::fs::remove_dir_all(dir).unwrap();
}
#[test]
fn renders_reports_and_empty_states() {
    assert_eq!(
        cli::render(br#"{"announcements":[]}"#, View::Plan).unwrap(),
        "no announcements; deploy a policy first\n"
    );
    assert_eq!(
        cli::render(br#"{"window":"24h","events":[]}"#, View::Attacks).unwrap(),
        "no attacks in the last 24h\n"
    );
    let overview=cli::render(&serde_json::to_vec(&json!({"window":"1h","prefixes":[{"prefix":"203.0.113.0/24","offered":200,"dropped":100,"mitigated_pct":50.0,"under_attack":true}]})).unwrap(),View::Overview).unwrap();
    assert!(overview.contains("50.0%"));
    assert!(overview.contains("UNDER ATTACK"));
    assert!(overview.ends_with("over the last 1h\n"));
    let attacks=cli::render(&serde_json::to_vec(&json!({"window":"1h","events":[{"prefix":"203.0.113.0/24","started_at":"2026-01-01T00:00:00.123Z","seconds":3661.9,"ongoing":true,"pulse":true,"vectors":[{"filter_id":"raknet","stage":"zc"},{"crafted":"stack","flows":3,"dropped":30}]}]})).unwrap(),View::Attacks).unwrap();
    assert!(attacks.contains("1h1m1s (ongoing)"));
    assert!(attacks.contains("raknet(zc) crafted-stack"));
    let reflected=cli::render(&serde_json::to_vec(&json!({"window":"1h","events":[{"prefix":"203.0.113.0/24","started_at":"2026-01-01T00:00:00.123Z","seconds":61.0,"ongoing":true,"pulse":false,"vectors":[{"reflection":"cldap","flows":3,"dropped":300}]}]})).unwrap(),View::Attacks).unwrap();
    assert!(reflected.contains("reflection-cldap"), "{reflected}");
    let botnet=cli::render(&serde_json::to_vec(&json!({"window":"1h","events":[{"prefix":"203.0.113.0/24","started_at":"2026-01-01T00:00:00.123Z","seconds":61.0,"ongoing":true,"pulse":false,"vectors":[{"protocol":"gre","flows":3,"dropped":300},{"ack_flood":"tcp","flows":1,"dropped":10000}]}]})).unwrap(),View::Attacks).unwrap();
    assert!(botnet.contains("protocol-gre ack-flood"), "{botnet}");
    let booter=cli::render(&serde_json::to_vec(&json!({"window":"1h","events":[{"prefix":"203.0.113.0/24","started_at":"2026-01-01T00:00:00.123Z","seconds":61.0,"ongoing":true,"pulse":false,"vectors":[{"syn_flood":"tcp","flows":1,"dropped":9000},{"fragment":"tcp","flows":2,"dropped":20},{"icmp":"smurf","flows":1,"dropped":5000},{"reflection":"memcached","flows":1,"dropped":800}]}]})).unwrap(),View::Attacks).unwrap();
    assert!(
        booter.contains("syn-flood fragment-tcp icmp-smurf reflection-memcached"),
        "{booter}"
    );
    assert!(attacks.contains("2026-01-01T00:00:00Z"));
}
fn server(status: &str, body: &str) -> (String, std::thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let status = status.to_owned();
    let body = body.to_owned();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut bytes = Vec::new();
        let mut buf = [0u8; 1024];
        let header_end;
        loop {
            let n = stream.read(&mut buf).unwrap();
            assert!(n > 0);
            bytes.extend_from_slice(&buf[..n]);
            if let Some(pos) = bytes.windows(4).position(|x| x == b"\r\n\r\n") {
                header_end = pos + 4;
                break;
            }
        }
        let header = String::from_utf8_lossy(&bytes[..header_end]);
        let length = header
            .lines()
            .find_map(|l| {
                l.to_ascii_lowercase()
                    .strip_prefix("content-length: ")
                    .and_then(|n| n.parse::<usize>().ok())
            })
            .unwrap_or(0);
        while bytes.len() < header_end + length {
            let n = stream.read(&mut buf).unwrap();
            assert!(n > 0);
            bytes.extend_from_slice(&buf[..n]);
        }
        write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
        String::from_utf8(bytes).unwrap()
    });
    (format!("http://{addr}"), handle)
}
#[test]
fn http_request_preserves_bearer_auth_method_path_and_body() {
    let (url, server) = server("200 OK", "{\"ok\":true}");
    let r = cli::request(&args(&["deploy", "pol-1"])).unwrap();
    let client = transport::client(None, Duration::from_secs(5)).unwrap();
    assert_eq!(
        cli::call(&client, &url, "test-token", &r).unwrap(),
        br#"{"ok":true}"#
    );
    let sent = server.join().unwrap();
    assert!(sent.starts_with("POST /v1/policies/pol-1/deploy HTTP/1.1\r\n"));
    assert!(sent
        .to_ascii_lowercase()
        .contains("authorization: bearer test-token\r\n"));
    assert!(sent.ends_with("{}"));
}
#[test]
fn http_errors_include_status_and_body() {
    let (url, server) = server("403 Forbidden", "denied");
    let r = cli::request(&args(&["nodes"])).unwrap();
    let client = transport::client(None, Duration::from_secs(5)).unwrap();
    let err = cli::call(&client, &url, "test-token", &r).unwrap_err();
    assert!(err.contains("403 Forbidden"));
    assert!(err.contains("denied"));
    server.join().unwrap();
}
#[test]
fn private_ca_bundle_is_validated() {
    let path = std::env::temp_dir().join(format!("pathfinder-bad-ca-{}.pem", std::process::id()));
    std::fs::write(&path, b"not a certificate").unwrap();
    assert!(transport::client(Some(&path), Duration::from_secs(1)).is_err());
    std::fs::remove_file(path).unwrap();
}
#[test]
fn the_settings_catalog_renders_as_a_table() {
    let catalog = serde_json::to_vec(&pathfinder::tuning::catalog()).unwrap();
    let out = cli::render(&catalog, View::Settings).unwrap();
    let mut lines = out.lines();
    assert!(lines.next().unwrap().starts_with("SETTING"));
    let row = |path: &str| {
        out.lines()
            .find(|l| l.split_whitespace().next() == Some(path))
            .unwrap_or_else(|| panic!("{path} missing:\n{out}"))
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    };
    assert_eq!(
        row("syn_flood.hold_seconds"),
        "syn_flood.hold_seconds 60 0..86400 seconds yes"
    );
    assert_eq!(row("pulse.duty"), "pulse.duty 0.5 0.01..1 -");
    assert_eq!(
        row("egress.lockdown"),
        "egress.lockdown off off | limit | drop -"
    );
    assert_eq!(
        row("reputation.penalty_box"),
        "reputation.penalty_box false true | false -"
    );
    assert_eq!(out.lines().count(), pathfinder::tuning::SETTINGS.len() + 1);
}

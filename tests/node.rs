//! Everything a policy can turn on, on one node at once: the rules on all three stages, the game
//! filters and their HTTP rules, the classifiers, reputation and the penalty box, return-traffic
//! lockdown, every kind of tunnel, customer BGP and on-demand mitigation. The policy is
//! configs/policy.everything.json, deployed through the API, and each test drives the pipeline
//! the node runs from its program, or reads back what the node renders and reports.
use pathfinder::{
    api::{Api, Shared},
    bgp, ml,
    model::*,
    pipeline::Pipeline,
    provision,
    store::Store,
    telemetry::Metrics,
    tunnel,
};
use serde_json::{json, Value};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
const OP: &str = "test-operator";
const ENROLL: &str = "test-enroll";
const T0: i64 = 1767225600000;
fn serve() -> String {
    let state: Shared = Arc::new(Mutex::new(Api::new(
        Store::open("").unwrap(),
        OP.into(),
        ENROLL.into(),
        "primary".into(),
    )));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                axum::serve(listener, Api::router(state)).await.unwrap();
            });
    });
    base
}
fn call(base: &str, method: &str, path: &str, token: &str, body: Value) -> (u16, Value) {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let mut req = client
        .request(method.parse().unwrap(), format!("{base}{path}"))
        .bearer_auth(token);
    if !body.is_null() {
        req = req.json(&body);
    }
    let resp = req.send().unwrap();
    let status = resp.status().as_u16();
    let text = resp.text().unwrap();
    (
        status,
        serde_json::from_str(&text).unwrap_or(Value::String(text)),
    )
}
/// A control plane with one node, the policy that turns everything on deployed to it, its
/// tunnels allocated to their customers, and both classifiers trained and published.
struct Fabric {
    base: String,
    node: Node,
    token: String,
    /// Each customer's name and id.
    tenants: Vec<(String, String)>,
}
impl Fabric {
    fn new() -> Self {
        let base = serve();
        let op = |method: &str, path: &str, body: Value| {
            let (status, answer) = call(&base, method, path, OP, body);
            assert_eq!(status, 200, "{method} {path}: {answer}");
            answer
        };
        let (status, registered) = call(
            &base,
            "POST",
            "/v1/nodes/register",
            ENROLL,
            // As the agent registers: its capacity, its backends and where it is reached.
            json!({"name":"lhr-1","region":"lhr","capacity_gbps":40,"capacity_pps":2_000_000,
                   "backends":["asic","fpga","zc"],"advertise":"192.0.2.1:9091","tunnel_src":"192.0.2.1"}),
        );
        assert_eq!(status, 200, "{registered}");
        let node: Node = serde_json::from_value(registered["node"].clone()).unwrap();
        let token = registered["token"].as_str().unwrap().to_string();
        let mut policy: Value =
            serde_json::from_str(include_str!("../configs/policy.everything.json")).unwrap();
        // Northwind's tunnel ends on this node, as the location chosen for them.
        policy["tunnels"][0]["node"] = json!(node.id);
        op("POST", "/v1/policies", policy);
        op("POST", "/v1/policies/everything/deploy", Value::Null);
        // Each customer's tunnel is theirs, allocated after the fact.
        let mut tenants = Vec::new();
        for (name, prefix, tunnel) in [
            ("northwind", "203.0.113.0/24", "northwind"),
            ("contoso", "198.51.100.0/24", "contoso"),
            ("fabrikam", "2001:db8:100::/48", "fabrikam"),
        ] {
            let tenant = op(
                "POST",
                "/v1/tenants",
                json!({"name":name,"prefixes":[prefix]}),
            );
            let tunnels = op("GET", "/v1/tunnels", Value::Null);
            let mut saved = tunnels["tunnels"]
                .as_array()
                .unwrap()
                .iter()
                .find(|t| t["id"] == tunnel)
                .unwrap()
                .clone();
            let saved = saved.as_object_mut().unwrap();
            saved.retain(|k, _| {
                [
                    "id",
                    "prefixes",
                    "type",
                    "remote",
                    "key",
                    "direction",
                    "rate_mbps",
                    "node",
                    "mitigation",
                    "attack_pps",
                    "attack_mbps",
                    "comment",
                ]
                .contains(&k.as_str())
            });
            saved.insert("tenant".into(), tenant["id"].clone());
            let path = format!("/v1/tunnels/{tunnel}");
            let allocated = op("PUT", &path, Value::Object(saved.clone()));
            assert_eq!(allocated["tunnel"]["tenant"], tenant["id"]);
            tenants.push((name.to_string(), tenant["id"].as_str().unwrap().to_string()));
        }
        let samples: Value =
            serde_json::from_str(include_str!("../configs/ml.samples.json")).unwrap();
        op("POST", "/v1/ml/samples", samples);
        let model = op(
            "POST",
            "/v1/ml/train",
            json!({"epochs":30,"lr":0.2,"threshold":0.65}),
        );
        assert!(
            model["ready"] == true && model["http"]["ready"] == true,
            "{model}"
        );
        Fabric {
            base,
            node,
            token,
            tenants,
        }
    }
    /// What the node fetches: its program, and the published models.
    fn program(&self) -> Program {
        let path = format!("/v1/nodes/{}/program", self.node.id);
        let (status, program) = call(&self.base, "GET", &path, &self.token, Value::Null);
        assert_eq!(status, 200, "{program}");
        serde_json::from_value(program).unwrap()
    }
    fn model(&self) -> ml::Model {
        let (status, model) = call(&self.base, "GET", "/v1/ml/model", &self.token, Value::Null);
        assert_eq!(status, 200, "{model}");
        serde_json::from_value(model).unwrap()
    }
    /// The pipeline the node runs, as its agent installs it.
    fn pipeline(&self) -> Pipeline {
        let mut pipe = Pipeline::new(self.program());
        pipe.model = self.model();
        pipe
    }
    fn heartbeat(&self, stats: Value, tunnels: Value) {
        let path = format!("/v1/nodes/{}/heartbeat", self.node.id);
        let body = json!({"stats":stats,"tunnels":tunnels});
        let (status, answer) = call(&self.base, "POST", &path, &self.token, body);
        assert_eq!(status, 200, "{answer}");
    }
}
fn flow(proto: &str, src: &str, dst: &str, dport: i64, pps: i64, payload: &[u8]) -> Flow {
    Flow {
        src_ip: src.into(),
        dst_ip: dst.into(),
        proto: proto.into(),
        sport: 50000,
        dport,
        pps,
        payload: payload.to_vec(),
        has_payload: true,
        ..Default::default()
    }
}
fn udp(src: &str, dst: &str, dport: i64, pps: i64, payload: &[u8]) -> Flow {
    flow("udp", src, dst, dport, pps, payload)
}
/// A request the way FiveM's client makes one, which the published request model passes.
fn get(src: &str, path: &str) -> Flow {
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: 203.0.113.20:30120\r\nUser-Agent: CitizenFX/1\r\nAccept: */*\r\nAccept-Encoding: gzip\r\n\r\n"
    );
    flow("tcp", src, "203.0.113.20", 30120, 1, request.as_bytes())
}
fn decided(pipe: &mut Pipeline, f: &Flow, at: i64) -> (String, String, String) {
    let d = pipe.decide(f, at);
    (d.action, d.stage, d.reason)
}
fn expect(pipe: &mut Pipeline, f: &Flow, at: i64, action: &str, reason: &str) {
    let (got, stage, why) = decided(pipe, f, at);
    assert_eq!(
        (got.as_str(), why.as_str()),
        (action, reason),
        "{} from {} to {}:{} ({stage})",
        f.proto,
        f.src_ip,
        f.dst_ip,
        f.dport
    );
}
/// The origin answering a client enough to confirm it.
fn answered(pipe: &mut Pipeline, origin: &str, client: &str, at: i64) {
    let reply = Flow {
        src_ip: origin.into(),
        dst_ip: client.into(),
        proto: "udp".into(),
        pps: 4,
        ..Default::default()
    };
    for tick in 0..3 {
        pipe.observe_return(&reply, at + tick * 250);
    }
}
const QUERY: &[u8] = b"\xff\xff\xff\xffTSource Engine Query\0";

#[test]
fn the_stages_the_game_filters_and_the_classifiers_decide_together() {
    let f = Fabric::new();
    let mut pipe = f.pipeline();
    let t = T0;
    let ml_pass = "PF_RING ZC ml pass";
    // The stages first: an allow list, then drops and meters.
    let monitoring = udp("192.0.2.250", "203.0.113.10", 19132, 1, &[0x84]);
    expect(&mut pipe, &monitoring, t, "permit", "TCAM ACL permit");
    let bogon = udp("0.0.0.7", "203.0.113.10", 19132, 1, &[0x84]);
    expect(&mut pipe, &bogon, t, "drop", "TCAM ACL drop");
    let reflected = Flow {
        sport: 53,
        ..udp("100.64.0.53", "203.0.113.10", 40000, 10, b"answer")
    };
    expect(&mut pipe, &reflected, t, "drop", "TCAM ACL drop");
    let flood = udp("100.64.0.1", "203.0.113.10", 19132, 250_000, &[0x84]);
    expect(
        &mut pipe,
        &flood,
        t,
        "drop",
        "FPGA meter 200000 pps exceeded",
    );
    let syn = Flow {
        flags: "syn".into(),
        ..flow("tcp", "100.64.0.2", "203.0.113.20", 30120, 30_000, &[])
    };
    expect(&mut pipe, &syn, t, "drop", "FPGA meter 20000 pps exceeded");
    let pings = flow("icmp", "100.64.0.3", "203.0.113.30", 0, 1500, &[]);
    expect(
        &mut pipe,
        &pings,
        t,
        "drop",
        "PF_RING ZC behavioral cap 1000 pps exceeded",
    );
    // The game filters: RakNet's handshake, A2S's challenge and FiveM's framing.
    let stranger = udp("100.64.1.1", "203.0.113.10", 19132, 1, &[0x84, 0, 0]);
    expect(
        &mut pipe,
        &stranger,
        t,
        "drop",
        "game filter raknet: packet id 0x84 from a source that has not completed the handshake",
    );
    let player = |payload: &[u8]| udp("192.0.2.10", "203.0.113.10", 19132, 1, payload);
    for step in [&[0x05][..], &[0x07], &[0x84, 0, 0]] {
        expect(&mut pipe, &player(step), t + 1, "permit", ml_pass);
    }
    let query = udp("192.0.2.11", "203.0.113.10", 27015, 1, QUERY);
    let d = pipe.decide(&query, t + 2);
    assert_eq!(
        (d.action.as_str(), d.reason.as_str()),
        ("challenge", "game filter a2s: unverified source challenged")
    );
    let answered_query = [QUERY, &d.reply[5..9]].concat();
    let answer = udp("192.0.2.11", "203.0.113.10", 27015, 1, &answered_query);
    expect(&mut pipe, &answer, t + 3, "permit", ml_pass);
    let runt = udp("100.64.1.2", "203.0.113.20", 30120, 1, &[1, 2]);
    expect(
        &mut pipe,
        &runt,
        t + 4,
        "drop",
        "game filter custom: packet is 2 bytes, shorter than the 4 this protocol allows",
    );
    // FiveM's HTTP on the same port, held to its rules and then to the request model.
    expect(
        &mut pipe,
        &get("192.0.2.12", "/players.json"),
        t + 5,
        "permit",
        ml_pass,
    );
    expect(
        &mut pipe,
        &get("192.0.2.12", "/players.json"),
        t + 6,
        "drop",
        "game filter http: GET /players.json: more than 1 request a second to this path from this source",
    );
    expect(
        &mut pipe,
        &get("192.0.2.13", "/admin/ban"),
        t + 7,
        "drop",
        "game filter http: GET /admin/ban: the path is blocked",
    );
    expect(
        &mut pipe,
        &get("192.0.2.13", "/secret"),
        t + 8,
        "drop",
        "game filter http: GET /secret: not a path this server allows",
    );
    let shaped = flow(
        "tcp",
        "100.64.1.3",
        "203.0.113.20",
        30120,
        1,
        b"GET /players.json?_=3c9e HTTP/1.0\r\n\r\n",
    );
    let (action, _, reason) = decided(&mut pipe, &shaped, t + 9);
    assert!(
        action == "drop" && reason.contains("by the request model"),
        "{reason}"
    );
    // The flow model has the last word on what no rule decides: here, NTP reflected at a game
    // port at a rate under every meter.
    let unnamed = Flow {
        sport: 123,
        ..udp("100.64.1.4", "203.0.113.30", 19132, 150_000, &[0; 8])
    };
    let (action, _, reason) = decided(&mut pipe, &unnamed, t + 10);
    assert!(
        action == "drop" && reason.starts_with("PF_RING ZC ml score"),
        "{reason}"
    );
    // And all of it holds over IPv6.
    let stranger6 = udp(
        "2001:db8:ffff::1",
        "2001:db8:100::10",
        19132,
        1,
        &[0x84, 0, 0],
    );
    expect(
        &mut pipe,
        &stranger6,
        t + 11,
        "drop",
        "game filter raknet: packet id 0x84 from a source that has not completed the handshake",
    );
    let player6 = |payload: &[u8]| udp("2001:db8:aaaa::1", "2001:db8:100::10", 19132, 1, payload);
    for step in [&[0x05][..], &[0x07], &[0x84, 0, 0]] {
        expect(&mut pipe, &player6(step), t + 12, "permit", ml_pass);
    }
    let stats = pipe.stats(t + 12);
    let game = |id: &str| {
        stats["games"]
            .as_array()
            .unwrap()
            .iter()
            .find(|g| g["filter_id"] == id)
            .unwrap()
            .clone()
    };
    assert_eq!(game("bedrock")["dropped"], 1);
    assert_eq!(game("bedrock-v6")["dropped"], 1);
    assert_eq!(game("fivem")["http_dropped"], 4);
    assert_eq!(stats["ml"]["http_drops"], 1);
}
#[test]
fn reputation_lockdown_and_budgets_work_beside_everything_else() {
    let f = Fabric::new();
    let mut pipe = f.pipeline();
    let t = T0;
    // A player the origin keeps answering is verified, and takes the short path.
    answered(&mut pipe, "203.0.113.20", "192.0.2.20", t);
    let play = udp("192.0.2.20", "203.0.113.20", 30120, 1, &[1, 2, 3, 4]);
    expect(
        &mut pipe,
        &play,
        t + 1000,
        "permit",
        "verified source, fast path",
    );
    // A flood spread across four hundred sources, each under its own rate, spends the player
    // list's budget: past it strangers wait and the verified player does not.
    for i in 0..400 {
        let src = format!("100.65.{}.{}", i / 250, i % 250 + 1);
        let (action, _, reason) = decided(&mut pipe, &get(&src, "/players.json"), t + 1001);
        assert_eq!(action, "permit", "{src}: {reason}");
    }
    expect(
        &mut pipe,
        &get("100.65.9.9", "/players.json"),
        t + 1002,
        "drop",
        "game filter http: GET /players.json: more than 400 requests a second to this path from everyone, and this source is not verified",
    );
    expect(
        &mut pipe,
        &get("192.0.2.20", "/players.json"),
        t + 1003,
        "permit",
        "verified source, fast path",
    );
    // A stranger that keeps failing the RakNet handshake is boxed...
    let junk = udp("100.64.2.1", "203.0.113.10", 19132, 1, &[0x84, 0, 0]);
    for i in 0..4 {
        pipe.decide(&junk, t + 2000 + i);
    }
    expect(
        &mut pipe,
        &junk,
        t + 2010,
        "drop",
        "source is in the penalty box",
    );
    // ...and released once the origin is seen answering it: a real client, wrongly boxed.
    answered(&mut pipe, "203.0.113.10", "100.64.2.1", t + 2100);
    expect(
        &mut pipe,
        &junk,
        t + 3000,
        "permit",
        "verified source, fast path",
    );
    // Bursts on the game prefix, while the origin's replies are visible, lock it down: a source
    // no reply confirms is held to a trickle once its grace is over.
    for burst in 0..3 {
        let reflected = Flow {
            sport: 53,
            ..udp("100.64.3.1", "203.0.113.10", 40000, 50_000, b"answer")
        };
        pipe.decide(&reflected, t + 10_000 + burst * 2000);
    }
    answered(&mut pipe, "203.0.113.20", "192.0.2.21", t + 15_000);
    let newcomer = udp("100.64.4.1", "203.0.113.20", 30120, 1000, &[1, 2, 3, 4]);
    pipe.decide(&newcomer, t + 16_000);
    expect(
        &mut pipe,
        &newcomer,
        t + 16_600,
        "drop",
        "no return traffic confirms this source while the prefix is under attack",
    );
    let confirmed = udp("192.0.2.21", "203.0.113.20", 30120, 1000, &[1, 2, 3, 4]);
    expect(
        &mut pipe,
        &confirmed,
        t + 16_700,
        "permit",
        "verified source, fast path",
    );
    // The operator's permit for its monitoring holds through lockdown too.
    let monitoring = udp("192.0.2.250", "203.0.113.20", 30120, 1000, &[1, 2, 3, 4]);
    pipe.decide(&monitoring, t + 16_000);
    expect(
        &mut pipe,
        &monitoring,
        t + 16_700,
        "permit",
        "TCAM ACL permit",
    );
    let stats = pipe.stats(t + 16_700);
    assert_eq!(stats["pulsing"], true);
    assert_eq!(
        (
            &stats["reputation"]["freed"],
            &stats["egress"]["locked_down"]
        ),
        (&json!(1), &json!(1))
    );
    let fivem = stats["games"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["filter_id"] == "fivem")
        .unwrap()
        .clone();
    assert_eq!(fivem["http_budget_dropped"], 1);
    // The trickle is per source and outlasts the fabric recompiling: a newcomer that spent most
    // of its allowance before a reload has only the rest of it after.
    let locked = "no return traffic confirms this source while the prefix is under attack";
    let trickle = udp("100.64.4.2", "203.0.113.20", 30120, 300, &[1, 2, 3, 4]);
    pipe.decide(&trickle, t + 17_000);
    let (_, _, why) = decided(&mut pipe, &trickle, t + 17_600);
    assert_ne!(why, locked);
    pipe.load(f.program());
    expect(&mut pipe, &trickle, t + 17_700, "drop", locked);
}
#[test]
fn on_demand_mitigation_watches_one_customer_while_the_rest_are_filtered() {
    let f = Fabric::new();
    let mut pipe = f.pipeline();
    let t = T0;
    let watching = "watching only: tunnel contoso is under its attack thresholds";
    // Contoso is idle: what a rule would drop passes, while its storefront's HTTP rules hold.
    let reflected = Flow {
        sport: 53,
        ..udp("100.64.5.53", "198.51.100.10", 40000, 10, b"answer")
    };
    expect(&mut pipe, &reflected, t, "permit", watching);
    let admin = flow(
        "tcp",
        "100.64.5.1",
        "198.51.100.80",
        80,
        1,
        b"GET /wp-admin/setup.php HTTP/1.1\r\nHost: shop\r\n\r\n",
    );
    expect(
        &mut pipe,
        &admin,
        t + 1,
        "drop",
        "game filter http: GET /wp-admin/setup.php: the path is blocked",
    );
    // The operator's permit for its monitoring holds there too, as it would under mitigation.
    let probe = Flow {
        src_ip: "192.0.2.250".into(),
        ..admin.clone()
    };
    expect(&mut pipe, &probe, t + 1, "permit", watching);
    // Northwind, filtered always, is not watched at all.
    let at_northwind = Flow {
        dst_ip: "203.0.113.10".into(),
        ..reflected.clone()
    };
    expect(&mut pipe, &at_northwind, t + 2, "drop", "TCAM ACL drop");
    // A flood at Contoso's threshold starts its mitigation, and its whole policy applies, to the
    // flood first.
    let flood = Flow {
        pps: 150_000,
        ..reflected.clone()
    };
    expect(&mut pipe, &flood, t + 3, "drop", "TCAM ACL drop");
    expect(&mut pipe, &reflected, t + 4, "drop", "TCAM ACL drop");
    let stats = pipe.stats(t + 5);
    let row = &stats["mitigation"][0];
    assert_eq!(
        (
            &row["tunnel_id"],
            &row["active"],
            &row["wave"],
            &row["hold_seconds"]
        ),
        (&json!("contoso"), &json!(true), &json!(1), &json!(300))
    );
    // The control plane hears of it with the next heartbeat.
    f.heartbeat(stats, Value::Null);
    let (_, tunnels) = call(&f.base, "GET", "/v1/tunnels", OP, Value::Null);
    let contoso = tunnels["tunnels"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["id"] == "contoso")
        .unwrap()
        .clone();
    let here = &contoso["nodes"][0];
    assert_eq!(
        (&here["mitigating"], &here["mitigation_wave"]),
        (&json!(true), &json!(1)),
        "{contoso}"
    );
}
#[test]
fn the_node_renders_and_reports_everything_it_is_given() {
    let f = Fabric::new();
    let program = f.program();
    // Three tunnels of every kind, their shapers and the firewall in front of them.
    let lines = tunnel::render(&program).unwrap();
    for id in ["northwind", "contoso", "fabrikam"] {
        assert!(
            lines.iter().any(|l| l.contains(&format!("scr-{id}"))),
            "{id}: {lines:#?}"
        );
    }
    let desired = provision::Desired {
        tunnels: program.tunnels.clone(),
        lines: lines.clone(),
        error: String::new(),
    };
    provision::plan(&desired, &Default::default()).unwrap();
    // Each rule keyed for the TCAM table its addresses belong in.
    let keys: Vec<_> = program.asic.iter().map(|r| r.tcam_key.as_str()).collect();
    assert_eq!(
        keys,
        [
            "v4 src=192.0.2.250/32 dst=* proto=* dport=0 sport=0 pri=10",
            "v4 src=0.0.0.0/8 dst=* proto=* dport=0 sport=0 pri=20",
            "any src=* dst=* proto=udp dport=0 sport=53 pri=30",
        ]
    );
    // Every prefix announced, with its communities, towards the node's address where the family
    // allows, and Contoso's own session.
    let commands = bgp::commands(&program.announcements, 64512).unwrap();
    assert_eq!(
        commands,
        [
            "announce route 198.51.100.0/24 next-hop 192.0.2.1 community [ 64512:200 no-export ]",
            "announce route 2001:db8:100::/48",
            "announce route 203.0.113.0/24 next-hop 192.0.2.1 community [ 64512:100 ]",
        ]
    );
    let node = Node {
        tunnel_src: program.tunnel_src.clone(),
        ..f.node.clone()
    };
    let sessions = bgp::session_config(&program.sessions, &node, 64512).unwrap();
    assert!(
        sessions.iter().any(|l| l.contains("contoso_edge")),
        "{sessions:#?}"
    );
    // What the node reports renders as its own metrics and reaches the control plane's.
    let mut pipe = f.pipeline();
    pipe.decide(&get("192.0.2.30", "/players.json"), T0);
    pipe.decide(&udp("192.0.2.30", "198.51.100.10", 9, 1, &[1]), T0);
    let stats = pipe.stats(T0);
    let statuses: Vec<TunnelStatus> = program
        .tunnels
        .iter()
        .map(|t| TunnelStatus {
            tunnel_id: t.id.clone(),
            state: "up".into(),
            ..Default::default()
        })
        .collect();
    let mut m = Metrics::new();
    m.reports(
        &[json!({"node_id":node.id,"name":node.name,"region":node.region,"stats":stats})],
        T0,
    );
    m.announcements(&program.announcements);
    m.tunnels(&node, &program.tunnels, &statuses);
    let local = m.render().unwrap();
    for series in [
        "scrubline_rule_matches_total{",
        "scrubline_game_http_requests_total{",
        "scrubline_tunnel_mitigating{",
        "scrubline_tunnel_up{",
        "scrubline_bgp_announced{",
        "scrubline_prefix_ml_threshold_cut{",
        "scrubline_reputation_freed_total{",
    ] {
        assert!(local.contains(series), "{series} missing from:\n{local}");
    }
    f.heartbeat(stats, json!(statuses));
    // A second report, after more traffic to every customer, is what analytics counts from.
    for (src, dst) in [
        ("192.0.2.31", "203.0.113.10"),
        ("192.0.2.31", "198.51.100.10"),
        ("2001:db8:aaaa::31", "2001:db8:100::10"),
    ] {
        pipe.decide(&udp(src, dst, 9, 5, &[1]), T0 + 1000);
    }
    f.heartbeat(pipe.stats(T0 + 1000), json!(statuses));
    // Each customer sees its own prefix and nobody else's.
    for ((name, id), prefix) in
        f.tenants
            .iter()
            .zip(["203.0.113.0/24", "198.51.100.0/24", "2001:db8:100::/48"])
    {
        let path = format!("/v1/tenants/{id}/token");
        let (_, issued) = call(&f.base, "POST", &path, OP, Value::Null);
        let token = issued["token"].as_str().unwrap();
        let (status, overview) = call(&f.base, "GET", "/v1/analytics/overview", token, Value::Null);
        assert_eq!(status, 200, "{name}: {overview}");
        let rows = overview["prefixes"].as_array().unwrap();
        assert!(
            rows.len() == 1 && rows[0]["prefix"] == prefix && rows[0]["offered"].as_u64() > Some(0),
            "{name}: {overview}"
        );
    }
    let (status, fleet) = call(&f.base, "GET", "/metrics", OP, Value::Null);
    let fleet = fleet.as_str().unwrap_or_default().to_string();
    assert_eq!(status, 200, "{fleet}");
    for series in [
        "scrubline_game_http_requests_total{",
        "scrubline_tunnel_mitigating{",
        "scrubline_tunnel_up{",
        "scrubline_control_ml_false_positive_rate",
    ] {
        assert!(fleet.contains(series), "{series} missing from:\n{fleet}");
    }
}
#[test]
fn changes_through_the_api_reach_the_running_node_without_losing_its_state() {
    let f = Fabric::new();
    let mut pipe = f.pipeline();
    let t = T0;
    let player = |payload: &[u8]| udp("192.0.2.40", "203.0.113.10", 19132, 1, payload);
    pipe.decide(&player(&[0x05]), t);
    pipe.decide(&player(&[0x07]), t + 1);
    expect(
        &mut pipe,
        &get("192.0.2.40", "/players.json"),
        t + 2,
        "permit",
        "PF_RING ZC ml pass",
    );
    // Contoso is switched to being filtered always, and the node installs the new program.
    let (status, answer) = call(
        &f.base,
        "PUT",
        "/v1/tunnels/contoso/mitigation",
        OP,
        json!({"mitigation":"always"}),
    );
    assert_eq!(status, 200, "{answer}");
    let program = f.program();
    assert!(program.tunnels.iter().all(|t| t.mitigation.is_empty()));
    pipe.load(program);
    // What Contoso's idle tunnel would have let through is dropped now...
    let reflected = Flow {
        sport: 53,
        ..udp("100.64.6.53", "198.51.100.10", 40000, 10, b"answer")
    };
    expect(&mut pipe, &reflected, t + 3, "drop", "TCAM ACL drop");
    // ...while the player connected before the change plays on, and the player list's rate,
    // counted before it, still holds.
    expect(
        &mut pipe,
        &player(&[0x84, 0, 0]),
        t + 4,
        "permit",
        "PF_RING ZC ml pass",
    );
    expect(
        &mut pipe,
        &get("192.0.2.40", "/players.json"),
        t + 5,
        "drop",
        "game filter http: GET /players.json: more than 1 request a second to this path from this source",
    );
}
/// The keys of `a` missing from `b`, recursively, by path.
fn missing(a: &Value, b: &Value, path: &str, out: &mut Vec<String>) {
    match (a, b) {
        (Value::Object(a), Value::Object(b)) => {
            for (k, v) in a {
                match b.get(k) {
                    Some(w) => missing(v, w, &format!("{path}.{k}"), out),
                    None => out.push(format!("{path}.{k}")),
                }
            }
        }
        (Value::Array(a), Value::Array(b)) => {
            for (i, (v, w)) in a.iter().zip(b).enumerate() {
                missing(v, w, &format!("{path}[{i}]"), out);
            }
        }
        _ => {}
    }
}
#[test]
fn the_control_plane_keeps_everything_the_node_reports() {
    let f = Fabric::new();
    let mut pipe = f.pipeline();
    // Enough traffic that every part of the report has something in it: rules, filters, HTTP,
    // the classifiers, reputation, return traffic, pulses and a mitigation.
    answered(&mut pipe, "203.0.113.20", "192.0.2.50", T0);
    pipe.decide(&get("192.0.2.51", "/players.json"), T0 + 1000);
    pipe.decide(
        &udp("100.64.7.1", "203.0.113.10", 19132, 1, &[0x84]),
        T0 + 1001,
    );
    let flood = Flow {
        sport: 53,
        ..udp("100.64.7.53", "198.51.100.10", 40000, 150_000, b"answer")
    };
    for burst in 0..3 {
        pipe.decide(&flood, T0 + 2000 + burst * 2000);
    }
    let stats = pipe.stats(T0 + 8000);
    assert!(stats["mitigation"].is_array() && stats["games"].is_array());
    let kept = serde_json::to_value(
        serde_json::from_value::<pathfinder::wire::Stats>(stats.clone()).unwrap(),
    )
    .unwrap();
    let mut lost = Vec::new();
    missing(&stats, &kept, "stats", &mut lost);
    assert!(
        lost.is_empty(),
        "dropped by the heartbeat contract: {lost:#?}"
    );
}

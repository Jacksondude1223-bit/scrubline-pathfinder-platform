//! Bounded, passive port learning from traffic seen in both directions.
use crate::{model::Flow, packet, wire::DiscoveredPort};
use ipnet::IpNet;
use std::{collections::HashMap, net::IpAddr};

pub const RETENTION_MS: i64 = 3_600_000;
pub const PORTS_MAX: usize = 1024;
const PAIR_MS: i64 = 10_000;
const PENDING_MAX: usize = 4096;
const MAGIC: &[u8] = &[
    0, 255, 255, 0, 254, 254, 254, 254, 253, 253, 253, 253, 18, 52, 86, 120,
];

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct Endpoint(IpAddr, u16);

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct Exchange {
    server: Endpoint,
    client: Endpoint,
    tcp: bool,
}

#[derive(Clone, Copy)]
struct Request {
    at: i64,
    a2s: bool,
    raknet_ping: Option<[u8; 8]>,
}

#[derive(Default)]
pub struct Discovery {
    pending: HashMap<Exchange, Request>,
    ports: HashMap<(Endpoint, bool, &'static str), DiscoveredPort>,
    swept: i64,
}

fn evidence(f: &Flow, reply: bool) -> Option<(Exchange, &[u8])> {
    let tcp = f.proto.eq_ignore_ascii_case("tcp");
    if f.fragment || !tcp && !f.proto.eq_ignore_ascii_case("udp") {
        return None;
    }
    let from = Endpoint(f.src_ip.parse().ok()?, u16::try_from(f.sport).ok()?);
    let to = Endpoint(f.dst_ip.parse().ok()?, u16::try_from(f.dport).ok()?);
    if from.0 == to.0 || from.1 == 0 || to.1 == 0 {
        return None;
    }
    let (flags, payload) = if f.packet.is_empty() {
        (packet::tcp_flags(&f.flags), f.payload.as_slice())
    } else {
        let (p, anomaly) = packet::parse(&f.packet);
        if anomaly.is_some()
            || p.fragment()
            || p.proto != if tcp { 6 } else { 17 }
            || p.src != Some(from.0)
            || p.dst != Some(to.0)
            || p.sport != from.1
            || p.dport != to.1
        {
            return None;
        }
        (p.flags, p.payload)
    };
    if tcp {
        let mask = packet::SYN | packet::ACK | packet::RST;
        let expected = if reply {
            packet::SYN | packet::ACK
        } else {
            packet::SYN
        };
        if flags.map(|f| f & mask) != Some(expected) {
            return None;
        }
    }
    let (server, client) = if reply { (from, to) } else { (to, from) };
    Some((
        Exchange {
            server,
            client,
            tcp,
        },
        payload,
    ))
}

impl Discovery {
    fn sweep(&mut self, now: i64) {
        if now - self.swept >= 5_000 {
            self.swept = now;
            self.pending
                .retain(|_, request| now - request.at <= PAIR_MS);
            self.ports
                .retain(|_, row| now - row.last_seen_ms <= RETENTION_MS);
        }
    }

    pub fn request(&mut self, f: &Flow, now: i64) {
        let Some((key, payload)) = evidence(f, false) else {
            return;
        };
        self.sweep(now);
        if self.pending.len() >= PENDING_MAX && !self.pending.contains_key(&key) {
            return;
        }
        let a2s = !key.tcp
            && payload.starts_with(b"\xff\xff\xff\xffTSource Engine Query\0")
            && matches!(payload.len(), 25 | 29);
        let raknet_ping = (!key.tcp
            && payload.len() == 33
            && matches!(payload[0], 1 | 2)
            && payload.get(9..25) == Some(MAGIC))
        .then(|| payload[1..9].try_into().unwrap());
        self.pending.insert(
            key,
            Request {
                at: now,
                a2s,
                raknet_ping,
            },
        );
    }

    pub fn reply(&mut self, f: &Flow, now: i64) {
        let Some((key, payload)) = evidence(f, true) else {
            return;
        };
        let Some(request) = self.pending.remove(&key) else {
            return;
        };
        if !(0..=PAIR_MS).contains(&(now - request.at)) {
            return;
        }
        let protocol = if request.a2s
            && payload.starts_with(&[255; 4])
            && (payload.len() == 9 && payload[4] == b'A'
                || payload.len() >= 16 && payload[4] == b'I')
        {
            "a2s"
        } else if request
            .raknet_ping
            .as_ref()
            .is_some_and(|ping| payload.get(1..9) == Some(ping.as_slice()))
            && payload.len() >= 35
            && payload[0] == 0x1c
            && payload.get(17..33) == Some(MAGIC)
            && payload.len() - 35 == u16::from_be_bytes([payload[33], payload[34]]) as usize
        {
            "raknet"
        } else {
            "unknown"
        };
        let id = (key.server, key.tcp, protocol);
        if self.ports.len() >= PORTS_MAX && !self.ports.contains_key(&id) {
            return;
        }
        let Endpoint(address, port) = key.server;
        let row = self.ports.entry(id).or_insert_with(|| DiscoveredPort {
            destination: format!("{address}/{}", if address.is_ipv4() { 32 } else { 128 }),
            port,
            transport: if key.tcp { "tcp" } else { "udp" }.into(),
            protocol: protocol.into(),
            first_seen_ms: now,
            last_seen_ms: now,
            confirmations: 0,
        });
        if now - row.last_seen_ms > RETENTION_MS {
            row.first_seen_ms = now;
            row.confirmations = 0;
        }
        row.last_seen_ms = now;
        row.confirmations = row.confirmations.saturating_add(1);
    }

    pub fn forget<T>(&mut self, prefixes: &[(String, IpNet, T)]) {
        let visible = |address: &IpAddr| prefixes.iter().any(|(_, net, _)| net.contains(address));
        self.pending.retain(|key, _| visible(&key.server.0));
        self.ports.retain(|(host, _, _), _| visible(&host.0));
    }

    pub fn report(&mut self, now: i64) -> Vec<DiscoveredPort> {
        self.sweep(now);
        self.ports
            .values()
            .filter(|row| row.confirmations >= 2 && now - row.last_seen_ms <= RETENTION_MS)
            .cloned()
            .collect()
    }
}

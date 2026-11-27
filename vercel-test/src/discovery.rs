//! Bounded, passive port learning from traffic seen in both directions.
use crate::{
    model::Flow,
    packet,
    wire::{AutoFilter, DiscoveredPort, GameMetadata, METADATA_TEXT_MAX},
};
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

/// Text a server sent, kept only as printable characters and bounded, so a hostile reply cannot
/// put markup, control characters or a megabyte into a report.
fn text(bytes: &[u8]) -> Option<String> {
    let s: String = String::from_utf8_lossy(bytes)
        .chars()
        .filter(|c| !c.is_control() && *c != '\u{fffd}')
        .take(METADATA_TEXT_MAX)
        .collect();
    let s = s.trim().to_owned();
    (!s.is_empty()).then_some(s)
}

/// Reads an A2S_INFO answer (`FF FF FF FF 'I' ...`) the way Valve's server query documents it:
/// protocol, name, map, folder, game, a 16-bit AppID, players, max players, bots, server type,
/// environment, visibility, VAC, The Ship's extra fields for its AppID, version, and the extra
/// data flags with the game port, Steam id, spectator port, keywords and 64-bit game id.
pub fn a2s_info(payload: &[u8]) -> Option<GameMetadata> {
    struct Reader<'a>(&'a [u8]);
    impl<'a> Reader<'a> {
        fn byte(&mut self) -> Option<u8> {
            let (b, rest) = self.0.split_first()?;
            self.0 = rest;
            Some(*b)
        }
        fn take(&mut self, n: usize) -> Option<&'a [u8]> {
            if self.0.len() < n {
                return None;
            }
            let (head, rest) = self.0.split_at(n);
            self.0 = rest;
            Some(head)
        }
        fn short(&mut self) -> Option<u16> {
            self.take(2).map(|b| u16::from_le_bytes([b[0], b[1]]))
        }
        fn long(&mut self) -> Option<u64> {
            self.take(8).map(|b| u64::from_le_bytes(b.try_into().unwrap()))
        }
        fn string(&mut self) -> Option<&'a [u8]> {
            let end = self.0.iter().position(|b| *b == 0)?;
            let s = &self.0[..end];
            self.0 = &self.0[end + 1..];
            Some(s)
        }
    }
    let mut r = Reader(payload.strip_prefix(b"\xff\xff\xff\xffI")?);
    r.byte()?;
    let name = r.string()?;
    r.string()?;
    let folder = r.string()?;
    let game = r.string()?;
    let id = r.short()?;
    let players = r.byte()?;
    let max = r.byte()?;
    r.byte()?;
    let kind = r.byte()?;
    r.take(3)?;
    if id == 2400 {
        r.take(3)?;
    }
    let mut m = GameMetadata {
        game: text(game),
        folder: text(folder),
        app_id: (id != 0).then_some(u64::from(id)),
        name: text(name),
        players: Some(players.into()),
        max_players: Some(max.into()),
        dedicated: Some(kind == b'd'),
        ..Default::default()
    };
    // Everything past the version is optional; what is cut short is simply not reported.
    let Some(version) = r.string() else {
        return Some(m);
    };
    m.version = text(version);
    let Some(edf) = r.byte() else {
        return Some(m);
    };
    if edf & 0x80 != 0 {
        m.game_port = r.short().filter(|p| *p != 0);
    }
    if edf & 0x10 != 0 && r.long().is_none() {
        return Some(m);
    }
    if edf & 0x40 != 0 && (r.short().is_none() || r.string().is_none()) {
        return Some(m);
    }
    if edf & 0x20 != 0 && r.string().is_none() {
        return Some(m);
    }
    if edf & 0x01 != 0 {
        if let Some(gameid) = r.long() {
            m.app_id = Some(gameid & 0xff_ffff).filter(|id| *id != 0).or(m.app_id);
        }
    }
    Some(m)
}

/// Reads a RakNet unconnected pong's advertisement. Minecraft: Bedrock Edition's is
/// `MCPE;motd;protocol;version;players;max;server id;level;game mode;mode number;port v4;port v6;`
/// (MCEE for Education Edition); any other game's is kept as its first field only.
pub fn raknet_pong(payload: &[u8]) -> Option<GameMetadata> {
    let advertised = payload.get(35..)?;
    let fields: Vec<&[u8]> = advertised.split(|b| *b == b';').collect();
    let number = |i: usize| -> Option<u32> {
        std::str::from_utf8(fields.get(i)?).ok()?.trim().parse().ok()
    };
    match fields.first().copied() {
        Some(edition @ (b"MCPE" | b"MCEE")) => Some(GameMetadata {
            game: Some(
                if edition == b"MCPE" {
                    "Minecraft: Bedrock Edition"
                } else {
                    "Minecraft: Education Edition"
                }
                .into(),
            ),
            edition: text(edition),
            name: fields.get(1).and_then(|f| text(f)),
            version: fields.get(3).and_then(|f| text(f)),
            players: number(4),
            max_players: number(5),
            game_port: number(10).and_then(|p| u16::try_from(p).ok()).filter(|p| *p != 0),
            ..Default::default()
        }),
        Some(first) => Some(GameMetadata {
            game: text(first),
            ..Default::default()
        }),
        None => None,
    }
}

/// Whether automatic filtering may install a game filter on a discovered port, decided from what
/// the server said about itself rather than from the shape of its packets alone:
///
/// - A2S needs an A2S_INFO answer naming a different game port. The a2s profile drops everything
///   that does not start with the query header, so on a port that also carries the game's own
///   traffic it would cut players off; without a game port in the answer, that cannot be ruled
///   out.
/// - RakNet needs a pong identifying Minecraft: Bedrock (or Education) Edition, whose handshake
///   the raknet profile follows, advertising this port or none.
/// - Unclassified ports and TCP never qualify.
///
/// Freshness, confirmations, the customer's protocol opt-in and conflicts with existing filters
/// remain the installer's to check.
pub fn auto_filter(row: &DiscoveredPort) -> AutoFilter {
    let refuse = |reason: &str| AutoFilter {
        eligible: false,
        profile: None,
        reason: reason.into(),
    };
    if row.transport != "udp" {
        return refuse("only UDP game protocols are filtered automatically");
    }
    let profile = row.protocol.as_str();
    if !matches!(profile, "a2s" | "raknet") {
        return refuse("no recognised game protocol answered on this port");
    }
    let Some(m) = &row.metadata else {
        return AutoFilter {
            eligible: false,
            profile: Some(profile.into()),
            reason: if profile == "a2s" {
                "no A2S_INFO answer yet, only a challenge; the server's metadata is needed to tell a dedicated query port from its game port".into()
            } else {
                "no RakNet pong advertisement seen to identify the game".into()
            },
        };
    };
    let game = m.game.as_deref().unwrap_or("an unnamed game");
    let decided = |eligible: bool, reason: String| AutoFilter {
        eligible,
        profile: Some(profile.into()),
        reason,
    };
    match profile {
        "a2s" => match m.game_port {
            Some(p) if p != row.port => decided(
                true,
                format!("{game} answers queries on this dedicated port; its game traffic uses port {p}"),
            ),
            Some(_) => decided(
                false,
                format!("{game} carries its game traffic on this query port; an A2S filter would drop players"),
            ),
            None => decided(
                false,
                format!("{game} does not say which port its game traffic uses, so this may not be a dedicated query port"),
            ),
        },
        _ => match (m.edition.as_deref(), m.game_port) {
            (Some("MCPE" | "MCEE"), Some(p)) if p != row.port => decided(
                false,
                format!("{game} advertises port {p}, not this one; the port may be translated"),
            ),
            (Some("MCPE" | "MCEE"), _) => decided(true, format!("{game} identified by its pong")),
            _ => decided(
                false,
                format!("RakNet server advertising {game:?} is not one the raknet profile is known to fit"),
            ),
        },
    }
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
            metadata: None,
            auto_filter: None,
        });
        if now - row.last_seen_ms > RETENTION_MS {
            row.first_seen_ms = now;
            row.confirmations = 0;
        }
        row.last_seen_ms = now;
        row.confirmations = row.confirmations.saturating_add(1);
        // The latest description wins: a server changes its name, version or player count, and a
        // challenge answer carries none, so it leaves the last description standing.
        let described = match protocol {
            "a2s" => a2s_info(payload),
            "raknet" => raknet_pong(payload),
            _ => None,
        };
        if described.is_some() {
            row.metadata = described;
        }
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
            .filter(|row| row.confirmations >= 1 && now - row.last_seen_ms <= RETENTION_MS)
            .cloned()
            .collect()
    }
}

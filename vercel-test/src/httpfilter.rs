//! Layer-7 filtering of the HTTP a game server answers on its own address. A flood of well-formed
//! requests at an expensive endpoint (a player list, a resource download, a script's handler)
//! looks like ordinary traffic to every stage before this one; here each request is held to the
//! methods, paths, clients, body sizes and per-source rates its game filter allows.
//!
//! A request is judged in the segment that carries its request line: at the start of a segment,
//! after other requests pipelined into the same one, or after a line break in a segment that
//! continues a body. The rest of a request, and anything that is not HTTP, passes: without the
//! stream reassembled there is nothing to hold it to, and dropping a body's later segments would
//! only break requests that were allowed.
use crate::{
    model::{Flow, GameHttp},
    Result,
};
use std::{collections::HashMap, net::IpAddr};

/// Most (rule, source) rate windows tracked at once.
pub const WINDOWS_MAX: usize = 65536;
/// Most requests judged in one segment; a segment pipelining more is dropped.
const PIPELINED_MAX: u64 = 64;

#[derive(Debug)]
struct Rule {
    /// As matching sees it, normalised the way request paths are.
    path: Vec<u8>,
    exact: bool,
    drop: bool,
    /// Empty when the filter's apply.
    methods: Vec<Vec<u8>>,
    user_agents: Vec<Vec<u8>>,
    rate: i64,
    /// Zero when the filter's applies.
    max_body: i64,
    key: u64,
}

/// A game filter's HTTP rules, compiled.
#[derive(Debug)]
pub struct Policy {
    /// The TCP ports judged; every port when empty.
    pub ports: Vec<i64>,
    methods: Vec<Vec<u8>>,
    /// Lowercased: a User-Agent matches one without regard to case.
    user_agents: Vec<Vec<u8>>,
    rate: i64,
    max_body: i64,
    default_drop: bool,
    rules: Vec<Rule>,
    key: u64,
}

fn methods(list: &[String], what: &str) -> Result<Vec<Vec<u8>>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    for m in list {
        let m = m.trim().to_ascii_uppercase();
        if m.is_empty() || m.len() > 16 || !m.bytes().all(|c| c.is_ascii_uppercase()) {
            return Err(format!("{what}: {m:?} is not an HTTP method"));
        }
        if out.iter().any(|v| v == m.as_bytes()) {
            return Err(format!("{what}: {m} is listed twice"));
        }
        out.push(m.into_bytes());
    }
    Ok(out)
}
fn agents(list: &[String], what: &str) -> Result<Vec<Vec<u8>>> {
    list.iter()
        .map(|a| {
            if a.is_empty() || a.len() > 256 || !a.bytes().all(|c| (b' '..=b'~').contains(&c)) {
                Err(format!(
                    "{what}: {a:?} must be 1 to 256 printable ASCII characters"
                ))
            } else {
                Ok(a.to_ascii_lowercase().into_bytes())
            }
        })
        .collect()
}
fn action(v: &str, what: &str) -> Result<bool> {
    match v.to_ascii_lowercase().as_str() {
        "" | "allow" => Ok(false),
        "drop" => Ok(true),
        _ => Err(format!("{what} must be allow or drop")),
    }
}
/// FNV-1a: a rate window's key, stable across reloads of the same rule.
fn key(filter: &str, exact: bool, path: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in filter
        .as_bytes()
        .iter()
        .chain(&[0, u8::from(exact), 0])
        .chain(path)
    {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Compiles a game filter's HTTP rules. Without ports of its own the filter's port is judged.
pub fn compile(filter: &str, h: &GameHttp, dport: i64) -> Result<Policy> {
    let mut ports = Vec::new();
    for p in &h.ports {
        if !(1..=65535).contains(p) {
            return Err(format!("http.ports: {p} is not a port"));
        }
        if ports.contains(p) {
            return Err(format!("http.ports: {p} is listed twice"));
        }
        ports.push(*p);
    }
    if ports.is_empty() && dport > 0 {
        ports.push(dport);
    }
    let mut allowed = methods(&h.methods, "http.methods")?;
    if allowed.is_empty() {
        allowed = ["GET", "HEAD", "POST"]
            .iter()
            .map(|m| m.as_bytes().to_vec())
            .collect();
    }
    if h.rate_per_source < 0 {
        return Err("http.rate_per_source must not be negative".into());
    }
    if h.max_body_bytes < 0 {
        return Err("http.max_body_bytes must not be negative".into());
    }
    let mut rules: Vec<Rule> = Vec::new();
    for (i, p) in h.paths.iter().enumerate() {
        let what = format!("http.paths[{i}]");
        let (raw, exact) = match (p.path.is_empty(), p.prefix.is_empty()) {
            (false, true) => (&p.path, true),
            (true, false) => (&p.prefix, false),
            _ => return Err(format!("{what}: set either path or prefix")),
        };
        if !raw.starts_with('/') || !raw.bytes().all(|c| (0x21..=0x7e).contains(&c)) {
            return Err(format!(
                "{what}: {raw:?} must start with / and hold no spaces or control characters"
            ));
        }
        let mut path = Vec::new();
        normalise(raw.as_bytes(), &mut path).map_err(|e| format!("{what}: {raw} has {e}"))?;
        let drop = action(&p.action, &format!("{what}.action"))?;
        if drop
            && (!p.methods.is_empty()
                || !p.user_agents.is_empty()
                || p.rate_per_source != 0
                || p.max_body_bytes != 0)
        {
            return Err(format!(
                "{what}: a path that drops takes no methods, user agents, rate or body limit"
            ));
        }
        if p.rate_per_source < 0 || p.max_body_bytes < 0 {
            return Err(format!(
                "{what}: rate_per_source and max_body_bytes must not be negative"
            ));
        }
        if rules.iter().any(|r| r.exact == exact && r.path == path) {
            return Err(format!(
                "{what}: {raw} is the same {} as an earlier rule",
                if exact { "path" } else { "prefix" }
            ));
        }
        rules.push(Rule {
            key: key(filter, exact, &path),
            path,
            exact,
            drop,
            methods: methods(&p.methods, &format!("{what}.methods"))?,
            user_agents: agents(&p.user_agents, &format!("{what}.user_agents"))?,
            rate: p.rate_per_source,
            max_body: p.max_body_bytes,
        });
    }
    Ok(Policy {
        ports,
        methods: allowed,
        user_agents: agents(&h.user_agents, "http.user_agents")?,
        rate: h.rate_per_source,
        max_body: h.max_body_bytes,
        default_drop: action(&h.default, "http.default")?,
        rules,
        key: key(filter, false, b"*"),
    })
}

/// The path a request target names, as matching sees it: percent-decoded, with backslashes read
/// as slashes, runs of slashes and dot segments resolved, and lowercased. A server may read any
/// of those spellings as the same path, so none of them gets a request past a rule. The asterisk
/// form stays `*`, and a target with no path (CONNECT's) is empty.
fn normalise(target: &[u8], out: &mut Vec<u8>) -> std::result::Result<(), &'static str> {
    normalise_from(target, false, out)
}
/// As `normalise`, for a target a segment cuts off: an escape the cut splits is dropped rather
/// than refused.
fn normalise_from(
    target: &[u8],
    cut: bool,
    out: &mut Vec<u8>,
) -> std::result::Result<(), &'static str> {
    out.clear();
    if target == b"*" {
        out.push(b'*');
        return Ok(());
    }
    let path: &[u8] = if target.first() == Some(&b'/') {
        target
    } else if let Some(rest) = [&b"http://"[..], b"https://"].iter().find_map(|scheme| {
        target
            .get(..scheme.len())
            .filter(|head| head.eq_ignore_ascii_case(scheme))
            .map(|_| &target[scheme.len()..])
    }) {
        // The absolute form a proxy is sent: the path starts after the authority.
        rest.iter()
            .position(|&c| c == b'/')
            .map_or(b"/", |i| &rest[i..])
    } else {
        return Ok(());
    };
    let path = &path[..path
        .iter()
        .position(|&c| c == b'?' || c == b'#')
        .unwrap_or(path.len())];
    let mut i = 0;
    while i < path.len() {
        let mut c = path[i];
        if c == b'%' {
            let hex = |c: u8| (c as char).to_digit(16);
            let (Some(hi), Some(lo)) = (
                path.get(i + 1).and_then(|c| hex(*c)),
                path.get(i + 2).and_then(|c| hex(*c)),
            ) else {
                if cut && i + 2 >= path.len() {
                    break;
                }
                return Err("a broken percent escape");
            };
            c = (hi * 16 + lo) as u8;
            i += 2;
        }
        if c < 0x20 || c == 0x7f {
            return Err("a control character in its path");
        }
        out.push(if c == b'\\' {
            b'/'
        } else {
            c.to_ascii_lowercase()
        });
        i += 1;
    }
    // Dot segments and empty ones, resolved in place: what is written never runs ahead of what
    // is read.
    let n = out.len();
    let (mut w, mut r) = (0, 0);
    let mut trailing = false;
    while r < n {
        let start = r + 1;
        let end = out[start.min(n)..]
            .iter()
            .position(|&c| c == b'/')
            .map_or(n, |j| start + j);
        let last = end >= n;
        match &out[start.min(n)..end] {
            b"" | b"." => trailing = last,
            b".." => {
                w = out[..w].iter().rposition(|&c| c == b'/').unwrap_or(0);
                trailing = last;
            }
            _ => {
                out[w] = b'/';
                out.copy_within(start..end, w + 1);
                w += 1 + end - start;
                trailing = false;
            }
        }
        r = end;
    }
    if trailing || w == 0 {
        out[w] = b'/';
        w += 1;
    }
    out.truncate(w);
    Ok(())
}

/// A request's head, as far as the segment carrying it holds it.
#[derive(Debug, Default)]
struct Head<'a> {
    method: &'a [u8],
    target: &'a [u8],
    user_agent: Option<&'a [u8]>,
    content_length: Option<u64>,
    chunked: bool,
    /// Whether the blank line ending the head is in the segment.
    complete: bool,
    /// Whether the segment ends inside the request line, so the target may be cut short.
    cut: bool,
    /// Whether it asks to switch the connection to cleartext HTTP/2.
    h2c: bool,
    /// Bytes from the request line through the blank line.
    len: usize,
}

/// Methods common enough that one followed by a path starts a request even before the line is
/// seen whole.
const KNOWN: [&[u8]; 8] = [
    b"GET", b"HEAD", b"POST", b"PUT", b"DELETE", b"OPTIONS", b"PATCH", b"TRACE",
];
/// A segment shorter than this that holds only part of a request line was split on purpose: a
/// client writes a line whole, and TCP cuts one only at a full segment.
const SPLIT: usize = 512;
/// The length of the method a request line starts with, if `s` starts one: up to sixteen
/// capitals and a space.
fn method(s: &[u8]) -> Option<usize> {
    let m = s
        .iter()
        .take(17)
        .take_while(|c| c.is_ascii_uppercase())
        .count();
    (m > 0 && m <= 16 && s.get(m) == Some(&b' ')).then_some(m)
}
/// Whether `s` starts with a whole, well-formed request line.
fn well_formed(s: &[u8]) -> bool {
    let (Some(m), Some((request, _))) = (method(s), line(s)) else {
        return false;
    };
    let rest = &request[m + 1..];
    rest.iter().position(|&c| c == b' ').is_some_and(|sp| {
        let (target, version) = (&rest[..sp], &rest[sp + 1..]);
        !target.is_empty()
            && target.iter().all(|c| (0x21..=0x7e).contains(c))
            && (version == b"HTTP/1.1" || version == b"HTTP/1.0")
    })
}
/// Whether a request starts at `s`: a well-known method before a target shaped like one, which
/// the request is then held to the grammar on, or any method on a whole, well-formed request
/// line. A body that merely begins with capitals and a space is neither.
fn starts(s: &[u8]) -> bool {
    let Some(m) = method(s) else {
        return false;
    };
    let target = &s[m + 1..];
    (KNOWN.contains(&&s[..m])
        && (matches!(target.first(), Some(b'/' | b'*'))
            || starts_with_ignore_case(target, b"http://")
            || starts_with_ignore_case(target, b"https://")))
        || well_formed(s)
}
fn line(s: &[u8]) -> Option<(&[u8], usize)> {
    let nl = s.iter().position(|&c| c == b'\n')?;
    Some((s[..nl].strip_suffix(b"\r").unwrap_or(&s[..nl]), nl + 1))
}
fn trim(s: &[u8]) -> &[u8] {
    let s = &s[s
        .iter()
        .position(|c| *c != b' ' && *c != b'\t')
        .unwrap_or(s.len())..];
    &s[..s
        .iter()
        .rposition(|c| *c != b' ' && *c != b'\t')
        .map_or(0, |i| i + 1)]
}
/// Parses the request starting at `s`, in a segment `whole` bytes long. What a server would
/// refuse as malformed, and what no client sends, is an error.
fn head(s: &[u8], whole: usize) -> std::result::Result<Head<'_>, String> {
    let m = method(s).unwrap_or(0);
    let Some((request, mut at)) = line(s) else {
        // A line that runs past a full segment is long, and what it shows of the target is
        // judged; one cut short in a short segment is someone hiding a path.
        if whole < SPLIT {
            return Err("a request line split across segments, which no client needs".into());
        }
        let rest = &s[m + 1..];
        let target = &rest[..rest.iter().position(|&c| c == b' ').unwrap_or(rest.len())];
        if !target.iter().all(|c| (0x21..=0x7e).contains(c)) {
            return Err("the request target holds characters a URL cannot".into());
        }
        return Ok(Head {
            method: &s[..m],
            target,
            cut: true,
            len: s.len(),
            ..Default::default()
        });
    };
    let rest = &request[m + 1..];
    let Some(sp) = rest.iter().position(|&c| c == b' ') else {
        return Err("the request line carries no HTTP version".into());
    };
    let (target, version) = (&rest[..sp], &rest[sp + 1..]);
    if target.is_empty() || !target.iter().all(|c| (0x21..=0x7e).contains(c)) {
        return Err("the request target holds characters a URL cannot".into());
    }
    if version != b"HTTP/1.1" && version != b"HTTP/1.0" {
        return Err(format!("{} is not HTTP/1.0 or HTTP/1.1", show(version)));
    }
    let mut h = Head {
        method: &s[..m],
        target,
        ..Default::default()
    };
    let mut encoded = false;
    while let Some((field, used)) = line(&s[at..]) {
        at += used;
        if field.is_empty() {
            h.complete = true;
            break;
        }
        if field[0] == b' ' || field[0] == b'\t' {
            return Err("a folded header line".into());
        }
        let Some(colon) = field.iter().position(|&c| c == b':') else {
            return Err("a header line with no colon".into());
        };
        let name = &field[..colon];
        if name.is_empty()
            || !name
                .iter()
                .all(|c| c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(c))
        {
            return Err("a header name no request can carry".into());
        }
        let value = trim(&field[colon + 1..]);
        if name.eq_ignore_ascii_case(b"user-agent") {
            h.user_agent.get_or_insert(value);
        } else if name.eq_ignore_ascii_case(b"content-length") {
            let n = std::str::from_utf8(value)
                .ok()
                .filter(|v| !v.is_empty() && v.len() <= 19 && v.bytes().all(|c| c.is_ascii_digit()))
                .and_then(|v| v.parse::<u64>().ok())
                .ok_or("a Content-Length that is not a number")?;
            if h.content_length.is_some_and(|v| v != n) {
                return Err("Content-Length headers that disagree".into());
            }
            h.content_length = Some(n);
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            encoded = true;
            h.chunked |= value.windows(7).any(|w| w.eq_ignore_ascii_case(b"chunked"));
        } else if name.eq_ignore_ascii_case(b"upgrade") {
            h.h2c |= value.windows(3).any(|w| w.eq_ignore_ascii_case(b"h2c"));
        }
    }
    if encoded && h.content_length.is_some() {
        return Err(
            "both Content-Length and Transfer-Encoding, the shape request smuggling takes".into(),
        );
    }
    h.len = at;
    Ok(h)
}
/// Where the next request line starts after a line break at or after `from`. Only a complete,
/// well-formed request line counts, so a body that merely mentions a method does not.
fn embedded(s: &[u8], from: usize) -> Option<usize> {
    let mut at = from;
    while let Some(i) = s.get(at..)?.iter().position(|&c| c == b'\n') {
        let p = at + i + 1;
        if well_formed(&s[p..]) {
            return Some(p);
        }
        at = p;
    }
    None
}
/// Bytes for a reason, readable and short.
fn show(s: &[u8]) -> String {
    let cut = s.len() > 96;
    let mut v = String::from_utf8_lossy(&s[..s.len().min(96)]).into_owned();
    if cut {
        v.push('…');
    }
    v
}
fn starts_with_ignore_case(s: &[u8], prefix: &[u8]) -> bool {
    s.get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

/// Request rates per (rule, source), each over the last second in four quarters.
#[derive(Default)]
pub struct Windows {
    map: HashMap<(u64, IpAddr), Window>,
    last_sweep: i64,
}
#[derive(Default)]
struct Window {
    slots: [i64; 4],
    count: [i64; 4],
}
impl Windows {
    pub fn len(&self) -> usize {
        self.map.len()
    }
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
    /// Counts `n` requests from a source and says whether they take it over `limit` a second. A
    /// table full of sources still active admits a new one rather than evicting them.
    fn over(&mut self, key: u64, src: IpAddr, n: i64, limit: i64, now: i64) -> bool {
        let slot = now.div_euclid(250);
        if !self.map.contains_key(&(key, src)) && self.map.len() >= WINDOWS_MAX {
            if now - self.last_sweep < 1000 {
                return false;
            }
            self.last_sweep = now;
            self.map
                .retain(|_, w| w.slots.iter().any(|at| *at >= slot - 3));
            if self.map.len() >= WINDOWS_MAX {
                return false;
            }
        }
        let w = self.map.entry((key, src)).or_default();
        let i = slot.rem_euclid(4) as usize;
        if w.slots[i] != slot {
            w.slots[i] = slot;
            w.count[i] = 0;
        }
        w.count[i] = w.count[i].saturating_add(n);
        w.count
            .iter()
            .zip(w.slots)
            .filter(|(_, at)| *at >= slot - 3 && *at <= slot)
            .fold(0i64, |t, (v, _)| t.saturating_add(*v))
            > limit
    }
}

/// What the filter made of one segment.
#[derive(Debug, Default)]
pub struct Judgement {
    pub drop: bool,
    pub reason: String,
    /// Requests judged in the segment.
    pub requests: u64,
    /// Whether the drop was for a rate.
    pub limited: bool,
}

impl Policy {
    /// Whether this policy judges a TCP port.
    pub fn covers(&self, dport: i64) -> bool {
        self.ports.is_empty() || self.ports.contains(&dport)
    }
    fn rule(&self, path: &[u8]) -> Option<&Rule> {
        self.rules
            .iter()
            .find(|r| r.exact && r.path == path)
            .or_else(|| {
                self.rules
                    .iter()
                    .filter(|r| !r.exact && path.starts_with(&r.path))
                    .max_by_key(|r| r.path.len())
            })
    }
    /// Holds one request to the rules for its path. Err carries why it is dropped, and whether
    /// for a rate.
    fn check(
        &self,
        h: &Head,
        windows: &mut Windows,
        scratch: &mut Vec<u8>,
        src: Option<IpAddr>,
        n: i64,
        now: i64,
    ) -> std::result::Result<(), (String, bool)> {
        normalise_from(h.target, h.cut, scratch)
            .map_err(|e| (format!("a malformed request: its target has {e}"), false))?;
        let path = &scratch[..];
        let refuse = |why: String, limited: bool| {
            Err((format!("{} {}: {why}", show(h.method), show(path)), limited))
        };
        let rule = self.rule(path);
        match rule {
            Some(r) if r.drop => return refuse("the path is blocked".into(), false),
            None if self.default_drop => {
                return refuse("not a path this server allows".into(), false)
            }
            _ => {}
        }
        if h.h2c {
            // Past the switch the connection speaks binary frames, which no rule could read.
            return refuse(
                "asks for cleartext HTTP/2, which the rules could not read".into(),
                false,
            );
        }
        let methods = rule
            .filter(|r| !r.methods.is_empty())
            .map_or(&self.methods, |r| &r.methods);
        if !methods.iter().any(|m| m == h.method) {
            return refuse("not a method this path allows".into(), false);
        }
        let agents = rule
            .filter(|r| !r.user_agents.is_empty())
            .map_or(&self.user_agents, |r| &r.user_agents);
        if !agents.is_empty() {
            match h.user_agent {
                None if h.complete => return refuse("no User-Agent".into(), false),
                None => {
                    return refuse(
                        "no User-Agent in the segment that starts the request".into(),
                        false,
                    )
                }
                Some(ua) if !agents.iter().any(|a| starts_with_ignore_case(ua, a)) => {
                    return refuse(
                        format!("User-Agent {} is not one this path allows", show(ua)),
                        false,
                    )
                }
                _ => {}
            }
        }
        let max = rule
            .map(|r| r.max_body)
            .filter(|v| *v > 0)
            .unwrap_or(self.max_body);
        if max > 0 {
            if h.chunked {
                return refuse(
                    format!("a chunked body, which cannot be held to the {max} bytes allowed"),
                    false,
                );
            }
            if let Some(len) = h.content_length.filter(|len| *len > max as u64) {
                return refuse(
                    format!("a {len}-byte body, over the {max} bytes allowed"),
                    false,
                );
            }
        }
        let requests = |n: i64| format!("{n} request{}", if n == 1 { "" } else { "s" });
        if let Some(src) = src {
            if let Some(r) = rule.filter(|r| r.rate > 0) {
                if windows.over(r.key, src, n, r.rate, now) {
                    return refuse(
                        format!(
                            "more than {} a second to this path from this source",
                            requests(r.rate)
                        ),
                        true,
                    );
                }
            }
            if self.rate > 0 && windows.over(self.key, src, n, self.rate, now) {
                return refuse(
                    format!(
                        "more than {} a second to this server from this source",
                        requests(self.rate)
                    ),
                    true,
                );
            }
        }
        Ok(())
    }
    /// Judges a segment with a payload: every request that starts in it, at its start, pipelined
    /// after another or after a line break in one that continues a body. The first request the
    /// rules refuse drops the segment.
    pub fn judge(
        &self,
        windows: &mut Windows,
        scratch: &mut Vec<u8>,
        f: &Flow,
        now: i64,
    ) -> Judgement {
        let s = &f.payload[..];
        let mut j = Judgement::default();
        if s.starts_with(b"PRI * HTTP/2.0") {
            j.drop = true;
            j.requests = 1;
            j.reason = "cleartext HTTP/2, which the rules cannot read".into();
            return j;
        }
        let mut at = if starts(s) {
            0
        } else if s.len() >= 3 && s[0] == 0x16 && s[1] == 0x03 && s[2] <= 0x04 {
            j.reason = "TLS, which the filter cannot read".into();
            return j;
        } else if let Some(at) = embedded(s, 0) {
            at
        } else {
            j.reason = "not the start of an HTTP request".into();
            return j;
        };
        let src = f.src_ip.parse::<IpAddr>().ok();
        let n = f.pps.max(1);
        loop {
            j.requests += 1;
            if j.requests > PIPELINED_MAX {
                j.drop = true;
                j.reason = format!("more than {PIPELINED_MAX} requests pipelined into a segment");
                return j;
            }
            let h = match head(&s[at..], s.len()) {
                Ok(h) => h,
                Err(e) => {
                    j.drop = true;
                    j.reason = format!("a malformed request: {e}");
                    return j;
                }
            };
            if let Err((why, limited)) = self.check(&h, windows, scratch, src, n, now) {
                j.drop = true;
                j.limited = limited;
                j.reason = why;
                return j;
            }
            // Another request in the segment starts after this one's body: right after it when
            // its length is declared, or at a request line found after a chunked one.
            if !h.complete {
                break;
            }
            let after = at + h.len;
            at = if h.chunked {
                match embedded(s, after) {
                    Some(next) => next,
                    None => break,
                }
            } else {
                let body = usize::try_from(h.content_length.unwrap_or(0)).unwrap_or(usize::MAX);
                match after.checked_add(body).filter(|next| *next < s.len()) {
                    None => break,
                    Some(next) if starts(&s[next..]) => next,
                    Some(next) => match embedded(s, next) {
                        Some(found) => found,
                        None => break,
                    },
                }
            };
        }
        j.reason = "HTTP requests allowed".into();
        j
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::GameHttpPath;
    fn head_of(s: &[u8]) -> std::result::Result<Head<'_>, String> {
        head(s, s.len())
    }
    fn norm(target: &str) -> String {
        let mut out = Vec::new();
        normalise(target.as_bytes(), &mut out).unwrap();
        String::from_utf8(out).unwrap()
    }
    #[test]
    fn paths_compare_however_they_are_spelled() {
        for (target, want) in [
            ("/players.json", "/players.json"),
            ("/Players.JSON?x=1", "/players.json"),
            ("/%70layers.json", "/players.json"),
            ("//players.json", "/players.json"),
            ("/files/../players.json", "/players.json"),
            ("/files/%2e%2e/players.json", "/players.json"),
            ("/files\\..\\players.json", "/players.json"),
            ("/./a/b/../c/", "/a/c/"),
            ("/a/b/..", "/a/"),
            ("/../..", "/"),
            ("/", "/"),
            ("http://203.0.113.20:30120/info.json", "/info.json"),
            ("HTTPS://host", "/"),
            ("*", "*"),
            ("host:443", ""),
        ] {
            assert_eq!(norm(target), want, "{target}");
        }
        let mut out = Vec::new();
        assert!(normalise(b"/%zz", &mut out).is_err());
        assert!(normalise(b"/a%00", &mut out).is_err());
        assert!(normalise(b"/a%0d%0a", &mut out).is_err());
    }
    #[test]
    fn heads_are_read_as_far_as_the_segment_holds_them() {
        let h = head_of(b"POST /client HTTP/1.1\r\nHost: x\r\nUser-Agent:  CitizenFX/1 \r\nContent-Length: 12\r\n\r\nmethod=initC").unwrap();
        assert_eq!((h.method, h.target), (&b"POST"[..], &b"/client"[..]));
        assert_eq!(h.user_agent, Some(&b"CitizenFX/1"[..]));
        assert_eq!((h.content_length, h.complete), (Some(12), true));
        let cut = head_of(b"GET / HTTP/1.1\r\nHost: x\r\nUser-Ag").unwrap();
        assert!(!cut.complete && cut.user_agent.is_none());
        for bad in [
            &b"GET /players.json"[..],
            b"GET /players.json\r\n",
            b"GET /a b HTTP/1.1\r\n",
            b"GET /players.json HTTP/2.0\r\n",
            b"GET / HTTP/1.1\r\nHost x\r\n\r\n",
            b"GET / HTTP/1.1\r\n folded\r\n\r\n",
            b"GET / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n",
            b"GET / HTTP/1.1\r\nContent-Length: 1e3\r\n\r\n",
            b"POST / HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
        ] {
            assert!(head_of(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
    }
    fn policy(h: GameHttp) -> Policy {
        compile("f", &h, 30120).unwrap()
    }
    fn flow(payload: &[u8]) -> Flow {
        Flow {
            src_ip: "192.0.2.1".into(),
            dst_ip: "203.0.113.20".into(),
            proto: "tcp".into(),
            dport: 30120,
            pps: 1,
            payload: payload.to_vec(),
            has_payload: true,
            ..Default::default()
        }
    }
    #[test]
    fn the_most_specific_rule_decides() {
        let p = policy(GameHttp {
            paths: vec![
                GameHttpPath {
                    prefix: "/files/".into(),
                    rate_per_source: 5,
                    ..Default::default()
                },
                GameHttpPath {
                    prefix: "/files/secret/".into(),
                    action: "drop".into(),
                    ..Default::default()
                },
                GameHttpPath {
                    path: "/files/secret/ok".into(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        });
        assert_eq!(p.rule(b"/files/a").unwrap().rate, 5);
        assert!(p.rule(b"/files/secret/a").unwrap().drop);
        assert!(!p.rule(b"/files/secret/ok").unwrap().drop);
        assert!(p.rule(b"/other").is_none());
    }
    #[test]
    fn requests_pipelined_into_a_segment_are_each_judged() {
        let p = policy(GameHttp {
            paths: vec![GameHttpPath {
                path: "/players.json".into(),
                action: "drop".into(),
                ..Default::default()
            }],
            ..Default::default()
        });
        let (mut w, mut scratch) = (Windows::default(), Vec::new());
        let mut judge = |payload: &[u8]| p.judge(&mut w, &mut scratch, &flow(payload), 0);
        let j = judge(b"GET / HTTP/1.1\r\n\r\nGET /players.json HTTP/1.1\r\n\r\n");
        assert!(j.drop && j.requests == 2, "{j:?}");
        let j = judge(
            b"POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcdGET /players.json HTTP/1.1\r\n\r\n",
        );
        assert!(j.drop && j.requests == 2, "after a body: {j:?}");
        // The segment after a body that ran on, with a request behind it.
        let j = judge(b"rest of a body\r\nGET /players.json HTTP/1.1\r\n\r\n");
        assert!(j.drop, "{j:?}");
        // A body that only mentions a method passes.
        let j = judge(b"rest of a body\r\nGET is what it says");
        assert!(!j.drop && j.requests == 0, "{j:?}");
        let j = judge(&[0x16, 0x03, 0x01, 0x02, 0x00]);
        assert!(!j.drop && j.reason.starts_with("TLS"));
    }
}

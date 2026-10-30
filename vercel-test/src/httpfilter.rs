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
//!
//! A request the rules allow is then scored by the request model, when one is published and the
//! policy has the classifiers run on everything.
//!
//! A flood spread across enough sources keeps each one under its rate, so a filter or a path can
//! also take a budget of requests a second from everyone together. Over it, only sources the
//! fabric has verified get through.
use crate::{
    ml,
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
    /// The path's budget from every source together; none at zero.
    total: i64,
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
    total: i64,
    max_body: i64,
    default_drop: bool,
    rules: Vec<Rule>,
    key: u64,
}

/// What judging a segment takes besides the rules: whether its source is verified, which a budget
/// for everyone spares, and the request model, if one is consulted, with the score it drops at
/// here, which is lower than its own threshold while the segment's target is being probed.
#[derive(Debug, Clone, Copy, Default)]
pub struct Context<'a> {
    pub verified: bool,
    pub model: Option<&'a ml::Model>,
    pub threshold: f64,
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
    if h.rate_total < 0 {
        return Err("http.rate_total must not be negative".into());
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
                || p.rate_total != 0
                || p.max_body_bytes != 0)
        {
            return Err(format!(
                "{what}: a path that drops takes no methods, user agents, rates or body limit"
            ));
        }
        if p.rate_per_source < 0 || p.rate_total < 0 || p.max_body_bytes < 0 {
            return Err(format!(
                "{what}: rate_per_source, rate_total and max_body_bytes must not be negative"
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
            total: p.rate_total,
            max_body: p.max_body_bytes,
        });
    }
    Ok(Policy {
        ports,
        methods: allowed,
        user_agents: agents(&h.user_agents, "http.user_agents")?,
        rate: h.rate_per_source,
        total: h.rate_total,
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
    /// What the request model looks at besides: the version, how many header lines there are,
    /// and which of the headers a browser sends it carries.
    http10: bool,
    headers: usize,
    accept: bool,
    accept_language: bool,
    accept_encoding: bool,
    cookie: bool,
    referer: bool,
}
impl Head<'_> {
    /// The request as the request model sees it, `position` into its segment.
    fn request(&self, position: u64) -> ml::Request {
        let (path, query) = match self.target.iter().position(|&c| c == b'?') {
            Some(q) => (&self.target[..q], self.target.len() - q - 1),
            None => (self.target, 0),
        };
        ml::Request {
            get: self.method == b"GET" || self.method == b"HEAD",
            post: self.method == b"POST",
            http10: self.http10,
            path: path.len(),
            depth: path.iter().filter(|&&c| c == b'/').count(),
            query,
            headers: self.headers,
            user_agent: self.user_agent.is_some(),
            accept: self.accept,
            accept_language: self.accept_language,
            accept_encoding: self.accept_encoding,
            cookie: self.cookie,
            referer: self.referer,
            body: self.content_length.unwrap_or(0),
            chunked: self.chunked,
            complete: self.complete,
            position,
        }
    }
}

/// Methods common enough that one followed by a path starts a request even before the line is
/// seen whole.
const KNOWN: [&[u8]; 8] = [
    b"GET", b"HEAD", b"POST", b"PUT", b"DELETE", b"OPTIONS", b"PATCH", b"TRACE",
];
/// A segment shorter than this that holds only part of a request line was split on purpose: a
/// client writes a line whole, and TCP cuts one only at a full segment.
const SPLIT: usize = 512;
/// The longest request or header line, and the most header lines, a request may carry: what
/// nginx and Apache refuse past by default, so nothing a server would accept is dropped, and the
/// overlong lines buffer overflows are built from never reach one.
const LINE_MAX: usize = 8192;
const HEADERS_MAX: usize = 100;
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
    let long = |what: &str| {
        Err(format!("a {what} line longer than {LINE_MAX} bytes, which servers refuse and buffer overflows are built from"))
    };
    let Some((request, mut at)) = line(s) else {
        // A line that runs past a full segment is long, and what it shows of the target is
        // judged; one cut short in a short segment is someone hiding a path.
        if whole < SPLIT {
            return Err("a request line split across segments, which no client needs".into());
        }
        if s.len() > LINE_MAX {
            return long("request");
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
    if request.len() > LINE_MAX {
        return long("request");
    }
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
        http10: version == b"HTTP/1.0",
        ..Default::default()
    };
    let mut encoded = false;
    while let Some((field, used)) = line(&s[at..]) {
        at += used;
        if field.is_empty() {
            h.complete = true;
            break;
        }
        h.headers += 1;
        if field.len() > LINE_MAX {
            return long("header");
        }
        if h.headers > HEADERS_MAX {
            return Err(format!(
                "more than {HEADERS_MAX} header lines, which servers refuse"
            ));
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
        } else if name.eq_ignore_ascii_case(b"accept") {
            h.accept = true;
        } else if name.eq_ignore_ascii_case(b"accept-language") {
            h.accept_language = true;
        } else if name.eq_ignore_ascii_case(b"accept-encoding") {
            h.accept_encoding = true;
        } else if name.eq_ignore_ascii_case(b"cookie") {
            h.cookie = true;
        } else if name.eq_ignore_ascii_case(b"referer") {
            h.referer = true;
        }
    }
    if encoded && h.content_length.is_some() {
        return Err(
            "both Content-Length and Transfer-Encoding, the shape request smuggling takes".into(),
        );
    }
    // A header line the segment ends inside is as long as what it shows of it, at least.
    if !h.complete && s.len() - at > LINE_MAX {
        return long("header");
    }
    h.len = at;
    Ok(h)
}
/// Where the request after `h`, which starts at `at` in `s`, starts: right after it when its body
/// length is declared, or at a request line found after a chunked one. None when the segment ends
/// first.
fn next(s: &[u8], at: usize, h: &Head) -> Option<usize> {
    if !h.complete {
        return None;
    }
    let after = at + h.len;
    if h.chunked {
        return embedded(s, after);
    }
    let body = usize::try_from(h.content_length.unwrap_or(0)).unwrap_or(usize::MAX);
    match after.checked_add(body).filter(|next| *next < s.len()) {
        None => None,
        Some(next) if starts(&s[next..]) => Some(next),
        Some(next) => embedded(s, next),
    }
}
/// Whether a segment is the start of a TLS record, which the filter cannot read.
fn tls(s: &[u8]) -> bool {
    s.len() >= 3 && s[0] == 0x16 && s[1] == 0x03 && s[2] <= 0x04
}
/// The requests a TCP segment carries, as the request model sees them: each one that starts in it,
/// as the rules would find them, up to the first that does not parse.
pub fn requests(f: &Flow) -> Vec<ml::Request> {
    let s = &f.payload[..];
    let mut out = Vec::new();
    if !f.proto.eq_ignore_ascii_case("tcp") || s.starts_with(b"PRI * HTTP/2.0") || tls(s) {
        return out;
    }
    let Some(mut at) = (if starts(s) { Some(0) } else { embedded(s, 0) }) else {
        return out;
    };
    while out.len() < PIPELINED_MAX as usize {
        let Ok(h) = head(&s[at..], s.len()) else {
            break;
        };
        out.push(h.request(out.len() as u64 + 1));
        match next(s, at, &h) {
            Some(n) => at = n,
            None => break,
        }
    }
    out
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

/// Request rates per (rule, source), and the rules' budgets for everyone, each over the last
/// second in four quarters.
#[derive(Default)]
pub struct Windows {
    map: HashMap<(u64, IpAddr), Window>,
    last_sweep: i64,
    /// Keyed by rule, so bounded by the policy; the bound only matters to rules a reload dropped.
    totals: HashMap<u64, Window>,
}
#[derive(Default)]
struct Window {
    slots: [i64; 4],
    count: [i64; 4],
}
impl Window {
    /// Counts `n` requests in the quarter `slot` and returns the count over the last second.
    fn add(&mut self, slot: i64, n: i64) -> i64 {
        let i = slot.rem_euclid(4) as usize;
        if self.slots[i] != slot {
            self.slots[i] = slot;
            self.count[i] = 0;
        }
        self.count[i] = self.count[i].saturating_add(n);
        self.count
            .iter()
            .zip(self.slots)
            .filter(|(_, at)| *at >= slot - 3 && *at <= slot)
            .fold(0i64, |t, (v, _)| t.saturating_add(*v))
    }
    fn live(&self, slot: i64) -> bool {
        self.slots.iter().any(|at| *at >= slot - 3)
    }
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
            self.map.retain(|_, w| w.live(slot));
            if self.map.len() >= WINDOWS_MAX {
                return false;
            }
        }
        self.map.entry((key, src)).or_default().add(slot, n) > limit
    }
    /// Counts `n` requests against a rule's budget for everyone and says whether they take it
    /// over `limit` a second.
    fn over_total(&mut self, key: u64, n: i64, limit: i64, now: i64) -> bool {
        let slot = now.div_euclid(250);
        if !self.totals.contains_key(&key) && self.totals.len() >= 4096 {
            self.totals.retain(|_, w| w.live(slot));
        }
        self.totals.entry(key).or_default().add(slot, n) > limit
    }
}

/// What the filter made of one segment.
#[derive(Debug, Default)]
pub struct Judgement {
    pub drop: bool,
    pub reason: String,
    /// Requests judged in the segment.
    pub requests: u64,
    /// Whether the drop was for a rate, and whether that was a budget for everyone, which the
    /// source was not verified to be spared.
    pub limited: bool,
    pub budget: bool,
    /// Of the requests the rules allowed, how many the request model scored, the highest score,
    /// and why the first it would drop should be, if it would drop any.
    pub scored: u64,
    pub score: f64,
    pub flagged: String,
}
/// What check() refused a request for, if a rate: its source's own, or a budget for everyone.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Limit {
    None,
    Source,
    Everyone,
}
/// A segment's requests as the rates count them: the source, whether it is verified, how many
/// requests each one counts as, and when they arrived.
#[derive(Clone, Copy)]
struct Arrival {
    src: Option<IpAddr>,
    verified: bool,
    n: i64,
    now: i64,
}

impl Policy {
    /// Whether this policy judges a TCP port.
    pub fn covers(&self, dport: i64) -> bool {
        self.ports.is_empty() || self.ports.contains(&dport)
    }
    /// Whether the filter or any of its paths holds a budget for everyone.
    pub fn budgeted(&self) -> bool {
        self.total > 0 || self.rules.iter().any(|r| r.total > 0)
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
    /// Holds one request to the rules for its path. Err carries why it is dropped, and which rate
    /// it was over, if one.
    fn check(
        &self,
        h: &Head,
        windows: &mut Windows,
        scratch: &mut Vec<u8>,
        a: Arrival,
    ) -> std::result::Result<(), (String, Limit)> {
        normalise_from(h.target, h.cut, scratch).map_err(|e| {
            (
                format!("a malformed request: its target has {e}"),
                Limit::None,
            )
        })?;
        let path = &scratch[..];
        let refuse = |why: String, limit: Limit| {
            Err((format!("{} {}: {why}", show(h.method), show(path)), limit))
        };
        let rule = self.rule(path);
        match rule {
            Some(r) if r.drop => return refuse("the path is blocked".into(), Limit::None),
            None if self.default_drop => {
                return refuse("not a path this server allows".into(), Limit::None)
            }
            _ => {}
        }
        if h.h2c {
            // Past the switch the connection speaks binary frames, which no rule could read.
            return refuse(
                "asks for cleartext HTTP/2, which the rules could not read".into(),
                Limit::None,
            );
        }
        let methods = rule
            .filter(|r| !r.methods.is_empty())
            .map_or(&self.methods, |r| &r.methods);
        if !methods.iter().any(|m| m == h.method) {
            return refuse("not a method this path allows".into(), Limit::None);
        }
        let agents = rule
            .filter(|r| !r.user_agents.is_empty())
            .map_or(&self.user_agents, |r| &r.user_agents);
        if !agents.is_empty() {
            match h.user_agent {
                None if h.complete => return refuse("no User-Agent".into(), Limit::None),
                None => {
                    return refuse(
                        "no User-Agent in the segment that starts the request".into(),
                        Limit::None,
                    )
                }
                Some(ua) if !agents.iter().any(|a| starts_with_ignore_case(ua, a)) => {
                    return refuse(
                        format!("User-Agent {} is not one this path allows", show(ua)),
                        Limit::None,
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
                    Limit::None,
                );
            }
            if let Some(len) = h.content_length.filter(|len| *len > max as u64) {
                return refuse(
                    format!("a {len}-byte body, over the {max} bytes allowed"),
                    Limit::None,
                );
            }
        }
        let requests = |n: i64| format!("{n} request{}", if n == 1 { "" } else { "s" });
        if let Some(src) = a.src {
            if let Some(r) = rule.filter(|r| r.rate > 0) {
                if windows.over(r.key, src, a.n, r.rate, a.now) {
                    return refuse(
                        format!(
                            "more than {} a second to this path from this source",
                            requests(r.rate)
                        ),
                        Limit::Source,
                    );
                }
            }
            if self.rate > 0 && windows.over(self.key, src, a.n, self.rate, a.now) {
                return refuse(
                    format!(
                        "more than {} a second to this server from this source",
                        requests(self.rate)
                    ),
                    Limit::Source,
                );
            }
        }
        // A flood spread across enough sources keeps each one under its rate, so a budget counts
        // every request that got this far. Over it, only a verified source's get through.
        if let Some(r) = rule.filter(|r| r.total > 0) {
            if windows.over_total(r.key, a.n, r.total, a.now) && !a.verified {
                return refuse(
                    format!(
                        "more than {} a second to this path from everyone, and this source is not verified",
                        requests(r.total)
                    ),
                    Limit::Everyone,
                );
            }
        }
        if self.total > 0 && windows.over_total(self.key, a.n, self.total, a.now) && !a.verified {
            return refuse(
                format!(
                    "more than {} a second to this server from everyone, and this source is not verified",
                    requests(self.total)
                ),
                Limit::Everyone,
            );
        }
        Ok(())
    }
    /// Judges a segment with a payload: every request that starts in it, at its start, pipelined
    /// after another or after a line break in one that continues a body. The first request the
    /// rules refuse drops the segment. Those they allow are scored by the context's model, if it
    /// has one, and whether it would drop one is left to the caller.
    pub fn judge(
        &self,
        windows: &mut Windows,
        scratch: &mut Vec<u8>,
        f: &Flow,
        now: i64,
        cx: Context,
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
        } else if tls(s) {
            j.reason = "TLS, which the filter cannot read".into();
            return j;
        } else if let Some(at) = embedded(s, 0) {
            at
        } else {
            j.reason = "not the start of an HTTP request".into();
            return j;
        };
        let arrival = Arrival {
            src: f.src_ip.parse::<IpAddr>().ok(),
            verified: cx.verified,
            n: f.pps.max(1),
            now,
        };
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
            if let Err((why, limit)) = self.check(&h, windows, scratch, arrival) {
                j.drop = true;
                j.limited = limit != Limit::None;
                j.budget = limit == Limit::Everyone;
                j.reason = why;
                return j;
            }
            if let Some(m) = cx.model {
                let score = ml::score_request(m, &h.request(j.requests), f.pps);
                j.scored += 1;
                j.score = j.score.max(score);
                if score >= cx.threshold && j.flagged.is_empty() {
                    // check() left the request's normalised path in scratch.
                    j.flagged = format!(
                        "{} {}: scored {score:.2} by the request model, which drops at {:.2}{}",
                        show(h.method),
                        show(scratch),
                        cx.threshold,
                        if cx.threshold < m.threshold {
                            " while this target is being probed"
                        } else {
                            ""
                        }
                    );
                }
            }
            match next(s, at, &h) {
                Some(n) => at = n,
                None => break,
            }
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
    fn consulting(model: &ml::Model) -> Context<'_> {
        Context {
            model: Some(model),
            threshold: model.threshold,
            ..Default::default()
        }
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
        let mut judge =
            |payload: &[u8]| p.judge(&mut w, &mut scratch, &flow(payload), 0, Context::default());
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
    #[test]
    fn a_budget_counts_what_got_past_each_sources_rate_and_spares_the_verified() {
        let p = policy(GameHttp {
            rate_per_source: 2,
            rate_total: 3,
            ..Default::default()
        });
        let (mut w, mut scratch) = (Windows::default(), Vec::new());
        let stranger = Context::default();
        let mut judge = |src: &str, cx: Context| {
            let f = Flow {
                src_ip: src.into(),
                ..flow(b"GET / HTTP/1.1\r\n\r\n")
            };
            p.judge(&mut w, &mut scratch, &f, 0, cx)
        };
        // A source over its own rate is held back by it, and does not spend the budget.
        assert!(!judge("192.0.2.1", stranger).drop);
        assert!(!judge("192.0.2.1", stranger).drop);
        let j = judge("192.0.2.1", stranger);
        assert!(j.drop && j.limited && !j.budget, "{j:?}");
        assert!(!judge("192.0.2.2", stranger).drop);
        // A fourth request that got past its source's rate is over the budget of three.
        let j = judge("192.0.2.3", stranger);
        assert!(j.drop && j.limited && j.budget, "{j:?}");
        assert_eq!(
            j.reason,
            "GET /: more than 3 requests a second to this server from everyone, and this source is not verified"
        );
        let verified = Context {
            verified: true,
            ..Default::default()
        };
        assert!(!judge("192.0.2.4", verified).drop);
    }
    #[test]
    fn the_request_model_sees_each_request_the_rules_would_find() {
        let rs = requests(&flow(
            b"GET /a/b?x=1 HTTP/1.0\r\nUser-Agent: c\r\nAccept: */*\r\nCookie: k=v\r\n\r\n\
              POST /c HTTP/1.1\r\nContent-Length: 2\r\n\r\nokGET /d HTTP/1.1\r\nHost: x",
        ));
        assert_eq!(
            rs[0],
            ml::Request {
                get: true,
                http10: true,
                path: 4,
                depth: 2,
                query: 3,
                headers: 3,
                user_agent: true,
                accept: true,
                cookie: true,
                complete: true,
                position: 1,
                ..Default::default()
            }
        );
        assert!(rs[1].post && rs[1].body == 2 && rs[1].position == 2);
        // The last head runs past the segment, its one header cut short, so what it lacks may
        // only be cut off.
        assert!(!rs[2].complete && rs[2].headers == 0 && rs[2].position == 3);
        assert_eq!(rs.len(), 3);
        // Nothing that is not HTTP over TCP is a request.
        assert!(requests(&flow(b"\x16\x03\x01\x00\x05hello")).is_empty());
        assert!(requests(&Flow {
            proto: "udp".into(),
            ..flow(b"GET / HTTP/1.1\r\n\r\n")
        })
        .is_empty());
    }
    #[test]
    fn allowed_requests_are_scored_and_the_first_over_the_threshold_named() {
        let p = policy(GameHttp::default());
        // A model that only looks at whether a request names its client.
        let mut weights = vec![0.0; ml::REQUEST_FEATURES];
        weights[8] = -8.0;
        let model = ml::Model {
            weights,
            bias: 4.0,
            threshold: 0.5,
            ready: true,
            ..Default::default()
        };
        let (mut w, mut scratch) = (Windows::default(), Vec::new());
        let j = p.judge(
            &mut w,
            &mut scratch,
            &flow(b"GET /ok HTTP/1.1\r\nUser-Agent: c\r\n\r\nGET /%61nonymous HTTP/1.1\r\n\r\n"),
            0,
            consulting(&model),
        );
        assert!(!j.drop && j.scored == 2, "{j:?}");
        assert_eq!(
            j.flagged,
            "GET /anonymous: scored 0.98 by the request model, which drops at 0.50"
        );
        assert!((j.score - 0.982).abs() < 0.001);
        // Requests the rules refuse are theirs to drop, not the model's.
        let p = policy(GameHttp {
            default: "drop".into(),
            ..Default::default()
        });
        let j = p.judge(
            &mut w,
            &mut scratch,
            &flow(b"GET / HTTP/1.1\r\n\r\n"),
            0,
            consulting(&model),
        );
        assert!(j.drop && j.scored == 0 && j.flagged.is_empty(), "{j:?}");
    }
}

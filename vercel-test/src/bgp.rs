//! Deterministic ExaBGP announcements and BIRD customer peering configuration.
use crate::{model::*, Result};
use ipnet::IpNet;
use std::{collections::HashSet, net::IpAddr};

pub fn validate_community(c: &str) -> Result<()> {
    if [
        "no-export",
        "no-advertise",
        "no-export-subconfed",
        "blackhole",
    ]
    .contains(&c.to_ascii_lowercase().as_str())
    {
        return Ok(());
    }
    let parts: Vec<_> = c.split(':').collect();
    let max = match parts.len() {
        2 => u16::MAX as u64,
        3 => u32::MAX as u64,
        _ => {
            return Err(format!(
                "community {c:?} is not a known name, ASN:value, or ASN:value:value"
            ))
        }
    };
    for p in parts {
        // Go's ParseUint accepts a leading +; preserve its numeric grammar.
        let digits = p.strip_prefix('+').unwrap_or(p);
        if digits.is_empty() || !digits.bytes().all(|c| c.is_ascii_digit()) {
            return Err(format!("community {c:?}: component {p:?} is not a number"));
        }
        if digits.parse::<u64>().map_err(|e| e.to_string())? > max {
            return Err(format!("community {c:?}: component {p:?} is above {max}"));
        }
    }
    Ok(())
}

pub fn commands(plan: &[Announcement], local_as: i64) -> Result<Vec<String>> {
    check_as(local_as)?;
    let mut rows: Vec<_> = plan.iter().collect();
    rows.sort_by_key(|a| (&a.prefix, &a.node_id));
    rows.into_iter()
        .map(|a| {
            a.prefix
                .parse::<IpNet>()
                .map_err(|e| format!("announcement for {:?}: {e}", a.prefix))?;
            let verb = match a.state.as_str() {
                "announce" => "announce",
                "withdraw" => "withdraw",
                _ => return Err(format!("unknown state {:?}", a.state)),
            };
            let mut line = format!("{verb} route {}", a.prefix);
            if !a.next_hop.is_empty() {
                a.next_hop.parse::<IpAddr>().map_err(|e| e.to_string())?;
                line += &format!(" next-hop {}", a.next_hop);
            }
            if a.state == "withdraw" {
                return Ok(line);
            }
            if a.prepends < 0 {
                return Err("negative prepends".into());
            }
            if a.prepends > 0 {
                if local_as == 0 {
                    return Err(
                        "announcement asks for prepends but no local AS is configured".into(),
                    );
                }
                // Plans come from the compiler (maximum 5); refuse unbounded allocation on external input.
                if a.prepends > 255 {
                    return Err("AS path exceeds 256 entries".into());
                }
                line += &format!(
                    " as-path [ {} ]",
                    vec![local_as.to_string(); a.prepends as usize + 1].join(" ")
                );
            }
            if !a.communities.is_empty() {
                for c in &a.communities {
                    validate_community(c)?;
                }
                line += &format!(" community [ {} ]", a.communities.join(" "));
            }
            Ok(line)
        })
        .collect()
}

fn check_as(asn: i64) -> Result<()> {
    if !(0..=u32::MAX as i64).contains(&asn) {
        Err(format!("local AS {asn} is out of range"))
    } else {
        Ok(())
    }
}

pub fn validate_session(s: &Session, protected: Option<&HashSet<String>>) -> Result<()> {
    let id = &s.id;
    if id.is_empty()
        || id.len() > 48
        || !id.as_bytes()[0].is_ascii_lowercase() && !id.as_bytes()[0].is_ascii_digit()
        || !id
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'_')
    {
        return Err("session id must be 1..48 lowercase letters, digits, dashes and underscores, starting with a letter or digit".into());
    }
    s.peer_ip.parse::<IpAddr>().map_err(|e| e.to_string())?;
    if s.peer_as <= 0 || s.peer_as > u32::MAX as i64 {
        return Err("peer_as is not a usable AS number".into());
    }
    check_as(s.local_as)?;
    if !(0..=255).contains(&s.multihop) {
        return Err("multihop must be in 0..255".into());
    }
    if s.max_prefixes < 0 {
        return Err("max_prefixes must not be negative".into());
    }
    if s.prefixes.is_empty() {
        return Err("session needs at least one prefix".into());
    }
    let mut seen = HashSet::new();
    for prefix in &s.prefixes {
        let p = prefix.parse::<IpNet>().map_err(|e| e.to_string())?;
        if p.addr() != p.network() {
            return Err(format!(
                "prefix {prefix} has host bits set; write it as {}",
                p.trunc()
            ));
        }
        if !seen.insert(prefix) {
            return Err(format!("duplicate prefix {prefix}"));
        }
        if protected.is_some_and(|ps| !ps.contains(prefix)) {
            return Err(format!("prefix {prefix} is not protected"));
        }
    }
    if s.password.len() > 80
        || !s
            .password
            .bytes()
            .all(|c| (0x21..=0x7e).contains(&c) && c != b'"' && c != b'\\')
    {
        return Err("password must be at most 80 printable ASCII characters without spaces, quotes or backslashes".into());
    }
    if s.regions
        .iter()
        .chain(&s.nodes)
        .any(|s| s.trim().is_empty())
    {
        return Err("session scope must not contain empty values".into());
    }
    Ok(())
}

pub fn terminates_on(s: &Session, n: &Node) -> bool {
    s.nodes.is_empty() && s.regions.is_empty()
        || s.nodes.iter().any(|id| id == &n.id || id == &n.name)
        || s.regions.contains(&n.region)
}
pub fn import_limit(s: &Session) -> i64 {
    if s.max_prefixes > 0 {
        s.max_prefixes
    } else {
        (s.prefixes.len() as i64 * 4).max(8)
    }
}

pub fn session_config(sessions: &[Session], node: &Node, local_as: i64) -> Result<Vec<String>> {
    check_as(local_as)?;
    let mut rows: Vec<_> = sessions.iter().collect();
    rows.sort_by_key(|s| &s.id);
    let mut out = Vec::new();
    for s in rows {
        validate_session(s, None)?;
        let asn = if s.local_as == 0 {
            local_as
        } else {
            s.local_as
        };
        if asn == 0 {
            return Err(format!("session {}: no local AS", s.id));
        }
        node.tunnel_src
            .parse::<IpAddr>()
            .map_err(|_| format!("node {} has no usable tunnel_src to peer from", node.id))?;
        let mut prefixes = s.prefixes.clone();
        prefixes.sort();
        let terms: Vec<_> = prefixes.into_iter().map(|p| format!("{p}+")).collect();
        out.push(format!("protocol bgp cust_{} {{", s.id.replace('-', "_")));
        let comment: String = s
            .comment
            .chars()
            .filter(|c| {
                c.is_ascii() && (' '..='~').contains(c) && !['"', '\\', '{', '}', ';'].contains(c)
            })
            .take(100)
            .collect();
        if !comment.trim().is_empty() {
            out.push(format!("    description \"{}\";", comment.trim()));
        }
        out.push(format!("    local {} as {asn};", node.tunnel_src));
        out.push(format!("    neighbor {} as {};", s.peer_ip, s.peer_as));
        if !s.password.is_empty() {
            out.push(format!("    password \"{}\";", s.password));
        }
        if s.passive {
            out.push("    passive;".into());
        }
        if s.multihop > 0 {
            out.push(format!("    multihop {};", s.multihop));
        }
        out.extend([
            "    ipv4 {".into(),
            format!(
                "        import filter {{ if net ~ [ {} ] then accept; reject; }};",
                terms.join(", ")
            ),
            format!("        import limit {} action restart;", import_limit(s)),
            "        export none;".into(),
            "    };".into(),
            "}".into(),
        ]);
    }
    Ok(out)
}

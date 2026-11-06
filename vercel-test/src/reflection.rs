//! The reflection guard: answers reflected at a protected address. An attacker sends small
//! requests to servers on the internet with the address forged as their source, and the servers
//! send their much larger answers there. The answers come from real servers, at real addresses,
//! so no rule on sources stops them; what gives them away is that nobody at the address asked.
//!
//! CLDAP (connectionless LDAP, UDP port 389) is the vector covered so far: a domain controller
//! answers a rootDSE query of about 50 bytes with several kilobytes, so its answers usually
//! arrive in fragments, and only the first fragment carries the port.
use crate::model::{Flow, ReflectionPolicy};
use serde_json::{json, Value};
use std::{collections::HashMap, net::IpAddr};

/// The port CLDAP answers come from.
pub const CLDAP_PORT: i64 = 389;
/// How many sources caught reflecting a node remembers at once.
pub const SOURCES_MAX: usize = 65536;
/// How long after its last answer a source caught reflecting has the later fragments of its
/// answers dropped: as long as a host holds fragments for reassembly.
pub const REFLECTING_FOR: i64 = 30_000;
/// How recently the origin must have sent an address an LDAP search for an answer from it to
/// count as one it asked for.
pub const ASKED_WITHIN: i64 = 30_000;

/// The operation an LDAP message opens with: after a SEQUENCE and its length, an INTEGER message
/// ID of one to four bytes, the tag of its protocolOp. The first fragment of a long message still
/// opens as one, though its length runs past the fragment.
fn ldap_operation(p: &[u8]) -> Option<u8> {
    if p.first() != Some(&0x30) {
        return None;
    }
    let mut i = 2;
    match p.get(1) {
        Some(&l) if l & 0x80 == 0 => {}
        // The long form gives the length in one to four bytes after it.
        Some(&l) if (1..=4).contains(&(l & 0x7f)) => i += usize::from(l & 0x7f),
        _ => return None,
    }
    if p.get(i) != Some(&0x02) {
        return None;
    }
    match p.get(i + 1) {
        Some(&n) if (1..=4).contains(&n) => i += 2 + usize::from(n),
        _ => return None,
    }
    p.get(i).copied()
}
/// Whether a payload opens as an LDAP answer to a search: an entry, a reference or the done that
/// ends them ([APPLICATION 4], [APPLICATION 19] and [APPLICATION 5]).
pub fn ldap_answer(p: &[u8]) -> bool {
    matches!(ldap_operation(p), Some(0x64 | 0x65 | 0x73))
}
/// Whether a payload opens as an LDAP search ([APPLICATION 3]), as a CLDAP query does.
pub fn ldap_search(p: &[u8]) -> bool {
    ldap_operation(p) == Some(0x63)
}

/// What the guard knows and has done.
pub struct Guard {
    /// "enforce", "observe" or "off" for CLDAP.
    pub cldap: String,
    /// Answers dropped, answers observed, answers let through because the origin had asked, and
    /// later fragments dropped.
    pub counts: [u64; 4],
    /// The sources caught reflecting, and when each last was.
    sources: HashMap<IpAddr, i64>,
    /// Sources not remembered because the table was full of ones still reflecting.
    pub untracked: u64,
    last_sweep: i64,
}
impl Default for Guard {
    fn default() -> Self {
        Self {
            cldap: "enforce".into(),
            counts: [0; 4],
            sources: HashMap::new(),
            untracked: 0,
            last_sweep: 0,
        }
    }
}
/// What a flow is to the guard.
#[derive(Debug, PartialEq)]
pub enum Seen {
    /// Nothing it looks for.
    Not,
    /// A CLDAP answer: UDP from port 389, opening as an LDAP answer when its payload is there to
    /// read.
    Answer,
    /// A fragment after the first, from a source caught reflecting.
    Fragment,
}
impl Guard {
    pub fn load(&mut self, policy: Option<&ReflectionPolicy>) {
        self.cldap = match policy.map(|r| r.cldap.as_str()) {
            Some(mode @ ("observe" | "off")) => mode.into(),
            _ => "enforce".into(),
        };
    }
    /// What the flow is, by its port and payload, or for a fragment after the first, which
    /// carries neither, by its source. `later_fragment` is asked only for a flow that could be
    /// one, since telling takes reading the packet.
    pub fn seen(&self, f: &Flow, now: i64, later_fragment: impl FnOnce() -> bool) -> Seen {
        if self.cldap == "off" || !f.proto.eq_ignore_ascii_case("udp") {
            return Seen::Not;
        }
        if f.sport == CLDAP_PORT {
            // A payload that does not open as an LDAP answer is not one: a player whose NAT
            // happened to map them to port 389, say. A record without its payload is judged by
            // the port alone.
            return if !f.has_payload || ldap_answer(&f.payload) {
                Seen::Answer
            } else {
                Seen::Not
            };
        }
        if f.sport == 0
            && !f.packet.is_empty()
            && self.reflecting(&f.src_ip, now)
            && later_fragment()
        {
            return Seen::Fragment;
        }
        Seen::Not
    }
    fn reflecting(&self, src: &str, now: i64) -> bool {
        src.parse::<IpAddr>()
            .ok()
            .and_then(|a| self.sources.get(&a))
            .is_some_and(|&t| now - t < REFLECTING_FOR)
    }
    /// Remembers a source caught reflecting. A full table is swept of sources no longer
    /// reflecting at most once a second, so a flood of new sources costs the node a sweep a
    /// second rather than one each; a source that finds it full of live ones is not remembered.
    pub fn caught(&mut self, src: &str, now: i64) {
        let Ok(addr) = src.parse::<IpAddr>() else {
            return;
        };
        if self.sources.len() >= SOURCES_MAX && !self.sources.contains_key(&addr) {
            if now - self.last_sweep >= 1000 {
                self.last_sweep = now;
                self.sources.retain(|_, &mut t| now - t < REFLECTING_FOR);
            }
            if self.sources.len() >= SOURCES_MAX {
                self.untracked += 1;
                return;
            }
        }
        self.sources.insert(addr, now);
    }
    pub fn sources(&self) -> usize {
        self.sources.len()
    }
    pub fn stats(&self) -> Value {
        let [dropped, observed, asked, fragments] = self.counts;
        json!({
            "sources": self.sources.len(),
            "sources_max": SOURCES_MAX,
            "sources_untracked": self.untracked,
            "vectors": [{
                "vector": "cldap",
                "port": CLDAP_PORT,
                "mode": self.cldap,
                "dropped": dropped,
                "observed": observed,
                "asked": asked,
                "fragments": fragments,
            }],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ldap_answers_are_told_from_other_payloads() {
        // Active Directory writes its lengths in four bytes.
        let ad = [
            0x30, 0x84, 0x00, 0x00, 0x0b, 0x9f, 0x02, 0x01, 0x01, 0x64, 0x84, 0x00, 0x00, 0x0b,
        ];
        assert!(ldap_answer(&ad));
        // OpenLDAP the shortest form it can; a done with no entry, as an error is answered.
        assert!(ldap_answer(&[
            0x30, 0x82, 0x01, 0x2c, 0x02, 0x02, 0x12, 0x34, 0x64
        ]));
        assert!(ldap_answer(&[
            0x30, 0x0c, 0x02, 0x01, 0x01, 0x65, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00
        ]));
        assert!(ldap_answer(&[0x30, 0x05, 0x02, 0x01, 0x07, 0x73, 0x00]));
        for not in [
            &[][..],
            &[0x30],
            // A request, not an answer: searchRequest is [APPLICATION 3].
            &[0x30, 0x25, 0x02, 0x01, 0x01, 0x63, 0x20],
            // A bind response.
            &[0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07],
            // Indefinite and over-long lengths, and message IDs of no bytes or five.
            &[0x30, 0x80, 0x02, 0x01, 0x01, 0x64],
            &[0x30, 0x85, 0, 0, 0, 0, 1, 0x02, 0x01, 0x01, 0x64],
            &[0x30, 0x05, 0x02, 0x00, 0x64],
            &[0x30, 0x0a, 0x02, 0x05, 1, 2, 3, 4, 5, 0x64],
            // Cut off before the result.
            &[0x30, 0x84, 0x00, 0x00, 0x0b, 0x9f, 0x02, 0x01, 0x01],
            // A game's packet.
            &[0xff, 0xff, 0xff, 0xff, 0x54, 0x53, 0x6f, 0x75],
        ] {
            assert!(!ldap_answer(not), "{not:02x?}");
        }
    }
    #[test]
    fn ldap_searches_are_told_from_answers_and_other_payloads() {
        // A domain controller locator's LDAP ping: a search of the rootDSE.
        let ping = [
            0x30, 0x84, 0x00, 0x00, 0x00, 0x7c, 0x02, 0x01, 0x01, 0x63, 0x84,
        ];
        assert!(ldap_search(&ping));
        assert!(!ldap_answer(&ping));
        assert!(!ldap_search(&[0x30, 0x0c, 0x02, 0x01, 0x01, 0x65, 0x07]));
        // A game's answer to a query, whatever port it is sent to.
        assert!(!ldap_search(&[0xff, 0xff, 0xff, 0xff, 0x49, 0x11]));
    }
    #[test]
    fn a_full_table_is_swept_once_a_second_and_counts_what_it_cannot_keep() {
        let mut g = Guard::default();
        let addr = |i: usize| format!("10.{}.{}.{}", i >> 16, (i >> 8) & 255, i & 255);
        for i in 0..SOURCES_MAX {
            g.caught(&addr(i), 1);
        }
        assert_eq!(g.sources(), SOURCES_MAX);
        // Full of sources still reflecting: the new one is counted, not kept.
        g.caught("192.0.2.1", 2);
        assert_eq!((g.sources(), g.untracked), (SOURCES_MAX, 1));
        assert!(g.reflecting(&addr(7), 2));
        assert!(!g.reflecting("192.0.2.1", 2));
        // Once they have stopped, the sweep makes room, and a source seen again is renewed.
        g.caught("192.0.2.1", 1 + REFLECTING_FOR);
        assert_eq!(g.sources(), 1);
        assert!(g.reflecting("192.0.2.1", REFLECTING_FOR + 2));
        assert!(!g.reflecting(&addr(7), REFLECTING_FOR + 2));
        g.caught("192.0.2.1", 2 * REFLECTING_FOR);
        assert!(g.reflecting("192.0.2.1", 3 * REFLECTING_FOR - 1));
        assert!(!g.reflecting("192.0.2.1", 3 * REFLECTING_FOR));
    }
}

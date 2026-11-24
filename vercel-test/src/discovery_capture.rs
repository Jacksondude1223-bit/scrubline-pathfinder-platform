use crate::{model::Flow, packet, Result};
use serde::{Deserialize, Serialize};
use std::io;

pub const BATCH: usize = 256;
pub const PACKET_MAX: usize = 65_535;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Direction {
    ToOrigin,
    FromOrigin,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Status {
    pub active: bool,
    pub packets: u64,
    pub observed: u64,
    pub invalid: u64,
    pub ignored: u64,
    pub busy: u64,
    pub kernel_dropped: u64,
    pub last_packet_ms: Option<i64>,
    pub error: Option<String>,
}

pub fn interfaces(value: &str) -> Result<Vec<String>> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    let mut names = Vec::new();
    for name in value.split(',') {
        if name.is_empty()
            || name.len() > 15
            || !name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
            || matches!(name, "." | ".." | "lo")
        {
            return Err("discovery-interfaces requires exact non-loopback interface names separated by commas".into());
        }
        if !names.iter().any(|existing| existing == name) {
            names.push(name.to_owned());
        }
        if names.len() > 16 {
            return Err("at most 16 discovery interfaces may be configured".into());
        }
    }
    Ok(names)
}

pub fn flow(bytes: &[u8]) -> Option<Flow> {
    let (p, anomaly) = packet::parse(bytes);
    if anomaly.is_some()
        || p.fragment()
        || !matches!(p.proto, 6 | 17)
        || p.sport == 0
        || p.dport == 0
    {
        return None;
    }
    Some(Flow {
        src_ip: p.src?.to_string(),
        dst_ip: p.dst?.to_string(),
        proto: if p.proto == 6 { "tcp" } else { "udp" }.into(),
        sport: p.sport.into(),
        dport: p.dport.into(),
        flags: p.flags.map(packet::flag_names).unwrap_or_default(),
        pps: 1,
        payload: p.payload.to_vec(),
        length: Some(p.length),
        ttl: Some(p.ttl),
        dscp: Some(p.dscp),
        ..Default::default()
    })
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use std::{
        ffi::CString,
        mem,
        os::fd::{AsRawFd, FromRawFd, OwnedFd},
    };

    pub struct Socket {
        fd: OwnedFd,
        index: u32,
    }
    fn index(name: &str) -> io::Result<u32> {
        let name = CString::new(name).map_err(|_| io::ErrorKind::InvalidInput)?;
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        if index == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(index)
        }
    }
    impl Socket {
        pub fn open(name: &str) -> io::Result<Self> {
            let index = index(name)?;
            let protocol = u16::to_be(libc::ETH_P_ALL as u16);
            let raw = unsafe {
                libc::socket(
                    libc::AF_PACKET,
                    libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                    0,
                )
            };
            if raw < 0 {
                return Err(io::Error::last_os_error());
            }
            let fd = unsafe { OwnedFd::from_raw_fd(raw) };
            let mut address: libc::sockaddr_ll = unsafe { mem::zeroed() };
            address.sll_family = libc::AF_PACKET as u16;
            address.sll_protocol = protocol;
            address.sll_ifindex = index as i32;
            let bound = unsafe {
                libc::bind(
                    fd.as_raw_fd(),
                    (&address as *const libc::sockaddr_ll).cast(),
                    mem::size_of_val(&address) as libc::socklen_t,
                )
            };
            if bound < 0 {
                return Err(io::Error::last_os_error());
            }
            let size: libc::c_int = 1 << 20;
            let configured = unsafe {
                libc::setsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_RCVBUF,
                    (&size as *const libc::c_int).cast(),
                    mem::size_of_val(&size) as libc::socklen_t,
                )
            };
            if configured < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self { fd, index })
        }
        pub fn current(&self, name: &str) -> bool {
            index(name).ok() == Some(self.index)
        }
        pub fn receive(&self, bytes: &mut [u8]) -> io::Result<Option<(usize, Option<Direction>)>> {
            let mut address: libc::sockaddr_ll = unsafe { mem::zeroed() };
            let mut size = mem::size_of_val(&address) as libc::socklen_t;
            let n = unsafe {
                libc::recvfrom(
                    self.fd.as_raw_fd(),
                    bytes.as_mut_ptr().cast(),
                    bytes.len(),
                    libc::MSG_DONTWAIT | libc::MSG_TRUNC,
                    (&mut address as *mut libc::sockaddr_ll).cast(),
                    &mut size,
                )
            };
            if n < 0 {
                let error = io::Error::last_os_error();
                return if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) {
                    Ok(None)
                } else {
                    Err(error)
                };
            }
            let direction = match (
                address.sll_ifindex == self.index as i32,
                address.sll_pkttype,
            ) {
                (true, libc::PACKET_OUTGOING) => Some(Direction::ToOrigin),
                (true, libc::PACKET_HOST) => Some(Direction::FromOrigin),
                _ => None,
            };
            Ok(Some((n as usize, direction)))
        }
        pub fn dropped(&self) -> io::Result<u64> {
            let mut stats: libc::tpacket_stats = unsafe { mem::zeroed() };
            let mut size = mem::size_of_val(&stats) as libc::socklen_t;
            let r = unsafe {
                libc::getsockopt(
                    self.fd.as_raw_fd(),
                    libc::SOL_PACKET,
                    libc::PACKET_STATISTICS,
                    (&mut stats as *mut libc::tpacket_stats).cast(),
                    &mut size,
                )
            };
            if r < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(stats.tp_drops.into())
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use super::*;
    pub struct Socket;
    impl Socket {
        pub fn open(_: &str) -> io::Result<Self> {
            Err(io::ErrorKind::Unsupported.into())
        }
        pub fn current(&self, _: &str) -> bool {
            false
        }
        pub fn receive(&self, _: &mut [u8]) -> io::Result<Option<(usize, Option<Direction>)>> {
            Err(io::ErrorKind::Unsupported.into())
        }
        pub fn dropped(&self) -> io::Result<u64> {
            Ok(0)
        }
    }
}
pub use platform::Socket;

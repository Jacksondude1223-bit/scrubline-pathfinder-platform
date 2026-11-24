//! Inline game-filter enforcement: forwarded packets the provisioner queues on NFQUEUE are judged
//! by the game-filter stage and accepted or dropped before they reach the customer.
//!
//! The provisioner queues only UDP going down a tunnel to an enforcing filter's port, with
//! `bypass`, and this side binds the queue fail-open, so the kernel forwards a packet unjudged
//! when no agent listens or the queue is full. A packet the agent cannot read is accepted too:
//! filtering stops before the customers' traffic does.
use crate::{model::Flow, Result};
use serde::{Deserialize, Serialize};
use std::io;

/// The most messages taken from the queue before verdicts go back, and so the most packets judged
/// under one hold of the agent's lock.
pub const BATCH: usize = 64;
/// How many packets the kernel holds for the agent before it forwards the rest unjudged.
pub const QUEUE_MAXLEN: u32 = 4096;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Status {
    pub active: bool,
    pub queue: u16,
    /// Packets the agent took from the queue.
    pub packets: u64,
    pub accepted: u64,
    pub dropped: u64,
    /// Packets dropped while the source was sent the protocol's challenge instead.
    pub challenged: u64,
    pub replies_failed: u64,
    /// Packets accepted unjudged because they could not be read as an IP packet.
    pub unreadable: u64,
    /// Times the socket's buffer overran and the kernel discarded queued packets' messages; those
    /// packets are forwarded once the queue gives up on them.
    pub overruns: u64,
    /// From the kernel: packets it forwarded unjudged because the queue was full, and those it
    /// could not hand to the agent.
    pub queue_dropped: u64,
    pub user_dropped: u64,
    pub last_packet_ms: Option<i64>,
    pub error: Option<String>,
}

/// What the agent does with a queued packet.
#[derive(Clone, Debug, PartialEq)]
pub enum Verdict {
    Accept,
    Drop,
    /// Drop it and send `reply` back to the packet's source, from the address and port it was
    /// sent to.
    Challenge(Vec<u8>),
}

/// The flow a queued packet is, for the game filters: a UDP packet with its payload.
pub fn flow(bytes: &[u8]) -> Option<Flow> {
    let mut f = crate::discovery_capture::flow(bytes)?;
    if f.proto != "udp" {
        return None;
    }
    f.has_payload = true;
    f.packet = bytes.to_vec();
    Some(f)
}

/// The kernel's counters for `queue`, from /proc/net/netfilter/nfnetlink_queue: (dropped because
/// the queue was full, dropped because the agent could not be sent them).
pub fn kernel_counters(table: &str, queue: u16) -> Option<(u64, u64)> {
    table.lines().find_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.first()?.parse::<u16>().ok()? != queue {
            return None;
        }
        Some((fields.get(5)?.parse().ok()?, fields.get(6)?.parse().ok()?))
    })
}

/// The UDP datagram answering `to` (the queued packet, already parsed), sent from where it was
/// going back to where it came from, as a whole IP packet for a raw socket.
pub fn reply_packet(to: &Flow, payload: &[u8]) -> Option<Vec<u8>> {
    let src: std::net::IpAddr = to.dst_ip.parse().ok()?;
    let dst: std::net::IpAddr = to.src_ip.parse().ok()?;
    let sport = u16::try_from(to.dport).ok()?;
    let dport = u16::try_from(to.sport).ok()?;
    let udp_len = u16::try_from(8 + payload.len()).ok()?;
    let mut udp = Vec::with_capacity(udp_len as usize);
    udp.extend_from_slice(&sport.to_be_bytes());
    udp.extend_from_slice(&dport.to_be_bytes());
    udp.extend_from_slice(&udp_len.to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(payload);
    let mut pseudo = Vec::new();
    match (src, dst) {
        (std::net::IpAddr::V4(s), std::net::IpAddr::V4(d)) => {
            pseudo.extend_from_slice(&s.octets());
            pseudo.extend_from_slice(&d.octets());
            pseudo.extend_from_slice(&[0, 17]);
            pseudo.extend_from_slice(&udp_len.to_be_bytes());
        }
        (std::net::IpAddr::V6(s), std::net::IpAddr::V6(d)) => {
            pseudo.extend_from_slice(&s.octets());
            pseudo.extend_from_slice(&d.octets());
            pseudo.extend_from_slice(&u32::from(udp_len).to_be_bytes());
            pseudo.extend_from_slice(&[0, 0, 0, 17]);
        }
        _ => return None,
    }
    pseudo.extend_from_slice(&udp);
    let sum = match checksum(&pseudo) {
        0 => 0xffff,
        sum => sum,
    };
    udp[6..8].copy_from_slice(&sum.to_be_bytes());
    let mut packet = Vec::with_capacity(40 + udp.len());
    match (src, dst) {
        (std::net::IpAddr::V4(s), std::net::IpAddr::V4(d)) => {
            let total = u16::try_from(20 + udp.len()).ok()?;
            packet.extend_from_slice(&[0x45, 0]);
            packet.extend_from_slice(&total.to_be_bytes());
            packet.extend_from_slice(&[0, 0, 0x40, 0, 64, 17, 0, 0]);
            packet.extend_from_slice(&s.octets());
            packet.extend_from_slice(&d.octets());
            let sum = checksum(&packet);
            packet[10..12].copy_from_slice(&sum.to_be_bytes());
        }
        (std::net::IpAddr::V6(s), std::net::IpAddr::V6(d)) => {
            packet.extend_from_slice(&[0x60, 0, 0, 0]);
            packet.extend_from_slice(&udp_len.to_be_bytes());
            packet.extend_from_slice(&[17, 64]);
            packet.extend_from_slice(&s.octets());
            packet.extend_from_slice(&d.octets());
        }
        _ => return None,
    }
    packet.extend_from_slice(&udp);
    Some(packet)
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|c| u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])))
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn queue_number(value: &str) -> Result<Option<u16>> {
    if value.is_empty() {
        return Ok(None);
    }
    value
        .parse::<u16>()
        .map(Some)
        .map_err(|_| "inline-queue requires an NFQUEUE number within 0..65535".into())
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use std::{
        mem,
        os::fd::{AsRawFd, FromRawFd, OwnedFd},
    };

    const NFNL_SUBSYS_QUEUE: u16 = 3;
    const NFQNL_MSG_PACKET: u16 = 0;
    const NFQNL_MSG_VERDICT: u16 = 1;
    const NFQNL_MSG_CONFIG: u16 = 2;
    const NFQA_PACKET_HDR: u16 = 1;
    const NFQA_VERDICT_HDR: u16 = 2;
    const NFQA_PAYLOAD: u16 = 10;
    const NFQA_CFG_CMD: u16 = 1;
    const NFQA_CFG_PARAMS: u16 = 2;
    const NFQA_CFG_QUEUE_MAXLEN: u16 = 3;
    const NFQA_CFG_MASK: u16 = 4;
    const NFQA_CFG_FLAGS: u16 = 5;
    const NFQNL_CFG_CMD_BIND: u8 = 1;
    const NFQNL_COPY_PACKET: u8 = 2;
    const NFQA_CFG_F_FAIL_OPEN: u32 = 1;
    const NF_DROP: u32 = 0;
    const NF_ACCEPT: u32 = 1;
    const NLMSG_ERROR: u16 = 2;
    const NETLINK_NO_ENOBUFS: libc::c_int = 5;

    fn align(n: usize) -> usize {
        (n + 3) & !3
    }
    fn attribute(out: &mut Vec<u8>, kind: u16, value: &[u8]) {
        out.extend_from_slice(&((4 + value.len()) as u16).to_ne_bytes());
        out.extend_from_slice(&kind.to_ne_bytes());
        out.extend_from_slice(value);
        out.resize(align(out.len()), 0);
    }
    /// A netfilter netlink message for the queue subsystem: the netlink header, the nfgenmsg
    /// naming the queue, and the attributes.
    fn message(kind: u16, flags: u16, queue: u16, attributes: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(20 + attributes.len());
        let length = (16 + 4 + attributes.len()) as u32;
        out.extend_from_slice(&length.to_ne_bytes());
        out.extend_from_slice(&((NFNL_SUBSYS_QUEUE << 8) | kind).to_ne_bytes());
        out.extend_from_slice(&(libc::NLM_F_REQUEST as u16 | flags).to_ne_bytes());
        out.extend_from_slice(&0u32.to_ne_bytes());
        out.extend_from_slice(&0u32.to_ne_bytes());
        out.extend_from_slice(&[libc::AF_UNSPEC as u8, 0]);
        out.extend_from_slice(&queue.to_be_bytes());
        out.extend_from_slice(attributes);
        out
    }
    /// Each attribute in `bytes` as (type, value).
    fn attributes(mut bytes: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
        std::iter::from_fn(move || {
            if bytes.len() < 4 {
                return None;
            }
            let length = u16::from_ne_bytes([bytes[0], bytes[1]]) as usize;
            let kind = u16::from_ne_bytes([bytes[2], bytes[3]]) & 0x3fff;
            if length < 4 || length > bytes.len() {
                return None;
            }
            let value = &bytes[4..length];
            bytes = &bytes[align(length).min(bytes.len())..];
            Some((kind, value))
        })
    }

    /// One queued packet: the kernel's id for the verdict, and the IP packet.
    pub struct Queued<'a> {
        pub id: u32,
        pub packet: Option<&'a [u8]>,
    }

    pub struct Queue {
        fd: OwnedFd,
        number: u16,
    }
    impl Queue {
        /// Binds NFQUEUE `number`, copying whole packets, fail-open when the queue is full.
        pub fn open(number: u16) -> io::Result<Self> {
            let raw = unsafe {
                libc::socket(
                    libc::AF_NETLINK,
                    libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                    libc::NETLINK_NETFILTER,
                )
            };
            if raw < 0 {
                return Err(io::Error::last_os_error());
            }
            let fd = unsafe { OwnedFd::from_raw_fd(raw) };
            let mut address: libc::sockaddr_nl = unsafe { mem::zeroed() };
            address.nl_family = libc::AF_NETLINK as u16;
            if unsafe {
                libc::bind(
                    fd.as_raw_fd(),
                    (&address as *const libc::sockaddr_nl).cast(),
                    mem::size_of_val(&address) as libc::socklen_t,
                )
            } < 0
            {
                return Err(io::Error::last_os_error());
            }
            let set = |level, name, value: libc::c_int| {
                let r = unsafe {
                    libc::setsockopt(
                        fd.as_raw_fd(),
                        level,
                        name,
                        (&value as *const libc::c_int).cast(),
                        mem::size_of_val(&value) as libc::socklen_t,
                    )
                };
                if r < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            };
            set(libc::SOL_SOCKET, libc::SO_RCVBUF, 8 << 20)?;
            // An overrun is counted and survived, not reported on every later read.
            set(libc::SOL_NETLINK, NETLINK_NO_ENOBUFS, 1)?;
            let timeout = libc::timeval {
                tv_sec: 0,
                tv_usec: 200_000,
            };
            if unsafe {
                libc::setsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_RCVTIMEO,
                    (&timeout as *const libc::timeval).cast(),
                    mem::size_of_val(&timeout) as libc::socklen_t,
                )
            } < 0
            {
                return Err(io::Error::last_os_error());
            }
            let queue = Self { fd, number };
            let mut bind = Vec::new();
            attribute(&mut bind, NFQA_CFG_CMD, &[NFQNL_CFG_CMD_BIND, 0, 0, 0]);
            queue.request(&bind)?;
            let mut params = Vec::new();
            let mut copy = 0xffffu32.to_be_bytes().to_vec();
            copy.push(NFQNL_COPY_PACKET);
            attribute(&mut params, NFQA_CFG_PARAMS, &copy);
            attribute(
                &mut params,
                NFQA_CFG_QUEUE_MAXLEN,
                &QUEUE_MAXLEN.to_be_bytes(),
            );
            attribute(
                &mut params,
                NFQA_CFG_FLAGS,
                &NFQA_CFG_F_FAIL_OPEN.to_be_bytes(),
            );
            attribute(
                &mut params,
                NFQA_CFG_MASK,
                &NFQA_CFG_F_FAIL_OPEN.to_be_bytes(),
            );
            queue.request(&params)?;
            Ok(queue)
        }
        /// Sends a configuration message and waits for the kernel's acknowledgement.
        fn request(&self, attributes: &[u8]) -> io::Result<()> {
            let m = message(
                NFQNL_MSG_CONFIG,
                libc::NLM_F_ACK as u16,
                self.number,
                attributes,
            );
            self.send(&m)?;
            let mut buffer = vec![0u8; 8192];
            for _ in 0..16 {
                let n = self.receive(&mut buffer)?.ok_or(io::ErrorKind::TimedOut)?;
                let mut rest = &buffer[..n];
                while rest.len() >= 16 {
                    let length = u32::from_ne_bytes(rest[0..4].try_into().unwrap()) as usize;
                    let kind = u16::from_ne_bytes([rest[4], rest[5]]);
                    if length < 16 || length > rest.len() {
                        break;
                    }
                    if kind == NLMSG_ERROR && length >= 20 {
                        let code = i32::from_ne_bytes(rest[16..20].try_into().unwrap());
                        return if code == 0 {
                            Ok(())
                        } else {
                            Err(io::Error::from_raw_os_error(-code))
                        };
                    }
                    rest = &rest[align(length).min(rest.len())..];
                }
            }
            Err(io::ErrorKind::TimedOut.into())
        }
        fn send(&self, bytes: &[u8]) -> io::Result<()> {
            let mut address: libc::sockaddr_nl = unsafe { mem::zeroed() };
            address.nl_family = libc::AF_NETLINK as u16;
            let n = unsafe {
                libc::sendto(
                    self.fd.as_raw_fd(),
                    bytes.as_ptr().cast(),
                    bytes.len(),
                    0,
                    (&address as *const libc::sockaddr_nl).cast(),
                    mem::size_of_val(&address) as libc::socklen_t,
                )
            };
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
        /// One datagram from the kernel, waiting up to the socket's timeout when `wait`; None when
        /// there is none. An overrun reads as `ErrorKind::OutOfMemory`.
        fn receive_with(&self, buffer: &mut [u8], wait: bool) -> io::Result<Option<usize>> {
            let flags = if wait { 0 } else { libc::MSG_DONTWAIT };
            let n = unsafe {
                libc::recv(
                    self.fd.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    flags,
                )
            };
            if n < 0 {
                let e = io::Error::last_os_error();
                return match e.raw_os_error() {
                    Some(libc::EAGAIN | libc::EINTR) => Ok(None),
                    Some(libc::ENOBUFS) => Err(io::ErrorKind::OutOfMemory.into()),
                    _ => Err(e),
                };
            }
            Ok(Some(n as usize))
        }
        fn receive(&self, buffer: &mut [u8]) -> io::Result<Option<usize>> {
            self.receive_with(buffer, true)
        }
        /// The queued packets in a datagram from `receive_batch`.
        pub fn packets(bytes: &[u8]) -> Vec<Queued<'_>> {
            let mut out = Vec::new();
            let mut rest = bytes;
            while rest.len() >= 16 {
                let length = u32::from_ne_bytes(rest[0..4].try_into().unwrap()) as usize;
                let kind = u16::from_ne_bytes([rest[4], rest[5]]);
                if length < 16 || length > rest.len() {
                    break;
                }
                if kind == (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_PACKET && length >= 20 {
                    let mut id = None;
                    let mut packet = None;
                    for (kind, value) in attributes(&rest[20..length]) {
                        match kind {
                            NFQA_PACKET_HDR if value.len() >= 4 => {
                                id = Some(u32::from_be_bytes(value[0..4].try_into().unwrap()))
                            }
                            NFQA_PAYLOAD => packet = Some(value),
                            _ => {}
                        }
                    }
                    if let Some(id) = id {
                        out.push(Queued { id, packet });
                    }
                }
                rest = &rest[align(length).min(rest.len())..];
            }
            out
        }
        /// Up to `BATCH` datagrams: waits for the first, then takes what is already there.
        /// Returns the datagrams' lengths within `buffers`.
        pub fn receive_batch(&self, buffers: &mut [Vec<u8>]) -> io::Result<(usize, u64)> {
            let mut taken = 0;
            let mut overruns = 0;
            while taken < buffers.len() {
                let wait = taken == 0;
                match self.receive_with(&mut buffers[taken][..], wait) {
                    Ok(Some(n)) => {
                        buffers[taken].truncate(n);
                        taken += 1;
                    }
                    Ok(None) => break,
                    Err(e) if e.kind() == io::ErrorKind::OutOfMemory => {
                        overruns += 1;
                        if !wait {
                            break;
                        }
                        return Ok((0, overruns));
                    }
                    Err(e) => return Err(e),
                }
            }
            Ok((taken, overruns))
        }
        pub fn verdict(&self, id: u32, accept: bool) -> io::Result<()> {
            let mut header = Vec::with_capacity(8);
            header.extend_from_slice(&(if accept { NF_ACCEPT } else { NF_DROP }).to_be_bytes());
            header.extend_from_slice(&id.to_be_bytes());
            let mut a = Vec::new();
            attribute(&mut a, NFQA_VERDICT_HDR, &header);
            self.send(&message(NFQNL_MSG_VERDICT, 0, self.number, &a))
        }
    }

    /// Sends whole IP packets the agent built, from addresses that are not the node's own: the
    /// protected addresses the packets they answer were going to.
    pub struct Sender {
        v4: Option<OwnedFd>,
        v6: Option<OwnedFd>,
    }
    fn raw(family: libc::c_int) -> Option<OwnedFd> {
        let fd = unsafe {
            libc::socket(
                family,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::IPPROTO_RAW,
            )
        };
        (fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fd) })
    }
    impl Sender {
        pub fn open() -> io::Result<Self> {
            let s = Self {
                v4: raw(libc::AF_INET),
                v6: raw(libc::AF_INET6),
            };
            if s.v4.is_none() && s.v6.is_none() {
                return Err(io::Error::last_os_error());
            }
            Ok(s)
        }
        pub fn send(&self, packet: &[u8]) -> io::Result<()> {
            let n = match packet.first().map(|b| b >> 4) {
                Some(4) if packet.len() >= 20 => {
                    let fd = self.v4.as_ref().ok_or(io::ErrorKind::Unsupported)?;
                    let mut to: libc::sockaddr_in = unsafe { mem::zeroed() };
                    to.sin_family = libc::AF_INET as u16;
                    to.sin_addr.s_addr = u32::from_ne_bytes(packet[16..20].try_into().unwrap());
                    unsafe {
                        libc::sendto(
                            fd.as_raw_fd(),
                            packet.as_ptr().cast(),
                            packet.len(),
                            0,
                            (&to as *const libc::sockaddr_in).cast(),
                            mem::size_of_val(&to) as libc::socklen_t,
                        )
                    }
                }
                Some(6) if packet.len() >= 40 => {
                    let fd = self.v6.as_ref().ok_or(io::ErrorKind::Unsupported)?;
                    let mut to: libc::sockaddr_in6 = unsafe { mem::zeroed() };
                    to.sin6_family = libc::AF_INET6 as u16;
                    to.sin6_addr.s6_addr = packet[24..40].try_into().unwrap();
                    unsafe {
                        libc::sendto(
                            fd.as_raw_fd(),
                            packet.as_ptr().cast(),
                            packet.len(),
                            0,
                            (&to as *const libc::sockaddr_in6).cast(),
                            mem::size_of_val(&to) as libc::socklen_t,
                        )
                    }
                }
                _ => return Err(io::ErrorKind::InvalidInput.into()),
            };
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub use platform::{Queue, Queued, Sender};

/// Runs queue `number` until the process ends: takes the queued packets in batches, judges each
/// batch with `judge` and sends the verdicts back, recording what it did in `status`. A queue
/// that cannot be opened or fails is retried every two seconds; the kernel forwards unjudged
/// meanwhile.
#[cfg(target_os = "linux")]
pub fn run<J, S>(number: u16, mut judge: J, mut status: S)
where
    J: FnMut(&[Option<Flow>], i64) -> Vec<Verdict>,
    S: FnMut(&Status),
{
    let mut state = Status {
        queue: number,
        ..Default::default()
    };
    let mut buffers: Vec<Vec<u8>> = (0..BATCH).map(|_| vec![0u8; 0x10000 + 512]).collect();
    loop {
        let queue = match Queue::open(number) {
            Ok(q) => q,
            Err(e) => {
                state.active = false;
                state.error = Some(format!("opening NFQUEUE {number}: {e}"));
                status(&state);
                std::thread::sleep(std::time::Duration::from_secs(2));
                continue;
            }
        };
        let sender = Sender::open();
        state.active = true;
        state.error = match &sender {
            Ok(_) => None,
            Err(e) => Some(format!("opening the raw socket for challenges: {e}")),
        };
        status(&state);
        let mut refreshed = 0i64;
        loop {
            for b in buffers.iter_mut() {
                b.resize(0x10000 + 512, 0);
            }
            let (taken, overruns) = match queue.receive_batch(&mut buffers) {
                Ok(v) => v,
                Err(e) => {
                    state.active = false;
                    state.error = Some(format!("reading NFQUEUE {number}: {e}"));
                    status(&state);
                    break;
                }
            };
            state.overruns += overruns;
            let now = chrono::Utc::now().timestamp_millis();
            let queued: Vec<Queued> = buffers[..taken]
                .iter()
                .flat_map(|b| Queue::packets(b))
                .collect();
            if !queued.is_empty() {
                let flows: Vec<Option<Flow>> =
                    queued.iter().map(|q| q.packet.and_then(flow)).collect();
                let verdicts = judge(&flows, now);
                for (i, q) in queued.iter().enumerate() {
                    state.packets += 1;
                    let verdict = if flows[i].is_none() {
                        state.unreadable += 1;
                        Verdict::Accept
                    } else {
                        verdicts.get(i).cloned().unwrap_or(Verdict::Accept)
                    };
                    let accept = verdict == Verdict::Accept;
                    match &verdict {
                        Verdict::Accept => state.accepted += 1,
                        Verdict::Drop => state.dropped += 1,
                        Verdict::Challenge(reply) => {
                            state.challenged += 1;
                            let sent = flows[i]
                                .as_ref()
                                .and_then(|f| reply_packet(f, reply))
                                .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))
                                .and_then(|p| match &sender {
                                    Ok(s) => s.send(&p),
                                    Err(_) => Err(io::ErrorKind::NotConnected.into()),
                                });
                            if sent.is_err() {
                                state.replies_failed += 1;
                            }
                        }
                    }
                    if let Err(e) = queue.verdict(q.id, accept) {
                        state.error = Some(format!("sending a verdict: {e}"));
                    }
                }
                state.last_packet_ms = Some(now);
            }
            if now - refreshed >= 1000 {
                refreshed = now;
                if let Some((full, user)) =
                    std::fs::read_to_string("/proc/net/netfilter/nfnetlink_queue")
                        .ok()
                        .and_then(|t| kernel_counters(&t, number))
                {
                    state.queue_dropped = full;
                    state.user_dropped = user;
                }
                status(&state);
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
}

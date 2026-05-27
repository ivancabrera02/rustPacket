//! ping6_rs — Pure-Rust ICMPv6 ping using raw sockets
//!
//! Usage: sudo ./ping6_rs <host> [-c count] [-i interval_ms] [-s size] [-W timeout_ms]
//!
//! Requires root privileges (or CAP_NET_RAW).
//! On Linux the kernel computes the ICMPv6 checksum automatically for
//! SOCK_RAW/IPPROTO_ICMPV6 sockets; we still compute it ourselves here
//! for portability across BSDs where the kernel does not.
//!
//! Build:
//!   cargo build --release
//!   sudo ./target/release/ping6_rs ::1
//!   sudo ./target/release/ping6_rs ipv6.google.com

use std::{
    io,
    mem::{self, MaybeUninit},
    net::{IpAddr, Ipv6Addr, ToSocketAddrs},
    time::{Duration, Instant},
};
use clap::Parser;

// ─── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(name = "ping6_rs", about = "ICMPv6 ping in pure Rust")]
struct Args {
    /// Target host name or IPv6 address
    host: String,

    /// Number of packets to send (0 = infinite)
    #[arg(short = 'c', long, default_value_t = 0)]
    count: u64,

    /// Interval between packets in milliseconds
    #[arg(short = 'i', long, default_value_t = 1000)]
    interval: u64,

    /// ICMP payload size in bytes
    #[arg(short = 's', long, default_value_t = 56)]
    size: usize,

    /// Receive timeout in milliseconds
    #[arg(short = 'W', long, default_value_t = 1000)]
    timeout: u64,
}

// ─── ICMPv6 constants (RFC 4443) ─────────────────────────────────────────────

const ICMPV6_ECHO_REQUEST: u8 = 128;
const ICMPV6_ECHO_REPLY:   u8 = 129;

// ─── Minimal libc bindings for IPv6 ─────────────────────────────────────────

mod libc {
    pub const AF_INET6:      i32 = 10;
    pub const SOCK_RAW:      i32 = 3;
    pub const IPPROTO_ICMPV6: i32 = 58;
    pub const SOL_SOCKET:    i32 = 1;
    pub const SO_RCVTIMEO:   i32 = 20;

    extern "C" {
        pub fn socket(domain: i32, typ: i32, protocol: i32) -> i32;
        pub fn setsockopt(
            sockfd: i32, level: i32, optname: i32,
            optval: *const core::ffi::c_void, optlen: u32,
        ) -> i32;
        pub fn sendto(
            sockfd: i32, buf: *const core::ffi::c_void, len: usize, flags: i32,
            dest_addr: *const core::ffi::c_void, addrlen: u32,
        ) -> isize;
        pub fn recvfrom(
            sockfd: i32, buf: *mut core::ffi::c_void, len: usize, flags: i32,
            src_addr: *mut core::ffi::c_void, addrlen: *mut u32,
        ) -> isize;
        pub fn close(fd: i32) -> i32;
    }

    #[repr(C)]
    pub struct Timeval { pub tv_sec: i64, pub tv_usec: i64 }
}

// ─── sockaddr_in6 ─────────────────────────────────────────────────────────────

/// POSIX sockaddr_in6 structure (RFC 3493).
#[repr(C)]
struct SockaddrIn6 {
    sin6_family:   u16,
    sin6_port:     u16,
    sin6_flowinfo: u32,
    sin6_addr:     [u8; 16],
    sin6_scope_id: u32,
}

fn make_sockaddr_in6(addr: Ipv6Addr) -> SockaddrIn6 {
    SockaddrIn6 {
        sin6_family:   libc::AF_INET6 as u16,
        sin6_port:     0,
        sin6_flowinfo: 0,
        sin6_addr:     addr.octets(),
        sin6_scope_id: 0,
    }
}

// ─── Internet checksum (RFC 1071) ─────────────────────────────────────────────

/// One's-complement 16-bit checksum.
///
/// For ICMPv6 a pseudo-header covering the IPv6 source/destination, payload
/// length and next-header field should be prepended before calling this
/// function. On Linux with SOCK_RAW/IPPROTO_ICMPV6 the kernel inserts the
/// correct checksum for us, so we pass the packet bytes only.
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }
    if i < data.len() {
        sum += u32::from(data[i]) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

// ─── Packet construction ──────────────────────────────────────────────────────

/// Build an ICMPv6 Echo Request packet.
///
/// Layout (RFC 4443 §4.1):
///   [0]   type  = 128
///   [1]   code  = 0
///   [2-3] checksum
///   [4-5] identifier
///   [6-7] sequence number
///   [8..] payload (nanosecond timestamp + incrementing fill)
fn build_icmpv6_packet(id: u16, seq: u16, payload_size: usize) -> Vec<u8> {
    let total = 8 + payload_size;
    let mut pkt = vec![0u8; total];

    pkt[0] = ICMPV6_ECHO_REQUEST;
    pkt[1] = 0; // code
    // Checksum bytes [2-3] start as zero; updated below
    pkt[4] = (id  >> 8) as u8;
    pkt[5] = (id  & 0xff) as u8;
    pkt[6] = (seq >> 8) as u8;
    pkt[7] = (seq & 0xff) as u8;

    // Embed a nanosecond-precision timestamp at the start of the payload
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    for (i, b) in ts.to_be_bytes().iter().enumerate() {
        if 8 + i < total { pkt[8 + i] = *b; }
    }
    // Fill the remainder with a simple byte pattern
    for i in 16..total {
        pkt[i] = (i & 0xff) as u8;
    }

    // On Linux the kernel overwrites [2-3] with the correct ICMPv6 checksum
    // (which includes a pseudo-header). We compute it anyway for portability.
    let cksum = internet_checksum(&pkt);
    pkt[2] = (cksum >> 8) as u8;
    pkt[3] = (cksum & 0xff) as u8;
    pkt
}

// ─── DNS resolution ───────────────────────────────────────────────────────────

/// Resolve a hostname to its first IPv6 address.
/// Accepts bare IPv6 literals (e.g. "::1") or hostnames with AAAA records.
fn resolve_ipv6(host: &str) -> io::Result<Ipv6Addr> {
    // Fast path: already a numeric IPv6 literal
    if let Ok(addr) = host.parse::<Ipv6Addr>() {
        return Ok(addr);
    }
    // Try "[host]:0" (bracketed form) then "host:0"
    format!("[{}]:0", host)
        .to_socket_addrs()
        .or_else(|_| format!("{}:0", host).to_socket_addrs())?
        .filter_map(|s| if let IpAddr::V6(v6) = s.ip() { Some(v6) } else { None })
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "no IPv6 address found"))
}

// ─── SIGINT handler ───────────────────────────────────────────────────────────

static STOP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

extern "C" fn sigint_handler(_: i32) {
    STOP.store(true, std::sync::atomic::Ordering::SeqCst);
}

// ─── Main ─────────────────────────────────────────────────────────────────────

fn main() -> io::Result<()> {
    let args = Args::parse();

    let dst_ip = resolve_ipv6(&args.host)?;
    let pid    = (std::process::id() & 0xffff) as u16;

    // Register Ctrl-C handler before entering the send/receive loop
    unsafe {
        extern "C" { fn signal(sig: i32, h: extern "C" fn(i32)) -> usize; }
        signal(2 /* SIGINT */, sigint_handler);
    }

    println!(
        "PING6 {} ({}) {}({}) bytes of data.",
        args.host, dst_ip,
        args.size,
        args.size + 8 + 40 // payload + ICMPv6 header + fixed IPv6 header
    );

    // Open raw ICMPv6 socket.
    // With AF_INET6/SOCK_RAW/IPPROTO_ICMPV6 the kernel delivers only ICMPv6
    // datagrams (IPv6 header is stripped on receive, added on send).
    let sock = unsafe {
        libc::socket(libc::AF_INET6, libc::SOCK_RAW, libc::IPPROTO_ICMPV6)
    };
    if sock < 0 {
        return Err(io::Error::last_os_error());
    }

    // Configure receive timeout
    let tv = libc::Timeval {
        tv_sec:  (args.timeout / 1000) as i64,
        tv_usec: ((args.timeout % 1000) * 1000) as i64,
    };
    unsafe {
        libc::setsockopt(
            sock, libc::SOL_SOCKET, libc::SO_RCVTIMEO,
            &tv as *const _ as *const _, mem::size_of::<libc::Timeval>() as u32,
        );
    }

    let dst_sa = make_sockaddr_in6(dst_ip);

    let mut seq: u16 = 1;
    let mut sent: u64 = 0;
    let mut received: u64 = 0;
    let mut rtts: Vec<f64> = Vec::new();
    let start = Instant::now();

    while !STOP.load(std::sync::atomic::Ordering::SeqCst) {
        if args.count > 0 && sent >= args.count {
            break;
        }

        let pkt = build_icmpv6_packet(pid, seq, args.size);
        let t0  = Instant::now();

        let n = unsafe {
            libc::sendto(
                sock, pkt.as_ptr() as *const _, pkt.len(), 0,
                &dst_sa as *const _ as *const _,
                mem::size_of::<SockaddrIn6>() as u32,
            )
        };

        if n < 0 {
            eprintln!("sendto: {}", io::Error::last_os_error());
            seq += 1;
            sent += 1;
            std::thread::sleep(Duration::from_millis(args.interval));
            continue;
        }
        sent += 1;

        // For AF_INET6/SOCK_RAW the kernel strips the IPv6 header before
        // delivering to recvfrom, so the buffer starts with the ICMPv6 header.
        let mut buf = [0u8; 1500];
        let mut src_sa: MaybeUninit<SockaddrIn6> = MaybeUninit::uninit();
        let mut sa_len = mem::size_of::<SockaddrIn6>() as u32;

        let rn = unsafe {
            libc::recvfrom(
                sock, buf.as_mut_ptr() as *mut _, buf.len(), 0,
                src_sa.as_mut_ptr() as *mut _, &mut sa_len,
            )
        };

        let rtt = t0.elapsed().as_secs_f64() * 1000.0;

        if rn < 0 {
            println!("Request timeout for icmp_seq {}", seq);
        } else {
            let rn = rn as usize;
            if rn >= 8 {
                let icmp_type = buf[0];
                let icmp_id   = u16::from_be_bytes([buf[4], buf[5]]);
                let icmp_seq  = u16::from_be_bytes([buf[6], buf[7]]);

                if icmp_type == ICMPV6_ECHO_REPLY && icmp_id == pid {
                    received += 1;
                    rtts.push(rtt);
                    let src_sa   = unsafe { src_sa.assume_init() };
                    let src_ip   = Ipv6Addr::from(src_sa.sin6_addr);
                    println!(
                        "{} bytes from {}: icmp_seq={} time={:.3} ms",
                        rn, src_ip, icmp_seq, rtt
                    );
                } else if icmp_type == 3 {
                    // ICMPv6 Time Exceeded
                    println!("From {} icmp_seq={} Time exceeded", dst_ip, seq);
                } else if icmp_type == 1 {
                    // ICMPv6 Destination Unreachable
                    println!(
                        "From {} icmp_seq={} Destination unreachable (code {})",
                        dst_ip, seq, buf[1]
                    );
                }
            }
        }

        seq += 1;
        if args.count == 0 || sent < args.count {
            std::thread::sleep(Duration::from_millis(args.interval));
        }
    }

    // ─── Final statistics ─────────────────────────────────────────────────────

    let elapsed_ms = start.elapsed().as_millis();
    let loss = if sent > 0 { 100.0 * (sent - received) as f64 / sent as f64 } else { 0.0 };

    println!("\n--- {} ping6 statistics ---", args.host);
    println!(
        "{} packets transmitted, {} received, {:.1}% packet loss, time {}ms",
        sent, received, loss, elapsed_ms
    );

    if !rtts.is_empty() {
        let min  = rtts.iter().cloned().fold(f64::INFINITY,     f64::min);
        let max  = rtts.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let avg  = rtts.iter().sum::<f64>() / rtts.len() as f64;
        let mdev = {
            let v = rtts.iter().map(|r| (r - avg).powi(2)).sum::<f64>() / rtts.len() as f64;
            v.sqrt()
        };
        println!("rtt min/avg/max/mdev = {:.3}/{:.3}/{:.3}/{:.3} ms", min, avg, max, mdev);
    }

    unsafe { libc::close(sock) };
    Ok(())
}

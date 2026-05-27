//! ping_rs — Pure-Rust ICMPv4 ping using raw sockets
//!
//! Usage: sudo ./ping_rs <host> [-c count] [-i interval_ms] [-s size] [-t ttl] [-W timeout_ms]
//!
//! Requires root privileges (or CAP_NET_RAW) to open raw sockets.
//! The kernel fills in the IP header; we build and checksum the ICMP layer manually.
//!
//! Build:
//!   cargo build --release
//!   sudo ./target/release/ping_rs google.com

use std::{
    io,
    mem::{self, MaybeUninit},
    net::{IpAddr, Ipv4Addr, ToSocketAddrs},
    time::{Duration, Instant},
};
use clap::Parser;

// ─── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(name = "ping_rs", about = "ICMPv4 ping in pure Rust", long_about = None)]
struct Args {
    /// Target host name or IPv4 address
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

    /// IP Time-To-Live
    #[arg(short = 't', long, default_value_t = 64)]
    ttl: u32,

    /// Receive timeout in milliseconds
    #[arg(short = 'W', long, default_value_t = 1000)]
    timeout: u64,
}

// ─── ICMP constants ───────────────────────────────────────────────────────────

const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_ECHO_REPLY:   u8 = 0;

// ─── Internet checksum (RFC 1071) ─────────────────────────────────────────────

/// Compute the one's-complement checksum used by ICMP and IP headers.
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    // Accumulate 16-bit words
    while i + 1 < data.len() {
        sum += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }
    // Handle odd trailing byte
    if i < data.len() {
        sum += u32::from(data[i]) << 8;
    }
    // Fold 32-bit carry back into 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

// ─── Packet construction ──────────────────────────────────────────────────────

/// Build a complete ICMP Echo Request packet ready for sendto().
///
/// Layout (RFC 792):
///   [0]   type  = 8 (Echo Request)
///   [1]   code  = 0
///   [2-3] checksum
///   [4-5] identifier  (process PID, to filter our own replies)
///   [6-7] sequence number
///   [8..] payload     (first 8 bytes = nanosecond timestamp, rest = pattern)
fn build_icmp_packet(id: u16, seq: u16, payload_size: usize) -> Vec<u8> {
    let total = 8 + payload_size;
    let mut pkt = vec![0u8; total];

    // ICMP header fields
    pkt[0] = ICMP_ECHO_REQUEST;
    pkt[1] = 0; // code
    // checksum written as zero; recalculated below
    pkt[4] = (id >> 8) as u8;
    pkt[5] = (id & 0xff) as u8;
    pkt[6] = (seq >> 8) as u8;
    pkt[7] = (seq & 0xff) as u8;

    // Embed a nanosecond timestamp in the first 8 payload bytes so the
    // receiver could compute RTT from the payload itself (we measure with
    // Instant instead, but it is good practice to include it).
    let ts = Instant::now().elapsed().as_nanos() as u64;
    for (i, b) in ts.to_be_bytes().iter().enumerate() {
        if 8 + i < total {
            pkt[8 + i] = *b;
        }
    }
    // Fill remaining payload with an incrementing byte pattern
    for i in 16..total {
        pkt[i] = (i & 0xff) as u8;
    }

    // Compute and insert checksum
    let cksum = internet_checksum(&pkt);
    pkt[2] = (cksum >> 8) as u8;
    pkt[3] = (cksum & 0xff) as u8;
    pkt
}

// ─── Minimal libc bindings ────────────────────────────────────────────────────

mod libc {
    pub const AF_INET:      i32 = 2;
    pub const SOCK_RAW:     i32 = 3;
    pub const IPPROTO_ICMP: i32 = 1;
    pub const IPPROTO_IP:   i32 = 0;
    pub const SOL_SOCKET:   i32 = 1;
    pub const SO_RCVTIMEO:  i32 = 20;
    pub const IP_TTL:       i32 = 2;

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

// ─── sockaddr_in helpers ──────────────────────────────────────────────────────

#[repr(C)]
struct InAddr { s_addr: u32 }

#[repr(C)]
struct SockaddrIn {
    sin_family: u16,
    sin_port:   u16,
    sin_addr:   InAddr,
    sin_zero:   [u8; 8],
}

fn sockaddr_in(addr: Ipv4Addr) -> SockaddrIn {
    SockaddrIn {
        sin_family: libc::AF_INET as u16,
        sin_port:   0u16.to_be(),
        sin_addr:   InAddr { s_addr: u32::from(addr).to_be() },
        sin_zero:   [0; 8],
    }
}

// ─── DNS resolution ───────────────────────────────────────────────────────────

/// Resolve a hostname (or dotted-decimal string) to its first IPv4 address.
fn resolve(host: &str) -> io::Result<Ipv4Addr> {
    format!("{}:0", host)
        .to_socket_addrs()?
        .filter_map(|s| if let IpAddr::V4(v4) = s.ip() { Some(v4) } else { None })
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "no IPv4 address found"))
}

// ─── SIGINT handler ───────────────────────────────────────────────────────────

// We store a boxed closure so that main() can check the running flag or print
// statistics before exiting. A static AtomicBool is simpler; here we show the
// closure-based approach for flexibility.
static mut SIGINT_CLOSURE: Option<Box<dyn Fn() + Send>> = None;

extern "C" fn sigint_trampoline(_: i32) {
    // SAFETY: written once before the loop; reads here are benign races on
    // the closure pointer (worst case we call it twice).
    unsafe {
        if let Some(ref h) = SIGINT_CLOSURE {
            h();
        }
    }
}

fn set_sigint_handler<F: Fn() + Send + 'static>(f: F) {
    unsafe {
        SIGINT_CLOSURE = Some(Box::new(f));
        extern "C" { fn signal(sig: i32, handler: extern "C" fn(i32)) -> usize; }
        signal(2 /* SIGINT */, sigint_trampoline);
    }
}

// ─── Main ─────────────────────────────────────────────────────────────────────

fn main() -> io::Result<()> {
    let args = Args::parse();

    let dst_ip = resolve(&args.host)?;
    // Use the lower 16 bits of the PID as the ICMP identifier so we can
    // distinguish our replies from those of any concurrent ping process.
    let pid = (std::process::id() & 0xffff) as u16;

    println!(
        "PING {} ({}) {}({}) bytes of data.",
        args.host, dst_ip,
        args.size,
        args.size + 8 + 20 // payload + ICMP header + IP header
    );

    // Open raw ICMP socket — the kernel will prepend the IP header on send
    // and deliver the full IP packet (including IP header) on receive.
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) };
    if sock < 0 {
        return Err(io::Error::last_os_error());
    }

    // Set IP TTL
    let ttl = args.ttl;
    unsafe {
        libc::setsockopt(
            sock, libc::IPPROTO_IP, libc::IP_TTL,
            &ttl as *const u32 as *const _, mem::size_of::<u32>() as u32,
        );
    }

    // Set receive timeout so recvfrom() doesn't block forever
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

    let dst_sa = sockaddr_in(dst_ip);

    let mut seq: u16 = 1;
    let mut sent: u64 = 0;
    let mut received: u64 = 0;
    let mut rtts: Vec<f64> = Vec::new();
    let start_time = Instant::now();

    // Trap Ctrl-C so we can print statistics before exiting
    let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let r = running.clone();
    set_sigint_handler(move || r.store(false, std::sync::atomic::Ordering::SeqCst));

    while running.load(std::sync::atomic::Ordering::SeqCst) {
        if args.count > 0 && sent >= args.count {
            break;
        }

        let pkt = build_icmp_packet(pid, seq, args.size);
        let t0 = Instant::now();

        let n = unsafe {
            libc::sendto(
                sock, pkt.as_ptr() as *const _, pkt.len(), 0,
                &dst_sa as *const _ as *const _,
                mem::size_of::<SockaddrIn>() as u32,
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

        // The kernel delivers the complete IP packet (IP hdr + ICMP hdr + payload).
        let mut buf = [0u8; 1500];
        let mut src_sa: MaybeUninit<SockaddrIn> = MaybeUninit::uninit();
        let mut sa_len = mem::size_of::<SockaddrIn>() as u32;

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
            // Skip the variable-length IP header (IHL field × 4 bytes)
            let ip_hdr_len = ((buf[0] & 0x0f) as usize) * 4;
            if rn > ip_hdr_len + 8 {
                let icmp     = &buf[ip_hdr_len..];
                let icmp_type = icmp[0];
                let icmp_id   = u16::from_be_bytes([icmp[4], icmp[5]]);
                let icmp_seq  = u16::from_be_bytes([icmp[6], icmp[7]]);

                if icmp_type == ICMP_ECHO_REPLY && icmp_id == pid {
                    received += 1;
                    rtts.push(rtt);
                    let resp_ttl     = buf[8]; // TTL is at byte 8 of the IP header
                    let payload_bytes = rn - ip_hdr_len - 8;
                    println!(
                        "{} bytes from {}: icmp_seq={} ttl={} time={:.3} ms",
                        payload_bytes + 8, dst_ip, icmp_seq, resp_ttl, rtt
                    );
                } else if icmp_type == 11 {
                    // ICMP Time Exceeded — our TTL hit zero in transit
                    println!("From {} icmp_seq={} Time to live exceeded", dst_ip, seq);
                }
            }
        }

        seq += 1;
        if args.count == 0 || sent < args.count {
            std::thread::sleep(Duration::from_millis(args.interval));
        }
    }

    // ─── Final statistics (mirrors Linux ping output) ─────────────────────────

    let elapsed_ms = start_time.elapsed().as_millis();
    let loss = if sent > 0 { 100.0 * (sent - received) as f64 / sent as f64 } else { 0.0 };

    println!("\n--- {} ping statistics ---", args.host);
    println!(
        "{} packets transmitted, {} received, {:.1}% packet loss, time {}ms",
        sent, received, loss, elapsed_ms
    );

    if !rtts.is_empty() {
        let min  = rtts.iter().cloned().fold(f64::INFINITY,     f64::min);
        let max  = rtts.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let avg  = rtts.iter().sum::<f64>() / rtts.len() as f64;
        let mdev = {
            let variance = rtts.iter().map(|r| (r - avg).powi(2)).sum::<f64>()
                         / rtts.len() as f64;
            variance.sqrt()
        };
        println!("rtt min/avg/max/mdev = {:.3}/{:.3}/{:.3}/{:.3} ms", min, avg, max, mdev);
    }

    unsafe { libc::close(sock) };
    Ok(())
}

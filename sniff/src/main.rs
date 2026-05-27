//! sniff_rs — Layer-3 packet sniffer in pure Rust
//!
//! Equivalent to Scapy/impacket's sniff() function: captures all IPv4 packets
//! arriving at the host and decodes their IP, TCP, UDP and ICMP headers in
//! real time.
//!
//! Uses AF_INET/SOCK_RAW/IPPROTO_RAW, which delivers every inbound IPv4
//! datagram including its IP header. No libpcap dependency required.
//!
//! Usage: sudo ./sniff_rs [options]
//!
//! Requires root (or CAP_NET_RAW).
//!
//! Build:
//!   cargo build --release
//!   sudo ./target/release/sniff_rs -c 100 --filter tcp
//!   sudo ./target/release/sniff_rs --filter udp -p 53 -x
//!   sudo ./target/release/sniff_rs -H 192.168.1.1 -v

use std::{
    io,
    mem::MaybeUninit,
    net::Ipv4Addr,
    time::{SystemTime, UNIX_EPOCH},
};
use clap::Parser;

// ─── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "sniff_rs",
    about = "Layer-3 IPv4 packet sniffer (like Scapy/impacket sniff())",
    long_about = "Captures and decodes IPv4/TCP/UDP/ICMP packets in real time.\n\
                  Requires sudo or CAP_NET_RAW."
)]
struct Args {
    /// Number of packets to capture (0 = infinite)
    #[arg(short = 'c', long, default_value_t = 0)]
    count: u64,

    /// Protocol filter: all | tcp | udp | icmp
    #[arg(short = 'f', long = "filter", default_value = "all")]
    filter: String,

    /// Dump payload as a hex+ASCII grid
    #[arg(short = 'x', long = "hex")]
    hex: bool,

    /// Only show packets to or from this IPv4 address
    #[arg(short = 'H', long = "host")]
    host: Option<String>,

    /// Only show packets with this source or destination port (TCP/UDP)
    #[arg(short = 'p', long = "port")]
    port: Option<u16>,

    /// Maximum payload bytes to include in the hex dump
    #[arg(long = "snaplen", default_value_t = 64)]
    snaplen: usize,

    /// Verbose: print all header fields
    #[arg(short = 'v', long)]
    verbose: bool,
}

// ─── Minimal libc bindings ────────────────────────────────────────────────────

mod libc {
    /// AF_INET/SOCK_RAW/IPPROTO_RAW delivers every inbound IPv4 datagram
    /// to the socket, with the IP header included in the buffer.
    pub const AF_INET:      i32 = 2;
    pub const SOCK_RAW:     i32 = 3;
    pub const IPPROTO_RAW:  i32 = 255;

    extern "C" {
        pub fn socket(domain: i32, typ: i32, protocol: i32) -> i32;
        pub fn recvfrom(
            sockfd: i32, buf: *mut core::ffi::c_void, len: usize, flags: i32,
            src_addr: *mut core::ffi::c_void, addrlen: *mut u32,
        ) -> isize;
        pub fn close(fd: i32) -> i32;
    }
}

// ─── Protocol enum ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

impl Protocol {
    fn from_u8(v: u8) -> Self {
        match v {
            6  => Protocol::Tcp,
            17 => Protocol::Udp,
            1  => Protocol::Icmp,
            x  => Protocol::Other(x),
        }
    }
    fn name(&self) -> String {
        match self {
            Protocol::Tcp      => "TCP".into(),
            Protocol::Udp      => "UDP".into(),
            Protocol::Icmp     => "ICMP".into(),
            Protocol::Other(x) => format!("PROTO({})", x),
        }
    }
}

// ─── Header parsers ───────────────────────────────────────────────────────────

/// Zero-copy view over a raw IPv4 header.
struct IpHeader<'a> { raw: &'a [u8] }

impl<'a> IpHeader<'a> {
    fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < 20 { return None; }
        Some(IpHeader { raw: data })
    }
    fn version(&self)    -> u8        { (self.raw[0] >> 4) & 0xf }
    fn ihl(&self)        -> usize     { ((self.raw[0] & 0xf) as usize) * 4 }
    fn tos(&self)        -> u8        { self.raw[1] }
    fn total_len(&self)  -> u16       { u16::from_be_bytes([self.raw[2],  self.raw[3]])  }
    fn id(&self)         -> u16       { u16::from_be_bytes([self.raw[4],  self.raw[5]])  }
    fn ttl(&self)        -> u8        { self.raw[8] }
    fn protocol(&self)   -> Protocol  { Protocol::from_u8(self.raw[9]) }
    fn checksum(&self)   -> u16       { u16::from_be_bytes([self.raw[10], self.raw[11]]) }
    fn src(&self)        -> Ipv4Addr  { Ipv4Addr::new(self.raw[12], self.raw[13], self.raw[14], self.raw[15]) }
    fn dst(&self)        -> Ipv4Addr  { Ipv4Addr::new(self.raw[16], self.raw[17], self.raw[18], self.raw[19]) }
    /// Slice starting right after the IP header options (if any)
    fn payload(&self)    -> &[u8]     { &self.raw[self.ihl().min(self.raw.len())..] }
}

/// Zero-copy view over a raw TCP header.
struct TcpHeader<'a> { raw: &'a [u8] }

impl<'a> TcpHeader<'a> {
    fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < 20 { return None; }
        Some(TcpHeader { raw: data })
    }
    fn src_port(&self)  -> u16   { u16::from_be_bytes([self.raw[0], self.raw[1]]) }
    fn dst_port(&self)  -> u16   { u16::from_be_bytes([self.raw[2], self.raw[3]]) }
    fn seq(&self)       -> u32   { u32::from_be_bytes([self.raw[4], self.raw[5], self.raw[6], self.raw[7]]) }
    fn ack(&self)       -> u32   { u32::from_be_bytes([self.raw[8], self.raw[9], self.raw[10], self.raw[11]]) }
    fn data_off(&self)  -> usize { ((self.raw[12] >> 4) as usize) * 4 }
    fn flags(&self)     -> u8    { self.raw[13] }
    fn window(&self)    -> u16   { u16::from_be_bytes([self.raw[14], self.raw[15]]) }
    fn checksum(&self)  -> u16   { u16::from_be_bytes([self.raw[16], self.raw[17]]) }

    /// Human-readable TCP flag abbreviations
    fn flags_str(&self) -> String {
        let f = self.flags();
        let mut parts = Vec::new();
        if f & 0x02 != 0 { parts.push("SYN"); }
        if f & 0x10 != 0 { parts.push("ACK"); }
        if f & 0x01 != 0 { parts.push("FIN"); }
        if f & 0x04 != 0 { parts.push("RST"); }
        if f & 0x08 != 0 { parts.push("PSH"); }
        if f & 0x20 != 0 { parts.push("URG"); }
        if parts.is_empty() { "NONE".into() } else { parts.join("|") }
    }
    fn payload(&self) -> &[u8] { &self.raw[self.data_off().min(self.raw.len())..] }
}

/// Zero-copy view over a raw UDP header.
struct UdpHeader<'a> { raw: &'a [u8] }

impl<'a> UdpHeader<'a> {
    fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < 8 { return None; }
        Some(UdpHeader { raw: data })
    }
    fn src_port(&self) -> u16  { u16::from_be_bytes([self.raw[0], self.raw[1]]) }
    fn dst_port(&self) -> u16  { u16::from_be_bytes([self.raw[2], self.raw[3]]) }
    fn length(&self)   -> u16  { u16::from_be_bytes([self.raw[4], self.raw[5]]) }
    fn checksum(&self) -> u16  { u16::from_be_bytes([self.raw[6], self.raw[7]]) }
    fn payload(&self)  -> &[u8] { &self.raw[8..] }
}

/// Zero-copy view over a raw ICMP header.
struct IcmpHeader<'a> { raw: &'a [u8] }

impl<'a> IcmpHeader<'a> {
    fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < 8 { return None; }
        Some(IcmpHeader { raw: data })
    }
    fn typ(&self)      -> u8  { self.raw[0] }
    fn code(&self)     -> u8  { self.raw[1] }
    fn checksum(&self) -> u16 { u16::from_be_bytes([self.raw[2], self.raw[3]]) }
    fn id(&self)       -> u16 { u16::from_be_bytes([self.raw[4], self.raw[5]]) }
    fn seq(&self)      -> u16 { u16::from_be_bytes([self.raw[6], self.raw[7]]) }
    fn type_name(&self) -> &'static str {
        match self.typ() {
            0  => "Echo Reply",
            3  => "Destination Unreachable",
            5  => "Redirect",
            8  => "Echo Request",
            11 => "Time Exceeded",
            _  => "Other",
        }
    }
}

// ─── Hex + ASCII dump ─────────────────────────────────────────────────────────

/// Print up to `max_bytes` of `data` as a classic hex+ASCII side-by-side dump.
fn hex_dump(data: &[u8], max_bytes: usize) {
    let data = &data[..data.len().min(max_bytes)];
    let mut i = 0;
    while i < data.len() {
        let end   = (i + 16).min(data.len());
        let chunk = &data[i..end];

        print!("  {:04x}  ", i);
        for (j, b) in chunk.iter().enumerate() {
            if j == 8 { print!(" "); }
            print!("{:02x} ", b);
        }
        // Pad short rows so the ASCII column lines up
        let pad = 16 - chunk.len();
        for j in 0..pad {
            if (chunk.len() + j) == 8 { print!(" "); }
            print!("   ");
        }
        print!(" |");
        for b in chunk {
            let c = if *b >= 0x20 && *b < 0x7f { *b as char } else { '.' };
            print!("{}", c);
        }
        println!("|");
        i += 16;
    }
    if data.len() == max_bytes {
        println!("  ... (truncated to {} bytes)", max_bytes);
    }
}

// ─── Timestamp ────────────────────────────────────────────────────────────────

/// Return the current wall-clock time as "HH:MM:SS.mmm".
fn now_str() -> String {
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let s   = ts.as_secs();
    let ms  = ts.subsec_millis();
    format!("{:02}:{:02}:{:02}.{:03}", (s % 86400) / 3600, (s % 3600) / 60, s % 60, ms)
}

// ─── Well-known ports ─────────────────────────────────────────────────────────

fn well_known_port(port: u16) -> Option<&'static str> {
    match port {
        20 | 21  => Some("FTP"),
        22        => Some("SSH"),
        23        => Some("Telnet"),
        25        => Some("SMTP"),
        53        => Some("DNS"),
        67 | 68   => Some("DHCP"),
        80        => Some("HTTP"),
        110       => Some("POP3"),
        143       => Some("IMAP"),
        443       => Some("HTTPS"),
        445       => Some("SMB"),
        3306      => Some("MySQL"),
        3389      => Some("RDP"),
        5432      => Some("PostgreSQL"),
        6379      => Some("Redis"),
        8080      => Some("HTTP-alt"),
        _         => None,
    }
}

/// Format a port number, optionally annotated with its well-known service name.
fn port_label(port: u16) -> String {
    match well_known_port(port) {
        Some(name) => format!("{}/{}", port, name),
        None       => port.to_string(),
    }
}

// ─── SIGINT handler ───────────────────────────────────────────────────────────

static STOP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

extern "C" fn sigint_handler(_: i32) {
    STOP.store(true, std::sync::atomic::Ordering::SeqCst);
}

// ─── Main ─────────────────────────────────────────────────────────────────────

fn main() -> io::Result<()> {
    let args = Args::parse();

    // Parse the protocol filter string once
    let filter_proto: Option<Protocol> = match args.filter.to_lowercase().as_str() {
        "tcp"  => Some(Protocol::Tcp),
        "udp"  => Some(Protocol::Udp),
        "icmp" => Some(Protocol::Icmp),
        _      => None, // "all" or anything else → no filter
    };

    // Parse the optional host filter (dotted-decimal only for now)
    let filter_host: Option<Ipv4Addr> = args.host.as_deref().map(|h| {
        h.parse().expect("invalid host filter IP address")
    });

    // Register SIGINT so Ctrl-C prints statistics before we exit
    unsafe {
        extern "C" { fn signal(sig: i32, h: extern "C" fn(i32)) -> usize; }
        signal(2 /* SIGINT */, sigint_handler);
    }

    // Open raw socket.  IPPROTO_RAW on Linux delivers every inbound IPv4
    // datagram with the full IP header included in the receive buffer.
    let sock = unsafe {
        libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW)
    };
    if sock < 0 {
        eprintln!("Failed to open raw socket: {}", io::Error::last_os_error());
        eprintln!("Are you running with sudo or CAP_NET_RAW?");
        std::process::exit(1);
    }

    println!("sniff_rs — capturing IPv4 packets (Ctrl-C to stop)");
    println!(
        "Filter: proto={} host={} port={}",
        args.filter,
        filter_host.map(|h| h.to_string()).unwrap_or_else(|| "any".into()),
        args.port.map(|p| p.to_string()).unwrap_or_else(|| "any".into()),
    );
    println!("{}", "─".repeat(70));

    let mut buf = vec![0u8; 65535];
    let mut total_captured: u64 = 0;
    let mut pkt_count: u64 = 0;

    while !STOP.load(std::sync::atomic::Ordering::SeqCst) {
        if args.count > 0 && pkt_count >= args.count {
            break;
        }

        let n = unsafe {
            libc::recvfrom(
                sock, buf.as_mut_ptr() as *mut _, buf.len(), 0,
                std::ptr::null_mut(), std::ptr::null_mut(),
            )
        };

        if n <= 0 {
            if STOP.load(std::sync::atomic::Ordering::SeqCst) { break; }
            continue;
        }
        let n = n as usize;
        let raw = &buf[..n];

        // Decode IP header
        let ip = match IpHeader::new(raw) {
            Some(h) => h,
            None    => continue,
        };

        // ── Protocol filter ───────────────────────────────────────────────────
        if let Some(fp) = filter_proto {
            if ip.protocol() != fp { continue; }
        }

        // ── Host filter ───────────────────────────────────────────────────────
        if let Some(fh) = filter_host {
            if ip.src() != fh && ip.dst() != fh { continue; }
        }

        let proto   = ip.protocol();
        let payload = ip.payload();

        // ── Port filter (TCP/UDP only) ─────────────────────────────────────────
        if let Some(port) = args.port {
            let port_match = match proto {
                Protocol::Tcp => TcpHeader::new(payload)
                    .map(|t| t.src_port() == port || t.dst_port() == port)
                    .unwrap_or(false),
                Protocol::Udp => UdpHeader::new(payload)
                    .map(|u| u.src_port() == port || u.dst_port() == port)
                    .unwrap_or(false),
                _ => false,
            };
            if !port_match { continue; }
        }

        total_captured += 1;
        pkt_count += 1;

        // ── Print packet summary ──────────────────────────────────────────────

        match proto {
            Protocol::Tcp => {
                if let Some(tcp) = TcpHeader::new(payload) {
                    // Annotate with the well-known service on whichever port we recognise
                    let svc = well_known_port(tcp.dst_port())
                        .or_else(|| well_known_port(tcp.src_port()))
                        .unwrap_or("");
                    println!(
                        "[{}] TCP  {}:{} → {}:{}  [{}]  seq={} ack={}  win={}  {}B{}",
                        now_str(),
                        ip.src(), port_label(tcp.src_port()),
                        ip.dst(), port_label(tcp.dst_port()),
                        tcp.flags_str(),
                        tcp.seq(), tcp.ack(),
                        tcp.window(),
                        ip.total_len(),
                        if svc.is_empty() { String::new() } else { format!("  [{}]", svc) },
                    );
                    if args.verbose {
                        println!(
                            "    IP  ver={} ihl={} tos={:#04x} id={:#06x} ttl={} cksum={:#06x}",
                            ip.version(), ip.ihl(), ip.tos(), ip.id(), ip.ttl(), ip.checksum()
                        );
                        println!("    TCP data_off={}  cksum={:#06x}", tcp.data_off(), tcp.checksum());
                    }
                    if args.hex && !tcp.payload().is_empty() {
                        println!("    Payload ({} bytes):", tcp.payload().len());
                        hex_dump(tcp.payload(), args.snaplen);
                    }
                }
            }

            Protocol::Udp => {
                if let Some(udp) = UdpHeader::new(payload) {
                    let svc = well_known_port(udp.dst_port())
                        .or_else(|| well_known_port(udp.src_port()))
                        .unwrap_or("");
                    println!(
                        "[{}] UDP  {}:{} → {}:{}  len={}{}",
                        now_str(),
                        ip.src(), port_label(udp.src_port()),
                        ip.dst(), port_label(udp.dst_port()),
                        udp.length(),
                        if svc.is_empty() { String::new() } else { format!("  [{}]", svc) },
                    );
                    if args.verbose {
                        println!("    IP  ttl={} cksum={:#06x}", ip.ttl(), ip.checksum());
                        println!("    UDP cksum={:#06x}", udp.checksum());
                    }
                    if args.hex && !udp.payload().is_empty() {
                        println!("    Payload ({} bytes):", udp.payload().len());
                        hex_dump(udp.payload(), args.snaplen);
                    }
                }
            }

            Protocol::Icmp => {
                if let Some(icmp) = IcmpHeader::new(payload) {
                    println!(
                        "[{}] ICMP {} → {}  type={} ({}) code={}  id={}  seq={}  len={}",
                        now_str(),
                        ip.src(), ip.dst(),
                        icmp.typ(), icmp.type_name(), icmp.code(),
                        icmp.id(), icmp.seq(),
                        ip.total_len(),
                    );
                    if args.verbose {
                        println!(
                            "    IP  ttl={} id={:#06x} cksum={:#06x}",
                            ip.ttl(), ip.id(), ip.checksum()
                        );
                        println!("    ICMP cksum={:#06x}", icmp.checksum());
                    }
                }
            }

            Protocol::Other(x) => {
                println!(
                    "[{}] PROTO({}) {} → {}  len={}",
                    now_str(), x, ip.src(), ip.dst(), ip.total_len()
                );
            }
        }
    }

    println!("{}", "─".repeat(70));
    println!("Total captured: {} packets", total_captured);
    unsafe { libc::close(sock) };
    Ok(())
}

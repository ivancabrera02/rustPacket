//! sniffer_rs — Sniffer estilo impacket en Rust puro con AF_PACKET (L2 completo)
//!
//! Basado en la arquitectura de impacket/examples/sniffer.py:
//!   - Captura a nivel Ethernet (L2) usando AF_PACKET/SOCK_RAW
//!   - Disecciona Ethernet → IP/IPv6/ARP → TCP/UDP/ICMP/ICMPv6 → payload
//!   - Estadísticas por protocolo al finalizar
//!   - Escritura opcional a fichero PCAP (formato libpcap)
//!   - Filtro BPF textual básico (proto, host, port, src, dst)
//!
//! Uso:  sudo ./sniffer_rs -i eth0 [-c 100] [-w captura.pcap] [--filter "tcp and port 80"]
//!
//! Requiere privilegios de root (o CAP_NET_RAW + CAP_NET_ADMIN).
//!
//! Compilar:
//!   cargo build --release
//!   sudo ./target/release/sniffer_rs -i eth0 -c 50 -w out.pcap

use std::{
    collections::HashMap,
    fs::File,
    io::{self, Write},
    net::{Ipv4Addr, Ipv6Addr},
    time::{SystemTime, UNIX_EPOCH},
};
use clap::Parser;

// ─── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "sniffer_rs",
    about = "Sniffer estilo impacket — captura L2 completo (Ethernet→IP→TCP/UDP/ICMP)",
    long_about = "Captura y disecciona tramas Ethernet completas.\n\
                  Basado en la arquitectura de impacket/examples/sniffer.py.\n\
                  Requiere sudo o CAP_NET_RAW."
)]
struct Args {
    /// Interfaz de red (ej: eth0, wlan0)
    #[arg(short = 'i', long = "iface", default_value = "eth0")]
    iface: String,

    /// Número de paquetes (0 = infinito)
    #[arg(short = 'c', long, default_value_t = 0)]
    count: u64,

    /// Escribir captura en formato PCAP
    #[arg(short = 'w', long)]
    write: Option<String>,

    /// Filtro simple: "tcp", "udp", "icmp", "arp", "port 80", "host 1.2.3.4", "src 1.2.3.4"
    #[arg(long, default_value = "")]
    filter: String,

    /// Mostrar payload en hex
    #[arg(short = 'x', long)]
    hex: bool,

    /// Bytes máximos de payload a mostrar en hex
    #[arg(long, default_value_t = 128)]
    snaplen: usize,

    /// Verbose: todas las cabeceras
    #[arg(short = 'v', long)]
    verbose: bool,

    /// Silencioso: solo guardar a PCAP sin imprimir
    #[arg(short = 'q', long)]
    quiet: bool,
}

// ─── Módulo libc (AF_PACKET / SOCK_RAW) ──────────────────────────────────────

mod libc {
    pub const AF_PACKET:   i32 = 17;
    pub const SOCK_RAW:    i32 = 3;
    pub const ETH_P_ALL:   i32 = 0x0003; // todos los protocolos Ethernet

    extern "C" {
        pub fn socket(domain: i32, typ: i32, protocol: i32) -> i32;
        pub fn recvfrom(
            sockfd: i32,
            buf:    *mut core::ffi::c_void,
            len:    usize,
            flags:  i32,
            src:    *mut core::ffi::c_void,
            srclen: *mut u32,
        ) -> isize;
    }

    #[cfg(not(windows))]
    extern "C" { pub fn close(fd: i32) -> i32; }

    #[cfg(windows)]
    pub unsafe fn close(fd: i32) -> i32 {
        extern "system" { fn closesocket(s: usize) -> i32; }
        closesocket(fd as usize)
    }
}

// ─── EtherType ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum EtherType {
    Ipv4,
    Ipv6,
    Arp,
    Vlan,
    Other(u16),
}

impl EtherType {
    fn from_u16(v: u16) -> Self {
        match v {
            0x0800 => EtherType::Ipv4,
            0x86DD => EtherType::Ipv6,
            0x0806 => EtherType::Arp,
            0x8100 => EtherType::Vlan,
            x      => EtherType::Other(x),
        }
    }
    fn name(&self) -> String {
        match self {
            EtherType::Ipv4     => "IPv4".into(),
            EtherType::Ipv6     => "IPv6".into(),
            EtherType::Arp      => "ARP".into(),
            EtherType::Vlan     => "VLAN".into(),
            EtherType::Other(x) => format!("0x{:04x}", x),
        }
    }
}

// ─── Trama Ethernet ───────────────────────────────────────────────────────────

struct EthFrame<'a> {
    raw: &'a [u8],
}

impl<'a> EthFrame<'a> {
    fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < 14 { return None; }
        Some(EthFrame { raw: data })
    }
    fn dst_mac(&self) -> [u8; 6]  { self.raw[0..6].try_into().unwrap() }
    fn src_mac(&self) -> [u8; 6]  { self.raw[6..12].try_into().unwrap() }
    fn ether_type(&self) -> EtherType {
        EtherType::from_u16(u16::from_be_bytes([self.raw[12], self.raw[13]]))
    }
    fn payload(&self) -> &[u8]    { &self.raw[14..] }
}

fn mac_str(m: &[u8; 6]) -> String {
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m[0], m[1], m[2], m[3], m[4], m[5])
}

// ─── IPv4 ─────────────────────────────────────────────────────────────────────

struct Ipv4Hdr<'a> { raw: &'a [u8] }

impl<'a> Ipv4Hdr<'a> {
    fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < 20 { return None; }
        Some(Ipv4Hdr { raw: data })
    }
    fn ihl(&self)      -> usize    { ((self.raw[0] & 0xf) as usize) * 4 }
    fn tos(&self)      -> u8       { self.raw[1] }
    fn total_len(&self)-> u16      { u16::from_be_bytes([self.raw[2], self.raw[3]]) }
    fn id(&self)       -> u16      { u16::from_be_bytes([self.raw[4], self.raw[5]]) }
    fn flags(&self)    -> u8       { self.raw[6] >> 5 }
    fn ttl(&self)      -> u8       { self.raw[8] }
    fn proto(&self)    -> u8       { self.raw[9] }
    fn src(&self)      -> Ipv4Addr { Ipv4Addr::new(self.raw[12], self.raw[13], self.raw[14], self.raw[15]) }
    fn dst(&self)      -> Ipv4Addr { Ipv4Addr::new(self.raw[16], self.raw[17], self.raw[18], self.raw[19]) }
    fn payload(&self)  -> &[u8]    { &self.raw[self.ihl().min(self.raw.len())..] }
}

// ─── IPv6 ─────────────────────────────────────────────────────────────────────

struct Ipv6Hdr<'a> { raw: &'a [u8] }

impl<'a> Ipv6Hdr<'a> {
    fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < 40 { return None; }
        Some(Ipv6Hdr { raw: data })
    }
    fn next_header(&self) -> u8 { self.raw[6] }
    fn hop_limit(&self)   -> u8 { self.raw[7] }
    fn src(&self) -> Ipv6Addr {
        let mut a = [0u8; 16];
        a.copy_from_slice(&self.raw[8..24]);
        Ipv6Addr::from(a)
    }
    fn dst(&self) -> Ipv6Addr {
        let mut a = [0u8; 16];
        a.copy_from_slice(&self.raw[24..40]);
        Ipv6Addr::from(a)
    }
    fn payload(&self) -> &[u8] { &self.raw[40..] }
    fn payload_len(&self) -> u16 { u16::from_be_bytes([self.raw[4], self.raw[5]]) }
}

// ─── ARP ──────────────────────────────────────────────────────────────────────

struct ArpPkt<'a> { raw: &'a [u8] }

impl<'a> ArpPkt<'a> {
    fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < 28 { return None; }
        Some(ArpPkt { raw: data })
    }
    fn op(&self)       -> u16       { u16::from_be_bytes([self.raw[6], self.raw[7]]) }
    fn sender_mac(&self) -> [u8;6]  { self.raw[8..14].try_into().unwrap() }
    fn sender_ip(&self)  -> Ipv4Addr { Ipv4Addr::new(self.raw[14], self.raw[15], self.raw[16], self.raw[17]) }
    fn target_mac(&self) -> [u8;6]  { self.raw[18..24].try_into().unwrap() }
    fn target_ip(&self)  -> Ipv4Addr { Ipv4Addr::new(self.raw[24], self.raw[25], self.raw[26], self.raw[27]) }
    fn op_str(&self) -> &'static str {
        match self.op() { 1 => "REQUEST", 2 => "REPLY", _ => "?" }
    }
}

// ─── TCP ──────────────────────────────────────────────────────────────────────

struct TcpHdr<'a> { raw: &'a [u8] }

impl<'a> TcpHdr<'a> {
    fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < 20 { return None; }
        Some(TcpHdr { raw: data })
    }
    fn src_port(&self) -> u16  { u16::from_be_bytes([self.raw[0], self.raw[1]]) }
    fn dst_port(&self) -> u16  { u16::from_be_bytes([self.raw[2], self.raw[3]]) }
    fn seq(&self)      -> u32  { u32::from_be_bytes([self.raw[4], self.raw[5], self.raw[6], self.raw[7]]) }
    fn ack(&self)      -> u32  { u32::from_be_bytes([self.raw[8], self.raw[9], self.raw[10], self.raw[11]]) }
    fn data_off(&self) -> usize { ((self.raw[12] >> 4) as usize) * 4 }
    fn flags(&self)    -> u8   { self.raw[13] }
    fn window(&self)   -> u16  { u16::from_be_bytes([self.raw[14], self.raw[15]]) }
    fn flags_str(&self) -> String {
        let f = self.flags();
        let mut v = vec![];
        if f & 0x02 != 0 { v.push("SYN"); }
        if f & 0x10 != 0 { v.push("ACK"); }
        if f & 0x01 != 0 { v.push("FIN"); }
        if f & 0x04 != 0 { v.push("RST"); }
        if f & 0x08 != 0 { v.push("PSH"); }
        if f & 0x20 != 0 { v.push("URG"); }
        if v.is_empty() { "NONE".into() } else { v.join("|") }
    }
    fn payload(&self)  -> &[u8] { &self.raw[self.data_off().min(self.raw.len())..] }
}

// ─── UDP ──────────────────────────────────────────────────────────────────────

struct UdpHdr<'a> { raw: &'a [u8] }

impl<'a> UdpHdr<'a> {
    fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < 8 { return None; }
        Some(UdpHdr { raw: data })
    }
    fn src_port(&self) -> u16  { u16::from_be_bytes([self.raw[0], self.raw[1]]) }
    fn dst_port(&self) -> u16  { u16::from_be_bytes([self.raw[2], self.raw[3]]) }
    fn length(&self)   -> u16  { u16::from_be_bytes([self.raw[4], self.raw[5]]) }
    fn payload(&self)  -> &[u8] { &self.raw[8..] }
}

// ─── ICMP ─────────────────────────────────────────────────────────────────────

struct IcmpHdr<'a> { raw: &'a [u8] }

impl<'a> IcmpHdr<'a> {
    fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < 8 { return None; }
        Some(IcmpHdr { raw: data })
    }
    fn typ(&self)  -> u8  { self.raw[0] }
    fn code(&self) -> u8  { self.raw[1] }
    fn id(&self)   -> u16 { u16::from_be_bytes([self.raw[4], self.raw[5]]) }
    fn seq(&self)  -> u16 { u16::from_be_bytes([self.raw[6], self.raw[7]]) }
    fn type_name(&self) -> &'static str {
        match self.typ() {
            0  => "Echo Reply",
            3  => "Dest Unreachable",
            5  => "Redirect",
            8  => "Echo Request",
            11 => "Time Exceeded",
            _  => "Other",
        }
    }
}

// ─── PCAP writer ─────────────────────────────────────────────────────────────

struct PcapWriter {
    file: File,
}

impl PcapWriter {
    fn new(path: &str) -> io::Result<Self> {
        let mut f = File::create(path)?;
        // Global header libpcap
        // magic, version_major, version_minor, thiszone, sigfigs, snaplen, network(1=Ethernet)
        let hdr: [u8; 24] = [
            0xd4, 0xc3, 0xb2, 0xa1, // magic LE
            0x02, 0x00,              // major
            0x04, 0x00,              // minor
            0x00, 0x00, 0x00, 0x00, // thiszone
            0x00, 0x00, 0x00, 0x00, // sigfigs
            0xff, 0xff, 0x00, 0x00, // snaplen 65535
            0x01, 0x00, 0x00, 0x00, // linktype = LINKTYPE_ETHERNET
        ];
        f.write_all(&hdr)?;
        Ok(PcapWriter { file: f })
    }

    fn write_packet(&mut self, data: &[u8]) -> io::Result<()> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let ts_sec  = ts.as_secs() as u32;
        let ts_usec = ts.subsec_micros();
        let len     = data.len() as u32;

        let mut rec = Vec::with_capacity(16 + data.len());
        rec.extend_from_slice(&ts_sec.to_le_bytes());
        rec.extend_from_slice(&ts_usec.to_le_bytes());
        rec.extend_from_slice(&len.to_le_bytes());
        rec.extend_from_slice(&len.to_le_bytes());
        rec.extend_from_slice(data);
        self.file.write_all(&rec)
    }
}

// ─── Filtro simple ────────────────────────────────────────────────────────────

#[derive(Default, Debug)]
struct Filter {
    proto:    Option<String>, // tcp / udp / icmp / arp
    host:     Option<Ipv4Addr>,
    src_host: Option<Ipv4Addr>,
    dst_host: Option<Ipv4Addr>,
    port:     Option<u16>,
}

fn parse_filter(s: &str) -> Filter {
    let mut f = Filter::default();
    let tokens: Vec<&str> = s.split_whitespace().collect();
    let mut i = 0;
    while i < tokens.len() {
        match tokens[i] {
            "tcp"  | "udp" | "icmp" | "arp" => f.proto = Some(tokens[i].into()),
            "host" if i + 1 < tokens.len() => {
                f.host = tokens[i+1].parse().ok(); i += 1;
            }
            "src" if i + 1 < tokens.len() => {
                f.src_host = tokens[i+1].parse().ok(); i += 1;
            }
            "dst" if i + 1 < tokens.len() => {
                f.dst_host = tokens[i+1].parse().ok(); i += 1;
            }
            "port" if i + 1 < tokens.len() => {
                f.port = tokens[i+1].parse().ok(); i += 1;
            }
            _ => {}
        }
        i += 1;
    }
    f
}

fn apply_filter_eth(filter: &Filter, frame: &EthFrame, ip4: Option<&Ipv4Hdr>) -> bool {
    // Filtro de protocolo
    if let Some(ref p) = filter.proto {
        match p.as_str() {
            "arp" => {
                if frame.ether_type() != EtherType::Arp { return false; }
            }
            "tcp" | "udp" | "icmp" => {
                match frame.ether_type() {
                    EtherType::Ipv4 => {
                        if let Some(ip) = ip4 {
                            let ok = match p.as_str() {
                                "tcp"  => ip.proto() == 6,
                                "udp"  => ip.proto() == 17,
                                "icmp" => ip.proto() == 1,
                                _      => true,
                            };
                            if !ok { return false; }
                        } else { return false; }
                    }
                    _ => return false,
                }
            }
            _ => {}
        }
    }

    // Filtro de host / src / dst
    if let Some(ip) = ip4 {
        if let Some(h) = filter.host {
            if ip.src() != h && ip.dst() != h { return false; }
        }
        if let Some(h) = filter.src_host {
            if ip.src() != h { return false; }
        }
        if let Some(h) = filter.dst_host {
            if ip.dst() != h { return false; }
        }
        // Filtro de puerto
        if let Some(port) = filter.port {
            let payload = ip.payload();
            let ok = match ip.proto() {
                6 => TcpHdr::new(payload).map(|t| t.src_port() == port || t.dst_port() == port).unwrap_or(false),
                17 => UdpHdr::new(payload).map(|u| u.src_port() == port || u.dst_port() == port).unwrap_or(false),
                _ => false,
            };
            if !ok { return false; }
        }
    }

    true
}

// ─── Utilidades ───────────────────────────────────────────────────────────────

fn now_str() -> String {
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let s = ts.as_secs();
    let ms = ts.subsec_millis();
    format!("{:02}:{:02}:{:02}.{:03}", (s % 86400) / 3600, (s % 3600) / 60, s % 60, ms)
}

fn hex_dump(data: &[u8], max: usize) {
    let data = &data[..data.len().min(max)];
    let mut i = 0;
    while i < data.len() {
        let end = (i + 16).min(data.len());
        let chunk = &data[i..end];
        print!("  {:04x}  ", i);
        for (j, b) in chunk.iter().enumerate() {
            if j == 8 { print!(" "); }
            print!("{:02x} ", b);
        }
        let pad = 16 - chunk.len();
        for j in 0..pad { if (chunk.len()+j)==8 { print!(" "); } print!("   "); }
        print!(" |");
        for b in chunk { print!("{}", if *b >= 0x20 && *b < 0x7f { *b as char } else { '.' }); }
        println!("|");
        i += 16;
    }
    if data.len() == max { println!("  ... (truncado a {} bytes)", max); }
}

fn port_name(p: u16) -> &'static str {
    match p {
        21 => "FTP", 22 => "SSH", 23 => "Telnet", 25 => "SMTP",
        53 => "DNS", 67|68 => "DHCP", 80 => "HTTP", 110 => "POP3",
        143 => "IMAP", 443 => "HTTPS", 445 => "SMB", 3306 => "MySQL",
        3389 => "RDP", 5432 => "PG", 6379 => "Redis", 8080 => "HTTP-alt",
        _ => "",
    }
}

fn port_label(p: u16) -> String {
    let n = port_name(p);
    if n.is_empty() { p.to_string() } else { format!("{}/{}", p, n) }
}

// ─── Estadísticas ─────────────────────────────────────────────────────────────

#[derive(Default)]
struct Stats {
    total: u64,
    per_proto: HashMap<String, u64>,
    bytes_total: u64,
}

impl Stats {
    fn record(&mut self, proto: &str, bytes: usize) {
        self.total += 1;
        self.bytes_total += bytes as u64;
        *self.per_proto.entry(proto.into()).or_insert(0) += 1;
    }
    fn print(&self) {
        println!("\n{}", "═".repeat(60));
        println!("  ESTADÍSTICAS FINALES");
        println!("{}", "═".repeat(60));
        println!("  Total paquetes : {}", self.total);
        println!("  Total bytes    : {}", self.bytes_total);
        println!("  Por protocolo:");
        let mut sorted: Vec<_> = self.per_proto.iter().collect();
        sorted.sort_by_key(|(_, v)| std::cmp::Reverse(**v));
        for (proto, count) in sorted {
            println!("    {:<10} {:>8}  ({:.1}%)",
                proto, count,
                100.0 * *count as f64 / self.total.max(1) as f64
            );
        }
        println!("{}", "═".repeat(60));
    }
}

// ─── SIGINT ───────────────────────────────────────────────────────────────────

static STOP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
extern "C" fn sigint_handler(_: i32) {
    STOP.store(true, std::sync::atomic::Ordering::SeqCst);
}

// ─── Main ─────────────────────────────────────────────────────────────────────

fn main() -> io::Result<()> {
    let args = Args::parse();
    let filter = parse_filter(&args.filter);

    // Registrar SIGINT
    unsafe {
        extern "C" { fn signal(sig: i32, h: extern "C" fn(i32)) -> usize; }
        signal(2, sigint_handler);
    }

    // Crear socket AF_PACKET (L2, todos los protocolos Ethernet)
    // ETH_P_ALL debe ir en big-endian como protocolo
    let eth_p_all_be = (libc::ETH_P_ALL as u16).to_be() as i32;
    let sock = unsafe {
        libc::socket(libc::AF_PACKET, libc::SOCK_RAW, eth_p_all_be)
    };
    if sock < 0 {
        eprintln!("Error al abrir AF_PACKET socket: {}", io::Error::last_os_error());
        eprintln!("¿Ejecutando con sudo?");
        std::process::exit(1);
    }

    // PCAP writer opcional
    let mut pcap: Option<PcapWriter> = None;
    if let Some(ref path) = args.write {
        let w = PcapWriter::new(path)?;
        pcap = Some(w);
        if !args.quiet {
            println!("Escribiendo captura en: {}", path);
        }
    }

    if !args.quiet {
        println!("sniffer_rs — interfaz: {}  filtro: {:?}", args.iface, args.filter);
        println!("{}", "─".repeat(70));
    }

    let mut buf = vec![0u8; 65535];
    let mut stats = Stats::default();
    let mut pkt_num: u64 = 0;

    while !STOP.load(std::sync::atomic::Ordering::SeqCst) {
        if args.count > 0 && pkt_num >= args.count {
            break;
        }

        let n = unsafe {
            libc::recvfrom(
                sock,
                buf.as_mut_ptr() as *mut _,
                buf.len(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };

        if n <= 0 {
            if STOP.load(std::sync::atomic::Ordering::SeqCst) { break; }
            continue;
        }

        let n = n as usize;
        let raw = &buf[..n];

        let frame = match EthFrame::new(raw) {
            Some(f) => f,
            None => continue,
        };

        // Pre-parseo IPv4 para filtros
        let ip4_parsed: Option<Ipv4Hdr> = match frame.ether_type() {
            EtherType::Ipv4 => Ipv4Hdr::new(frame.payload()),
            _ => None,
        };

        // Aplicar filtro
        if !apply_filter_eth(&filter, &frame, ip4_parsed.as_ref()) {
            continue;
        }

        // Guardar en PCAP si corresponde
        if let Some(ref mut w) = pcap {
            let _ = w.write_packet(raw);
        }

        pkt_num += 1;

        if args.quiet { continue; }

        // ─── Disección y presentación ─────────────────────────────────────────

        let et = frame.ether_type();

        match et {
            EtherType::Arp => {
                if let Some(arp) = ArpPkt::new(frame.payload()) {
                    println!(
                        "[{}] #{:<5} ARP {}  {} ({}) → {} ({})",
                        now_str(), pkt_num,
                        arp.op_str(),
                        arp.sender_ip(), mac_str(&arp.sender_mac()),
                        arp.target_ip(), mac_str(&arp.target_mac()),
                    );
                    stats.record("ARP", n);
                }
            }

            EtherType::Ipv4 => {
                if let Some(ip) = ip4_parsed {
                    match ip.proto() {
                        6 => { // TCP
                            if let Some(tcp) = TcpHdr::new(ip.payload()) {
                                let app = if !port_name(tcp.dst_port()).is_empty() {
                                    port_name(tcp.dst_port())
                                } else { port_name(tcp.src_port()) };

                                println!(
                                    "[{}] #{:<5} TCP  {}:{} → {}:{}  [{}]  seq={} ack={}  win={}  {}bytes{}",
                                    now_str(), pkt_num,
                                    ip.src(), port_label(tcp.src_port()),
                                    ip.dst(), port_label(tcp.dst_port()),
                                    tcp.flags_str(),
                                    tcp.seq(), tcp.ack(),
                                    tcp.window(),
                                    n,
                                    if app.is_empty() { "".into() } else { format!("  [{}]", app) },
                                );
                                if args.verbose {
                                    println!("       Eth: {} → {}",
                                        mac_str(&frame.src_mac()), mac_str(&frame.dst_mac()));
                                    println!("       IP:  ttl={} id={:#06x} tos={:#04x}",
                                        ip.ttl(), ip.id(), ip.tos());
                                }
                                if args.hex && !tcp.payload().is_empty() {
                                    println!("       Payload ({} bytes):", tcp.payload().len());
                                    hex_dump(tcp.payload(), args.snaplen);
                                }
                                stats.record("TCP", n);
                            }
                        }
                        17 => { // UDP
                            if let Some(udp) = UdpHdr::new(ip.payload()) {
                                let app = if !port_name(udp.dst_port()).is_empty() {
                                    port_name(udp.dst_port())
                                } else { port_name(udp.src_port()) };

                                println!(
                                    "[{}] #{:<5} UDP  {}:{} → {}:{}  len={}{}",
                                    now_str(), pkt_num,
                                    ip.src(), port_label(udp.src_port()),
                                    ip.dst(), port_label(udp.dst_port()),
                                    udp.length(),
                                    if app.is_empty() { "".into() } else { format!("  [{}]", app) },
                                );
                                if args.verbose {
                                    println!("       Eth: {} → {}",
                                        mac_str(&frame.src_mac()), mac_str(&frame.dst_mac()));
                                    println!("       IP:  ttl={} id={:#06x}", ip.ttl(), ip.id());
                                }
                                if args.hex && !udp.payload().is_empty() {
                                    println!("       Payload ({} bytes):", udp.payload().len());
                                    hex_dump(udp.payload(), args.snaplen);
                                }
                                stats.record("UDP", n);
                            }
                        }
                        1 => { // ICMP
                            if let Some(icmp) = IcmpHdr::new(ip.payload()) {
                                println!(
                                    "[{}] #{:<5} ICMP {} → {}  type={} ({}) code={}  id={}  seq={}",
                                    now_str(), pkt_num,
                                    ip.src(), ip.dst(),
                                    icmp.typ(), icmp.type_name(), icmp.code(),
                                    icmp.id(), icmp.seq(),
                                );
                                if args.verbose {
                                    println!("       IP ttl={} id={:#06x}", ip.ttl(), ip.id());
                                }
                                stats.record("ICMP", n);
                            }
                        }
                        x => {
                            println!("[{}] #{:<5} IPv4 PROTO({}) {} → {}  len={}",
                                now_str(), pkt_num, x, ip.src(), ip.dst(), n);
                            stats.record(&format!("PROTO({})", x), n);
                        }
                    }
                }
            }

            EtherType::Ipv6 => {
                if let Some(ip6) = Ipv6Hdr::new(frame.payload()) {
                    let proto_name = match ip6.next_header() {
                        6  => "TCP",
                        17 => "UDP",
                        58 => "ICMPv6",
                        _  => "OTHER",
                    };
                    println!(
                        "[{}] #{:<5} IPv6/{} {} → {}  hop={}  paylen={}",
                        now_str(), pkt_num,
                        proto_name,
                        ip6.src(), ip6.dst(),
                        ip6.hop_limit(), ip6.payload_len(),
                    );
                    stats.record(&format!("IPv6/{}", proto_name), n);
                }
            }

            EtherType::Vlan => {
                println!("[{}] #{:<5} VLAN frame ({} bytes)", now_str(), pkt_num, n);
                stats.record("VLAN", n);
            }

            EtherType::Other(x) => {
                println!("[{}] #{:<5} ETH 0x{:04x} {} → {}  {} bytes",
                    now_str(), pkt_num,
                    x,
                    mac_str(&frame.src_mac()),
                    mac_str(&frame.dst_mac()),
                    n,
                );
                stats.record(&format!("ETH-0x{:04x}", x), n);
            }
        }
    }

    stats.print();
    unsafe { libc::close(sock) };
    Ok(())
}

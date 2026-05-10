use anyhow::{anyhow, Context, Result};
use clap::Parser;
use colored::*;
use ldap3::{Ldap, LdapConnAsync, LdapConnSettings, Scope, SearchEntry};
use std::collections::HashMap;

// ─── UAC Flags ───────────────────────────────────────────────────────────────
const UF_ACCOUNTDISABLE: u64                          = 0x0000_0002;
const UF_TRUSTED_FOR_DELEGATION: u64                  = 0x0008_0000; // Unconstrained
const UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION: u64  = 0x0100_0000; // Constrained w/ Protocol Transition

// ─── CLI ─────────────────────────────────────────────────────────────────────

/// find_delegation – enumerate Kerberos delegation in Active Directory.
///
/// Examples
///   find_delegation -d corp.local -u Administrator -p 'P@ss1' -H 192.168.1.1
///   find_delegation -d corp.local -u svc -H -nt aad3b4... (pass-the-hash)
///   find_delegation -d corp.local -u Administrator -p 'P@ss1' --disabled
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Target domain (e.g. corp.local)
    #[arg(short = 'd', long)]
    domain: String,

    /// Username
    #[arg(short = 'u', long)]
    username: String,

    /// Password (omit to prompt)
    #[arg(short = 'p', long, default_value = "")]
    password: String,

    /// DC IP or hostname (defaults to domain name)
    #[arg(short = 'H', long = "dc-ip")]
    dc_ip: Option<String>,

    /// NT hash for pass-the-hash (format: aabbcc…)
    #[arg(long = "nt")]
    nt_hash: Option<String>,

    /// Filter by specific sAMAccountName
    #[arg(long)]
    user: Option<String>,

    /// Include disabled accounts
    #[arg(long, default_value_t = false)]
    disabled: bool,

    /// Use LDAPS (port 636)
    #[arg(long, default_value_t = false)]
    ldaps: bool,

    /// Verbose / debug output
    #[arg(long, short = 'v', default_value_t = false)]
    verbose: bool,
}

// ─── Domain helpers ──────────────────────────────────────────────────────────

fn domain_to_base_dn(domain: &str) -> String {
    domain
        .split('.')
        .map(|part| format!("dc={}", part))
        .collect::<Vec<_>>()
        .join(",")
}

// ─── LDAP helpers ────────────────────────────────────────────────────────────

fn first_attr(entry: &SearchEntry, attr: &str) -> Option<String> {
    entry.attrs.get(attr)?.first().cloned()
}

fn all_attr(entry: &SearchEntry, attr: &str) -> Vec<String> {
    entry.attrs.get(attr).cloned().unwrap_or_default()
}

fn first_bin_attr(entry: &SearchEntry, attr: &str) -> Option<Vec<u8>> {
    entry.bin_attrs.get(attr)?.first().cloned()
}

async fn ldap_connect(args: &Args) -> Result<Ldap> {
    let host = args.dc_ip.as_deref().unwrap_or(&args.domain);
    let (scheme, port) = if args.ldaps {
        ("ldaps", 636u16)
    } else {
        ("ldap", 389u16)
    };
    let url = format!("{}://{}:{}", scheme, host, port);

    if args.verbose {
        eprintln!("[*] Connecting to {}", url);
    }

    let settings = LdapConnSettings::new();
    let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &url)
        .await
        .with_context(|| format!("Failed to connect to {}", url))?;

    // Drive the connection in the background
    ldap3::drive!(conn);

    // Build bind DN: DOMAIN\user or user@domain
    let bind_dn = format!("{}@{}", args.username, args.domain);

    let password = if args.password.is_empty() {
        rpassword_simple()
    } else {
        args.password.clone()
    };

    ldap.simple_bind(&bind_dn, &password)
        .await
        .context("LDAP bind failed")?
        .success()
        .context("LDAP bind returned non-success")?;

    if args.verbose {
        eprintln!("[*] Authenticated as {}", bind_dn);
    }

    Ok(ldap)
}

fn rpassword_simple() -> String {
    eprint!("Password: ");
    let mut pw = String::new();
    std::io::stdin().read_line(&mut pw).unwrap();
    pw.trim().to_string()
}

// ─── SID parsing (Windows binary SID → S-1-5-…) ────────────────────────────

fn parse_sid(data: &[u8]) -> Option<String> {
    if data.len() < 8 {
        return None;
    }
    let revision = data[0];
    let sub_count = data[1] as usize;
    if data.len() < 8 + sub_count * 4 {
        return None;
    }
    // Authority (6 bytes big-endian)
    let mut authority: u64 = 0;
    for &b in &data[2..8] {
        authority = (authority << 8) | b as u64;
    }
    let mut parts = vec![format!("S-{}-{}", revision, authority)];
    for i in 0..sub_count {
        let off = 8 + i * 4;
        let sub = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
        parts.push(sub.to_string());
    }
    Some(parts.join("-"))
}

// ─── Security Descriptor → list of SIDs in the DACL ─────────────────────────

/// Parse a self-relative Windows Security Descriptor and return the list of
/// trustee SIDs from the DACL ACEs. Handles the subset used by
/// msDS-AllowedToActOnBehalfOfOtherIdentity.
fn sids_from_security_descriptor(data: &[u8]) -> Vec<String> {
    // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7d4dac05-9cef-4563-a058-f108abecce1d
    if data.len() < 20 {
        return vec![];
    }
    // Offset 16: DACL offset (4 bytes LE)
    let dacl_off = u32::from_le_bytes([data[16], data[17], data[18], data[19]]) as usize;
    if dacl_off == 0 || dacl_off + 8 > data.len() {
        return vec![];
    }
    // ACL header: revision(1) sbz1(1) size(2) ace_count(2) sbz2(2)
    let ace_count = u16::from_le_bytes([data[dacl_off + 4], data[dacl_off + 5]]) as usize;
    let mut pos = dacl_off + 8;
    let mut sids = Vec::new();

    for _ in 0..ace_count {
        if pos + 4 > data.len() {
            break;
        }
        // ACE header: type(1) flags(1) size(2)
        let ace_size = u16::from_le_bytes([data[pos + 2], data[pos + 3]]) as usize;
        if ace_size < 4 || pos + ace_size > data.len() {
            break;
        }
        let ace_type = data[pos];
        // Access-allowed (0) and Access-allowed object (5) ACEs have SID after the mask
        if ace_type == 0x00 {
            // ACCESS_ALLOWED_ACE: header(4) + mask(4) + SID
            if let Some(sid) = parse_sid(&data[pos + 8..pos + ace_size]) {
                sids.push(sid);
            }
        } else if ace_type == 0x05 {
            // ACCESS_ALLOWED_OBJECT_ACE: header(4) + mask(4) + flags(4) + optional GUIDs + SID
            // We skip the optional GUIDs via flags
            if pos + 12 > data.len() {
                pos += ace_size;
                continue;
            }
            let obj_flags = u32::from_le_bytes([
                data[pos + 8],
                data[pos + 9],
                data[pos + 10],
                data[pos + 11],
            ]);
            let mut sid_off = pos + 12;
            if obj_flags & 0x1 != 0 {
                sid_off += 16; // ObjectType GUID
            }
            if obj_flags & 0x2 != 0 {
                sid_off += 16; // InheritedObjectType GUID
            }
            if sid_off < pos + ace_size {
                if let Some(sid) = parse_sid(&data[sid_off..pos + ace_size]) {
                    sids.push(sid);
                }
            }
        }
        pos += ace_size;
    }
    sids
}

// ─── SID → sAMAccountName lookup ─────────────────────────────────────────────

async fn resolve_sids(
    ldap: &mut Ldap,
    base_dn: &str,
    sids: &[String],
    include_disabled: bool,
    verbose: bool,
) -> Result<Vec<(String, String)>> {
    if sids.is_empty() {
        return Ok(vec![]);
    }

    let sid_filters: String = sids
        .iter()
        .map(|s| format!("(objectSid={})", s))
        .collect();

    let disabled_filter = if include_disabled {
        "(userAccountControl:1.2.840.113556.1.4.803:=2)"
    } else {
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
    };

    let filter = format!("(&(|{}){}))", sid_filters, disabled_filter);

    if verbose {
        eprintln!("[*] SID resolve filter: {}", filter);
    }

    let (rs, _res) = ldap
        .search(
            base_dn,
            Scope::Subtree,
            &filter,
            vec!["sAMAccountName", "objectCategory"],
        )
        .await?
        .success()?;

    let mut results = Vec::new();
    for entry in rs {
        let entry = SearchEntry::construct(entry);
        if let Some(sam) = first_attr(&entry, "sAMAccountName") {
            let obj_type = first_attr(&entry, "objectCategory")
                .and_then(|c| c.split('=').nth(1).map(|s| s.split(',').next().unwrap_or("").to_string()))
                .unwrap_or_else(|| "Unknown".to_string());
            results.push((sam, obj_type));
        }
    }
    Ok(results)
}

// ─── SPN existence check ─────────────────────────────────────────────────────

async fn spn_exists(ldap: &mut Ldap, base_dn: &str, sam: &str, rights: &str) -> Result<bool> {
    let filter = if rights == "N/A" {
        format!("(servicePrincipalName=HOST/{})", sam.trim_end_matches('$'))
    } else {
        format!("(servicePrincipalName={})", rights)
    };

    let (rs, _) = ldap
        .search(base_dn, Scope::Subtree, &filter, vec!["servicePrincipalName"])
        .await?
        .success()?;

    Ok(!rs.is_empty())
}

// ─── Delegation record ───────────────────────────────────────────────────────

#[derive(Debug)]
struct DelegationEntry {
    account_name: String,
    account_type: String,
    delegation_type: String,
    rights_to: String,
    spn_exists: String,
}

// ─── Core logic ──────────────────────────────────────────────────────────────

async fn find_delegation(args: &Args) -> Result<()> {
    let mut ldap = ldap_connect(args).await?;
    let base_dn = domain_to_base_dn(&args.domain);

    // Build the search filter
    // We look for:
    //   UAC bit 0x80000  → Unconstrained delegation
    //   UAC bit 0x1000000 → Constrained w/ Protocol Transition
    //   msDS-AllowedToDelegateTo presence → Constrained w/o Protocol Transition
    //   msDS-AllowedToActOnBehalfOfOtherIdentity presence → RBCD
    let disabled_filter = if args.disabled {
        "(userAccountControl:1.2.840.113556.1.4.803:=2)"
    } else {
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
    };

    let user_filter = if let Some(ref u) = args.user {
        format!("(sAMAccountName={})", u)
    } else {
        String::new()
    };

    let filter = format!(
        "(&(|{delegation_bits}(msDS-AllowedToDelegateTo=*)(msDS-AllowedToActOnBehalfOfOtherIdentity=*)){disabled}{user})",
        delegation_bits = "(userAccountControl:1.2.840.113556.1.4.803:=524288)(userAccountControl:1.2.840.113556.1.4.803:=16777216)",
        disabled = disabled_filter,
        user = user_filter,
    );

    if args.verbose {
        eprintln!("[*] Base DN: {}", base_dn);
        eprintln!("[*] LDAP filter: {}", filter);
    }

    let attrs = vec![
        "sAMAccountName",
        "userAccountControl",
        "objectCategory",
        "msDS-AllowedToDelegateTo",
        "msDS-AllowedToActOnBehalfOfOtherIdentity",
    ];

    let (rs, _res) = ldap
        .search(&base_dn, Scope::Subtree, &filter, attrs)
        .await
        .context("LDAP search failed")?
        .success()
        .context("LDAP search returned error")?;

    if args.verbose {
        eprintln!("[*] Raw entries returned: {}", rs.len());
    }

    let mut entries: Vec<DelegationEntry> = Vec::new();

    for raw in rs {
        let entry = SearchEntry::construct(raw);

        let sam = match first_attr(&entry, "sAMAccountName") {
            Some(s) => s,
            None => continue,
        };

        let uac: u64 = first_attr(&entry, "userAccountControl")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);

        let obj_type = first_attr(&entry, "objectCategory")
            .and_then(|c| {
                c.split('=')
                    .nth(1)
                    .map(|s| s.split(',').next().unwrap_or("").to_string())
            })
            .unwrap_or_else(|| "Unknown".to_string());

        // ── Unconstrained ────────────────────────────────────────────────────
        if uac & UF_TRUSTED_FOR_DELEGATION != 0 {
            let spn = spn_exists(&mut ldap, &base_dn, &sam, "N/A")
                .await
                .unwrap_or(false);
            entries.push(DelegationEntry {
                account_name: sam.clone(),
                account_type: obj_type.clone(),
                delegation_type: "Unconstrained".to_string(),
                rights_to: "N/A".to_string(),
                spn_exists: bool_to_yn(spn),
            });
            // Unconstrained and RBCD can coexist, so we don't skip RBCD check
        }

        // ── Constrained (with or without Protocol Transition) ─────────────
        let allowed_to: Vec<String> = all_attr(&entry, "msDS-AllowedToDelegateTo");
        if !allowed_to.is_empty() {
            let deleg_type = if uac & UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION != 0 {
                "Constrained w/ Protocol Transition"
            } else {
                "Constrained w/o Protocol Transition"
            };
            for right in &allowed_to {
                let spn = spn_exists(&mut ldap, &base_dn, &sam, right)
                    .await
                    .unwrap_or(false);
                entries.push(DelegationEntry {
                    account_name: sam.clone(),
                    account_type: obj_type.clone(),
                    delegation_type: deleg_type.to_string(),
                    rights_to: right.clone(),
                    spn_exists: bool_to_yn(spn),
                });
            }
        } else if uac & UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION != 0 {
            // Protocol transition flag set but no specific targets → show as-is
            let spn = spn_exists(&mut ldap, &base_dn, &sam, "N/A")
                .await
                .unwrap_or(false);
            entries.push(DelegationEntry {
                account_name: sam.clone(),
                account_type: obj_type.clone(),
                delegation_type: "Constrained w/ Protocol Transition".to_string(),
                rights_to: "N/A".to_string(),
                spn_exists: bool_to_yn(spn),
            });
        }

        // ── Resource-Based Constrained Delegation (RBCD) ──────────────────
        if let Some(sd_bytes) =
            first_bin_attr(&entry, "msDS-AllowedToActOnBehalfOfOtherIdentity")
        {
            let sids = sids_from_security_descriptor(&sd_bytes);
            if args.verbose {
                eprintln!("[*] RBCD SIDs for {}: {:?}", sam, sids);
            }
            let principals =
                resolve_sids(&mut ldap, &base_dn, &sids, args.disabled, args.verbose).await?;

            for (principal_sam, principal_type) in &principals {
                let spn = spn_exists(&mut ldap, &base_dn, &sam, principal_sam)
                    .await
                    .unwrap_or(false);
                entries.push(DelegationEntry {
                    account_name: principal_sam.clone(),
                    account_type: principal_type.clone(),
                    delegation_type: "Resource-Based Constrained".to_string(),
                    rights_to: sam.clone(),
                    spn_exists: bool_to_yn(spn),
                });
            }
        }
    }

    ldap.unbind().await.ok();

    // ── Print results ────────────────────────────────────────────────────────
    if entries.is_empty() {
        println!("{}", "No delegation relationships found.".yellow());
        return Ok(());
    }

    print_table(&entries);
    Ok(())
}

fn bool_to_yn(b: bool) -> String {
    if b { "Yes".to_string() } else { "No".to_string() }
}

// ─── Pretty-print table ───────────────────────────────────────────────────────

fn print_table(entries: &[DelegationEntry]) {
    let headers = ["AccountName", "AccountType", "DelegationType", "DelegationRightsTo", "SPN Exists"];

    // Column widths
    let mut widths = headers.map(|h| h.len());
    for e in entries {
        let row = [
            e.account_name.as_str(),
            e.account_type.as_str(),
            e.delegation_type.as_str(),
            e.rights_to.as_str(),
            e.spn_exists.as_str(),
        ];
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.len());
        }
    }

    // Header
    let header_line: String = headers
        .iter()
        .enumerate()
        .map(|(i, h)| format!("{:<width$}", h.bold().underline(), width = widths[i] + 2))
        .collect::<Vec<_>>()
        .join(" ");
    println!("\n{}", header_line);

    // Separator
    let sep: String = widths
        .iter()
        .map(|&w| "-".repeat(w + 2))
        .collect::<Vec<_>>()
        .join(" ");
    println!("{}", sep);

    // Rows
    for e in entries {
        let deleg_colored = match e.delegation_type.as_str() {
            "Unconstrained" => e.delegation_type.red().to_string(),
            s if s.starts_with("Constrained") => e.delegation_type.yellow().to_string(),
            _ => e.delegation_type.cyan().to_string(),
        };

        let spn_colored = if e.spn_exists == "Yes" {
            e.spn_exists.green().to_string()
        } else {
            e.spn_exists.normal().to_string()
        };

        // For color, we need to pad without ANSI codes messing up alignment.
        // So we pad the raw string and then colorize.
        println!(
            "{:<w0$}  {:<w1$}  {:<w2$}  {:<w3$}  {:<w4$}",
            e.account_name,
            e.account_type,
            deleg_colored,
            e.rights_to,
            spn_colored,
            w0 = widths[0],
            w1 = widths[1],
            w2 = widths[2] + 10, // padding for ANSI escape codes
            w3 = widths[3],
            w4 = widths[4] + 10,
        );
    }

    println!("\nTotal entries: {}", entries.len().to_string().bold());
}

// ─── Entry point ─────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let banner = r#"
  __ _           _   ____       _                 _   _             
 / _(_)_ __   __| | |  _ \  ___| | ___  __ _  __ _| |_(_) ___  _ __  
| |_| | '_ \ / _` | | | | |/ _ \ |/ _ \/ _` |/ _` | __| |/ _ \| '_ \ 
|  _| | | | | (_| | | |_| |  __/ |  __/ (_| | (_| | |_| | (_) | | | |
|_| |_|_| |_|\__,_| |____/ \___|_|\___|\__, |\__,_|\__|_|\___/|_| |_|
                                        |___/                          
  Kerberos Delegation Finder — Rust port of impacket/findDelegation.py
"#;

    println!("{}", banner.cyan());

    let args = Args::parse();

    if let Err(e) = find_delegation(&args).await {
        eprintln!("{} {}", "[ERROR]".red().bold(), e);
        std::process::exit(1);
    }
}

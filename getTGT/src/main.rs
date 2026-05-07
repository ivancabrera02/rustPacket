use anyhow::{anyhow, bail, Context, Result};
use ascii::AsciiString;
use clap::Parser;
use kerbeiros::TgtRequester;
use kerberos_crypto::Key;
use std::net::IpAddr;

// ─── CLI ────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "get_tgt",
    about = "Request a TGT and save it as ccache (Rust reimplementation of Impacket getTGT)"
)]
struct Args {
    /// [domain/]username[:password]
    #[arg(value_name = "identity")]
    identity: String,

    /// NTLM hashes in LMHASH:NTHASH format (LM can be empty)
    #[arg(short = 'H', long = "hashes")]
    hashes: Option<String>,

    /// AES key (128 or 256 bit hex)
    #[arg(short = 'a', long = "aesKey")]
    aes_key: Option<String>,

    /// IP address of the domain controller / KDC
    #[arg(short = 'd', long = "dc-ip")]
    dc_ip: Option<String>,

    /// Don't ask for password
    #[arg(long = "no-pass")]
    no_pass: bool,

    /// Output ccache file name (default: <username>.ccache)
    #[arg(short = 'o', long = "output")]
    output: Option<String>,

    /// Enable verbose/debug output
    #[arg(long = "debug")]
    debug: bool,
}

struct Identity {
    domain: String,
    username: String,
    password: Option<String>,
}

fn parse_identity(raw: &str) -> Result<Identity> {
    let (domain_user, password) = match raw.find(':') {
        Some(idx) => {
            let pwd = raw[idx + 1..].to_string();
            (
                &raw[..idx],
                if pwd.is_empty() { None } else { Some(pwd) },
            )
        }
        None => (raw, None),
    };

    let (domain, username) = match domain_user.find('/') {
        Some(idx) => (
            domain_user[..idx].to_string(),
            domain_user[idx + 1..].to_string(),
        ),
        None => (String::new(), domain_user.to_string()),
    };

    Ok(Identity {
        domain,
        username,
        password,
    })
}

fn resolve_key(args: &Args, identity: &Identity) -> Result<Key> {
    if let Some(ref aes_hex) = args.aes_key {
        let raw = hex::decode(aes_hex).context("Invalid AES key hex")?;
        match raw.len() {
            16 => Ok(Key::AES128Key(raw.try_into().unwrap())),
            32 => Ok(Key::AES256Key(raw.try_into().unwrap())),
            _ => bail!("AES key must be 16 bytes (128-bit) or 32 bytes (256-bit)"),
        }
    } else if let Some(ref hashes) = args.hashes {
        let parts: Vec<&str> = hashes.splitn(2, ':').collect();
        let nt_hex = if parts.len() == 2 { parts[1] } else { parts[0] };
        if nt_hex.is_empty() {
            bail!("NT hash cannot be empty in --hashes");
        }
        let nt_bytes = hex::decode(nt_hex).context("Invalid NT hash hex")?;
        if nt_bytes.len() != 16 {
            bail!("NT hash must be 16 bytes");
        }
        Ok(Key::RC4Key(nt_bytes.try_into().unwrap()))
    } else if let Some(ref pwd) = identity.password {

        let salt = format!("{}{}", identity.domain.to_uppercase(), identity.username);
        let cipher = kerberos_crypto::new_kerberos_cipher(
            kerberos_constants::etypes::AES256_CTS_HMAC_SHA1_96,
        )
        .map_err(|e| anyhow!("Cipher init: {}", e))?;
        let raw_key = cipher.generate_key_from_string(pwd, salt.as_bytes());
        let key_arr: [u8; 32] = raw_key
            .try_into()
            .map_err(|_| anyhow!("AES256 key derivation produced wrong length"))?;
        Ok(Key::AES256Key(key_arr))
    } else {
        bail!("No credentials. Supply password, --hashes, or --aesKey");
    }
}

fn key_type_name(key: &Key) -> &'static str {
    match key {
        Key::Secret(_) => "Password (deferred derivation)",
        Key::RC4Key(_) => "RC4-HMAC (NT hash)",
        Key::AES128Key(_) => "AES128-CTS-HMAC-SHA1-96",
        Key::AES256Key(_) => "AES256-CTS-HMAC-SHA1-96",
    }
}


fn run(args: Args) -> Result<()> {
    let mut identity = parse_identity(&args.identity)?;

    if identity.domain.is_empty() {
        bail!("Domain required. Use: DOMAIN/username[:password]");
    }

    if identity.password.is_none() && args.hashes.is_none() && args.aes_key.is_none() {
        if args.no_pass {
            bail!("No credentials and --no-pass specified");
        }
        let pwd = rpassword::prompt_password(format!("Password for {}: ", identity.username))
            .context("Failed to read password")?;
        identity.password = Some(pwd);
    }

    let user_key = resolve_key(&args, &identity)?;
    let domain = identity.domain.to_uppercase();
    let username = &identity.username;

    let kdc_ip: IpAddr = if let Some(ref ip_str) = args.dc_ip {
        ip_str
            .parse()
            .with_context(|| format!("Invalid DC IP: {}", ip_str))?
    } else {
        domain
            .parse()
            .map_err(|_| anyhow!(
                "Cannot resolve domain '{}' to IP. Use --dc-ip to specify the KDC address.",
                domain
            ))?
    };

    println!("[*] Target domain  : {}", domain);
    println!("[*] Username       : {}", username);
    println!("[*] KDC address    : {}", kdc_ip);
    println!("[*] Credential     : {}", key_type_name(&user_key));

    let realm = AsciiString::from_ascii(domain.clone())
        .map_err(|_| anyhow!("Domain '{}' contains non-ASCII characters", domain))?;
    let ascii_username = AsciiString::from_ascii(username.to_string())
        .map_err(|_| anyhow!("Username '{}' contains non-ASCII characters", username))?;

    println!("[*] Requesting TGT from KDC...");

    let tgt_requester = TgtRequester::new(realm, kdc_ip);

    let credential = tgt_requester
        .request(&ascii_username, Some(&user_key))
        .map_err(|e| anyhow!("TGT request failed: {:?}", e))?;

    println!("[+] Got TGT successfully!");

    let out_file = args
        .output
        .clone()
        .unwrap_or_else(|| format!("{}.ccache", username));

    if args.debug {
        let kirbi_file = format!(
            "{}.kirbi",
            out_file.strip_suffix(".ccache").unwrap_or(&out_file)
        );
        if let Err(e) = credential.clone().save_into_krb_cred_file(&kirbi_file) {
            eprintln!("[DEBUG] Could not save .kirbi: {:?}", e);
        } else {
            println!("[DEBUG] Also saved as: {}", kirbi_file);
        }
    }

    credential
        .save_into_ccache_file(&out_file)
        .map_err(|e| anyhow!("Failed to save ccache: {:?}", e))?;

    println!("[+] TGT saved to: {}", out_file);
    println!("[*] Export with  : export KRB5CCNAME={}", out_file);

    Ok(())
}

fn main() {
    let args = Args::parse();

    println!();
    println!("get_tgt v0.3.0 — Rust Kerberos TGT Requester");
    println!("Inspired by Impacket's getTGT.py");
    println!();

    if let Err(e) = run(args) {
        eprintln!("[-] Error: {:#}", e);
        std::process::exit(1);
    }
}

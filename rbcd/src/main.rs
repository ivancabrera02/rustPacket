mod ldap_client;
mod ntlm;
mod logging;
mod rbcd;
mod security;

use anyhow::{anyhow, bail, Result};
use ldap_client::{AuthMethod, ConnConfig};
use logging::log_debug;



fn print_banner() {
    println!("  rbcd — Rust  | Inspired by impacket rbcd.py\n");
}


#[derive(Debug, Default)]
struct Args {
     
    identity: Option<String>,

    delegate_to: Option<String>,

    delegate_from: Option<String>,
    action: Option<String>,   // read | write | remove | flush  (default: read)
    use_ldaps: bool,
    ts: bool,
    debug: bool,

    hashes: Option<String>,   // LMHASH:NTHASH
    no_pass: bool,
    kerberos: bool,
    aes_key: Option<String>,

    dc_ip: Option<String>,
    dc_host: Option<String>,
}

fn usage() -> String {
    format!(
        r#"usage: rbcd [-h] -delegate-to DELEGATE_TO [-delegate-from DELEGATE_FROM]
            [-action {{read,write,remove,flush}}] [-use-ldaps] [-debug] [-ts]
            [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key]
            [-dc-ip ip address] [-dc-host hostname]
            identity


positional arguments:
  identity              domain.local/username[:password]

options:
  -h, --help            show this help message and exit
  -delegate-to DELEGATE_TO
                        Target account the DACL is to be read/edited/etc.
  -delegate-from DELEGATE_FROM
                        Attacker controlled account to write on the rbcd
                        property of -delegate-to (only when using -action write)
  -action {{read,write,remove,flush}}
  -use-ldaps            Use LDAPS instead of LDAP
  -ts                   Adds timestamp to every logging output
  -debug                Turn DEBUG output ON

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME) based on target parameters.
                        If valid credentials cannot be found, it will use the
                        ones specified in the command line
  -aesKey hex key       AES key to use for Kerberos Authentication
                        (128 or 256 bits)

connection:
  -dc-ip ip address     IP Address of the domain controller or KDC. If
                        omitted it will use the domain part (FQDN) specified
                        in the identity parameter
  -dc-host hostname     Hostname of the domain controller or KDC. If omitted,
                        -dc-ip will be used

examples:
  rbcd CORP/alice:Password1 -delegate-to VICTIM$ -dc-ip 10.0.0.1
  rbcd CORP/alice -delegate-to VICTIM$ -delegate-from ATTACKER$ -action write -dc-ip 10.0.0.1
  rbcd CORP/alice -delegate-to VICTIM$ -delegate-from ATTACKER$ -action remove -dc-ip 10.0.0.1
  rbcd CORP/alice -delegate-to VICTIM$ -action flush -dc-ip 10.0.0.1
  rbcd CORP/alice -delegate-to VICTIM$ -k -no-pass -dc-ip 10.0.0.1"#
    )
}

fn parse_args(argv: &[String]) -> Result<Args> {
    let mut args = Args::default();
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
        // Strip leading dashes — accept both "-flag" and "--flag"
        let flag = tok.trim_start_matches('-');

        match flag {
            "h" | "help" => {
                print_banner();
                println!("{}", usage());
                std::process::exit(0);
            }
            "delegate-to" => args.delegate_to = Some(next_val!("-delegate-to")),
            "delegate-from" => args.delegate_from = Some(next_val!("-delegate-from")),
            "action" => args.action = Some(next_val!("-action")),
            "use-ldaps" => args.use_ldaps = true,
            "ts" => args.ts = true,
            "debug" => args.debug = true,
            "hashes" => args.hashes = Some(next_val!("-hashes")),
            "no-pass" => args.no_pass = true,
            "k" => args.kerberos = true,
            "aesKey" | "aes-key" | "aeskey" => args.aes_key = Some(next_val!("-aesKey")),
            "dc-ip" => args.dc_ip = Some(next_val!("-dc-ip")),
            "dc-host" => args.dc_host = Some(next_val!("-dc-host")),
            _ if !tok.starts_with('-') => {
                // Positional argument
                if args.identity.is_none() {
                    args.identity = Some(tok.clone());
                } else {
                    bail!("Unexpected positional argument: {tok}");
                }
            }
            _ => bail!("Unknown flag: {tok}"),
        }

        i += 1;
    }

    Ok(args)
}


struct Identity {
    domain: String,
    username: String,
    password: Option<String>,
}

fn parse_identity(s: &str) -> Result<Identity> {
    let (domain, rest) = s.split_once('/')
        .ok_or_else(|| anyhow!("Identity must be DOMAIN/username[:password], got: {s}"))?;
    if domain.is_empty() {
        bail!("Domain part of identity is empty");
    }

    let (username, password) = match rest.split_once(':') {
        Some((u, p)) => (u, Some(p.to_string())),
        None         => (rest, None),
    };

    if username.is_empty() {
        bail!("Username part of identity is empty");
    }

    Ok(Identity {
        domain: domain.to_string(),
        username: username.to_string(),
        password,
    })
}


fn parse_hashes(s: &str) -> Result<(String, String)> {
    let (lm, nt) = s.split_once(':')
        .ok_or_else(|| anyhow!("-hashes must be in LMHASH:NTHASH format, got: {s}"))?;
    Ok((lm.to_string(), nt.to_string()))
}


#[tokio::main]
async fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();

    if argv.is_empty() {
        print_banner();
        eprintln!("{}", usage());
        std::process::exit(1);
    }

    if let Err(e) = run(argv).await {
        eprintln!("[-] {:#}", e);
        std::process::exit(1);
    }
}

async fn run(argv: Vec<String>) -> Result<()> {
    print_banner();

    let args = parse_args(&argv)?;


    let identity_str = args.identity
        .as_deref()
        .ok_or_else(|| anyhow!("the following arguments are required: identity"))?;

    let delegate_to = args.delegate_to
        .as_deref()
        .ok_or_else(|| anyhow!("the following arguments are required: -delegate-to"))?;

    let action = args.action.as_deref().unwrap_or("read");
    match action {
        "read" | "write" | "remove" | "flush" => {}
        other => bail!("invalid -action value '{other}': must be read, write, remove, or flush"),
    }

    if (action == "write" || action == "remove") && args.delegate_from.is_none() {
        bail!("`-delegate-from` should be specified when using `-action {action}` !");
    }


    let mut identity = parse_identity(identity_str)?;


    let auth = if args.kerberos {
        AuthMethod::Kerberos { aes_key: args.aes_key.clone() }
    } else if let Some(ref hashes) = args.hashes {
        let (lm, nt) = parse_hashes(hashes)?;
        AuthMethod::NtlmHash { lm_hash: lm, nt_hash: nt }
    } else {
        // Password auth
        if !args.no_pass && identity.password.is_none() {
            // Prompt exactly like impacket does
            let prompt = format!("Password for {}/{}: ", identity.domain, identity.username);
            let pw = rpassword::prompt_password(prompt)
                .map_err(|e| anyhow!("Failed to read password: {e}"))?;
            identity.password = Some(pw);
        }
        AuthMethod::Password(identity.password.clone().unwrap_or_default())
    };

    let host = args.dc_host
        .as_deref()
        .or(args.dc_ip.as_deref())
        .unwrap_or(&identity.domain)
        .to_string();

    let port: u16 = if args.use_ldaps { 636 } else { 389 };


    let cfg = ConnConfig {
        host: host.clone(),
        port,
        use_ldaps: args.use_ldaps,
        domain: identity.domain.clone(),
        username: identity.username.clone(),
        auth,
        debug: args.debug,
    };

    if args.debug {
        log_debug(&format!("Connecting to {:?}", cfg), args.ts);
    }


    let mut client = ldap_client::LdapClient::connect(&cfg).await?;

    let base_dn = client.get_default_naming_context().await?;

    if args.debug {
        log_debug(&format!("Base DN: {base_dn}"), args.ts);
    }


    match action {
        "read" => {
            rbcd::action_read(&mut client, &base_dn, delegate_to, args.ts).await?;
        }
        "write" => {
            let from = args.delegate_from.as_deref().unwrap();
            rbcd::action_write(&mut client, &base_dn, delegate_to, from, args.ts).await?;
        }
        "remove" => {
            let from = args.delegate_from.as_deref().unwrap();
            rbcd::action_remove(&mut client, &base_dn, delegate_to, from, args.ts).await?;
        }
        "flush" => {
            rbcd::action_flush(&mut client, &base_dn, delegate_to, args.ts).await?;
        }
        _ => unreachable!(),
    }

    Ok(())
}


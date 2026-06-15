#![allow(non_snake_case)]

mod controller;
mod error;
mod ntlm;
mod service;
mod smb2;
mod svcctl;
mod util;

use std::io::Write;
use clap::{Parser, CommandFactory};




fn print_banner() {
    println!("\npsexec — Rust  | Inspired by impacket psexec.py\n");
}

fn preprocess_args() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut past_separator = false;

    for arg in std::env::args() {
        if past_separator {
            out.push(arg);
            continue;
        }
        if arg == "--" {
            past_separator = true;
            out.push(arg);
            continue;
        }
        // Single-dash + more than one character → make it double-dash
        if arg.starts_with('-') && !arg.starts_with("--") {
            let body = &arg[1..];
            if body.len() > 1 && !body.starts_with('-') {
                out.push(format!("--{}", body));
                continue;
            }
        }
        out.push(arg);
    }
    out
}



#[derive(Parser, Debug)]
#[command(
    name    = "psexec",
    version = "0.1.0",
    // Override the default usage line to show the impacket-style target format
    override_usage = "psexec [[domain/]username[:password]@]<target> [command ...]\n\
                      \n       psexec -h | --help"
)]
pub struct Cli {

    /// [[domain/]username[:password]@]<targetName or address>
    #[arg(value_name = "target")]
    pub raw_target: Option<String>,

    /// command (and arguments) to execute at the target  [default: cmd.exe]
    #[arg(
        value_name = "command",
        trailing_var_arg = true,
        allow_hyphen_values = true,
        num_args = 0..,
    )]
    pub command: Vec<String>,


    /// copy this local binary to the target and use it as the service executable
    #[arg(long, short = 'c', value_name = "pathname")]
    pub c: Option<String>,

    /// path on the target where the service binary will be placed
    #[arg(long, value_name = "path")]
    pub path: Option<String>,

    /// alternative RemCom-compatible binary (must not require CRT)
    #[arg(long, value_name = "filename")]
    pub file: Option<String>,


    /// add timestamp to every log line
    #[arg(long)]
    pub ts: bool,

    /// turn DEBUG output on
    #[arg(long)]
    pub debug: bool,

    /// output encoding from the target (default: UTF-8)
    #[arg(long, value_name = "codec")]
    pub codec: Option<String>,


    /// NTLM hashes — format is LMHASH:NTHASH
    #[arg(long, value_name = "LMHASH:NTHASH")]
    pub hashes: Option<String>,

    /// don't ask for password (useful when relaying through ntlmrelayx)
    #[arg(long)]
    pub no_pass: bool,

    /// use Kerberos authentication  [not yet implemented]
    #[arg(short = 'k', long = "k")]
    pub kerberos: bool,

    /// AES key for Kerberos (128 or 256 bits)  [not yet implemented]
    #[arg(long = "aesKey", value_name = "hex key")]
    pub aes_key: Option<String>,

    /// read Kerberos keys from keytab file  [not yet implemented]
    #[arg(long, value_name = "keytab")]
    pub keytab: Option<String>,


    /// IP address of the domain controller
    #[arg(long, value_name = "ip address")]
    pub dc_ip: Option<String>,

    /// IP address of the target machine (when target is a NetBIOS name)
    #[arg(long, value_name = "ip address")]
    pub target_ip: Option<String>,

    /// destination SMB port
    #[arg(long, value_name = "destination port", default_value = "445")]
    pub port: u16,


    /// name of the Windows service used to trigger the payload
    #[arg(long, value_name = "service_name")]
    pub service_name: Option<String>,

    /// name of the executable uploaded to the target
    #[arg(long, value_name = "remote_binary_name")]
    pub remote_binary_name: Option<String>,


    /// administrative share to upload the service binary into
    #[arg(long, value_name = "share", default_value = "ADMIN$")]
    pub share: String,


    /// running as a Windows service on the target  [internal — do not use]
    #[arg(long, hide = true)]
    pub service: bool,

    /// service name registered with SCM              [internal — do not use]
    #[arg(long, hide = true)]
    pub svc_name: Option<String>,
}


#[derive(Debug)]
pub struct TargetInfo {
    pub domain:   String,
    pub username: String,
    pub password: Option<String>, 
    pub host:     String,         
}

/// Parse [[domain/]username[:password]@]<host> into its components
fn parse_target(raw: &str) -> TargetInfo {
    let (auth_part, host_part) = if let Some(at) = raw.rfind('@') {
        (&raw[..at], &raw[at + 1..])
    } else {
        ("", raw)
    };

    let (domain, userpass) = if let Some(sl) = auth_part.find('/') {
        (&auth_part[..sl], &auth_part[sl + 1..])
    } else {
        ("", auth_part)
    };

    let (username, password) = if let Some(col) = userpass.find(':') {
        (&userpass[..col], Some(userpass[col + 1..].to_string()))
    } else {
        (userpass, None)
    };

    TargetInfo {
        domain:   domain.to_string(),
        username: username.to_string(),
        password,
        host:     host_part.to_string(),
    }
}


fn prompt_password(username: &str, domain: &str, host: &str) -> String {
    use windows_sys::Win32::System::Console::*;
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;

    let label = if domain.is_empty() {
        format!("Password for {}@{}: ", username, host)
    } else {
        format!("Password for {}/{}@{}: ", domain, username, host)
    };

    let _ = std::io::stderr().write_all(label.as_bytes());
    let _ = std::io::stderr().flush();

    unsafe {
        let stdin = GetStdHandle(STD_INPUT_HANDLE);
        let can_echo = stdin != INVALID_HANDLE_VALUE && stdin != 0;
        let mut old_mode = 0u32;

        if can_echo {
            GetConsoleMode(stdin, &mut old_mode);
            SetConsoleMode(stdin, old_mode & !ENABLE_ECHO_INPUT);
        }

        let mut pass = String::new();
        let _ = std::io::stdin().read_line(&mut pass);
        let _ = std::io::stderr().write_all(b"\n");

        if can_echo {
            SetConsoleMode(stdin, old_mode);
        }

        pass.trim().to_string()
    }
}


fn main() {

    print_banner();

    let cli = Cli::parse_from(preprocess_args());

    if cli.service {
        let svc_name = cli.svc_name.unwrap_or_else(|| "rustexec".to_string());
        service::run(svc_name);
        return;
    }

    let raw = match &cli.raw_target {
        Some(t) => t.clone(),
        None => {
            Cli::command().print_help().ok();
            eprintln!();
            std::process::exit(1);
        }
    };

    let ti = parse_target(&raw);

    // Warn about unimplemented options
    if cli.kerberos || cli.aes_key.is_some() || cli.keytab.is_some() {
        eprintln!("[!] -k / -aesKey / -keytab: Kerberos is not yet implemented; using NTLM.");
    }

    let host = cli.target_ip.as_deref().unwrap_or(&ti.host).to_string();

    let command = if cli.command.is_empty() {
        "cmd.exe".to_string()
    } else {
        cli.command.join(" ")
    };

    // Determine binary to upload 
    let custom_binary: Option<String> = cli.c.clone();

    // Determine password — skip prompt when --hashes or --no-pass is used
    let password: Option<String> = if cli.no_pass || cli.hashes.is_some() {
        None
    } else if ti.password.is_none() && !ti.username.is_empty() {
        Some(prompt_password(&ti.username, &ti.domain, &host))
    } else {
        ti.password.clone()
    };

    if cli.debug {
        eprintln!("[DEBUG] target     = {}", host);
        eprintln!("[DEBUG] domain     = {}", ti.domain);
        eprintln!("[DEBUG] username   = {}", ti.username);
        eprintln!("[DEBUG] command    = {}", command);
        eprintln!("[DEBUG] share      = {}", cli.share);
        eprintln!("[DEBUG] port       = {}", cli.port);
        if let Some(ref sn) = cli.service_name       { eprintln!("[DEBUG] svc-name   = {}", sn); }
        if let Some(ref bn) = cli.remote_binary_name { eprintln!("[DEBUG] bin-name   = {}", bn); }
    }

    if let Err(e) = controller::run(controller::RunOptions {
        target:              host,
        port:                cli.port,
        username:            if ti.username.is_empty() { None } else { Some(ti.username) },
        password,
        hashes:              cli.hashes,
        domain:              ti.domain,
        command,
        share:               cli.share,
        custom_binary,
        service_name:        cli.service_name,
        remote_binary_name:  cli.remote_binary_name,
        path_override:       cli.path,
        debug:               cli.debug,
        ts:                  cli.ts,
    }) {
        eprintln!("[!] Fatal: {}", e);
        std::process::exit(1);
    }
}

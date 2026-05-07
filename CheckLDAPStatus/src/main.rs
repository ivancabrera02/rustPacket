use clap::Parser;
use ldap3::{LdapConnAsync, LdapError};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts, NameServerConfig, Protocol};
use trust_dns_resolver::TokioAsyncResolver;
use std::error::Error;

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long)]
    domain: String,
    #[arg(long)]
    dc_ip: String,
}

async fn get_dc_list(domain: &str, dns_server: &str) -> Vec<String> {
    let mut config = ResolverConfig::new();
    
    config.add_name_server(NameServerConfig {
        socket_addr: format!("{}:53", dns_server).parse().unwrap(),
        protocol: Protocol::Udp,
        tls_dns_name: None,
        trust_negative_responses: false, 
        bind_addr: None,
    });

    let resolver = TokioAsyncResolver::tokio(config, ResolverOpts::default());
    let query = format!("_ldap._tcp.dc._msdcs.{}", domain);
    
    match resolver.srv_lookup(query).await {
        Ok(srv) => srv.iter().map(|s| s.target().to_string().trim_end_matches('.').to_string()).collect(),
        Err(_) => vec![dns_server.to_string()],
    }
}

async fn check_signing(host: &str, domain: &str) -> String {
    let url = format!("ldap://{}:389", host);
    let (conn, mut ldap) = match LdapConnAsync::new(&url).await {
        Ok(c) => c,
        Err(_) => return "Conn Error".to_string(),
    };
    ldap3::drive!(conn);

    match ldap.simple_bind(&format!("invalid@{}", domain), "invalid").await {
        Err(LdapError::LdapResult { result: res }) if res.rc == 8 => {
            "Required (Enforced)".to_string()
        },
        Err(e) => {
            let err_str = format!("{:?}", e);
            if err_str.contains(" 8") || err_str.contains("strongerAuthRequired") { 
                "Required".to_string() 
            } else { 
                if err_str.contains("52e") {
                    "Not Required (Accepts Auth)".to_string()
                } else {
                    format!("Unknown error: {}", err_str)
                }
            }
        },
        _ => "Not Required".to_string(),
    }
}

fn res_code_from_err(err: &str) -> &str {
    if err.contains("52e") { "Invalid Creds" }
    else if err.contains("532") { "Password Expired" }
    else { "OK/Other" }
}

async fn check_cbt(host: &str, domain: &str) -> String {
    let url = format!("ldaps://{}:636", host);
    let (conn, mut ldap) = match LdapConnAsync::new(&url).await {
        Ok(c) => c,
        Err(e) => return format!("No LDAPS (SSL Error: {:?})", e),
    };
    ldap3::drive!(conn);

    match ldap.simple_bind(&format!("invalid@{}", domain), "invalid").await {
        Err(e) => {
            let err_msg = format!("{:?}", e);
            if err_msg.contains("80090346") {
                "Always (Required)".to_string()
            } else if err_msg.contains("52e") {
                "Never / Optional (Accepted login attempt)".to_string()
            } else {
                format!("Unknown (Check Debug: {})", err_msg)
            }
        },
        _ => "Never (Insecure)".to_string(),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    println!("[*] CheckLDAPStatus Rust Edition");
    println!("[*] Solving DCs for: {}", args.domain);

    let dcs = get_dc_list(&args.domain, &args.dc_ip).await;
    println!("[+] Found {} DC(s)\n", dcs.len());

    for dc in dcs {
        println!("Hostname: {}", dc);
        let signing = check_signing(&dc, &args.domain).await;
        let cbt = check_cbt(&dc, &args.domain).await;
        
        println!("\t> LDAP Signing: {}", signing);
        println!("\t> LDAPS Channel Binding: {}\n", cbt);
    }

    Ok(())
}
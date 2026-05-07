use clap::Parser;
use ldap3::{LdapConnAsync, Scope, SearchEntry};
use std::error::Error;

#[derive(Parser, Debug)]
#[command(author, version, about = "Rust version of Impacket's GetADComputers", long_about = None)]
struct Args {
    /// Target IP or Hostname of the Domain Controller
    #[arg(short, long)]
    target: String,

    /// Domain (e.g., corp.local)
    #[arg(short, long)]
    domain: String,

    /// Username
    #[arg(short, long)]
    user: String,

    /// Password
    #[arg(short, long)]
    pass: String,

    /// Custom LDAP Filter for computers
    #[arg(short, long, default_value = "(sAMAccountType=805306369)")]
    filter: String,
}

fn domain_to_dn(domain: &str) -> String {
    domain.split('.')
        .map(|s| format!("DC={}", s))
        .collect::<Vec<String>>()
        .join(",")
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let ldap_url = format!("ldap://{}:389", args.target);
    let base_dn = domain_to_dn(&args.domain);
    let bind_dn = format!("{}@{}", args.user, args.domain);

    println!("[*] Connecting to {}...", ldap_url);

    let (conn, mut ldap) = LdapConnAsync::new(&ldap_url).await?;
    ldap3::drive!(conn);

    println!("[*] Authenticating as {}...", bind_dn);
    match ldap.simple_bind(&bind_dn, &args.pass).await?.success() {
        Ok(_) => println!("[+] Successful authentication."),
        Err(e) => {
            eprintln!("[-] Authentication error: {:?}", e);
            return Ok(());
        }
    }

    println!("[*] Looking for computers in: {}\n", base_dn);

    let attributes = vec![
        "sAMAccountName", 
        "dNSHostName", 
        "operatingSystem", 
        "operatingSystemVersion",
        "distinguishedName"
    ];

    let (rs, _res) = ldap.search(
        &base_dn,
        Scope::Subtree,
        &args.filter,
        attributes
    ).await?.success()?;

    println!("{:<20} | {:<25} | {:<20}", "Name", "DNS Hostname", "OS");
    println!("{}", "-".repeat(80));

    for entry in rs {
        let comp = SearchEntry::construct(entry);
        
        let name = comp.attrs.get("sAMAccountName")
            .and_then(|v| v.first()).cloned().unwrap_or_else(|| "N/A".to_string());
            
        let dns = comp.attrs.get("dNSHostName")
            .and_then(|v| v.first()).cloned().unwrap_or_else(|| "N/A".to_string());
            
        let os = comp.attrs.get("operatingSystem")
            .and_then(|v| v.first()).cloned().unwrap_or_else(|| "Unknown".to_string());

        println!("{:<20} | {:<25} | {:<20}", name, dns, os);
    }

    ldap.unbind().await?;
    Ok(())
}
use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use red_asn1::Asn1Object;
use tracing::{debug, info};

use kerberos_asn1::{
    ApReq, AsRep, AsReq, Authenticator, EncAsRepPart, EncTicketPart,
    EncryptedData as KrbEncryptedData, KdcReqBody, PaData,
    PrincipalName, TgsRep, TgsReq, Ticket,
};
use kerberos_constants::etypes::*;
use kerberos_constants::principal_names::*;
use kerberos_crypto::new_kerberos_cipher;

mod krb;
mod pac;

// ─── CLI ───────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "getpac",
    about = "Retrieve the PAC of a target user via S4U2Self + U2U (Rust)",
    long_about = "Similar to impacket's getPac.py. Uses S4U2Self combined with \
                  User-to-User Kerberos authentication to obtain and decode the \
                  PAC of a specified target user, given valid domain credentials."
)]
struct Cli {
    /// Domain name (e.g. CONTOSO.LOCAL)
    #[arg(short, long)]
    domain: String,

    /// Username for authentication
    #[arg(short, long)]
    username: String,

    /// Password (omit if using --hashes)
    #[arg(short, long, default_value = "")]
    password: String,

    /// Target user whose PAC to retrieve
    #[arg(short = 't', long)]
    target_user: String,

    /// NTLM hashes in LMHASH:NTHASH format
    #[arg(long)]
    hashes: Option<String>,

    /// KDC (Domain Controller) address. If omitted, DNS lookup is used.
    #[arg(short = 'k', long)]
    kdc: Option<String>,

    /// Enable verbose/debug output
    #[arg(long)]
    debug: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let filter = if cli.debug { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();


    let domain = cli.domain.to_uppercase();
    let (_lm_hash, nt_hash) = parse_hashes(&cli.hashes)?;

    let kdc_addr = match &cli.kdc {
        Some(addr) => addr.clone(),
        None => resolve_kdc(&domain)?,
    };

    // Step 1: Get TGT
    let tgt_result =
        get_tgt(&kdc_addr, &domain, &cli.username, &cli.password, &nt_hash)?;

    // Step 2: S4U2Self + U2U TGS-REQ
    let tgs_rep = send_s4u2self_u2u(
        &kdc_addr,
        &domain,
        &cli.username,
        &cli.target_user,
        &tgt_result,
    )?;

    let cipher = new_kerberos_cipher(tgt_result.etype)
        .map_err(|e| anyhow!("Unsupported etype {}: {:?}", tgt_result.etype, e))?;

    // S4USelf + U2U: ticket encrypted with TGT session key, key usage 2
    let plaintext = cipher
        .decrypt(
            &tgt_result.session_key,
            2,
            &tgs_rep.ticket.enc_part.cipher,
        )
        .map_err(|e| anyhow!("Ticket decryption failed: {:?}", e))?;

    debug!("Decrypted ticket: {} bytes", plaintext.len());

    let (_, enc_ticket) = EncTicketPart::parse(&plaintext)
        .map_err(|e| anyhow!("Failed to parse EncTicketPart: {:?}", e))?;

    // Walk authorization-data → AD-IF-RELEVANT(1) → AD-WIN2K-PAC(128)
    let auth_data = enc_ticket
        .authorization_data
        .ok_or_else(|| anyhow!("No authorization-data in ticket"))?;

    let mut pac_data: Option<Vec<u8>> = None;
    for ad_entry in &auth_data {
        if ad_entry.ad_type == 1 {
            if let Ok((_, inner_ads)) =
                <kerberos_asn1::AuthorizationData as Asn1Object>::parse(&ad_entry.ad_data)
            {
                for inner in &inner_ads {
                    if inner.ad_type == 128 {
                        pac_data = Some(inner.ad_data.clone());
                    }
                }
            }
        }
    }

    let pac_bytes = pac_data.ok_or_else(|| anyhow!("No PAC found in ticket"))?;

    println!();
    println!("================================================================");
    println!("  PAC Information for: {}", cli.target_user);
    println!("================================================================");
    println!();

    pac::parse_and_display_pac(&pac_bytes)?;

    info!("[+] Done!");
    Ok(())
}

// ─── HASH PARSING ──────────────────────────────────────────────────────

fn parse_hashes(hashes: &Option<String>) -> Result<(Vec<u8>, Vec<u8>)> {
    match hashes {
        Some(h) => {
            let parts: Vec<&str> = h.split(':').collect();
            if parts.len() != 2 {
                bail!("Hashes must be in LMHASH:NTHASH format");
            }
            let lm = hex::decode(parts[0]).context("Invalid LM hash hex")?;
            let nt = hex::decode(parts[1]).context("Invalid NT hash hex")?;
            Ok((lm, nt))
        }
        None => Ok((vec![], vec![])),
    }
}

// ─── KDC RESOLUTION ────────────────────────────────────────────────────

fn resolve_kdc(domain: &str) -> Result<String> {
    use dns_lookup::lookup_host;
    let ips = lookup_host(domain).context(format!(
        "Failed to resolve KDC for '{}'. Use --kdc to specify manually.",
        domain
    ))?;
    ips.into_iter()
        .next()
        .map(|ip| ip.to_string())
        .ok_or_else(|| anyhow!("No IP found for '{}'", domain))
}

// ─── TGT RESULT ────────────────────────────────────────────────────────

pub struct TgtResult {
    pub ticket: Ticket,
    pub session_key: Vec<u8>,
    pub etype: i32,
    pub crealm: String,
    pub cname: PrincipalName,
}

// ─── GET TGT (AS-REQ / AS-REP) ────────────────────────────────────────

fn get_tgt(
    kdc: &str,
    domain: &str,
    username: &str,
    password: &str,
    nt_hash: &[u8],
) -> Result<TgtResult> {
    let client_name = krb::make_principal_name(NT_PRINCIPAL, username);
    let server_name = krb::make_principal_name_2(NT_SRV_INST, "krbtgt", domain);

    let now = chrono::Utc::now();
    let till = now + chrono::Duration::hours(24);
    let nonce: u32 = rand::random();

    let etypes = vec![AES256_CTS_HMAC_SHA1_96, AES128_CTS_HMAC_SHA1_96, RC4_HMAC];

    let kdc_body = KdcReqBody {
        kdc_options: kerberos_asn1::KerberosFlags::from(
            krb::KDC_OPT_FORWARDABLE
                | krb::KDC_OPT_RENEWABLE
                | krb::KDC_OPT_CANONICALIZE,
        ),
        cname: Some(client_name.clone()),
        realm: domain.into(),
        sname: Some(server_name),
        from: None,
        till: krb::krb_time(till),
        rtime: Some(krb::krb_time(till)),
        nonce,
        etypes: etypes.clone(),
        addresses: None,
        enc_authorization_data: None,
        additional_tickets: None,
    };

    // First try without pre-auth
    let as_req = AsReq {
        pvno: 5,
        msg_type: 10,
        padata: None,
        req_body: kdc_body.clone(),
    };

    let reply = krb::send_krb_tcp(kdc, &as_req.build())?;

    // Check if we got AS-REP directly (no pre-auth required)
    if let Ok((_, as_rep)) = AsRep::parse(&reply) {
        return finish_as_rep(as_rep, password, domain, username, nt_hash);
    }

    // Parse KRB-ERROR to get etype
    let etype = krb::select_etype_from_error(&reply, &etypes)?;
    debug!("Selected etype {} for pre-auth", etype);

    let key = krb::derive_key(etype, password, domain, username, nt_hash)?;

    let cipher = new_kerberos_cipher(etype)
        .map_err(|e| anyhow!("Unsupported etype: {:?}", e))?;

    // Build PA-ENC-TIMESTAMP
    let timestamp = krb::build_pa_enc_timestamp(cipher.as_ref(), &key);

    let as_req2 = AsReq {
        pvno: 5,
        msg_type: 10,
        padata: Some(vec![PaData::new(
            kerberos_constants::pa_data_types::PA_ENC_TIMESTAMP,
            timestamp,
        )]),
        req_body: kdc_body,
    };

    let reply2 = krb::send_krb_tcp(kdc, &as_req2.build())?;

    let (_, as_rep) = AsRep::parse(&reply2).map_err(|e| {
        if let Ok((_, krb_err)) = kerberos_asn1::KrbError::parse(&reply2) {
            anyhow!(
                "KDC error code {}: {:?}",
                krb_err.error_code,
                krb_err.e_text
            )
        } else {
            anyhow!("Failed to parse AS-REP: {:?}", e)
        }
    })?;

    // Decrypt enc-part (key usage 3 for AS-REP)
    let dec = cipher
        .decrypt(&key, 3, &as_rep.enc_part.cipher)
        .map_err(|e| anyhow!("AS-REP decryption failed: {:?}", e))?;

    let (_, enc_part) = EncAsRepPart::parse(&dec)
        .map_err(|e| anyhow!("Failed to parse EncAsRepPart: {:?}", e))?;

    Ok(TgtResult {
        ticket: as_rep.ticket,
        session_key: enc_part.key.keyvalue.clone(),
        etype,
        crealm: as_rep.crealm.clone(),
        cname: as_rep.cname.clone(),
    })
}

fn finish_as_rep(
    as_rep: AsRep,
    password: &str,
    domain: &str,
    username: &str,
    nt_hash: &[u8],
) -> Result<TgtResult> {
    let etype = as_rep.enc_part.etype;
    let key = krb::derive_key(etype, password, domain, username, nt_hash)?;
    let cipher = new_kerberos_cipher(etype)
        .map_err(|e| anyhow!("Unsupported etype: {:?}", e))?;

    let dec = cipher
        .decrypt(&key, 3, &as_rep.enc_part.cipher)
        .map_err(|e| anyhow!("AS-REP decryption failed: {:?}", e))?;

    let (_, enc_part) = EncAsRepPart::parse(&dec)
        .map_err(|e| anyhow!("Failed to parse EncAsRepPart: {:?}", e))?;

    Ok(TgtResult {
        ticket: as_rep.ticket,
        session_key: enc_part.key.keyvalue.clone(),
        etype,
        crealm: as_rep.crealm.clone(),
        cname: as_rep.cname.clone(),
    })
}

// ─── S4U2SELF + U2U TGS-REQ ───────────────────────────────────────────

fn send_s4u2self_u2u(
    kdc: &str,
    domain: &str,
    username: &str,
    target_user: &str,
    tgt: &TgtResult,
) -> Result<TgsRep> {
    let cipher = new_kerberos_cipher(tgt.etype)
        .map_err(|e| anyhow!("Unsupported etype: {:?}", e))?;

    let now = chrono::Utc::now();

    // Build Authenticator for AP-REQ
    let authenticator = Authenticator {
        authenticator_vno: 5,
        crealm: tgt.crealm.clone(),
        cname: tgt.cname.clone(),
        cksum: None,
        cusec: (now.timestamp_subsec_micros() % 1_000_000) as i32,
        ctime: krb::krb_time(now),
        subkey: None,
        seq_number: Some(rand::random::<u32>()),
        authorization_data: None,
    };

    // cipher.encrypt returns Vec<u8> directly, not Result
    let enc_auth = cipher.encrypt(
        &tgt.session_key,
        7, // KEY_USAGE_TGS_REQ_AUTHEN
        &authenticator.build(),
    );

    let ap_req = ApReq {
        pvno: 5,
        msg_type: 14,
        ap_options: kerberos_asn1::KerberosFlags::from(0u32),
        ticket: tgt.ticket.clone(),
        authenticator: KrbEncryptedData::new(tgt.etype, None, enc_auth),
    };

    // Build PA-FOR-USER (S4U2Self)
    let pa_for_user = krb::build_pa_for_user(target_user, domain, &tgt.session_key)?;

    // sname = username (service ticket to ourselves)
    let server_name = krb::make_principal_name(NT_UNKNOWN, username);

    let till = now + chrono::Duration::hours(24);

    let kdc_opts = krb::KDC_OPT_FORWARDABLE
        | krb::KDC_OPT_RENEWABLE
        | krb::KDC_OPT_CANONICALIZE
        | krb::KDC_OPT_ENC_TKT_IN_SKEY;

    let req_body = KdcReqBody {
        kdc_options: kerberos_asn1::KerberosFlags::from(kdc_opts),
        cname: None,
        realm: domain.into(),
        sname: Some(server_name),
        from: None,
        till: krb::krb_time(till),
        rtime: None,
        nonce: rand::random(),
        etypes: vec![tgt.etype, RC4_HMAC],
        addresses: None,
        enc_authorization_data: None,
        additional_tickets: Some(vec![tgt.ticket.clone()]),
    };

    let tgs_req = TgsReq {
        pvno: 5,
        msg_type: 12,
        padata: Some(vec![
            PaData::new(
                kerberos_constants::pa_data_types::PA_TGS_REQ,
                ap_req.build(),
            ),
            PaData::new(
                krb::PA_FOR_USER,
                pa_for_user,
            ),
        ]),
        req_body,
    };

    let reply = krb::send_krb_tcp(kdc, &tgs_req.build())?;

    let (_, tgs_rep) = TgsRep::parse(&reply).map_err(|_| {
        if let Ok((_, krb_err)) = kerberos_asn1::KrbError::parse(&reply) {
            anyhow!(
                "KDC returned error code {}: {:?}",
                krb_err.error_code,
                krb_err.e_text
            )
        } else {
            anyhow!("Failed to parse TGS-REP (and not a KRB-ERROR either)")
        }
    })?;

    Ok(tgs_rep)
}

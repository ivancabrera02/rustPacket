// ccache.rs — MIT Kerberos Credential Cache (ccache) file format writer
//
// Format reference:
//   https://web.mit.edu/kerberos/krb5-devel/doc/formats/ccache_file_format.html
//
// File layout (version 0x0504):
//   [2 bytes]  file_format_version = 0x0504
//   [2 bytes]  headerlen
//   [header]   tag/length/value fields
//   [principal] default principal
//   [credentials...]  credential entries

use anyhow::Result;
use kerberos_asn1::{AsRep, EncAsRepPart};
use red_asn1::Asn1Object;

pub struct CCache {
    pub version: u16,
    pub default_principal: CcachePrincipal,
    pub credentials: Vec<CcacheCredential>,
}

pub struct CcachePrincipal {
    pub name_type: u32,
    pub realm: String,
    pub components: Vec<String>,
}

pub struct CcacheCredential {
    pub client: CcachePrincipal,
    pub server: CcachePrincipal,
    pub keyblock: CcacheKeyblock,
    pub authtime: u32,
    pub starttime: u32,
    pub endtime: u32,
    pub renew_till: u32,
    pub is_skey: u8,
    pub ticket_flags: u32,
    pub ticket: Vec<u8>,
    pub second_ticket: Vec<u8>,
}

pub struct CcacheKeyblock {
    pub keytype: u16,
    pub keyvalue: Vec<u8>,
}

impl CCache {
    pub fn from_as_rep(
        as_rep: &AsRep,
        enc_part: &EncAsRepPart,
        domain: &str,
        username: &str,
    ) -> Result<Self> {
        let realm = domain.to_uppercase();

        let default_principal = CcachePrincipal {
            name_type: 1, // NT_PRINCIPAL
            realm: realm.clone(),
            components: vec![username.to_string()],
        };

        let session_key_type: i32 = enc_part.key.keytype.into();
        let session_key_value: Vec<u8> = enc_part.key.keyvalue.clone().into();

        // DER-encode the Ticket from the AS-REP
        let ticket_der = as_rep.ticket.build();

        // Time fields from decrypted enc-part
        // KerberosTime stores a chrono DateTime<Utc> internally.
        // We access the .flags.flags field (u32) directly.
        let authtime = kerb_time_to_epoch(&enc_part.authtime);
        let starttime = enc_part
            .starttime
            .as_ref()
            .map(kerb_time_to_epoch)
            .unwrap_or(authtime);
        let endtime = kerb_time_to_epoch(&enc_part.endtime);
        let renew_till = enc_part
            .renew_till
            .as_ref()
            .map(kerb_time_to_epoch)
            .unwrap_or(0);

        // Ticket flags from the enc-part (KerberosFlags { flags: u32 })
        let ticket_flags = enc_part.flags.flags;

        let server = CcachePrincipal {
            name_type: 2, // NT_SRV_INST
            realm: realm.clone(),
            components: vec!["krbtgt".to_string(), realm.clone()],
        };

        let credential = CcacheCredential {
            client: CcachePrincipal {
                name_type: 1,
                realm: realm.clone(),
                components: vec![username.to_string()],
            },
            server,
            keyblock: CcacheKeyblock {
                keytype: session_key_type as u16,
                keyvalue: session_key_value,
            },
            authtime,
            starttime,
            endtime,
            renew_till,
            is_skey: 0,
            ticket_flags,
            ticket: ticket_der,
            second_ticket: vec![],
        };

        Ok(CCache {
            version: 0x0504,
            default_principal,
            credentials: vec![credential],
        })
    }

    pub fn build(&self) -> Vec<u8> {
        let mut out = Vec::new();

        // Version
        out.extend_from_slice(&self.version.to_be_bytes());

        // Header (version 0x0504 requires a header block)
        let header = build_ccache_header();
        out.extend_from_slice(&(header.len() as u16).to_be_bytes());
        out.extend_from_slice(&header);

        // Default principal
        write_principal(&mut out, &self.default_principal);

        // Credentials
        for cred in &self.credentials {
            write_credential(&mut out, cred);
        }

        out
    }
}

// ─── Binary serialization ───────────────────────────────────────────────────

fn build_ccache_header() -> Vec<u8> {
    let mut hdr = Vec::new();
    // Tag 1: deltatime offset (seconds + microseconds)
    hdr.extend_from_slice(&1u16.to_be_bytes()); // tag
    hdr.extend_from_slice(&8u16.to_be_bytes()); // length
    hdr.extend_from_slice(&0u32.to_be_bytes()); // seconds
    hdr.extend_from_slice(&0u32.to_be_bytes()); // microseconds
    hdr
}

fn write_principal(out: &mut Vec<u8>, p: &CcachePrincipal) {
    out.extend_from_slice(&p.name_type.to_be_bytes());
    out.extend_from_slice(&(p.components.len() as u32).to_be_bytes());
    write_counted_string(out, &p.realm);
    for comp in &p.components {
        write_counted_string(out, comp);
    }
}

fn write_counted_string(out: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn write_keyblock(out: &mut Vec<u8>, kb: &CcacheKeyblock) {
    out.extend_from_slice(&kb.keytype.to_be_bytes());
    out.extend_from_slice(&(kb.keyvalue.len() as u32).to_be_bytes());
    out.extend_from_slice(&kb.keyvalue);
}

fn write_credential(out: &mut Vec<u8>, cred: &CcacheCredential) {
    write_principal(out, &cred.client);
    write_principal(out, &cred.server);
    write_keyblock(out, &cred.keyblock);

    // Times (4 × u32)
    out.extend_from_slice(&cred.authtime.to_be_bytes());
    out.extend_from_slice(&cred.starttime.to_be_bytes());
    out.extend_from_slice(&cred.endtime.to_be_bytes());
    out.extend_from_slice(&cred.renew_till.to_be_bytes());

    // is_skey (1 byte)
    out.push(cred.is_skey);

    // ticket_flags (u32, MSB = bit 0 per Kerberos convention)
    out.extend_from_slice(&cred.ticket_flags.to_be_bytes());

    // addresses count = 0
    out.extend_from_slice(&0u32.to_be_bytes());

    // authdata count = 0
    out.extend_from_slice(&0u32.to_be_bytes());

    // ticket (counted octet string)
    out.extend_from_slice(&(cred.ticket.len() as u32).to_be_bytes());
    out.extend_from_slice(&cred.ticket);

    // second_ticket (counted octet string)
    out.extend_from_slice(&(cred.second_ticket.len() as u32).to_be_bytes());
    out.extend_from_slice(&cred.second_ticket);
}

// ─── Time conversion ────────────────────────────────────────────────────────

/// Convert KerberosTime to Unix epoch seconds.
///
/// KerberosTime wraps chrono::DateTime<Utc> internally.
/// We use its Debug representation "YYYYMMDDHHMMSSZ" to parse,
/// or fall back to current time.
fn kerb_time_to_epoch(kt: &kerberos_asn1::KerberosTime) -> u32 {
    // The Debug output of KerberosTime is the raw GeneralizedTime string
    // e.g. "20260430120000Z"
    let dbg = format!("{:?}", kt);

    // Try parsing the GeneralizedTime string
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(
        dbg.trim_matches('"').trim_end_matches('Z'),
        "%Y%m%d%H%M%S",
    ) {
        return dt.and_utc().timestamp() as u32;
    }

    // Fallback: use current time
    chrono::Utc::now().timestamp() as u32
}

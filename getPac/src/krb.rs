// krb.rs — Kerberos protocol helpers

use anyhow::{anyhow, bail, Result};
use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use md5::{Md5, Digest};
use red_asn1::Asn1Object;
use std::io::{Cursor, Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use tracing::debug;

use kerberos_asn1::{
    Checksum as KrbChecksum, EtypeInfo2Entry, KerberosTime, PaData, PaEncTsEnc,
    PaForUser, PrincipalName,
};
use kerberos_constants::etypes::*;
use kerberos_constants::principal_names::*;
use kerberos_crypto::{new_kerberos_cipher, KerberosCipher};

type HmacMd5 = Hmac<Md5>;

// ─── CONSTANTS ─────────────────────────────────────────────────────────

// KDC Options flags (bit positions per RFC 4120)
pub const KDC_OPT_FORWARDABLE: u32     = 0x40000000; // bit 1
pub const KDC_OPT_RENEWABLE: u32       = 0x00800000; // bit 8
pub const KDC_OPT_CANONICALIZE: u32    = 0x00010000; // bit 15
pub const KDC_OPT_ENC_TKT_IN_SKEY: u32 = 0x00000008; // bit 28

// PA-FOR-USER type = 129 (MS-SFU, not in kerberos_constants)
pub const PA_FOR_USER: i32 = 129;

// ─── PRINCIPAL NAME HELPERS ────────────────────────────────────────────

/// PrincipalName::new(name_type, string) in kerberos_asn1 0.2.1
/// takes a single KerberosString (= String), not a Vec.
/// For single-component names (NT_PRINCIPAL, NT_UNKNOWN):
pub fn make_principal_name(name_type: i32, name: &str) -> PrincipalName {
    PrincipalName::new(name_type, name.to_string())
}

/// For two-component names like krbtgt/DOMAIN (NT_SRV_INST).
/// We construct the PrincipalName manually since ::new only takes one string.
pub fn make_principal_name_2(name_type: i32, comp1: &str, comp2: &str) -> PrincipalName {
    PrincipalName {
        name_type,
        name_string: vec![comp1.to_string(), comp2.to_string()],
    }
}

// ─── TIME HELPER ───────────────────────────────────────────────────────

pub fn krb_time(dt: DateTime<Utc>) -> KerberosTime {
    KerberosTime::from(dt)
}

// ─── TCP TRANSPORT ─────────────────────────────────────────────────────

/// Send Kerberos message over TCP (4-byte big-endian length prefix).
pub fn send_krb_tcp(kdc: &str, data: &[u8]) -> Result<Vec<u8>> {
    let addr = format!("{}:88", kdc);
    debug!("TCP connect to {}", addr);

    let mut stream =
        TcpStream::connect_timeout(&addr.parse()?, Duration::from_secs(10))
            .map_err(|e| anyhow!("TCP connect to {} failed: {}", addr, e))?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;

    let mut buf = Vec::with_capacity(4 + data.len());
    buf.write_u32::<BigEndian>(data.len() as u32)?;
    buf.extend_from_slice(data);
    stream.write_all(&buf)?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let resp_len = Cursor::new(&len_buf).read_u32::<BigEndian>()? as usize;
    if resp_len > 1_048_576 {
        bail!("KDC response too large: {} bytes", resp_len);
    }

    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp)?;
    debug!("Received {} bytes from KDC", resp_len);
    Ok(resp)
}

// ─── KEY DERIVATION ────────────────────────────────────────────────────

pub fn derive_key(
    etype: i32,
    password: &str,
    domain: &str,
    username: &str,
    nt_hash: &[u8],
) -> Result<Vec<u8>> {
    if !nt_hash.is_empty() && etype == RC4_HMAC {
        return Ok(nt_hash.to_vec());
    }
    if nt_hash.is_empty() && password.is_empty() {
        bail!("Either --password or --hashes is required");
    }

    let cipher = new_kerberos_cipher(etype)
        .map_err(|e| anyhow!("Unsupported etype {}: {:?}", etype, e))?;

    let salt = if etype == RC4_HMAC {
        String::new()
    } else {
        format!("{}{}", domain.to_uppercase(), username)
    };

    Ok(cipher.generate_key_from_string(password, salt.as_bytes()))
}

// ─── PA-ENC-TIMESTAMP ──────────────────────────────────────────────────

/// Build encrypted PA-ENC-TIMESTAMP. Returns raw EncryptedData DER bytes.
/// Note: cipher.encrypt returns Vec<u8> directly (not Result).
pub fn build_pa_enc_timestamp(cipher: &dyn KerberosCipher, key: &[u8]) -> Vec<u8> {
    let now = Utc::now();
    let ts = PaEncTsEnc {
        patimestamp: KerberosTime::from(now),
        pausec: Some((now.timestamp_subsec_micros() % 1_000_000) as i32),
    };

    let encrypted = cipher.encrypt(key, 1, &ts.build());
    let enc_data = kerberos_asn1::EncryptedData::new(cipher.etype(), None, encrypted);
    enc_data.build()
}

// ─── PA-FOR-USER (S4U2Self) ────────────────────────────────────────────

/// Build PA-FOR-USER padata for S4U2Self.
pub fn build_pa_for_user(
    target_user: &str,
    domain: &str,
    session_key: &[u8],
) -> Result<Vec<u8>> {
    let mut s4u_bytes = Vec::new();
    s4u_bytes.write_u32::<LittleEndian>(NT_PRINCIPAL as u32)?;
    s4u_bytes.extend_from_slice(target_user.as_bytes());
    s4u_bytes.extend_from_slice(domain.as_bytes());
    s4u_bytes.extend_from_slice(b"Kerberos");

    debug!("S4U byte array ({} bytes)", s4u_bytes.len());

    let checksum = hmac_md5_checksum(session_key, 17, &s4u_bytes)?;
    debug!("PA-FOR-USER checksum: {}", hex::encode(&checksum));

    let pa = PaForUser {
        username: make_principal_name(NT_PRINCIPAL, target_user),
        userrealm: domain.into(),
        cksum: KrbChecksum {
            cksumtype: -138,
            checksum,
        },
        auth_package: "Kerberos".into(),
    };

    Ok(pa.build())
}

/// KERB_CHECKSUM_HMAC_MD5:
///   1. Ksign = HMAC-MD5(key, "signaturekey\0")
///   2. tmp = MD5(usage_le32 || data)
///   3. result = HMAC-MD5(Ksign, tmp)
fn hmac_md5_checksum(key: &[u8], usage: i32, data: &[u8]) -> Result<Vec<u8>> {
    let mut mac1 =
        HmacMd5::new_from_slice(key).map_err(|e| anyhow!("HMAC init: {}", e))?;
    mac1.update(b"signaturekey\0");
    let ksign = mac1.finalize().into_bytes();

    let mut hasher = Md5::new();
    hasher.update(&(usage as u32).to_le_bytes());
    hasher.update(data);
    let tmp = hasher.finalize();

    let mut mac2 = HmacMd5::new_from_slice(&ksign)
        .map_err(|e| anyhow!("HMAC init: {}", e))?;
    mac2.update(&tmp);
    Ok(mac2.finalize().into_bytes().to_vec())
}

// ─── ETYPE SELECTION FROM KRB-ERROR ────────────────────────────────────

pub fn select_etype_from_error(error_bytes: &[u8], preferred: &[i32]) -> Result<i32> {
    let (_, krb_err) = kerberos_asn1::KrbError::parse(error_bytes)
        .map_err(|e| anyhow!("Cannot parse KRB-ERROR: {:?}", e))?;

    debug!(
        "KRB-ERROR: code={}, text={:?}",
        krb_err.error_code, krb_err.e_text
    );

    if krb_err.error_code != 25 {
        bail!(
            "Unexpected KRB-ERROR code {}: {:?}",
            krb_err.error_code,
            krb_err.e_text
        );
    }

    if let Some(ref e_data) = krb_err.e_data {
        if let Ok((_, pa_datas)) =
            <Vec<PaData> as Asn1Object>::parse(e_data)
        {
            for pa in &pa_datas {
                if pa.padata_type == 19 {
                    if let Ok((_, entries)) =
                        <Vec<EtypeInfo2Entry> as Asn1Object>::parse(&pa.padata_value)
                    {
                        let server_etypes: Vec<i32> =
                            entries.iter().map(|e| e.etype).collect();
                        debug!("Server etypes: {:?}", server_etypes);

                        for p in preferred {
                            if server_etypes.contains(p) {
                                return Ok(*p);
                            }
                        }
                        if let Some(&first) = server_etypes.first() {
                            return Ok(first);
                        }
                    }
                }
            }
        }
    }

    preferred
        .first()
        .copied()
        .ok_or_else(|| anyhow!("No supported etype"))
}

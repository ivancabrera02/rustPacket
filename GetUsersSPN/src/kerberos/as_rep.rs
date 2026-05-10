//! AS-REP + KRB-ERROR parser (RFC 4120).

use crate::error::{KrbError, krb_error_string};
use crate::kerberos::asn1::*;
use crate::kerberos::crypto::{rc4_hmac_decrypt, aes_hmac_sha1_decrypt};

// ── KRB-ERROR ─────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct KrbErrorMsg {
    pub error_code: i64,
    pub e_text:     String,
    pub e_data:     Vec<u8>,   // raw bytes of the e-data OCTET STRING
}

/// Try to parse a KRB-ERROR (APPLICATION 30, tag 0x7e).
/// RFC 4120 §5.9.1 field tags:
///   [0] pvno  [1] msg-type  [4] stime  [5] susec
///   [6] error-code  [8] crealm  [9] cname  [10] realm  [11] e-text  [12] e-data
pub fn try_parse_krb_error(data: &[u8]) -> Option<KrbErrorMsg> {
    if data.len() < 2 || data[0] != 0x7e { return None; }

    let mut pos = 0;
    let (_, app_inner) = read_tlv(data, &mut pos).ok()?;
    // app_inner = SEQUENCE { fields }
    let mut p  = 0;
    let (_, seq) = read_tlv(app_inner, &mut p).ok()?;

    let mut sp         = 0;
    let mut error_code = 0i64;
    let mut e_text     = String::new();
    let mut e_data     = Vec::new();

    while sp < seq.len() {
        let (tag, val) = match read_tlv(seq, &mut sp) {
            Ok(v) => v,
            Err(_) => break,
        };
        match tag {
            0xa6 => {                                       // error-code [6]
                let mut ip = 0;
                if let Ok((_, iv)) = read_tlv(val, &mut ip) {
                    error_code = decode_integer(iv).unwrap_or(0);
                }
            }
            0xab => {                                       // e-text [11] GeneralString
                let mut tp = 0;
                if let Ok((_, tv)) = read_tlv(val, &mut tp) {
                    e_text = String::from_utf8_lossy(tv).to_string();
                }
            }
            0xac => {                                       // e-data [12] OCTET STRING
                let mut dp = 0;
                if let Ok((_, dv)) = read_tlv(val, &mut dp) {
                    e_data = dv.to_vec();
                }
            }
            _ => {}
        }
    }

    Some(KrbErrorMsg { error_code, e_text, e_data })
}

// ── ETYPE_INFO2 (from e-data of PREAUTH_REQUIRED) ─────────────────────────────

#[derive(Debug, Clone)]
pub struct EtypeInfo2Entry {
    pub etype: i64,
    pub salt:  Option<String>,
}

/// Parse ETYPE_INFO2 (or ETYPE_INFO) entries from the e-data bytes of a
/// KDC_ERR_PREAUTH_REQUIRED response.
///
/// e_data is a DER SEQUENCE OF PA-DATA. We look for:
///   PA_ETYPE_INFO2 (type 19) → SEQUENCE OF { [0] etype, [1] salt OPTIONAL, … }
///   PA_ETYPE_INFO  (type 11) → SEQUENCE OF { [0] etype, [1] salt OPTIONAL }
pub fn parse_etype_info2(e_data: &[u8]) -> Vec<EtypeInfo2Entry> {
    let mut results = Vec::new();
    if e_data.is_empty() { return results; }

    // outer: SEQUENCE OF PA-DATA
    let mut pos = 0;
    let outer_seq = match read_tlv(e_data, &mut pos) {
        Ok((TAG_SEQUENCE, v)) => v,
        _ => return results,
    };

    let mut sp = 0;
    while sp < outer_seq.len() {
        // each PA-DATA ::= SEQUENCE { [1] padata-type, [2] padata-value }
        let (_, pa_der) = match read_tlv(outer_seq, &mut sp) {
            Ok(v) => v,
            Err(_) => break,
        };

        let mut ptype  = 0i64;
        let mut pvalue = &[][..];
        let mut pp = 0;
        while pp < pa_der.len() {
            let (tag, val) = match read_tlv(pa_der, &mut pp) {
                Ok(v) => v,
                Err(_) => break,
            };
            match tag {
                0xa1 => { // [1] padata-type
                    let mut ip = 0;
                    if let Ok((_, iv)) = read_tlv(val, &mut ip) {
                        ptype = decode_integer(iv).unwrap_or(0);
                    }
                }
                0xa2 => { // [2] padata-value (OCTET STRING)
                    let mut ip = 0;
                    if let Ok((_, iv)) = read_tlv(val, &mut ip) {
                        pvalue = iv;
                    }
                }
                _ => {}
            }
        }

        if ptype == 19 || ptype == 11 {
            results.extend(parse_etype_info_value(pvalue));
        }
    }
    results
}

fn parse_etype_info_value(data: &[u8]) -> Vec<EtypeInfo2Entry> {
    let mut out = Vec::new();
    let mut pos = 0;

    // SEQUENCE OF ETYPE_INFO(2)_ENTRY
    let outer = match read_tlv(data, &mut pos) {
        Ok((TAG_SEQUENCE, v)) => v,
        _ => return out,
    };

    let mut sp = 0;
    while sp < outer.len() {
        let (_, entry) = match read_tlv(outer, &mut sp) {
            Ok(v) => v,
            Err(_) => break,
        };

        let mut etype = 0i64;
        let mut salt: Option<String> = None;
        let mut ep = 0;
        while ep < entry.len() {
            let (tag, val) = match read_tlv(entry, &mut ep) {
                Ok(v) => v,
                Err(_) => break,
            };
            match tag {
                0xa0 => { // [0] etype
                    let mut ip = 0;
                    if let Ok((_, iv)) = read_tlv(val, &mut ip) {
                        etype = decode_integer(iv).unwrap_or(23);
                    }
                }
                0xa1 => { // [1] salt (KerberosString / OCTET STRING)
                    let mut ip = 0;
                    if let Ok((_, iv)) = read_tlv(val, &mut ip) {
                        salt = Some(String::from_utf8_lossy(iv).to_string());
                    }
                }
                _ => {}
            }
        }
        out.push(EtypeInfo2Entry { etype, salt });
    }
    out
}

// ── AS-REP ────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct AsRep {
    pub ticket_der:    Vec<u8>,
    pub session_key:   Vec<u8>,
    pub session_etype: i64,
    pub crealm:        String,
}

pub fn parse_as_rep(data: &[u8], client_key: &[u8], etype: i64) -> Result<AsRep, KrbError> {
    if data.is_empty() {
        return Err(KrbError::Parse("Empty AS-REP response".into()));
    }
    if data[0] == 0x7e {
        if let Some(err) = try_parse_krb_error(data) {
            return Err(KrbError::KrbErrorCode(
                err.error_code,
                format!("{} — {}", krb_error_string(err.error_code), err.e_text),
            ));
        }
        return Err(KrbError::Parse("KRB-ERROR (unparseable)".into()));
    }
    if data[0] != 0x6b {
        return Err(KrbError::Parse(format!(
            "Expected AS-REP (0x6b), got 0x{:02x} — first bytes: {}",
            data[0], hex::encode(&data[..data.len().min(16)])
        )));
    }

    let mut pos = 0;
    let (_, app_inner) = read_tlv(data, &mut pos)?;
    let mut p = 0;
    let seq_val = if !app_inner.is_empty() && app_inner[0] == TAG_SEQUENCE {
        let (_, sv) = read_tlv(app_inner, &mut p)?;
        sv
    } else {
        app_inner
    };

    let mut crealm          = String::new();
    let mut ticket_der      = Vec::new();
    let mut enc_part_etype  = 0i64;
    let mut enc_part_cipher = Vec::new();

    let mut sp = 0;
    while sp < seq_val.len() {
        let (tag, val) = read_tlv(seq_val, &mut sp)?;
        match tag {
            0xa3 => {
                let mut vp = 0;
                if let Ok((_, rv)) = read_tlv(val, &mut vp) {
                    crealm = String::from_utf8_lossy(rv).to_string();
                }
            }
            0xa5 => { ticket_der = val.to_vec(); }
            0xa6 => {
                let mut vp = 0;
                let enc_seq = if !val.is_empty() && val[0] == TAG_SEQUENCE {
                    let (_, sv) = read_tlv(val, &mut vp)?; sv
                } else { val };
                let mut ep = 0;
                while ep < enc_seq.len() {
                    let (et, ev) = read_tlv(enc_seq, &mut ep)?;
                    match et {
                        0xa0 => {
                            let mut ip = 0;
                            if let Ok((_, iv)) = read_tlv(ev, &mut ip) {
                                enc_part_etype = decode_integer(iv).unwrap_or(23);
                            }
                        }
                        0xa2 => {
                            let mut ip = 0;
                            if let Ok((_, iv)) = read_tlv(ev, &mut ip) {
                                enc_part_cipher = iv.to_vec();
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    if ticket_der.is_empty()      { return Err(KrbError::Parse("No ticket in AS-REP".into())); }
    if enc_part_cipher.is_empty() { return Err(KrbError::Parse("No enc-part in AS-REP".into())); }

    // Decrypt enc-part: RC4 key-usage 8 (MS-KILE), AES key-usage 3 (RFC 4120)
    let decrypted = match etype {
        23      => rc4_hmac_decrypt(client_key, 8, &enc_part_cipher)?,
        17 | 18 => aes_hmac_sha1_decrypt(client_key, 3, &enc_part_cipher)?,
        _       => return Err(KrbError::UnsupportedEtype(etype)),
    };

    let session_key = extract_session_key(&decrypted)?;
    Ok(AsRep { ticket_der, session_key, session_etype: enc_part_etype, crealm })
}

fn extract_session_key(data: &[u8]) -> Result<Vec<u8>, KrbError> {
    if data.is_empty() {
        return Err(KrbError::Parse("Empty decrypted AS-REP enc-part".into()));
    }
    let inner: &[u8] = match data[0] {
        0x79 | 0x7a => {
            let mut p = 0;
            let (_, v) = read_tlv(data, &mut p)?;
            if !v.is_empty() && v[0] == TAG_SEQUENCE {
                let mut p2 = 0;
                let (_, sv) = read_tlv(v, &mut p2)?;
                sv
            } else { v }
        }
        TAG_SEQUENCE => { let mut p = 0; let (_, v) = read_tlv(data, &mut p)?; v }
        _ => data,
    };

    let mut sp = 0;
    while sp < inner.len() {
        let (tag, val) = match read_tlv(inner, &mut sp) {
            Ok(v) => v,
            Err(_) => break,
        };
        if tag == 0xa0 {
            let mut vp = 0;
            let key_blob = if !val.is_empty() && val[0] == TAG_SEQUENCE {
                let (_, ks) = read_tlv(val, &mut vp)?; ks
            } else { val };
            let mut kp = 0;
            while kp < key_blob.len() {
                let (kt, kv) = match read_tlv(key_blob, &mut kp) {
                    Ok(v) => v,
                    Err(_) => break,
                };
                if kt == 0xa1 {
                    let mut kvp = 0;
                    if let Ok((_, kb)) = read_tlv(kv, &mut kvp) {
                        return Ok(kb.to_vec());
                    }
                }
            }
        }
    }
    Err(KrbError::Parse("Session key not found in EncASRepPart".into()))
}

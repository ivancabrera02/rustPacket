//! AS-REQ builder (RFC 4120 §5.4.1).
//! Matches Impacket's getKerberosTGT two-step flow:
//!  Step 1 – probe: no pre-auth (only PA-PAC-REQUEST) → KDC returns ETYPE_INFO2
//!  Step 2 – real:  PA-ENC-TIMESTAMP encrypted with the correct key + etype

use crate::error::KrbError;
use crate::kerberos::asn1::*;
use crate::kerberos::crypto::build_pa_enc_timestamp;

// kdc-options: forwardable(1) | proxiable(3) | renewable(8)
// bit positions are from MSB in a 32-bit KerberosFlags BitString:
//   bit 1  → 0x40000000
//   bit 3  → 0x10000000
//   bit 8  → 0x00800000
const KDC_FLAGS: u32 = 0x50800000;

// far-future "till" timestamp
const TILL: &str = "20370913024805Z";

fn build_kdc_options() -> Vec<u8> {
    tlv(0x03 /*BIT STRING*/, &[
        0x00u8,                                 // 0 unused bits
        ((KDC_FLAGS >> 24) & 0xFF) as u8,
        ((KDC_FLAGS >> 16) & 0xFF) as u8,
        ((KDC_FLAGS >>  8) & 0xFF) as u8,
        ( KDC_FLAGS        & 0xFF) as u8,
    ])
}

fn build_pac_request_padata() -> Vec<u8> {
    // KERB-PA-PAC-REQUEST ::= SEQUENCE { include-pac [0] BOOLEAN TRUE }
    let inner = sequence(&ctx(0, &tlv(0x01 /*BOOLEAN*/, &[0xff])));
    sequence(&[
        ctx(1, &encode_integer(128)),           // padata-type = PA_PAC_REQUEST
        ctx(2, &encode_octet(&inner)),          // padata-value
    ].concat())
}

fn build_req_body(username: &str, realm: &str, etype: i64, nonce: u32) -> Vec<u8> {
    let cname = encode_principal_name(1, &[username]);
    let sname = encode_principal_name(2, &["krbtgt", realm]);
    let till  = encode_generalized_time(TILL);

    sequence(&[
        ctx(0, &build_kdc_options()),
        ctx(1, &cname),
        ctx(2, &encode_realm(realm)),
        ctx(3, &sname),
        ctx(5, &till),
        ctx(7, &encode_uint(nonce)),
        // etype list: only the etype we're using (matches Impacket behaviour)
        ctx(8, &sequence(&encode_integer(etype))),
    ].concat())
}

/// Step 1 – probe AS-REQ: only PA-PAC-REQUEST, no PA-ENC-TIMESTAMP.
/// The KDC will reply with KDC_ERR_PREAUTH_REQUIRED and include ETYPE_INFO2
/// so we can learn the supported etype and the correct salt.
pub fn build_as_req_probe(username: &str, realm: &str, nonce: u32) -> Vec<u8> {
    let padata = sequence(&build_pac_request_padata());  // SEQUENCE OF PA-DATA (one entry)

    let kdc_req = sequence(&[
        ctx(1, &encode_integer(5)),             // pvno
        ctx(2, &encode_integer(10)),            // msg-type = AS-REQ
        ctx(3, &padata),                        // padata
        ctx(4, &build_req_body(username, realm, 18, nonce)), // etype=18 for probe
    ].concat());

    tlv(0x6a /*APPLICATION 10*/, &kdc_req)
}

/// Step 2 – full AS-REQ with PA-ENC-TIMESTAMP pre-auth.
pub fn build_as_req(
    username: &str,
    realm:    &str,
    key:      &[u8],
    etype:    i64,
    nonce:    u32,
) -> Result<Vec<u8>, KrbError> {
    let pa_enc_ts = build_pa_enc_timestamp(key, etype)?;

    // EncryptedData = SEQUENCE { etype [0], cipher [2] }
    let enc_data = sequence(&[
        ctx(0, &encode_integer(etype)),
        ctx(2, &encode_octet(&pa_enc_ts)),
    ].concat());

    // PA-DATA: padata-type [1] = 2 (PA_ENC_TIMESTAMP), padata-value [2]
    let pa_enc_ts_entry = sequence(&[
        ctx(1, &encode_integer(2)),
        ctx(2, &encode_octet(&enc_data)),
    ].concat());

    // SEQUENCE OF PA-DATA (two entries: PA-ENC-TIMESTAMP, PA-PAC-REQUEST)
    let padata = sequence(&[pa_enc_ts_entry, build_pac_request_padata()].concat());

    let kdc_req = sequence(&[
        ctx(1, &encode_integer(5)),
        ctx(2, &encode_integer(10)),
        ctx(3, &padata),
        ctx(4, &build_req_body(username, realm, etype, nonce)),
    ].concat());

    Ok(tlv(0x6a, &kdc_req))
}

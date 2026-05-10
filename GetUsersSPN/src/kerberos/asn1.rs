//! Minimal ASN.1 DER encoder/decoder for Kerberos messages.
//! Implements only the tags and structures needed for AS-REQ and TGS-REQ.

use crate::error::KrbError;

// ── Universal tags ────────────────────────────────────────────────────────────
pub const TAG_INTEGER:    u8 = 0x02;
pub const TAG_OCTET:      u8 = 0x04;
pub const TAG_NULL:       u8 = 0x05;
pub const TAG_OID:        u8 = 0x06;
pub const TAG_SEQUENCE:   u8 = 0x30;
pub const TAG_SET:        u8 = 0x31;
pub const TAG_GENTIME:    u8 = 0x18; // GeneralizedTime
pub const TAG_GENERAL:    u8 = 0x1b; // GeneralString

// ── DER length encoding ───────────────────────────────────────────────────────
pub fn encode_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len <= 0xFF {
        vec![0x81, len as u8]
    } else if len <= 0xFFFF {
        vec![0x82, (len >> 8) as u8, len as u8]
    } else {
        vec![
            0x83,
            (len >> 16) as u8,
            (len >> 8) as u8,
            len as u8,
        ]
    }
}

pub fn decode_length(data: &[u8], pos: &mut usize) -> Result<usize, KrbError> {
    let b = data[*pos];
    *pos += 1;
    if b & 0x80 == 0 {
        Ok(b as usize)
    } else {
        let n = (b & 0x7f) as usize;
        if *pos + n > data.len() {
            return Err(KrbError::Parse("length overrun".into()));
        }
        let mut len = 0usize;
        for _ in 0..n {
            len = (len << 8) | data[*pos] as usize;
            *pos += 1;
        }
        Ok(len)
    }
}

// ── TLV helpers ───────────────────────────────────────────────────────────────
pub fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(encode_length(value.len()));
    out.extend_from_slice(value);
    out
}

/// Context-specific constructed tag [n]
pub fn ctx(n: u8, inner: &[u8]) -> Vec<u8> {
    tlv(0xa0 | n, inner)
}

pub fn sequence(inner: &[u8]) -> Vec<u8> {
    tlv(TAG_SEQUENCE, inner)
}

pub fn set(inner: &[u8]) -> Vec<u8> {
    tlv(TAG_SET, inner)
}

// ── Primitive encoders ────────────────────────────────────────────────────────
pub fn encode_integer(v: i64) -> Vec<u8> {
    let mut bytes = v.to_be_bytes().to_vec();
    // strip leading 0x00 except when needed for sign
    while bytes.len() > 1 && bytes[0] == 0 && bytes[1] & 0x80 == 0 {
        bytes.remove(0);
    }
    tlv(TAG_INTEGER, &bytes)
}

pub fn encode_uint(v: u32) -> Vec<u8> {
    encode_integer(v as i64)
}

pub fn encode_octet(v: &[u8]) -> Vec<u8> {
    tlv(TAG_OCTET, v)
}

pub fn encode_general_string(s: &str) -> Vec<u8> {
    tlv(TAG_GENERAL, s.as_bytes())
}

pub fn encode_generalized_time(s: &str) -> Vec<u8> {
    tlv(TAG_GENTIME, s.as_bytes())
}

// PrincipalName ::= SEQUENCE { name-type [0] Int32, name-string [1] SEQUENCE OF GeneralString }
pub fn encode_principal_name(name_type: i64, parts: &[&str]) -> Vec<u8> {
    let name_string_inner: Vec<u8> = parts
        .iter()
        .flat_map(|p| encode_general_string(p))
        .collect();
    sequence(&[
        ctx(0, &encode_integer(name_type)),
        ctx(1, &sequence(&name_string_inner)),
    ].concat())
}

/// KerberosString is GeneralString
pub fn encode_kerberos_string(s: &str) -> Vec<u8> {
    encode_general_string(s)
}

// Realm ::= GeneralString
pub fn encode_realm(r: &str) -> Vec<u8> {
    encode_general_string(r)
}

// ── Primitive decoders ────────────────────────────────────────────────────────
pub fn read_tag(data: &[u8], pos: &mut usize) -> Result<u8, KrbError> {
    if *pos >= data.len() {
        return Err(KrbError::Parse("unexpected EOF reading tag".into()));
    }
    let t = data[*pos];
    *pos += 1;
    Ok(t)
}

pub fn expect_tag(data: &[u8], pos: &mut usize, expected: u8) -> Result<(), KrbError> {
    let t = read_tag(data, pos)?;
    if t != expected {
        return Err(KrbError::Parse(format!(
            "expected tag 0x{:02x}, got 0x{:02x}", expected, t
        )));
    }
    Ok(())
}

pub fn read_tlv<'a>(data: &'a [u8], pos: &mut usize) -> Result<(u8, &'a [u8]), KrbError> {
    let tag = read_tag(data, pos)?;
    let len = decode_length(data, pos)?;
    if *pos + len > data.len() {
        return Err(KrbError::Parse("TLV value overrun".into()));
    }
    let val = &data[*pos..*pos + len];
    *pos += len;
    Ok((tag, val))
}

pub fn decode_integer(data: &[u8]) -> Result<i64, KrbError> {
    if data.is_empty() {
        return Ok(0);
    }
    let mut v: i64 = if data[0] & 0x80 != 0 { -1 } else { 0 };
    for b in data {
        v = (v << 8) | (*b as i64);
    }
    Ok(v)
}

/// Read a context-specific constructed tag [n] and return its contents
pub fn enter_ctx<'a>(data: &'a [u8], pos: &mut usize, n: u8) -> Result<&'a [u8], KrbError> {
    let expected = 0xa0 | n;
    let (tag, val) = read_tlv(data, pos)?;
    if tag != expected {
        return Err(KrbError::Parse(format!(
            "expected ctx[{}] (0x{:02x}), got 0x{:02x}", n, expected, tag
        )));
    }
    Ok(val)
}

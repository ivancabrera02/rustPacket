//! NTLMv2 authentication for SMB session setup
//!
//! Implements the NTLM challenge-response mechanism needed to authenticate
//! against the SMB server. Supports both password and pass-the-hash.

use hmac::{Hmac, Mac};
use md5::Md5;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacMd5 = Hmac<Md5>;

// ---------------------------------------------------------------
// NTLM negotiate flags
// ---------------------------------------------------------------
#[allow(dead_code)]
const NTLMSSP_NEGOTIATE_UNICODE: u32          = 0x0000_0001;
#[allow(dead_code)]
const NTLMSSP_NEGOTIATE_OEM: u32              = 0x0000_0002;
#[allow(dead_code)]
const NTLMSSP_REQUEST_TARGET: u32             = 0x0000_0004;
#[allow(dead_code)]
const NTLMSSP_NEGOTIATE_SIGN: u32             = 0x0000_0010;
#[allow(dead_code)]
const NTLMSSP_NEGOTIATE_SEAL: u32             = 0x0000_0020;
#[allow(dead_code)]
const NTLMSSP_NEGOTIATE_LM_KEY: u32           = 0x0000_0080;
#[allow(dead_code)]
const NTLMSSP_NEGOTIATE_NTLM: u32             = 0x0000_0200;
#[allow(dead_code)]
const NTLMSSP_NEGOTIATE_ALWAYS_SIGN: u32      = 0x0000_8000;
#[allow(dead_code)]
const NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY: u32 = 0x0008_0000;
#[allow(dead_code)]
const NTLMSSP_NEGOTIATE_TARGET_INFO: u32      = 0x0080_0000;
#[allow(dead_code)]
const NTLMSSP_NEGOTIATE_VERSION: u32          = 0x0200_0000;
#[allow(dead_code)]
const NTLMSSP_NEGOTIATE_128: u32              = 0x2000_0000;
#[allow(dead_code)]
const NTLMSSP_NEGOTIATE_KEY_EXCH: u32         = 0x4000_0000;
#[allow(dead_code)]
const NTLMSSP_NEGOTIATE_56: u32               = 0x8000_0000;

/// Flags we send in Type 1 (NEGOTIATE)
const NEGOTIATE_FLAGS: u32 =
    NTLMSSP_NEGOTIATE_UNICODE
    | NTLMSSP_REQUEST_TARGET
    | NTLMSSP_NEGOTIATE_NTLM
    | NTLMSSP_NEGOTIATE_ALWAYS_SIGN
    | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
    | NTLMSSP_NEGOTIATE_TARGET_INFO
    | NTLMSSP_NEGOTIATE_128
    | NTLMSSP_NEGOTIATE_56;

/// Compute the NT hash (MD4 of UTF-16LE password)
pub fn nt_hash(password: &str) -> Vec<u8> {
    let utf16: Vec<u8> = password
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    md4_hash(&utf16)
}

/// Simple MD4 implementation (needed for NT hash)
fn md4_hash(data: &[u8]) -> Vec<u8> {
    let bit_len = (data.len() as u64) * 8;

    // Padding
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    let mut a0: u32 = 0x6745_2301;
    let mut b0: u32 = 0xEFCD_AB89;
    let mut c0: u32 = 0x98BA_DCFE;
    let mut d0: u32 = 0x1032_5476;

    for chunk in msg.chunks(64) {
        let mut x = [0u32; 16];
        for (i, word) in chunk.chunks(4).enumerate() {
            x[i] = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
        }

        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);

        // Round 1
        macro_rules! ff {
            ($a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $s:expr) => {
                $a = $a
                    .wrapping_add(($b & $c) | (!$b & $d))
                    .wrapping_add(x[$k]);
                $a = $a.rotate_left($s);
            };
        }
        for &(k, s) in &[
            (0,3),(1,7),(2,11),(3,19),(4,3),(5,7),(6,11),(7,19),
            (8,3),(9,7),(10,11),(11,19),(12,3),(13,7),(14,11),(15,19),
        ] {
            ff!(a, b, c, d, k, s);
            let tmp = d; d = c; c = b; b = a; a = tmp;
        }

        // Round 2
        macro_rules! gg {
            ($a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $s:expr) => {
                $a = $a
                    .wrapping_add(($b & $c) | ($b & $d) | ($c & $d))
                    .wrapping_add(x[$k])
                    .wrapping_add(0x5A82_7999);
                $a = $a.rotate_left($s);
            };
        }
        for &(k, s) in &[
            (0,3),(4,5),(8,9),(12,13),(1,3),(5,5),(9,9),(13,13),
            (2,3),(6,5),(10,9),(14,13),(3,3),(7,5),(11,9),(15,13),
        ] {
            gg!(a, b, c, d, k, s);
            let tmp = d; d = c; c = b; b = a; a = tmp;
        }

        // Round 3
        macro_rules! hh {
            ($a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $s:expr) => {
                $a = $a
                    .wrapping_add($b ^ $c ^ $d)
                    .wrapping_add(x[$k])
                    .wrapping_add(0x6ED9_EBA1);
                $a = $a.rotate_left($s);
            };
        }
        for &(k, s) in &[
            (0,3),(8,9),(4,11),(12,15),(2,3),(10,9),(6,11),(14,15),
            (1,3),(9,9),(5,11),(13,15),(3,3),(11,9),(7,11),(15,15),
        ] {
            hh!(a, b, c, d, k, s);
            let tmp = d; d = c; c = b; b = a; a = tmp;
        }

        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut result = Vec::with_capacity(16);
    result.extend_from_slice(&a0.to_le_bytes());
    result.extend_from_slice(&b0.to_le_bytes());
    result.extend_from_slice(&c0.to_le_bytes());
    result.extend_from_slice(&d0.to_le_bytes());
    result
}

/// Compute NTLMv2 response
pub fn ntlmv2_response(
    nt_hash_bytes: &[u8],
    username: &str,
    domain: &str,
    server_challenge: &[u8],
    server_info: &[u8], // AV_PAIRS from CHALLENGE message
) -> (Vec<u8>, Vec<u8>) {
    // NTLMv2 hash = HMAC-MD5(NT_Hash, UPPER(username) + domain) in UTF-16LE
    let user_domain: Vec<u8> = username
        .to_uppercase()
        .encode_utf16()
        .chain(domain.encode_utf16())
        .flat_map(|c| c.to_le_bytes())
        .collect();

    let ntlmv2_hash = hmac_md5(nt_hash_bytes, &user_domain);

    // Client challenge (8 random bytes)
    let client_challenge: [u8; 8] = rand_bytes();

    // Timestamp (Windows FILETIME: 100-ns intervals since 1601-01-01)
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    let filetime = (now / 100) + 116_444_736_000_000_000;

    // Build the blob (NTLMv2 client challenge structure)
    let mut blob = Vec::new();
    blob.push(0x01);       // RespType
    blob.push(0x01);       // HiRespType
    blob.extend_from_slice(&[0x00; 6]); // Reserved1 + Reserved2
    blob.extend_from_slice(&filetime.to_le_bytes()); // TimeStamp
    blob.extend_from_slice(&client_challenge);        // ChallengeFromClient
    blob.extend_from_slice(&[0x00; 4]);               // Reserved3
    blob.extend_from_slice(server_info);               // AvPairs from challenge
    blob.extend_from_slice(&[0x00; 4]);               // End padding

    // NTProofStr = HMAC-MD5(NTLMv2Hash, ServerChallenge + Blob)
    let mut challenge_blob = Vec::new();
    challenge_blob.extend_from_slice(server_challenge);
    challenge_blob.extend_from_slice(&blob);
    let nt_proof_str = hmac_md5(&ntlmv2_hash, &challenge_blob);

    // NT response = NTProofStr + Blob
    let mut nt_response = Vec::new();
    nt_response.extend_from_slice(&nt_proof_str);
    nt_response.extend_from_slice(&blob);

    // Session key = HMAC-MD5(NTLMv2Hash, NTProofStr)
    let session_key = hmac_md5(&ntlmv2_hash, &nt_proof_str);

    (nt_response, session_key)
}

/// Build NTLM NEGOTIATE message (Type 1)
pub fn build_negotiate_message() -> Vec<u8> {
    let mut msg = Vec::with_capacity(40);

    // Signature: "NTLMSSP\0"
    msg.extend_from_slice(b"NTLMSSP\x00");
    // MessageType: 1 (Negotiate)
    msg.extend_from_slice(&1u32.to_le_bytes());
    // NegotiateFlags
    msg.extend_from_slice(&NEGOTIATE_FLAGS.to_le_bytes());

    // DomainNameFields: Len(2) + MaxLen(2) + Offset(4) = all zeros (not supplied)
    msg.extend_from_slice(&0u16.to_le_bytes()); // DomainNameLen
    msg.extend_from_slice(&0u16.to_le_bytes()); // DomainNameMaxLen
    msg.extend_from_slice(&0u32.to_le_bytes()); // DomainNameBufferOffset

    // WorkstationFields: same, all zeros
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&0u32.to_le_bytes());

    // Total: 8 + 4 + 4 + 8 + 8 = 32 bytes (no version field)
    msg
}

/// Parse NTLM CHALLENGE message (Type 2), returns (server_challenge, flags, target_info)
pub fn parse_challenge_message(data: &[u8]) -> Result<(Vec<u8>, u32, Vec<u8>), String> {
    if data.len() < 32 {
        return Err("Challenge message too short".to_string());
    }
    if &data[0..8] != b"NTLMSSP\x00" {
        return Err("Invalid NTLMSSP signature".to_string());
    }
    let msg_type = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    if msg_type != 2 {
        return Err(format!("Expected type 2, got {}", msg_type));
    }

    // Flags at offset 20
    let flags = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);

    // ServerChallenge at offset 24 (8 bytes)
    let server_challenge = data[24..32].to_vec();

    // TargetInfoFields at offset 40 (if present): Len(2) + MaxLen(2) + Offset(4)
    let target_info = if data.len() >= 48 {
        let ti_len = u16::from_le_bytes([data[40], data[41]]) as usize;
        let ti_offset = u32::from_le_bytes([data[44], data[45], data[46], data[47]]) as usize;
        if ti_len > 0 && ti_offset + ti_len <= data.len() {
            data[ti_offset..ti_offset + ti_len].to_vec()
        } else {
            vec![]
        }
    } else {
        vec![]
    };

    Ok((server_challenge, flags, target_info))
}

/// Build NTLM AUTHENTICATE message (Type 3)
///
/// MS-NLMP §2.2.1.3 — AUTHENTICATE_MESSAGE
///
/// Fixed header is 72 bytes:
///   Signature(8) + Type(4) + LmResponse(8) + NtResponse(8) +
///   Domain(8) + User(8) + Workstation(8) + EncryptedRandomSessionKey(8) +
///   Flags(4) + Version(8)
///
/// We order the payload as: Domain, User, Workstation, LmResponse, NtResponse.
/// We do NOT send EncryptedRandomSessionKey (length=0) because we don't
/// negotiate NTLMSSP_NEGOTIATE_KEY_EXCH.
/// Returns (authenticate_message, session_key)
pub fn build_authenticate_message(
    domain: &str,
    username: &str,
    nt_hash_bytes: &[u8],
    server_challenge: &[u8],
    target_info: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let (nt_response, session_key) =
        ntlmv2_response(nt_hash_bytes, username, domain, server_challenge, target_info);

    let domain_utf16: Vec<u8> = domain
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let username_utf16: Vec<u8> = username
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let workstation_utf16: Vec<u8> = "WORKSTATION"
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    // LM response: for NTLMv2 we send a zero-filled 24-byte response
    let lm_response: Vec<u8> = vec![0u8; 24];

    // Fixed header size = 72 bytes (with version, without MIC)
    let header_size: u32 = 72;

    // Payload order: Domain, User, Workstation, LmResponse, NtResponse
    let domain_offset = header_size;
    let user_offset = domain_offset + domain_utf16.len() as u32;
    let ws_offset = user_offset + username_utf16.len() as u32;
    let lm_offset = ws_offset + workstation_utf16.len() as u32;
    let nt_offset = lm_offset + lm_response.len() as u32;

    let mut msg = Vec::new();

    // Signature (8 bytes)
    msg.extend_from_slice(b"NTLMSSP\x00");

    // MessageType (4 bytes) -> total 12
    msg.extend_from_slice(&3u32.to_le_bytes());

    // LmChallengeResponseFields: Len(2) + MaxLen(2) + Offset(4) -> total 20
    msg.extend_from_slice(&(lm_response.len() as u16).to_le_bytes());
    msg.extend_from_slice(&(lm_response.len() as u16).to_le_bytes());
    msg.extend_from_slice(&lm_offset.to_le_bytes());

    // NtChallengeResponseFields -> total 28
    msg.extend_from_slice(&(nt_response.len() as u16).to_le_bytes());
    msg.extend_from_slice(&(nt_response.len() as u16).to_le_bytes());
    msg.extend_from_slice(&nt_offset.to_le_bytes());

    // DomainNameFields -> total 36
    msg.extend_from_slice(&(domain_utf16.len() as u16).to_le_bytes());
    msg.extend_from_slice(&(domain_utf16.len() as u16).to_le_bytes());
    msg.extend_from_slice(&domain_offset.to_le_bytes());

    // UserNameFields -> total 44
    msg.extend_from_slice(&(username_utf16.len() as u16).to_le_bytes());
    msg.extend_from_slice(&(username_utf16.len() as u16).to_le_bytes());
    msg.extend_from_slice(&user_offset.to_le_bytes());

    // WorkstationFields -> total 52
    msg.extend_from_slice(&(workstation_utf16.len() as u16).to_le_bytes());
    msg.extend_from_slice(&(workstation_utf16.len() as u16).to_le_bytes());
    msg.extend_from_slice(&ws_offset.to_le_bytes());

    // EncryptedRandomSessionKeyFields (empty — no KEY_EXCH) -> total 60
    msg.extend_from_slice(&0u16.to_le_bytes());  // Len = 0
    msg.extend_from_slice(&0u16.to_le_bytes());  // MaxLen = 0
    msg.extend_from_slice(&0u32.to_le_bytes());  // Offset = 0 (unused)

    // NegotiateFlags -> total 64
    msg.extend_from_slice(&NEGOTIATE_FLAGS.to_le_bytes());

    // Version (8 bytes) -> total 72
    // ProductMajorVersion=10, Minor=0, Build=19041, Revision=15
    msg.push(10);  // Major
    msg.push(0);   // Minor
    msg.extend_from_slice(&19041u16.to_le_bytes()); // Build
    msg.extend_from_slice(&[0x00, 0x00, 0x00]); // Revision padding
    msg.push(0x0F); // NTLMRevisionCurrent = 15

    debug_assert_eq!(msg.len(), header_size as usize);

    // Payload
    msg.extend_from_slice(&domain_utf16);
    msg.extend_from_slice(&username_utf16);
    msg.extend_from_slice(&workstation_utf16);
    msg.extend_from_slice(&lm_response);
    msg.extend_from_slice(&nt_response);

    (msg, session_key)
}

fn hmac_md5(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac =
        HmacMd5::new_from_slice(key).expect("HMAC-MD5 accepts any key size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn rand_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    use std::io::Read;
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut buf);
    } else {
        // Fallback: use system time as seed (not crypto-secure, but functional)
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        for (i, b) in buf.iter_mut().enumerate() {
            *b = ((seed >> (i % 16 * 8)) & 0xFF) as u8;
        }
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nt_hash_password() {
        let hash = nt_hash("Password");
        assert_eq!(hash.len(), 16);
        let expected = [
            0xa4, 0xf4, 0x9c, 0x40, 0x65, 0x10, 0xbd, 0xca,
            0xb6, 0x82, 0x4e, 0xe7, 0xc3, 0x0f, 0xd8, 0x52,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_negotiate_message_size() {
        let msg = build_negotiate_message();
        assert_eq!(msg.len(), 32);
        assert_eq!(&msg[0..8], b"NTLMSSP\x00");
        assert_eq!(u32::from_le_bytes([msg[8], msg[9], msg[10], msg[11]]), 1);
    }

    #[test]
    fn test_authenticate_message_header_size() {
        let nt_h = nt_hash("test");
        let challenge = [0u8; 8];
        let target_info = [];
        let (msg, _key) = build_authenticate_message("DOMAIN", "user", &nt_h, &challenge, &target_info);
        // Header should be 72 bytes, payload after that
        assert!(msg.len() >= 72);
        assert_eq!(&msg[0..8], b"NTLMSSP\x00");
        assert_eq!(u32::from_le_bytes([msg[8], msg[9], msg[10], msg[11]]), 3);
    }
}

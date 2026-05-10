//! Kerberos cryptography primitives.
//! Supports etype 23 (RC4-HMAC) and etypes 17/18 (AES128/256-CTS-HMAC-SHA1-96).

use hmac::{Hmac, Mac};
use md5::Md5;
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use rc4::{KeyInit, Rc4, StreamCipher};
use aes::cipher::{generic_array::GenericArray, BlockEncrypt, BlockDecrypt};
use aes::{Aes128, Aes256};

use crate::error::KrbError;

// ── RC4-HMAC (etype 23) ───────────────────────────────────────────────────────

pub fn rc4_hmac_decrypt(key: &[u8], key_usage: u32, ciphertext: &[u8]) -> Result<Vec<u8>, KrbError> {
    if ciphertext.len() < 16 {
        return Err(KrbError::Parse("RC4-HMAC ciphertext too short".into()));
    }
    let checksum = &ciphertext[..16];
    let data = &ciphertext[16..];
    let usage_bytes = key_usage.to_le_bytes();
    let k1 = hmac_md5(key, &usage_bytes);
    let k3 = hmac_md5(&k1, checksum);
    let mut rc4 = Rc4::<rc4::consts::U16>::new_from_slice(&k3)
        .map_err(|_| KrbError::Parse("RC4 key error".into()))?;
    let mut plaintext = data.to_vec();
    rc4.apply_keystream(&mut plaintext);
    if plaintext.len() < 8 {
        return Err(KrbError::Parse("RC4-HMAC decrypted too short".into()));
    }
    Ok(plaintext[8..].to_vec())
}

pub fn ntlm_hash(password: &str) -> Vec<u8> {
    let utf16: Vec<u8> = password.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    md4_digest(&utf16)
}

fn md4_digest(input: &[u8]) -> Vec<u8> {
    let mut msg = input.to_vec();
    let bit_len = (input.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 { msg.push(0x00); }
    msg.extend_from_slice(&bit_len.to_le_bytes());
    let mut a: u32 = 0x67452301;
    let mut b: u32 = 0xEFCDAB89;
    let mut c: u32 = 0x98BADCFE;
    let mut d: u32 = 0x10325476;
    for chunk in msg.chunks(64) {
        let mut x = [0u32; 16];
        for (i, w) in x.iter_mut().enumerate() {
            *w = u32::from_le_bytes(chunk[i*4..i*4+4].try_into().unwrap());
        }
        let (aa, bb, cc, dd) = (a, b, c, d);
        macro_rules! r1 {
            ($a:expr,$b:expr,$c:expr,$d:expr,$k:expr,$s:expr) => {
                $a = $a.wrapping_add(($b & $c) | (!$b & $d)).wrapping_add(x[$k]);
                $a = $a.rotate_left($s);
            };
        }
        r1!(a,b,c,d, 0, 3); r1!(d,a,b,c, 1, 7); r1!(c,d,a,b, 2,11); r1!(b,c,d,a, 3,19);
        r1!(a,b,c,d, 4, 3); r1!(d,a,b,c, 5, 7); r1!(c,d,a,b, 6,11); r1!(b,c,d,a, 7,19);
        r1!(a,b,c,d, 8, 3); r1!(d,a,b,c, 9, 7); r1!(c,d,a,b,10,11); r1!(b,c,d,a,11,19);
        r1!(a,b,c,d,12, 3); r1!(d,a,b,c,13, 7); r1!(c,d,a,b,14,11); r1!(b,c,d,a,15,19);
        macro_rules! r2 {
            ($a:expr,$b:expr,$c:expr,$d:expr,$k:expr,$s:expr) => {
                $a = $a.wrapping_add(($b & $c) | ($b & $d) | ($c & $d))
                       .wrapping_add(x[$k]).wrapping_add(0x5A827999u32);
                $a = $a.rotate_left($s);
            };
        }
        r2!(a,b,c,d, 0, 3); r2!(d,a,b,c, 4, 5); r2!(c,d,a,b, 8, 9); r2!(b,c,d,a,12,13);
        r2!(a,b,c,d, 1, 3); r2!(d,a,b,c, 5, 5); r2!(c,d,a,b, 9, 9); r2!(b,c,d,a,13,13);
        r2!(a,b,c,d, 2, 3); r2!(d,a,b,c, 6, 5); r2!(c,d,a,b,10, 9); r2!(b,c,d,a,14,13);
        r2!(a,b,c,d, 3, 3); r2!(d,a,b,c, 7, 5); r2!(c,d,a,b,11, 9); r2!(b,c,d,a,15,13);
        macro_rules! r3 {
            ($a:expr,$b:expr,$c:expr,$d:expr,$k:expr,$s:expr) => {
                $a = $a.wrapping_add($b ^ $c ^ $d)
                       .wrapping_add(x[$k]).wrapping_add(0x6ED9EBA1u32);
                $a = $a.rotate_left($s);
            };
        }
        r3!(a,b,c,d, 0, 3); r3!(d,a,b,c, 8, 9); r3!(c,d,a,b, 4,11); r3!(b,c,d,a,12,15);
        r3!(a,b,c,d, 2, 3); r3!(d,a,b,c,10, 9); r3!(c,d,a,b, 6,11); r3!(b,c,d,a,14,15);
        r3!(a,b,c,d, 1, 3); r3!(d,a,b,c, 9, 9); r3!(c,d,a,b, 5,11); r3!(b,c,d,a,13,15);
        r3!(a,b,c,d, 3, 3); r3!(d,a,b,c,11, 9); r3!(c,d,a,b, 7,11); r3!(b,c,d,a,15,15);
        a = a.wrapping_add(aa); b = b.wrapping_add(bb);
        c = c.wrapping_add(cc); d = d.wrapping_add(dd);
    }
    let mut out = Vec::with_capacity(16);
    out.extend_from_slice(&a.to_le_bytes());
    out.extend_from_slice(&b.to_le_bytes());
    out.extend_from_slice(&c.to_le_bytes());
    out.extend_from_slice(&d.to_le_bytes());
    out
}

fn hmac_md5(key: &[u8], data: &[u8]) -> Vec<u8> {
    type HmacMd5 = Hmac<Md5>;
    let mut mac = <HmacMd5 as Mac>::new_from_slice(key).expect("HMAC key");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

pub fn rc4_hmac_encrypt(key: &[u8], key_usage: u32, plaintext: &[u8]) -> Vec<u8> {
    use rand::RngCore;
    let mut confounder = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut confounder);
    let usage_bytes = key_usage.to_le_bytes();
    let k1 = hmac_md5(key, &usage_bytes);
    let k2 = hmac_md5(&k1, &confounder);
    let mut data = confounder.to_vec();
    data.extend_from_slice(plaintext);
    let checksum = hmac_md5(&k2, &data);
    let k3 = hmac_md5(&k1, &checksum);
    let mut rc4 = Rc4::<rc4::consts::U16>::new_from_slice(&k3).expect("RC4 key");
    let mut cipher_data = data.clone();
    rc4.apply_keystream(&mut cipher_data);
    let mut out = checksum;
    out.extend(cipher_data);
    out
}

// ── AES helpers ───────────────────────────────────────────────────────────────

fn aes_ecb_encrypt_block(key: &[u8], block: &[u8]) -> Vec<u8> {
    if key.len() == 32 {
        let cipher = Aes256::new(GenericArray::from_slice(key));
        let mut b = *GenericArray::from_slice(block);
        cipher.encrypt_block(&mut b);
        b.to_vec()
    } else {
        let cipher = Aes128::new(GenericArray::from_slice(key));
        let mut b = *GenericArray::from_slice(block);
        cipher.encrypt_block(&mut b);
        b.to_vec()
    }
}

fn aes_ecb_decrypt_block(key: &[u8], block: &[u8]) -> Vec<u8> {
    if key.len() == 32 {
        let cipher = Aes256::new(GenericArray::from_slice(key));
        let mut b = *GenericArray::from_slice(block);
        cipher.decrypt_block(&mut b);
        b.to_vec()
    } else {
        let cipher = Aes128::new(GenericArray::from_slice(key));
        let mut b = *GenericArray::from_slice(block);
        cipher.decrypt_block(&mut b);
        b.to_vec()
    }
}

// ── RFC 3961 n-fold ───────────────────────────────────────────────────────────

fn gcd_n(a: usize, b: usize) -> usize { if b == 0 { a } else { gcd_n(b, a % b) } }
fn lcm_n(a: usize, b: usize) -> usize { a / gcd_n(a, b) * b }

/// RFC 3961 §5.1 n-fold: compress/expand `input` to exactly `n_bits` bits.
///
/// "Before each repetition the input is rotated to the RIGHT by 13 bit positions."
/// Rotate-right-by-k means: new[j] = old[(j + N - k) % N]
fn n_fold(input: &[u8], n_bits: usize) -> Vec<u8> {
    let in_bytes = input.len();
    let in_bits  = in_bytes * 8;
    let out_bytes = n_bits / 8;
    let lcm_bytes = lcm_n(in_bytes, out_bytes);

    let mut buf = vec![0u8; lcm_bytes];
    for i in 0..lcm_bytes {
        let copy_num   = i / in_bytes;
        let byte_in_cp = i % in_bytes;
        // rotate right by (13 * copy_num) bits
        let rot       = (13 * copy_num) % in_bits;
        // new bit (byte_in_cp*8) comes from old bit (byte_in_cp*8 + in_bits - rot) % in_bits
        let start_bit = (byte_in_cp * 8 + in_bits - rot) % in_bits;
        let src = start_bit / 8;
        let off = start_bit % 8;
        buf[i] = if off == 0 {
            input[src]
        } else {
            (((input[src] as u16) << off) | ((input[(src + 1) % in_bytes] as u16) >> (8 - off))) as u8
        };
    }

    // 1's complement sum of out_bytes-length pieces.
    let mut result = vec![0u8; out_bytes];
    let chunks = lcm_bytes / out_bytes;
    for c in 0..chunks {
        let mut carry = 0u32;
        for j in (0..out_bytes).rev() {
            let s = result[j] as u32 + buf[c * out_bytes + j] as u32 + carry;
            result[j] = (s & 0xFF) as u8;
            carry     = s >> 8;
        }
        // end-around carry
        let mut k = out_bytes as isize - 1;
        while carry > 0 {
            let s = result[k as usize] as u32 + carry;
            result[k as usize] = (s & 0xFF) as u8;
            carry = s >> 8;
            k = ((k - 1) + out_bytes as isize) % out_bytes as isize;
        }
    }
    result
}

// ── RFC 3961/3962 key derivation ─────────────────────────────────────────────

/// DK(Key, Constant) — RFC 3961 §5.1
/// = k-truncate(E(Key, n-fold(Constant, 128), CBC-ECB-chain))
fn dk(key: &[u8], constant: &[u8]) -> Vec<u8> {
    let key_len = key.len();
    let folded  = n_fold(constant, 128);    // n-fold constant to one AES block
    let mut result = Vec::new();
    let mut block  = folded;
    while result.len() < key_len {
        let enc = aes_ecb_encrypt_block(key, &block);
        result.extend_from_slice(&enc);
        block = enc;
    }
    result.truncate(key_len);
    result
}

/// DK for key-usage derivation: constant = usage(4 BE bytes) || octet
fn dk_aes(key: &[u8], usage: u32, octet: u8) -> Vec<u8> {
    let mut constant = usage.to_be_bytes().to_vec();
    constant.push(octet);
    dk(key, &constant)
}

// ── AES-CBC-CTS ───────────────────────────────────────────────────────────────

/// AES-CBC-CTS encrypt — matches Impacket's `basic_encrypt` exactly.
///
/// Output length = input length (proper CTS: last block is truncated, not padded).
/// Algorithm:
///   1. Zero-pad plaintext to 16-byte multiple → run AES-CBC with zero IV
///   2. If len > 16: rearrange last two CBC blocks:
///      output = cbc[:-32] + cbc[-16:] + cbc[-32:-16][:lastlen]
fn aes_cts_encrypt(key: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let plen = plaintext.len();

    // pad for CBC
    let mut padded = plaintext.to_vec();
    while padded.len() % 16 != 0 { padded.push(0); }

    // AES-CBC with zero IV
    let mut cbc = Vec::with_capacity(padded.len());
    let mut prev = [0u8; 16];
    for chunk in padded.chunks(16) {
        let xored: Vec<u8> = chunk.iter().zip(prev.iter()).map(|(a, b)| a ^ b).collect();
        let enc = aes_ecb_encrypt_block(key, &xored);
        cbc.extend_from_slice(&enc);
        prev.copy_from_slice(&enc);
    }

    if plen <= 16 {
        return cbc[..plen].to_vec();
    }

    // CTS rearrangement (Impacket CS3 variant):
    //   lastlen  = len(plaintext) % 16, or 16 if a perfect multiple
    //   output   = cbc[:-32]  +  cbc[-16:]  +  cbc[-32:-16][:lastlen]
    let lastlen = if plen % 16 == 0 { 16 } else { plen % 16 };
    let n = cbc.len();

    let mut out = Vec::with_capacity(plen);
    out.extend_from_slice(&cbc[..n - 32]);                  // all blocks except last 2
    out.extend_from_slice(&cbc[n - 16..]);                  // last CBC block  (16 bytes)
    out.extend_from_slice(&cbc[n - 32..n - 16][..lastlen]); // 2nd-to-last[:lastlen]
    // total = (n-32) + 16 + lastlen = plen  ✓
    out
}

/// AES-CBC-CTS decrypt — matches Impacket's `basic_decrypt` exactly.
fn aes_cts_decrypt(key: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let clen = ciphertext.len();

    if clen == 16 {
        return aes_ecb_decrypt_block(key, ciphertext);
    }

    // Split into 16-byte chunks (last may be short)
    let cblocks: Vec<&[u8]> = ciphertext.chunks(16).collect();
    let lastlen  = cblocks.last().unwrap().len();
    let nblocks  = cblocks.len();

    let mut plaintext = Vec::new();
    let mut prev      = vec![0u8; 16];

    // Decrypt all blocks except the last two via CBC
    for i in 0..nblocks - 2 {
        let dec: Vec<u8> = aes_ecb_decrypt_block(key, cblocks[i])
            .iter().zip(prev.iter()).map(|(a, b)| a ^ b).collect();
        plaintext.extend_from_slice(&dec);
        prev = cblocks[i].to_vec();
    }

    // Reverse CTS for the last two "blocks"
    let second_last = cblocks[nblocks - 2];   // full 16-byte block
    let last        = cblocks[nblocks - 1];   // may be shorter than 16 bytes

    // Decrypt the second-to-last block → produces plaintext that fills in the gap
    let bb      = aes_ecb_decrypt_block(key, second_last);
    let last_pt: Vec<u8> = bb[..lastlen].iter().zip(last.iter()).map(|(a, b)| a ^ b).collect();
    let omitted = &bb[lastlen..];  // bytes stolen to pad `last` to 16

    // Rebuild the full last block and decrypt it with CBC
    let mut last_padded = last.to_vec();
    last_padded.extend_from_slice(omitted);
    let second_dec: Vec<u8> = aes_ecb_decrypt_block(key, &last_padded)
        .iter().zip(prev.iter()).map(|(a, b)| a ^ b).collect();

    plaintext.extend_from_slice(&second_dec);
    plaintext.extend_from_slice(&last_pt);
    plaintext
}

// ── AES-CTS-HMAC-SHA1-96 (etypes 17 & 18) ────────────────────────────────────

fn hmac_sha1_96(key: &[u8], data: &[u8]) -> Vec<u8> {
    type HmacSha1 = Hmac<Sha1>;
    let mut mac = <HmacSha1 as Mac>::new_from_slice(key).expect("HMAC key");
    mac.update(data);
    mac.finalize().into_bytes()[..12].to_vec()
}

/// AES-CTS-HMAC-SHA1-96 encrypt (RFC 3961 §5.3 / RFC 3962).
///   C := AES-CTS(Ke, confounder || plaintext)
///   H := HMAC-SHA1-96(Ki, confounder || plaintext)   ← over plaintext only, NOT ciphertext
///   output := C || H
pub fn aes_hmac_sha1_encrypt(key: &[u8], key_usage: u32, plaintext: &[u8]) -> Vec<u8> {
    use rand::RngCore;
    let mut confounder = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut confounder);
    let mut data = confounder.to_vec();
    data.extend_from_slice(plaintext);

    let ke = dk_aes(key, key_usage, 0xAA);
    let ki = dk_aes(key, key_usage, 0x55);

    let ct       = aes_cts_encrypt(&ke, &data);
    let checksum = hmac_sha1_96(&ki, &data);   // RFC 3962: HMAC over plaintext only

    let mut out = ct;
    out.extend(checksum);
    out
}

/// AES-CTS-HMAC-SHA1-96 decrypt. Returns the plaintext (confounder stripped).
pub fn aes_hmac_sha1_decrypt(key: &[u8], key_usage: u32, ciphertext: &[u8]) -> Result<Vec<u8>, KrbError> {
    // wire format: ciphertext || 12-byte HMAC
    if ciphertext.len() < 28 {
        return Err(KrbError::Parse("AES ciphertext too short".into()));
    }
    let (ct, _mac) = ciphertext.split_at(ciphertext.len() - 12);

    let ke = dk_aes(key, key_usage, 0xAA);
    let plain = aes_cts_decrypt(&ke, ct);

    // confounder = first 16 bytes for AES
    if plain.len() < 16 {
        return Err(KrbError::Parse("AES decrypted too short".into()));
    }
    Ok(plain[16..].to_vec())
}

// ── AES string-to-key (RFC 3962 §4) ─────────────────────────────────────────

/// RFC 3962 §4 string-to-key:
///   tkey     = PBKDF2-HMAC-SHA1(passphrase, salt, iter=4096, len=key_len)
///   base-key = DK(tkey, "kerberos")
pub fn aes_string_to_key(password: &str, salt: &str, etype: i64) -> Vec<u8> {
    let key_len = if etype == 18 { 32usize } else { 16usize };
    let mut tkey = vec![0u8; key_len];
    pbkdf2_hmac::<Sha1>(password.as_bytes(), salt.as_bytes(), 4096, &mut tkey);
    // mandatory DK step — without this the key does NOT match what Windows KDC expects
    dk(&tkey, b"kerberos")
}

// ── PA-ENC-TIMESTAMP ─────────────────────────────────────────────────────────

use crate::kerberos::asn1::*;

pub fn build_pa_enc_timestamp(key: &[u8], etype: i64) -> Result<Vec<u8>, KrbError> {
    let now    = chrono::Utc::now();
    let ts_str = now.format("%Y%m%d%H%M%SZ").to_string();
    let usec   = now.timestamp_subsec_micros();

    let inner = sequence(&[
        ctx(0, &encode_generalized_time(&ts_str)),
        ctx(1, &encode_uint(usec)),
    ].concat());

    let encrypted = match etype {
        23        => rc4_hmac_encrypt(key, 1, &inner),
        17 | 18   => aes_hmac_sha1_encrypt(key, 1, &inner),
        e         => return Err(KrbError::UnsupportedEtype(e)),
    };
    Ok(encrypted)
}

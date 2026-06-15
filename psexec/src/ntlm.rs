
use hmac::{Hmac, Mac};
use md5::Md5;
use rand::Rng;

type HmacMd5 = Hmac<Md5>;


pub const NTLMSSP_SIGNATURE: &[u8; 8] = b"NTLMSSP\0";

pub const NTLM_NEGOTIATE:    u32 = 1;
pub const NTLM_CHALLENGE:    u32 = 2;
pub const NTLM_AUTHENTICATE: u32 = 3;

pub const NTLMSSP_NEGOTIATE_UNICODE:    u32 = 0x0000_0001;
pub const NTLMSSP_REQUEST_TARGET:       u32 = 0x0000_0004;
pub const NTLMSSP_NEGOTIATE_SIGN:       u32 = 0x0000_0010;
pub const NTLMSSP_NEGOTIATE_NTLM:       u32 = 0x0000_0200;
pub const NTLMSSP_NEGOTIATE_EXTENDED:   u32 = 0x0008_0000; 
pub const NTLMSSP_NEGOTIATE_TARGET_INFO: u32 = 0x0080_0000;
pub const NTLMSSP_NEGOTIATE_VERSION:    u32 = 0x0200_0000;
pub const NTLMSSP_NEGOTIATE_128:        u32 = 0x2000_0000;
pub const NTLMSSP_NEGOTIATE_KEY_EXCH:   u32 = 0x4000_0000;
pub const NTLMSSP_NEGOTIATE_56:         u32 = 0x8000_0000;

// Default flags sent in NEGOTIATE
const TYPE1_FLAGS: u32 = NTLMSSP_NEGOTIATE_UNICODE
    | NTLMSSP_REQUEST_TARGET
    | NTLMSSP_NEGOTIATE_NTLM
    | NTLMSSP_NEGOTIATE_EXTENDED
    | NTLMSSP_NEGOTIATE_TARGET_INFO
    | NTLMSSP_NEGOTIATE_VERSION
    | NTLMSSP_NEGOTIATE_128
    | NTLMSSP_NEGOTIATE_KEY_EXCH
    | NTLMSSP_NEGOTIATE_56;


fn md4(data: &[u8]) -> [u8; 16] {
    let mut a: u32 = 0x6745_2301;
    let mut b: u32 = 0xEFCD_AB89;
    let mut c: u32 = 0x98BA_DCFE;
    let mut d: u32 = 0x1032_5476;

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 { msg.push(0); }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    for chunk in msg.chunks(64) {
        let mut x = [0u32; 16];
        for i in 0..16 {
            x[i] = u32::from_le_bytes([
                chunk[i * 4], chunk[i * 4 + 1], chunk[i * 4 + 2], chunk[i * 4 + 3],
            ]);
        }

        let (mut aa, mut bb, mut cc, mut dd) = (a, b, c, d);

        macro_rules! f { ($x:expr,$y:expr,$z:expr) => { ($x & $y) | (!$x & $z) } }
        macro_rules! r1 { ($a:ident,$b:ident,$c:ident,$d:ident,$k:expr,$s:expr) => {
            $a = ($a.wrapping_add(f!($b,$c,$d)).wrapping_add(x[$k])).rotate_left($s);
        }}
        r1!(aa,bb,cc,dd, 0, 3); r1!(dd,aa,bb,cc, 1, 7); r1!(cc,dd,aa,bb, 2,11); r1!(bb,cc,dd,aa, 3,19);
        r1!(aa,bb,cc,dd, 4, 3); r1!(dd,aa,bb,cc, 5, 7); r1!(cc,dd,aa,bb, 6,11); r1!(bb,cc,dd,aa, 7,19);
        r1!(aa,bb,cc,dd, 8, 3); r1!(dd,aa,bb,cc, 9, 7); r1!(cc,dd,aa,bb,10,11); r1!(bb,cc,dd,aa,11,19);
        r1!(aa,bb,cc,dd,12, 3); r1!(dd,aa,bb,cc,13, 7); r1!(cc,dd,aa,bb,14,11); r1!(bb,cc,dd,aa,15,19);

        macro_rules! g { ($x:expr,$y:expr,$z:expr) => { ($x & $y) | ($x & $z) | ($y & $z) } }
        macro_rules! r2 { ($a:ident,$b:ident,$c:ident,$d:ident,$k:expr,$s:expr) => {
            $a = ($a.wrapping_add(g!($b,$c,$d)).wrapping_add(x[$k]).wrapping_add(0x5A82_7999u32)).rotate_left($s);
        }}
        r2!(aa,bb,cc,dd, 0, 3); r2!(dd,aa,bb,cc, 4, 5); r2!(cc,dd,aa,bb, 8, 9); r2!(bb,cc,dd,aa,12,13);
        r2!(aa,bb,cc,dd, 1, 3); r2!(dd,aa,bb,cc, 5, 5); r2!(cc,dd,aa,bb, 9, 9); r2!(bb,cc,dd,aa,13,13);
        r2!(aa,bb,cc,dd, 2, 3); r2!(dd,aa,bb,cc, 6, 5); r2!(cc,dd,aa,bb,10, 9); r2!(bb,cc,dd,aa,14,13);
        r2!(aa,bb,cc,dd, 3, 3); r2!(dd,aa,bb,cc, 7, 5); r2!(cc,dd,aa,bb,11, 9); r2!(bb,cc,dd,aa,15,13);

        macro_rules! h { ($x:expr,$y:expr,$z:expr) => { $x ^ $y ^ $z } }
        macro_rules! r3 { ($a:ident,$b:ident,$c:ident,$d:ident,$k:expr,$s:expr) => {
            $a = ($a.wrapping_add(h!($b,$c,$d)).wrapping_add(x[$k]).wrapping_add(0x6ED9_EBA1u32)).rotate_left($s);
        }}
        r3!(aa,bb,cc,dd, 0, 3); r3!(dd,aa,bb,cc, 8, 9); r3!(cc,dd,aa,bb, 4,11); r3!(bb,cc,dd,aa,12,15);
        r3!(aa,bb,cc,dd, 2, 3); r3!(dd,aa,bb,cc,10, 9); r3!(cc,dd,aa,bb, 6,11); r3!(bb,cc,dd,aa,14,15);
        r3!(aa,bb,cc,dd, 1, 3); r3!(dd,aa,bb,cc, 9, 9); r3!(cc,dd,aa,bb, 5,11); r3!(bb,cc,dd,aa,13,15);
        r3!(aa,bb,cc,dd, 3, 3); r3!(dd,aa,bb,cc,11, 9); r3!(cc,dd,aa,bb, 7,11); r3!(bb,cc,dd,aa,15,15);

        a = a.wrapping_add(aa); b = b.wrapping_add(bb);
        c = c.wrapping_add(cc); d = d.wrapping_add(dd);
    }

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a.to_le_bytes()); out[4..8].copy_from_slice(&b.to_le_bytes());
    out[8..12].copy_from_slice(&c.to_le_bytes()); out[12..16].copy_from_slice(&d.to_le_bytes());
    out
}

fn rc4(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut s: [u8; 256] = core::array::from_fn(|i| i as u8);
    let mut j = 0usize;
    for i in 0..256 {
        j = (j + s[i] as usize + key[i % key.len()] as usize) % 256;
        s.swap(i, j);
    }
    let (mut i, mut j) = (0usize, 0usize);
    data.iter().map(|&b| {
        i = (i + 1) % 256;
        j = (j + s[i] as usize) % 256;
        s.swap(i, j);
        b ^ s[(s[i] as usize + s[j] as usize) % 256]
    }).collect()
}

fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut mac = HmacMd5::new_from_slice(key).expect("HMAC-MD5 key");
    mac.update(data);
    mac.finalize().into_bytes().into()
}


/// Compute NT hash 
pub fn nt_hash_from_password(password: &str) -> [u8; 16] {
    let utf16: Vec<u8> = password
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    md4(&utf16)
}

/// Parse LMHASH:NTHASH hex string
pub fn parse_hash_string(s: &str) -> crate::error::Result<[u8; 16]> {
    let parts: Vec<&str> = s.splitn(2, ':').collect();
    if parts.len() != 2 {
        return Err("hashes must be in LMHASH:NTHASH format".into());
    }
    let nt_hex = parts[1];
    if nt_hex.len() != 32 {
        return Err(format!("NT hash must be 32 hex chars, got {}", nt_hex.len()).into());
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&nt_hex[i*2..i*2+2], 16)
            .map_err(|_| "invalid hex in NT hash")?;
    }
    Ok(out)
}


#[derive(Clone)]
pub struct NtlmContext {
    pub username: String,
    pub domain:   String,
    pub nt_hash:  [u8; 16],
}

impl NtlmContext {
    pub fn from_password(username: &str, domain: &str, password: &str) -> Self {
        Self {
            username: username.to_string(),
            domain:   domain.to_string(),
            nt_hash:  nt_hash_from_password(password),
        }
    }

    pub fn from_nt_hash(username: &str, domain: &str, nt_hash: [u8; 16]) -> Self {
        Self { username: username.to_string(), domain: domain.to_string(), nt_hash }
    }

    pub fn negotiate(&self) -> Vec<u8> {
        
        const HDR: usize = 40;
        let mut m = Vec::with_capacity(HDR);
        m.extend_from_slice(NTLMSSP_SIGNATURE);
        m.extend_from_slice(&NTLM_NEGOTIATE.to_le_bytes());
        m.extend_from_slice(&TYPE1_FLAGS.to_le_bytes());
        m.extend_from_slice(&0u16.to_le_bytes()); 
        m.extend_from_slice(&0u16.to_le_bytes()); 
        m.extend_from_slice(&(HDR as u32).to_le_bytes());
        m.extend_from_slice(&0u16.to_le_bytes());
        m.extend_from_slice(&0u16.to_le_bytes());
        m.extend_from_slice(&(HDR as u32).to_le_bytes());
        m.extend_from_slice(&[10, 0, 0x61, 0x4a, 0x00, 0x00, 0x00, 0x0f]);
        m
    }

    
    pub fn authenticate(
        &self,
        type2: &[u8],
        client_nonce: &[u8; 8],
    ) -> crate::error::Result<(Vec<u8>, [u8; 16])> {
        if type2.len() < 56 {
            return Err("NTLM Type2 too short".into());
        }
        let server_flags = u32::from_le_bytes(type2[20..24].try_into().unwrap());
        let server_key_exch = (server_flags & NTLMSSP_NEGOTIATE_KEY_EXCH) != 0;
        let server_challenge: [u8; 8] = type2[24..32].try_into().unwrap();

        let ti_len    = u16::from_le_bytes(type2[40..42].try_into().unwrap()) as usize;
        let ti_offset = u32::from_le_bytes(type2[44..48].try_into().unwrap()) as usize;
        let target_info = if ti_len > 0 && ti_offset + ti_len <= type2.len() {
            type2[ti_offset..ti_offset + ti_len].to_vec()
        } else {
            Vec::new()
        };


        let user_upper: Vec<u8> = self.username
            .to_uppercase()
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let domain_wide: Vec<u8> = self.domain
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let mut identity = user_upper;
        identity.extend_from_slice(&domain_wide);
        let ntv2_hash = hmac_md5(&self.nt_hash, &identity);


        let timestamp = windows_filetime();

        let mut blob = Vec::new();
        blob.extend_from_slice(&[0x01, 0x01, 0x00, 0x00]); 
        blob.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); 
        blob.extend_from_slice(&timestamp.to_le_bytes());
        blob.extend_from_slice(client_nonce);
        blob.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); 
        blob.extend_from_slice(&target_info);
        blob.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); 

        let mut proof_data = server_challenge.to_vec();
        proof_data.extend_from_slice(&blob);
        let nt_proof_str = hmac_md5(&ntv2_hash, &proof_data);

        let mut nt_response = nt_proof_str.to_vec();
        nt_response.extend_from_slice(&blob);

        let session_base_key: [u8; 16] = hmac_md5(&ntv2_hash, &nt_proof_str);

        let domain_bytes: Vec<u8> = self.domain
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let user_bytes: Vec<u8> = self.username
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let host_bytes: Vec<u8> = b"WORKSTATION"
            .iter()
            .flat_map(|&b| (b as u16).to_le_bytes())
            .collect();

        let lm_response = [0u8; 24];

  
        
        let hdr_size   = 88usize;
        let lm_off     = hdr_size;
        let nt_off     = lm_off + lm_response.len();
        let dom_off    = nt_off + nt_response.len();
        let user_off   = dom_off + domain_bytes.len();
        let host_off   = user_off + user_bytes.len();
        let session_off = host_off + host_bytes.len();
        
        
        let session_key_bytes: Vec<u8> = if server_key_exch {
            let exp: [u8; 16] = rand::thread_rng().gen();
            rc4(&session_base_key, &exp)
        } else {
            vec![]
        };

        let flags = TYPE1_FLAGS; // reuse same flags

        let mut t3 = Vec::new();
        t3.extend_from_slice(NTLMSSP_SIGNATURE);
        t3.extend_from_slice(&NTLM_AUTHENTICATE.to_le_bytes());

        // Security buffers (len, maxlen, offset):
        push_sec_buf(&mut t3, lm_response.len() as u16,  lm_off  as u32);
        push_sec_buf(&mut t3, nt_response.len() as u16,  nt_off  as u32);
        push_sec_buf(&mut t3, domain_bytes.len()  as u16, dom_off  as u32);
        push_sec_buf(&mut t3, user_bytes.len()    as u16, user_off as u32);
        push_sec_buf(&mut t3, host_bytes.len()    as u16, host_off as u32);
        push_sec_buf(&mut t3, session_key_bytes.len() as u16, session_off as u32);
        t3.extend_from_slice(&flags.to_le_bytes());
        t3.extend_from_slice(&[10, 0, 0, 0, 0, 0, 0, 15]);
        t3.extend_from_slice(&[0u8; 16]);

        // Payload
        t3.extend_from_slice(&lm_response);
        t3.extend_from_slice(&nt_response);
        t3.extend_from_slice(&domain_bytes);
        t3.extend_from_slice(&user_bytes);
        t3.extend_from_slice(&host_bytes);
        t3.extend_from_slice(&session_key_bytes);

        Ok((t3, session_base_key))
    }
}



const NTLMSSP_OID: &[u8] = &[
    0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a,
]; 

/// Wrap an NTLM NEGOTIATE message in SPNEGO negTokenInit 
pub fn spnego_wrap_negotiate(ntlm: &[u8]) -> Vec<u8> {
    let mech_token = asn1_explicit(2, &asn1_octet_string(ntlm));
    let mech_types = asn1_explicit(0, &asn1_sequence(&asn1_oid(NTLMSSP_OID)));
    let neg_init = asn1_sequence(&[mech_types, mech_token].concat());
    let token_init = asn1_explicit(0, &neg_init);
   
    let spnego_oid_encoded = asn1_oid(&[
        0x2b, 0x06, 0x01, 0x05, 0x05, 0x02, 
    ]);
    asn1_application(&[spnego_oid_encoded, token_init].concat())
}

/// Wrap an NTLM AUTHENTICATE message in SPNEGO negTokenResp
pub fn spnego_wrap_authenticate(ntlm: &[u8]) -> Vec<u8> {
    let resp_token = asn1_explicit(2, &asn1_octet_string(ntlm));
    let neg_resp = asn1_sequence(&resp_token);
    asn1_explicit(1, &neg_resp) 
}


fn asn1_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xff) as u8]
    }
}

fn asn1_tlv(tag: u8, data: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    v.extend(asn1_len(data.len()));
    v.extend_from_slice(data);
    v
}

fn asn1_sequence(data: &[u8]) -> Vec<u8>        { asn1_tlv(0x30, data) }
fn asn1_octet_string(data: &[u8]) -> Vec<u8>    { asn1_tlv(0x04, data) }
fn asn1_oid(oid: &[u8]) -> Vec<u8>              { asn1_tlv(0x06, oid) }
fn asn1_explicit(n: u8, data: &[u8]) -> Vec<u8> { asn1_tlv(0xa0 | n, data) }
fn asn1_application(data: &[u8]) -> Vec<u8>     { asn1_tlv(0x60, data) }


fn push_sec_buf(v: &mut Vec<u8>, len: u16, offset: u32) {
    v.extend_from_slice(&len.to_le_bytes());
    v.extend_from_slice(&len.to_le_bytes()); // max == len
    v.extend_from_slice(&offset.to_le_bytes());
}

fn windows_filetime() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    (secs + 11_644_473_600) * 10_000_000
}

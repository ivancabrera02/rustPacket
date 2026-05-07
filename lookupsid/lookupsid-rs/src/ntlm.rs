/// NTLM Authentication (NTLMv2) — MS-NLMP
use anyhow::{anyhow, Result};
use hmac::{Hmac, Mac};
use md5::Md5;

type HmacMd5 = Hmac<Md5>;

pub const NTLM_NEGOTIATE: u32 = 1;
pub const NTLM_CHALLENGE: u32 = 2;
pub const NTLM_AUTHENTICATE: u32 = 3;

pub const NTLMSSP_NEGOTIATE_UNICODE: u32 = 0x00000001;
pub const NTLMSSP_REQUEST_TARGET: u32 = 0x00000004;
pub const NTLMSSP_NEGOTIATE_NTLM: u32 = 0x00000200;
pub const NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY: u32 = 0x00080000;
pub const NTLMSSP_NEGOTIATE_ALWAYS_SIGN: u32 = 0x00008000;
pub const NTLMSSP_NEGOTIATE_56: u32 = 0x80000000;
pub const NTLMSSP_NEGOTIATE_128: u32 = 0x20000000;

const SIG: &[u8] = b"NTLMSSP\x00";

pub struct NtlmContext {
    pub username: String,
    pub password: String,
    pub domain: String,
    pub lm_hash: Option<Vec<u8>>,
    pub nt_hash: Option<Vec<u8>>,
}

pub struct NtlmChallenge {
    pub target_name: String,
    pub flags: u32,
    pub server_challenge: Vec<u8>,
    pub target_info: Vec<u8>,
}

/// Result of build_authenticate: the NTLM Type-3 message + the session base key
pub struct AuthenticateResult {
    pub message: Vec<u8>,
    pub session_key: Vec<u8>,
}

impl NtlmContext {
    pub fn new(username: &str, password: &str, domain: &str) -> Self {
        Self { username: username.into(), password: password.into(), domain: domain.into(), lm_hash: None, nt_hash: None }
    }
    pub fn with_hashes(username: &str, domain: &str, lm: Vec<u8>, nt: Vec<u8>) -> Self {
        Self { username: username.into(), password: String::new(), domain: domain.into(), lm_hash: Some(lm), nt_hash: Some(nt) }
    }

    pub fn build_negotiate(&self) -> Vec<u8> {
        let flags: u32 = NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_REQUEST_TARGET | NTLMSSP_NEGOTIATE_NTLM
            | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY | NTLMSSP_NEGOTIATE_ALWAYS_SIGN
            | NTLMSSP_NEGOTIATE_128 | NTLMSSP_NEGOTIATE_56;
        let mut m = Vec::with_capacity(32);
        m.extend_from_slice(SIG);
        m.extend_from_slice(&NTLM_NEGOTIATE.to_le_bytes());
        m.extend_from_slice(&flags.to_le_bytes());
        m.extend_from_slice(&[0u8; 8]); // DomainNameFields
        m.extend_from_slice(&[0u8; 8]); // WorkstationFields
        m
    }

    pub fn parse_challenge(&self, data: &[u8]) -> Result<NtlmChallenge> {
        if data.len() < 32 { return Err(anyhow!("challenge too short")); }
        if &data[0..8] != SIG { return Err(anyhow!("bad NTLM sig")); }
        if u32::from_le_bytes(data[8..12].try_into()?) != NTLM_CHALLENGE {
            return Err(anyhow!("not a Type-2"));
        }
        let tn_len = u16::from_le_bytes(data[12..14].try_into()?) as usize;
        let tn_off = u32::from_le_bytes(data[16..20].try_into()?) as usize;
        let flags = u32::from_le_bytes(data[20..24].try_into()?);
        let sc = data[24..32].to_vec();
        let (ti_len, ti_off) = if data.len() >= 48 {
            (u16::from_le_bytes(data[40..42].try_into()?) as usize,
             u32::from_le_bytes(data[44..48].try_into()?) as usize)
        } else { (0,0) };
        let ti = if ti_len > 0 && ti_off+ti_len <= data.len() { data[ti_off..ti_off+ti_len].to_vec() } else { vec![] };
        let tn = if tn_len > 0 && tn_off+tn_len <= data.len() { utf16le_decode(&data[tn_off..tn_off+tn_len]) } else { String::new() };
        Ok(NtlmChallenge { target_name: tn, flags, server_challenge: sc, target_info: ti })
    }

    /// Build Type-3 and return it together with the session base key (for SMB signing).
    pub fn build_authenticate(&self, ch: &NtlmChallenge) -> Result<AuthenticateResult> {
        let nt_hash = self.compute_nt_hash();
        let cc = rand_bytes(8);
        let ts = extract_timestamp(&ch.target_info).unwrap_or_else(|| filetime_now());
        let (nt_resp, lm_resp, session_key) = self.ntlmv2(&nt_hash, &ch.server_challenge, &cc, &ch.target_info, ts)?;

        let flags: u32 = NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_REQUEST_TARGET | NTLMSSP_NEGOTIATE_NTLM
            | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY | NTLMSSP_NEGOTIATE_ALWAYS_SIGN
            | NTLMSSP_NEGOTIATE_128 | NTLMSSP_NEGOTIATE_56;

        let dom = utf16le_encode(&self.domain);
        let usr = utf16le_encode(&self.username);
        let ws  = utf16le_encode("WORKSTATION");

        // Header = 64 bytes.  Payload order: domain, user, ws, lm, nt
        let hlen: usize = 64;
        let d_off = hlen;
        let u_off = d_off + dom.len();
        let w_off = u_off + usr.len();
        let l_off = w_off + ws.len();
        let n_off = l_off + lm_resp.len();

        let mut m = Vec::with_capacity(hlen + dom.len() + usr.len() + ws.len() + lm_resp.len() + nt_resp.len());
        m.extend_from_slice(SIG);
        m.extend_from_slice(&NTLM_AUTHENTICATE.to_le_bytes());
        sec_buf(&mut m, lm_resp.len() as u16, l_off as u32);
        sec_buf(&mut m, nt_resp.len() as u16, n_off as u32);
        sec_buf(&mut m, dom.len() as u16, d_off as u32);
        sec_buf(&mut m, usr.len() as u16, u_off as u32);
        sec_buf(&mut m, ws.len() as u16, w_off as u32);
        sec_buf(&mut m, 0, 0); // EncryptedRandomSessionKey
        m.extend_from_slice(&flags.to_le_bytes());
        debug_assert_eq!(m.len(), hlen);

        m.extend_from_slice(&dom);
        m.extend_from_slice(&usr);
        m.extend_from_slice(&ws);
        m.extend_from_slice(&lm_resp);
        m.extend_from_slice(&nt_resp);

        Ok(AuthenticateResult { message: m, session_key })
    }

    fn compute_nt_hash(&self) -> Vec<u8> {
        if let Some(ref h) = self.nt_hash { return h.clone(); }
        md4(&utf16le_encode(&self.password))
    }

    fn ntlmv2(&self, nt_hash: &[u8], sc: &[u8], cc: &[u8], ti: &[u8], ts: u64)
        -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)>
    {
        let rk = hmac_md5(nt_hash, &[utf16le_encode(&self.username.to_uppercase()), utf16le_encode(&self.domain)].concat());

        let mut blob = Vec::with_capacity(28 + ti.len() + 4);
        blob.extend_from_slice(&[1, 1, 0, 0]);
        blob.extend_from_slice(&0u32.to_le_bytes());
        blob.extend_from_slice(&ts.to_le_bytes());
        blob.extend_from_slice(cc);
        blob.extend_from_slice(&0u32.to_le_bytes());
        blob.extend_from_slice(ti);

        let proof = hmac_md5(&rk, &[sc, &blob].concat());
        let nt_resp = [&proof[..], &blob].concat();
        let lm_resp = [&hmac_md5(&rk, &[sc, cc].concat())[..], cc].concat();
        let sk = hmac_md5(&rk, &proof);
        Ok((nt_resp, lm_resp, sk))
    }
}

fn sec_buf(buf: &mut Vec<u8>, len: u16, off: u32) {
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(&off.to_le_bytes());
}

pub fn extract_timestamp(ti: &[u8]) -> Option<u64> {
    let mut o = 0;
    while o + 4 <= ti.len() {
        let id = u16::from_le_bytes(ti[o..o+2].try_into().ok()?);
        let ln = u16::from_le_bytes(ti[o+2..o+4].try_into().ok()?) as usize;
        o += 4;
        if id == 0 { break; }
        if id == 7 && ln == 8 && o+8 <= ti.len() {
            return Some(u64::from_le_bytes(ti[o..o+8].try_into().ok()?));
        }
        o += ln;
    }
    None
}

pub fn extract_av_string(ti: &[u8], target_id: u16) -> Option<String> {
    let mut o = 0;
    while o + 4 <= ti.len() {
        let id = u16::from_le_bytes(ti[o..o+2].try_into().ok()?);
        let ln = u16::from_le_bytes(ti[o+2..o+4].try_into().ok()?) as usize;
        o += 4;
        if id == 0 { break; }
        if id == target_id && ln > 0 && o+ln <= ti.len() {
            return Some(utf16le_decode(&ti[o..o+ln]));
        }
        o += ln;
    }
    None
}

pub fn utf16le_encode(s: &str) -> Vec<u8> { s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect() }
pub fn utf16le_decode(b: &[u8]) -> String {
    String::from_utf16_lossy(&b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0],c[1]])).collect::<Vec<_>>())
}

pub fn hmac_md5(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut m = HmacMd5::new_from_slice(key).unwrap();
    m.update(data);
    m.finalize().into_bytes().to_vec()
}

fn rand_bytes(n: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut b = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut b);
    b
}

fn filetime_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let s = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    (s + 11644473600) * 10_000_000
}

/// MD4 per RFC 1320
pub fn md4(data: &[u8]) -> Vec<u8> {
    let mut st: [u32;4] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476];
    let bits = (data.len() as u64) * 8;
    let mut p = data.to_vec();
    p.push(0x80);
    while p.len() % 64 != 56 { p.push(0); }
    p.extend_from_slice(&bits.to_le_bytes());
    for blk in p.chunks(64) {
        let mut x = [0u32;16];
        for i in 0..16 { x[i] = u32::from_le_bytes(blk[i*4..i*4+4].try_into().unwrap()); }
        let (mut a,mut b,mut c,mut d) = (st[0],st[1],st[2],st[3]);
        macro_rules! r1 { ($a:expr,$b:expr,$c:expr,$d:expr,$k:expr,$s:expr) => {
            $a = $a.wrapping_add(($b&$c)|(!$b&$d)).wrapping_add(x[$k]).rotate_left($s); }; }
        r1!(a,b,c,d,0,3);r1!(d,a,b,c,1,7);r1!(c,d,a,b,2,11);r1!(b,c,d,a,3,19);
        r1!(a,b,c,d,4,3);r1!(d,a,b,c,5,7);r1!(c,d,a,b,6,11);r1!(b,c,d,a,7,19);
        r1!(a,b,c,d,8,3);r1!(d,a,b,c,9,7);r1!(c,d,a,b,10,11);r1!(b,c,d,a,11,19);
        r1!(a,b,c,d,12,3);r1!(d,a,b,c,13,7);r1!(c,d,a,b,14,11);r1!(b,c,d,a,15,19);
        macro_rules! r2 { ($a:expr,$b:expr,$c:expr,$d:expr,$k:expr,$s:expr) => {
            $a = $a.wrapping_add(($b&$c)|($b&$d)|($c&$d)).wrapping_add(x[$k]).wrapping_add(0x5A827999).rotate_left($s); }; }
        r2!(a,b,c,d,0,3);r2!(d,a,b,c,4,5);r2!(c,d,a,b,8,9);r2!(b,c,d,a,12,13);
        r2!(a,b,c,d,1,3);r2!(d,a,b,c,5,5);r2!(c,d,a,b,9,9);r2!(b,c,d,a,13,13);
        r2!(a,b,c,d,2,3);r2!(d,a,b,c,6,5);r2!(c,d,a,b,10,9);r2!(b,c,d,a,14,13);
        r2!(a,b,c,d,3,3);r2!(d,a,b,c,7,5);r2!(c,d,a,b,11,9);r2!(b,c,d,a,15,13);
        macro_rules! r3 { ($a:expr,$b:expr,$c:expr,$d:expr,$k:expr,$s:expr) => {
            $a = $a.wrapping_add($b^$c^$d).wrapping_add(x[$k]).wrapping_add(0x6ED9EBA1).rotate_left($s); }; }
        r3!(a,b,c,d,0,3);r3!(d,a,b,c,8,9);r3!(c,d,a,b,4,11);r3!(b,c,d,a,12,15);
        r3!(a,b,c,d,2,3);r3!(d,a,b,c,10,9);r3!(c,d,a,b,6,11);r3!(b,c,d,a,14,15);
        r3!(a,b,c,d,1,3);r3!(d,a,b,c,9,9);r3!(c,d,a,b,5,11);r3!(b,c,d,a,13,15);
        r3!(a,b,c,d,3,3);r3!(d,a,b,c,11,9);r3!(c,d,a,b,7,11);r3!(b,c,d,a,15,15);
        st[0]=st[0].wrapping_add(a);st[1]=st[1].wrapping_add(b);
        st[2]=st[2].wrapping_add(c);st[3]=st[3].wrapping_add(d);
    }
    st.iter().flat_map(|s| s.to_le_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn md4_vectors() {
        assert_eq!(hex::encode(md4(b"")), "31d6cfe0d16ae931b73c59d7e0c089c0");
        assert_eq!(hex::encode(md4(b"a")), "bde52cb31de33e46245e05fbdbd6fb24");
        assert_eq!(hex::encode(md4(b"abc")), "a448017aaf21d8525fc10ae87aa6729d");
    }
    #[test] fn nt_hash_empty() {
        let c = NtlmContext::new("","","");
        assert_eq!(hex::encode(c.compute_nt_hash()), "31d6cfe0d16ae931b73c59d7e0c089c0");
    }
    #[test] fn nt_hash_pass() {
        let c = NtlmContext::new("","Password","");
        assert_eq!(hex::encode(c.compute_nt_hash()), "a4f49c406510bdcab6824ee7c30fd852");
    }
}

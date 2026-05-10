
use anyhow::{anyhow, bail, Result};
use hmac::{Hmac, Mac};
use md4::Md4;
use md5::Md5;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub fn nt_hash_from_password(password: &str) -> [u8; 16] {
    let utf16: Vec<u8> = password.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    use md4::Digest;
    let mut h = Md4::new();
    h.update(&utf16);
    let result = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&result);
    out
}

pub fn parse_nt_hash(nt_hex: &str) -> Result<[u8; 16]> {
    let s = nt_hex.trim();
    if s.is_empty() {
        return Ok([0u8; 16]);
    }
    let bytes = hex::decode(s).map_err(|e| anyhow!("Invalid NT hash hex: {e}"))?;
    if bytes.len() != 16 {
        bail!("NT hash must be 16 bytes (32 hex chars), got {}", bytes.len());
    }
    Ok(bytes.try_into().unwrap())
}


fn windows_filetime_now() -> u64 {
    const EPOCH_DIFF_SECS: u64 = 11_644_473_600;
    let s = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    (s + EPOCH_DIFF_SECS) * 10_000_000
}

fn compute_ntlmv2(
    nt_hash: &[u8; 16],
    username: &str,
    domain: &str,
    server_challenge: &[u8; 8],
    client_challenge: &[u8; 8],
    target_info: &[u8],
    timestamp: u64,
) -> Vec<u8> {
    // ResponseKeyNT = HMAC-MD5(NT_hash, UPPER(user)||domain) 
    let upper: Vec<u8> = username.to_uppercase().encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let dom: Vec<u8> = domain.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let mut h1: Hmac<Md5> = Hmac::<Md5>::new_from_slice(nt_hash).unwrap();
    h1.update(&upper);
    h1.update(&dom);
    let response_key_nt: [u8; 16] = h1.finalize().into_bytes().into();

    let mut blob = Vec::new();
    blob.extend_from_slice(&[0x01, 0x01]);      
    blob.extend_from_slice(&[0u8; 6]);           
    blob.extend_from_slice(&timestamp.to_le_bytes());
    blob.extend_from_slice(client_challenge);
    blob.extend_from_slice(&[0u8; 4]);           
    blob.extend_from_slice(target_info);
    blob.extend_from_slice(&[0u8; 4]);          

    // NTProofStr = HMAC-MD5(ResponseKeyNT, ServerChallenge||blob)
    let mut h2: Hmac<Md5> = Hmac::<Md5>::new_from_slice(&response_key_nt).unwrap();
    h2.update(server_challenge);
    h2.update(&blob);
    let nt_proof: [u8; 16] = h2.finalize().into_bytes().into();

    let mut response = Vec::with_capacity(16 + blob.len());
    response.extend_from_slice(&nt_proof);
    response.extend_from_slice(&blob);
    response
}


const SIGNATURE: &[u8; 8] = b"NTLMSSP\0";

mod nflags {
    pub const UNICODE:       u32 = 0x0000_0001;
    pub const REQ_TARGET:    u32 = 0x0000_0004;
    pub const NTLM:          u32 = 0x0000_0200;
    pub const ALWAYS_SIGN:   u32 = 0x0000_8000;
    pub const EXT_SESSION:   u32 = 0x0008_0000;
    pub const TARGET_INFO:   u32 = 0x0080_0000;
    pub const KEY_128:       u32 = 0x2000_0000;
    pub const KEY_56:        u32 = 0x8000_0000;
}

pub fn build_negotiate() -> Vec<u8> {
    let flags = nflags::UNICODE | nflags::REQ_TARGET | nflags::NTLM
              | nflags::ALWAYS_SIGN | nflags::EXT_SESSION
              | nflags::TARGET_INFO | nflags::KEY_128 | nflags::KEY_56;
    let mut m = Vec::new();
    m.extend_from_slice(SIGNATURE);
    m.extend_from_slice(&1u32.to_le_bytes()); 
    m.extend_from_slice(&flags.to_le_bytes());
    m.extend_from_slice(&[0u8; 8]);  
    m.extend_from_slice(&[0u8; 8]);  
    m
}

pub fn parse_challenge(data: &[u8]) -> Result<([u8; 8], Vec<u8>)> {
    if data.len() < 56 { bail!("CHALLENGE too short ({} bytes)", data.len()); }
    if &data[0..8] != SIGNATURE { bail!("Bad NTLMSSP signature"); }
    if u32::from_le_bytes(data[8..12].try_into().unwrap()) != 2 {
        bail!("Expected CHALLENGE (type 2)");
    }
    let sc: [u8; 8] = data[24..32].try_into().unwrap();
    let ti_len = u16::from_le_bytes([data[40], data[41]]) as usize;
    let ti_off = u32::from_le_bytes([data[44], data[45], data[46], data[47]]) as usize;
    let ti = if ti_len > 0 && ti_off + ti_len <= data.len() {
        data[ti_off..ti_off + ti_len].to_vec()
    } else {
        Vec::new()
    };
    Ok((sc, ti))
}

pub fn build_authenticate(nt_hash: &[u8; 16], username: &str, domain: &str,
                          server_challenge: &[u8; 8], target_info: &[u8]) -> Vec<u8> {
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let client_challenge: [u8; 8] = {
        let mut cc = [0u8; 8];
        let nano = ts.subsec_nanos().to_le_bytes();
        cc[..4].copy_from_slice(&nano);
        cc[4..].copy_from_slice(&(ts.as_secs() as u32).to_le_bytes());
        cc
    };

    let nt_resp = compute_ntlmv2(nt_hash, username, domain, server_challenge,
                                  &client_challenge, target_info, windows_filetime_now());

    let dom_bytes: Vec<u8> = domain.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let usr_bytes: Vec<u8> = username.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let ws_bytes:  Vec<u8> = b"WORKSTATION".iter().flat_map(|&b| [b, 0]).collect();
    let lm_resp = vec![0u8; 24]; // empty LM response for pass-the-hash

 
    let hdr: u32 = 64;
    let lm_off  = hdr;
    let nt_off  = lm_off  + lm_resp.len() as u32;
    let dom_off = nt_off  + nt_resp.len() as u32;
    let usr_off = dom_off + dom_bytes.len() as u32;
    let ws_off  = usr_off + usr_bytes.len() as u32;
    let key_off = ws_off  + ws_bytes.len() as u32;

    let flags = nflags::UNICODE | nflags::REQ_TARGET | nflags::NTLM
              | nflags::ALWAYS_SIGN | nflags::EXT_SESSION | nflags::TARGET_INFO;

    let mut m = Vec::new();
    m.extend_from_slice(SIGNATURE);
    m.extend_from_slice(&3u32.to_le_bytes()); 

    for (len, off) in [
        (lm_resp.len(), lm_off), (nt_resp.len(), nt_off),
        (dom_bytes.len(), dom_off), (usr_bytes.len(), usr_off),
        (ws_bytes.len(), ws_off), (0usize, key_off),
    ] {
        m.extend_from_slice(&(len as u16).to_le_bytes());
        m.extend_from_slice(&(len as u16).to_le_bytes());
        m.extend_from_slice(&off.to_le_bytes());
    }
    m.extend_from_slice(&flags.to_le_bytes());
    m.extend_from_slice(&lm_resp);
    m.extend_from_slice(&nt_resp);
    m.extend_from_slice(&dom_bytes);
    m.extend_from_slice(&usr_bytes);
    m.extend_from_slice(&ws_bytes);
    m
}

const OID_SPNEGO:  &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
const OID_NTLMSSP: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];

fn der_len(n: usize) -> Vec<u8> {
    if n < 128 { vec![n as u8] }
    else if n < 256 { vec![0x81, n as u8] }
    else { vec![0x82, (n >> 8) as u8, (n & 0xff) as u8] }
}

fn der_tlv(tag: u8, val: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    v.extend(der_len(val.len()));
    v.extend_from_slice(val);
    v
}

pub fn spnego_initial(ntlmssp: &[u8]) -> Vec<u8> {
    let mech_oid    = der_tlv(0x06, OID_NTLMSSP);
    let mech_types  = der_tlv(0xa0, &der_tlv(0x30, &mech_oid));
    let mech_token  = der_tlv(0xa2, &der_tlv(0x04, ntlmssp));
    let mut ti = Vec::new();
    ti.extend_from_slice(&mech_types);
    ti.extend_from_slice(&mech_token);
    let neg_init  = der_tlv(0xa0, &der_tlv(0x30, &ti));
    let spnego_oid = der_tlv(0x06, OID_SPNEGO);
    let mut inner = Vec::new();
    inner.extend_from_slice(&spnego_oid);
    inner.extend_from_slice(&neg_init);
    der_tlv(0x60, &inner)
}

pub fn spnego_resp(ntlmssp: &[u8]) -> Vec<u8> {
    let resp_token = der_tlv(0xa2, &der_tlv(0x04, ntlmssp));
    der_tlv(0xa1, &der_tlv(0x30, &resp_token))
}

pub fn unwrap_spnego(data: &[u8]) -> Vec<u8> {
    if let Some(off) = data.windows(8).position(|w| w == b"NTLMSSP\0") {
        data[off..].to_vec()
    } else {
        data.to_vec()
    }
}


fn ber_len(data: &[u8], pos: &mut usize) -> Result<usize> {
    if *pos >= data.len() { bail!("BER truncated"); }
    let b = data[*pos]; *pos += 1;
    if b < 0x80 { return Ok(b as usize); }
    let n = (b & 0x7f) as usize;
    if *pos + n > data.len() { bail!("BER long-form truncated"); }
    let mut len = 0usize;
    for _ in 0..n { len = (len << 8) | data[*pos] as usize; *pos += 1; }
    Ok(len)
}

fn ber_skip_tlv(data: &[u8], pos: &mut usize) -> Result<()> {
    if *pos >= data.len() { bail!("BER: unexpected end"); }
    *pos += 1; // tag
    let len = ber_len(data, pos)?;
    *pos += len;
    Ok(())
}

fn ber_read_tlv<'a>(data: &'a [u8], pos: &mut usize) -> Result<(u8, &'a [u8])> {
    if *pos >= data.len() { bail!("BER: unexpected end"); }
    let tag = data[*pos]; *pos += 1;
    let len = ber_len(data, pos)?;
    if *pos + len > data.len() { bail!("BER: value truncated"); }
    let val = &data[*pos..*pos + len];
    *pos += len;
    Ok((tag, val))
}



fn encode_int(n: u32) -> Vec<u8> {
    if n == 0 { return vec![0x02, 0x01, 0x00]; }
    let mut bytes = Vec::new();
    let mut v = n;
    while v > 0 { bytes.push((v & 0xff) as u8); v >>= 8; }
    bytes.reverse();
    if bytes[0] & 0x80 != 0 { bytes.insert(0, 0); }
    der_tlv(0x02, &bytes)
}

fn encode_str(s: &str) -> Vec<u8> { der_tlv(0x04, s.as_bytes()) }

pub fn encode_bind_request(msg_id: u32, mechanism: &str, credentials: &[u8]) -> Vec<u8> {
    
    let version = der_tlv(0x02, &[3u8]);
    let name    = der_tlv(0x04, b"");
    let mech    = der_tlv(0x04, mechanism.as_bytes());
    let creds   = der_tlv(0x04, credentials);
    let mut sasl_inner = Vec::new();
    sasl_inner.extend_from_slice(&mech);
    sasl_inner.extend_from_slice(&creds);
    let sasl = der_tlv(0xa3, &sasl_inner);

    let mut bind_inner = Vec::new();
    bind_inner.extend_from_slice(&version);
    bind_inner.extend_from_slice(&name);
    bind_inner.extend_from_slice(&sasl);
    let bind_req = der_tlv(0x60, &bind_inner); 

    let mut ldap = Vec::new();
    ldap.extend_from_slice(&encode_int(msg_id));
    ldap.extend_from_slice(&bind_req);
    der_tlv(0x30, &ldap) 
}

pub fn decode_bind_response(data: &[u8]) -> Result<(u32, Vec<u8>)> {
    let mut pos = 0;
    let (_, outer) = ber_read_tlv(data, &mut pos)?; // LDAPMessage SEQUENCE
    let mut p = 0;
    ber_skip_tlv(outer, &mut p)?; // messageID INTEGER

    let (_, bind_resp) = ber_read_tlv(outer, &mut p)?; // BindResponse 

    let mut bp = 0;
    let (_, rc_bytes) = ber_read_tlv(bind_resp, &mut bp)?;
    let rc = rc_bytes.first().copied().unwrap_or(0) as u32;

    let mut sasl_creds = Vec::new();
    while bp < bind_resp.len() {
        let tag = bind_resp[bp];
        if tag == 0x87 {
            // [7] IMPLICIT OCTET STRING = serverSaslCreds
            bp += 1;
            let cred_len = ber_len(bind_resp, &mut bp)?;
            if bp + cred_len <= bind_resp.len() {
                sasl_creds = bind_resp[bp..bp + cred_len].to_vec();
            }
            break;
        }
        // Skip any other TLV
        if ber_skip_tlv(bind_resp, &mut bp).is_err() { break; }
    }
    Ok((rc, sasl_creds))
}

fn encode_search_request(msg_id: u32, base: &str, scope: u8,
                          filter: &[u8], attrs: &[&str]) -> Vec<u8> {
    let mut req = Vec::new();
    req.extend_from_slice(&encode_str(base));           // baseObject
    req.extend_from_slice(&der_tlv(0x0a, &[scope]));   // scope ENUMERATED
    req.extend_from_slice(&der_tlv(0x0a, &[0]));        // derefAliases=never
    req.extend_from_slice(&der_tlv(0x02, &[0]));        // sizeLimit=0
    req.extend_from_slice(&der_tlv(0x02, &[0]));        // timeLimit=0
    req.extend_from_slice(&der_tlv(0x01, &[0]));        // typesOnly=false
    req.extend_from_slice(filter);
    let attrs_enc: Vec<u8> = attrs.iter().flat_map(|a| encode_str(a)).collect();
    req.extend_from_slice(&der_tlv(0x30, &attrs_enc));  // attributes

    let mut ldap = Vec::new();
    ldap.extend_from_slice(&encode_int(msg_id));
    ldap.extend_from_slice(&der_tlv(0x63, &req));       
    der_tlv(0x30, &ldap)
}

pub fn encode_present_filter(attr: &str) -> Vec<u8> {
    der_tlv(0x87, attr.as_bytes()) 
}

pub fn encode_equality_filter(attr: &str, value: &[u8]) -> Vec<u8> {
    let mut inner = Vec::new();
    inner.extend_from_slice(&encode_str(attr));
    inner.extend_from_slice(&der_tlv(0x04, value));
    der_tlv(0xa3, &inner) // [3] equalityMatch
}

fn encode_modify_request(msg_id: u32, dn: &str, attr: &str, value: Option<&[u8]>) -> Vec<u8> {
    let operation = der_tlv(0x0a, &[2u8]); 
    let attr_type = encode_str(attr);
    let vals = match value {
        Some(v) => der_tlv(0x31, &der_tlv(0x04, v)), 
        None    => der_tlv(0x31, &[]),          
    };
    let mut part_attr = Vec::new();
    part_attr.extend_from_slice(&attr_type);
    part_attr.extend_from_slice(&vals);
    let modification = der_tlv(0x30, &part_attr);
    let mut change = Vec::new();
    change.extend_from_slice(&operation);
    change.extend_from_slice(&modification);
    let changes = der_tlv(0x30, &der_tlv(0x30, &change));

    let mut mod_inner = Vec::new();
    mod_inner.extend_from_slice(&encode_str(dn));
    mod_inner.extend_from_slice(&changes);

    let mut ldap = Vec::new();
    ldap.extend_from_slice(&encode_int(msg_id));
    ldap.extend_from_slice(&der_tlv(0x66, &mod_inner)); 
    der_tlv(0x30, &ldap)
}

fn decode_modify_response(data: &[u8]) -> Result<u32> {
    let mut pos = 0;
    let (_, outer) = ber_read_tlv(data, &mut pos)?;
    let mut p = 0;
    ber_skip_tlv(outer, &mut p)?; // messageID
    let (_, resp) = ber_read_tlv(outer, &mut p)?; 
    let mut bp = 0;
    let (_, rc_bytes) = ber_read_tlv(resp, &mut bp)?;
    Ok(rc_bytes.first().copied().unwrap_or(0) as u32)
}


pub struct SearchEntry {
    pub dn: String,
    pub attrs: Vec<(String, Vec<String>)>,
    pub bin_attrs: Vec<(String, Vec<Vec<u8>>)>,
}

pub struct RawLdapConn {
    stream: TcpStream,
    next_id: u32,
}

impl RawLdapConn {
    pub async fn connect(host: &str, port: u16) -> Result<Self> {
        let stream = TcpStream::connect(format!("{host}:{port}"))
            .await
            .map_err(|e| anyhow!("TCP connect to {host}:{port} failed: {e}"))?;
        Ok(RawLdapConn { stream, next_id: 1 })
    }

    fn next_msg_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    async fn send_recv_one(&mut self, req: &[u8]) -> Result<Vec<u8>> {
        self.stream.write_all(req).await?;
        self.stream.flush().await?;
        read_ldap_message(&mut self.stream).await
    }

    pub async fn ntlm_bind(&mut self, nt_hash: &[u8; 16],
                           username: &str, domain: &str) -> Result<()> {
        let nego = spnego_initial(&build_negotiate());
        let req1 = encode_bind_request(self.next_msg_id(), "GSS-SPNEGO", &nego);
        let resp1 = self.send_recv_one(&req1).await?;
        let (rc1, sasl1) = decode_bind_response(&resp1)?;
        if rc1 != 14 {
            bail!("NTLM step 1: expected saslBindInProgress (14), got {rc1}");
        }

        let challenge_bytes = unwrap_spnego(&sasl1);
        let (server_challenge, target_info) = parse_challenge(&challenge_bytes)?;
        let auth = build_authenticate(nt_hash, username, domain, &server_challenge, &target_info);
        let req2 = encode_bind_request(self.next_msg_id(), "GSS-SPNEGO", &spnego_resp(&auth));
        let resp2 = self.send_recv_one(&req2).await?;
        let (rc2, _) = decode_bind_response(&resp2)?;
        if rc2 != 0 {
            bail!("NTLM authentication failed (LDAP result {rc2}): check credentials");
        }
        Ok(())
    }

    pub async fn get_default_naming_context(&mut self) -> Result<String> {
        let filter = encode_present_filter("objectClass");
        let entries = self.search("", 0, &filter, &["defaultNamingContext"]).await?;
        for e in &entries {
            for (k, v) in &e.attrs {
                if k.to_lowercase() == "defaultnamingcontext" {
                    if let Some(s) = v.first() { return Ok(s.clone()); }
                }
            }
        }
        bail!("defaultNamingContext not found in RootDSE")
    }

    pub async fn search(&mut self, base: &str, scope: u8,
                        filter: &[u8], attrs: &[&str]) -> Result<Vec<SearchEntry>> {
        let id = self.next_msg_id();
        let req = encode_search_request(id, base, scope, filter, attrs);
        self.stream.write_all(&req).await?;
        self.stream.flush().await?;
        collect_search_results(&mut self.stream).await
    }

    pub async fn modify_replace(&mut self, dn: &str, attr: &str,
                                value: Option<&[u8]>) -> Result<()> {
        let id = self.next_msg_id();
        let req = encode_modify_request(id, dn, attr, value);
        let resp = self.send_recv_one(&req).await?;
        let rc = decode_modify_response(&resp)?;
        match rc {
            0  => Ok(()),
            50 => bail!("Could not modify object, the server reports insufficient rights"),
            19 => bail!("Could not modify object, the server reports a constrained violation"),
            _  => bail!("LDAP modify error (code {rc})"),
        }
    }
}


async fn collect_search_results(stream: &mut TcpStream) -> Result<Vec<SearchEntry>> {
    let mut results = Vec::new();
    loop {
        let msg = read_ldap_message(stream).await?;
        if msg.is_empty() { break; }

        let mut pos = 0;
        let (_, outer) = ber_read_tlv(&msg, &mut pos)?;
        let mut p = 0;
        ber_skip_tlv(outer, &mut p)?; // messageID

        if p >= outer.len() { break; }
        let proto_tag = outer[p];

        match proto_tag {
            0x64 => {
                p += 1;
                let content_len = ber_len(outer, &mut p)?;
                let content_end = p + content_len;
                let content = &outer[p..content_end];
                p = content_end;

                let mut cp = 0;
                let (_, dn_bytes) = ber_read_tlv(content, &mut cp)?;
                let dn = String::from_utf8_lossy(dn_bytes).to_string();

                let (_, attrs_data) = ber_read_tlv(content, &mut cp)?;
                let mut ap = 0;
                let mut str_attrs = Vec::new();
                let mut bin_attrs = Vec::new();

                while ap < attrs_data.len() {
                    if let Ok((_, pa_data)) = ber_read_tlv(attrs_data, &mut ap) {
                        let mut pp = 0;
                        if let (Ok((_, type_bytes)), Ok((_, vals_data))) = (
                            ber_read_tlv(pa_data, &mut pp),
                            { let _ = (); ber_read_tlv(pa_data, &mut pp) }
                        ) {
                            let attr_name = String::from_utf8_lossy(type_bytes).to_lowercase();
                            let mut svs = Vec::new();
                            let mut bvs: Vec<Vec<u8>> = Vec::new();
                            let mut vp = 0;
                            while vp < vals_data.len() {
                                if let Ok((_, val)) = ber_read_tlv(vals_data, &mut vp) {
                                    bvs.push(val.to_vec());
                                    if let Ok(s) = std::str::from_utf8(val) {
                                        svs.push(s.to_string());
                                    }
                                } else { break; }
                            }
                            str_attrs.push((attr_name.clone(), svs));
                            bin_attrs.push((attr_name, bvs));
                        }
                    } else { break; }
                }
                let _ = p;
                results.push(SearchEntry { dn, attrs: str_attrs, bin_attrs });
            }
            0x65 => { 
                break;
            }
            _ => { break; }
        }
    }
    Ok(results)
}

async fn read_ldap_message(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut tag = [0u8; 1];
    if stream.read_exact(&mut tag).await.is_err() { return Ok(Vec::new()); }

    let mut lb = [0u8; 1];
    stream.read_exact(&mut lb).await?;

    let (content_len, extra): (usize, Vec<u8>) = if lb[0] < 0x80 {
        (lb[0] as usize, Vec::new())
    } else {
        let n = (lb[0] & 0x7f) as usize;
        let mut ex = vec![0u8; n];
        stream.read_exact(&mut ex).await?;
        let mut l = 0usize;
        for b in &ex { l = (l << 8) | *b as usize; }
        (l, ex)
    };

    let mut content = vec![0u8; content_len];
    stream.read_exact(&mut content).await?;

    let mut msg = Vec::new();
    msg.push(tag[0]);
    msg.push(lb[0]);
    msg.extend_from_slice(&extra);
    msg.extend_from_slice(&content);
    Ok(msg)
}


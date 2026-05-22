use anyhow::{anyhow, bail, Result};
use chrono::Utc;
use kerberos_asn1::{
    AsRep, Asn1Object, EncryptedData, KdcReqBody, KerberosFlags,
    KerberosTime, KrbError, PaData, PaEncTsEnc, PrincipalName,
};
use kerberos_constants::{
    etypes::*, key_usages::*, pa_data_types::*, principal_names::*,
};
use kerberos_crypto::{new_kerberos_cipher, Key as KcKey};
use rand::Rng;

use crate::network::kdc_send_recv;

const KDC_OPTS: u32 = 0x40810010; // FORWARDABLE | RENEWABLE | CANONICALIZE | RENEWABLE-OK

pub struct AuthInfo {
    pub domain: String,
    pub username: String,
    pub password: String,
    pub nt_hash: Vec<u8>,
    pub aes_key: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Ticket2 {
    pub service: String,
    pub server_realm: Option<String>,
    pub ticket_data: Vec<u8>,
    pub session_key: Vec<u8>,
    pub session_etype: i32,
    pub flags: u32,
    pub auth_time: u32,
    pub start_time: u32,
    pub end_time: u32,
    pub renew_till: u32,
}

fn make_key(auth: &AuthInfo, etype: i32, salt: &str) -> Result<KcKey> {
    if !auth.aes_key.is_empty() {
        if auth.aes_key.len() == 16 {
            return Ok(KcKey::AES128Key(auth.aes_key.clone().try_into()
                .map_err(|_| anyhow!("AES128 key length"))?));
        } else {
            return Ok(KcKey::AES256Key(auth.aes_key.clone().try_into()
                .map_err(|_| anyhow!("AES256 key length"))?));
        }
    }
    if !auth.nt_hash.is_empty() {
        return Ok(KcKey::RC4Key(auth.nt_hash.clone().try_into()
            .map_err(|_| anyhow!("RC4 key length"))?));
    }
    if !auth.password.is_empty() {
        let cipher = new_kerberos_cipher(etype)
            .map_err(|e| anyhow!("Cipher init etype {}: {}", etype, e))?;
        let raw = cipher.generate_key_from_string(&auth.password, salt.as_bytes());
        return Ok(match etype {
            AES256_CTS_HMAC_SHA1_96 => KcKey::AES256Key(raw.try_into()
                .map_err(|_| anyhow!("AES256 from s2k"))?),
            AES128_CTS_HMAC_SHA1_96 => KcKey::AES128Key(raw.try_into()
                .map_err(|_| anyhow!("AES128 from s2k"))?),
            _ => KcKey::RC4Key(raw.try_into()
                .map_err(|_| anyhow!("RC4 from s2k"))?),
        });
    }
    bail!("No credential provided")
}

fn raw_key(k: &KcKey) -> Vec<u8> {
    match k {
        KcKey::Secret(s) => s.as_bytes().to_vec(),
        KcKey::RC4Key(k) => k.to_vec(),
        KcKey::AES128Key(k) => k.to_vec(),
        KcKey::AES256Key(k) => k.to_vec(),
    }
}

fn encrypt(key: &KcKey, usage: i32, pt: &[u8]) -> Result<Vec<u8>> {
    let etype = match key {
        KcKey::AES256Key(_) => AES256_CTS_HMAC_SHA1_96,
        KcKey::AES128Key(_) => AES128_CTS_HMAC_SHA1_96,
        _ => RC4_HMAC,
    };
    let cipher = new_kerberos_cipher(etype)
        .map_err(|e| anyhow!("Cipher: {}", e))?;
    Ok(cipher.encrypt(&raw_key(key), usage, pt))
}

fn decrypt(key: &KcKey, usage: i32, ct: &[u8]) -> Result<Vec<u8>> {
    let etype = match key {
        KcKey::AES256Key(_) => AES256_CTS_HMAC_SHA1_96,
        KcKey::AES128Key(_) => AES128_CTS_HMAC_SHA1_96,
        _ => RC4_HMAC,
    };
    let cipher = new_kerberos_cipher(etype)
        .map_err(|e| anyhow!("Cipher: {}", e))?;
    cipher.decrypt(&raw_key(key), usage, ct)
        .map_err(|e| anyhow!("Decrypt: {}", e))
}

fn key_etype(k: &KcKey) -> i32 {
    match k { KcKey::AES256Key(_) => AES256_CTS_HMAC_SHA1_96, KcKey::AES128Key(_) => AES128_CTS_HMAC_SHA1_96, _ => RC4_HMAC }
}

pub fn key_to_kerberos_key(k: &crate::crypto::Key) -> anyhow::Result<KcKey> {
    Ok(match k.etype {
        18 => KcKey::AES256Key(k.key.clone().try_into().map_err(|_| anyhow::anyhow!("bad AES256 key len"))?),
        17 => KcKey::AES128Key(k.key.clone().try_into().map_err(|_| anyhow::anyhow!("bad AES128 key len"))?),
        _  => KcKey::RC4Key(k.key.clone().try_into().map_err(|_| anyhow::anyhow!("bad RC4 key len"))?),
    })
}

pub fn krb_encrypt_with_key(key: &KcKey, usage: i32, pt: &[u8]) -> anyhow::Result<Vec<u8>> {
    let etype = key_etype(key);
    let cipher = new_kerberos_cipher(etype).map_err(|e| anyhow::anyhow!("cipher: {}", e))?;
    Ok(cipher.encrypt(&raw_key(key), usage, pt))
}

fn build_pa_enc_ts(key: &KcKey) -> Result<PaData> {
    let now = Utc::now();
    let pa_ts = PaEncTsEnc {
        patimestamp: KerberosTime::from(now),
        pausec: Some((now.timestamp_subsec_micros() as i32).into()),
    };
    let pt = pa_ts.build();
    let ct = encrypt(key, KEY_USAGE_AS_REQ_TIMESTAMP, &pt)?;
    let ed = EncryptedData { etype: key_etype(key).into(), kvno: None, cipher: ct.into() };
    Ok(PaData { padata_type: PA_ENC_TIMESTAMP.into(), padata_value: ed.build().into() })
}

fn build_pa_pac_request(include_pac: bool) -> PaData {
    let b: u8 = if include_pac { 0xff } else { 0x00 };
    let enc = vec![0x30,0x05,0xa0,0x03,0x01,0x01,b];
    PaData { padata_type: PA_PAC_REQUEST.into(), padata_value: enc.into() }
}

fn kdc_req_body(domain: &str, username: &str, etypes: &[i32]) -> KdcReqBody {
    let now = Utc::now();
    let till = now + chrono::Duration::hours(24);
    let nonce: u32 = rand::thread_rng().gen::<u32>() & 0x7FFF_FFFF;
    KdcReqBody {
        kdc_options: KerberosFlags { flags: KDC_OPTS },
        cname: Some(PrincipalName { name_type: NT_PRINCIPAL, name_string: vec![username.into()].into() }),
        realm: domain.to_uppercase().into(),
        sname: Some(PrincipalName { name_type: NT_SRV_INST, name_string: vec!["krbtgt".into(), domain.to_uppercase().into()].into() }),
        from: None,
        till: KerberosTime::from(till),
        rtime: Some(KerberosTime::from(till)),
        nonce: nonce.into(),
        etypes: etypes.to_vec().into(),
        addresses: None,
        enc_authorization_data: None,
        additional_tickets: None,
    }
}

fn get_etype_salt(krb_err: &KrbError, auth: &AuthInfo) -> (i32, String) {
    let default_salt = format!("{}{}", auth.domain.to_uppercase(), auth.username);
    // Parse e-data from KRB-ERROR for ETYPE-INFO2
    if let Some(edata) = &krb_err.e_data {
        let edata_bytes: &[u8] = edata.as_ref();
        if let Ok((_, _pa_seq)) = kerberos_asn1::PaData::parse(edata_bytes) {
            // Try to find PA-ETYPE-INFO2 (type 19)
            // edata is SEQUENCE OF PA-DATA
        }
        // Manual parse: edata = OCTET STRING containing SEQUENCE OF PA-DATA
        if let Ok(inner) = parse_edata_padatas(edata_bytes) {
            for (pa_type, pa_val) in inner {
                if pa_type == 19 || pa_type == 11 {
                    if let Ok((etype, salt)) = parse_etype_info2(&pa_val, &default_salt) {
                        return (etype, salt);
                    }
                }
            }
        }
    }
    (AES256_CTS_HMAC_SHA1_96, default_salt)
}

fn parse_edata_padatas(data: &[u8]) -> Result<Vec<(i32, Vec<u8>)>> {
    use crate::asn1::Reader;
    // data may start with OCTET STRING tag or directly SEQUENCE
    let mut p = 0usize;
    // Skip OCTET STRING wrapper if present
    let content = if !data.is_empty() && data[0] == 0x04 {
        p += 1;
        let (l, np) = crate::asn1::decode_length_pair(data, p)?;
        p = np;
        &data[p..p+l]
    } else {
        data
    };
    // Parse SEQUENCE OF PA-DATA
    if content.is_empty() || content[0] != 0x30 { return Ok(vec![]); }
    let mut r = Reader::new(content);
    let (_, seq) = r.tlv()?;
    let mut r2 = Reader::new(seq);
    let mut result = Vec::new();
    while !r2.done() {
        let (_, entry) = r2.tlv()?;
        let mut er = Reader::new(entry);
        let pa_type = er.ctx(1).ok()
            .and_then(|v| Reader::new(v).read_int().ok())
            .unwrap_or(-1) as i32;
        let pa_val = er.ctx(2).ok()
            .and_then(|v| Reader::new(v).read_ostr().ok().map(|b| b.to_vec()))
            .unwrap_or_default();
        result.push((pa_type, pa_val));
    }
    Ok(result)
}

fn parse_etype_info2(data: &[u8], default_salt: &str) -> Result<(i32, String)> {
    use crate::asn1::Reader;
    let mut r = Reader::new(data);
    let (_, seq) = r.tlv()?;
    let mut r2 = Reader::new(seq);
    while !r2.done() {
        let (_, entry) = r2.tlv()?;
        let mut er = Reader::new(entry);
        let etype = er.ctx(0).ok()
            .and_then(|v| Reader::new(v).read_int().ok())
            .unwrap_or(-1) as i32;
        let salt = if !er.done() && er.peek() == Some(0xA1) {
            er.ctx(1).ok()
                .and_then(|v| Reader::new(v).read_gstr().ok())
                .unwrap_or_else(|| default_salt.to_string())
        } else { default_salt.to_string() };
        if etype == AES256_CTS_HMAC_SHA1_96 || etype == AES128_CTS_HMAC_SHA1_96 {
            return Ok((etype, salt));
        }
    }
    Ok((RC4_HMAC, default_salt.to_string()))
}

/// Extract the raw ticket DER bytes from AS-REP without re-encoding.
/// Re-encoding via kerberos_asn1::Ticket::build() may produce different bytes,
/// corrupting the KDC's cryptographic signature on the ticket.
fn extract_ticket_raw(as_rep_der: &[u8]) -> Result<Vec<u8>> {
    use crate::asn1::{unwrap_app, decode_length};
    // AS-REP (KDC-REP) is APP[11], SEQUENCE with:
    // [0]pvno [1]msg-type [2]padata(opt) [3]crealm [4]cname [5]ticket [6]enc-part
    //
    // Scan raw bytes directly for 0xA5 (ctx[5] = ticket field)
    let inner = unwrap_app(as_rep_der, 11)?;
    // Skip SEQUENCE tag (0x30) and length
    if inner.is_empty() || inner[0] != 0x30 { anyhow::bail!("AS-REP: expected SEQUENCE"); }
    let mut pos = 1usize;
    let seq_len = decode_length(inner, &mut pos)?;
    let seq_end = pos + seq_len;

    while pos < seq_end && pos < inner.len() {
        let field_tag = inner[pos];
        let _field_start = pos;
        pos += 1;
        let field_len = decode_length(inner, &mut pos)?;


        if field_tag == 0xA5 {
            // Content of ctx[5] is the Ticket (starts with APP[1] = 0x61)
            if pos + field_len > inner.len() {
                anyhow::bail!("AS-REP ticket field truncated: have {} need {}", inner.len()-pos, field_len);
            }
            let ticket_bytes = &inner[pos..pos+field_len];
            return Ok(ticket_bytes.to_vec());
        }
        pos += field_len;
    }
    anyhow::bail!("Ticket (ctx[5]=0xA5) not found in AS-REP after scanning {} bytes", seq_end)
}

pub fn do_as_req(dc: &str, auth: &AuthInfo) -> Result<(Vec<u8>, Vec<u8>, i32)> {
    let offered = vec![AES256_CTS_HMAC_SHA1_96, AES128_CTS_HMAC_SHA1_96, RC4_HMAC];

    // Use default salt = REALM + username (standard Windows AD convention)
    // Skip the probe entirely to ensure a single, fresh AS-REQ produces
    // a consistent TGT + EncAsRepPart pair.
    let default_salt = format!("{}{}", auth.domain.to_uppercase(), auth.username);
    let etype = AES256_CTS_HMAC_SHA1_96;
    let salt = default_salt.clone();
    if crate::is_debug() { eprintln!("[*] Using default salt ({} bytes): {:?}", salt.len(), &salt[..salt.len().min(30)]); }

    let key = make_key(auth, etype, &salt)?;
    if crate::is_debug() { eprintln!("[*] Key etype={} key={}", key_etype(&key), hex::encode(raw_key(&key))); }

    // Single AS-REQ with PA-ENC-TIMESTAMP
    let pa_ts = build_pa_enc_ts(&key)?;
    let pa_pac = build_pa_pac_request(true);
    let req2 = kerberos_asn1::AsReq {
        pvno: 5.into(), msg_type: 10.into(),
        padata: Some(vec![pa_ts, pa_pac].into()),
        req_body: kdc_req_body(&auth.domain, &auth.username, &offered),
    }.build();

    let resp2 = kdc_send_recv(dc, &req2)
        .map_err(|e| anyhow!("AS-REQ failed: {}", e))?;
    
    if let Ok((_, krb_err)) = KrbError::parse(&resp2) {
        let code: i32 = krb_err.error_code.into();
        if code == 25 {
            // PREAUTH_REQUIRED: wrong salt — get correct salt from KDC and retry
            if crate::is_debug() { eprintln!("[*] Getting correct salt from KDC..."); }
            let (etype2, salt2) = get_etype_salt(&krb_err, auth);
            let key2 = make_key(auth, etype2, &salt2)?;
            if crate::is_debug() { eprintln!("[*] Retrying with salt={:?}", &salt2[..salt2.len().min(30)]); }
            let pa_ts2 = build_pa_enc_ts(&key2)?;
            let pa_pac2 = build_pa_pac_request(true);
            let req3 = kerberos_asn1::AsReq {
                pvno: 5.into(), msg_type: 10.into(),
                padata: Some(vec![pa_ts2, pa_pac2].into()),
                req_body: kdc_req_body(&auth.domain, &auth.username, &offered),
            }.build();
            let resp3 = kdc_send_recv(dc, &req3)
                .map_err(|e| anyhow!("AS-REQ retry failed: {}", e))?;
            if let Ok((_, krb_err2)) = KrbError::parse(&resp3) {
                let code2: i32 = krb_err2.error_code.into();
                bail!("KDC error: {} (code {})", krb_error_name(code2), code2);
            }
            // Use resp3 as the AS-REP — but this still has two requests!
            // TODO: handle this case properly
            bail!("Unexpected KDC behavior with PREAUTH_REQUIRED retry");
        }
        bail!("KDC error: {} (code {})", krb_error_name(code), code);
    }

    let (_, as_rep) = AsRep::parse(&resp2)
        .map_err(|_| anyhow!("Failed to parse AS-REP"))?;

    // Decrypt enc-part
    let enc_bytes: Vec<u8> = <Vec<u8> as AsRef<[u8]>>::as_ref(&as_rep.enc_part.cipher).to_vec();
    let pt = decrypt(&key, KEY_USAGE_AS_REP_ENC_PART, &enc_bytes)
        .or_else(|_| {
            decrypt(&key, KEY_USAGE_TGS_REP_ENC_PART_SESSION_KEY, &enc_bytes)
        })?;

    // Parse EncAsRepPart - Windows may use tag 0x7a (EncTGSRepPart) instead of 0x79
    let pt2 = if !pt.is_empty() && pt[0] == 0x7a {
        let mut p = pt.clone(); p[0] = 0x79; p
    } else { pt.clone() };

    
    let (_, enc_rep) = kerberos_asn1::EncAsRepPart::parse(&pt2)
        .map_err(|_| anyhow!("Failed to parse EncAsRepPart"))?;

    let sess_key: Vec<u8> = <Vec<u8> as AsRef<[u8]>>::as_ref(&enc_rep.key.keyvalue).to_vec();
    let sess_etype: i32 = enc_rep.key.keytype.into();

    // Extract raw ticket bytes from the AS-REP DER (WITHOUT re-encoding via build())
    // Re-encoding would corrupt the KDC signature on the ticket.
    let tkt_raw = extract_ticket_raw(&resp2)?;
    

let tkt_der = tkt_raw;  // Use raw extraction

    if crate::is_debug() { eprintln!("[+] Got TGT, session key etype={}", sess_etype); }
    Ok((tkt_der, sess_key, sess_etype))
}

fn krb_error_name(code: i32) -> &'static str {
    match code {
        6  => "KDC_ERR_C_PRINCIPAL_UNKNOWN",
        7  => "KDC_ERR_S_PRINCIPAL_UNKNOWN",
        12 => "KDC_ERR_POLICY",
        13 => "KDC_ERR_BADOPTION",
        14 => "KDC_ERR_ETYPE_NOSUPP",
        17 => "KDC_ERR_KEY_EXPIRED",
        18 => "KDC_ERR_PREAUTH_FAILED",
        24 => "KDC_ERR_PREAUTH_REQUIRED",
        25 => "KDC_ERR_SERVER_NOMATCH",
        32 => "KRB_AP_ERR_BAD_INTEGRITY",
        37 => "KRB_AP_ERR_SKEW",
        68 => "KDC_ERR_WRONG_REALM",
        _  => "KRB_ERR_UNKNOWN",
    }
}

// TGS-REQ / S4U / ccache structs — these use our asn1/crypto for TGS
// (AS is now handled by kerberos_crypto above)



pub fn get_service_ticket(
    dc: &str, auth: &AuthInfo, spn: &str,
    impersonate: Option<&str>, additional_ticket: Option<&str>,
    altservice: Option<&str>, self_only: bool, _force_forwardable: bool,
    _u2u: bool, renew: bool,
) -> Result<Ticket2> {
    eprintln!("[*] Requesting TGT...");
    let (tgt, sess_key, sess_etype) = do_as_req(dc, auth)?;
    eprintln!("[+] Got TGT");
    let sess = crate::crypto::Key { etype: sess_etype, key: sess_key };

    if let Some(imp) = impersonate {
        eprintln!("[*] S4U2Self for '{}'...", imp);
        let s4u_tkt = do_s4u2self(dc, auth, &tgt, &sess, imp)?;
        eprintln!("[+] Got S4U2Self ticket");
        if self_only { return Ok(s4u_tkt); }
        let addl = if let Some(path) = additional_ticket {
            eprintln!("[*] Loading additional ticket from '{}'", path);
            let (td,_,_) = crate::ccache::read_ccache(path)?; td
        } else {
            s4u_tkt.ticket_data.clone()
        };
        eprintln!("[*] S4U2Proxy for '{}'...", spn);
        let final_tkt = do_s4u2proxy(dc, auth, &tgt, &sess, &addl, spn, altservice)?;
        eprintln!("[+] Got S4U2Proxy ticket");
        return Ok(final_tkt);
    }
    eprintln!("[*] Requesting ST for '{}'...", spn);
    let st = do_tgs_req(dc, auth, &tgt, &sess, spn, altservice, renew)?;
    eprintln!("[+] Got ST");
    Ok(st)
}

// ── TGS-REQ helpers using our asn1/crypto ──────────────────────────────────

fn do_tgs_req(dc: &str, auth: &AuthInfo, tgt: &[u8], sess: &crate::crypto::Key, spn: &str, altservice: Option<&str>, renew: bool) -> Result<Ticket2> {
    let tgsreq = build_tgs_req(auth, tgt, sess, spn, &[], renew, None)?;
    let resp = kdc_send_recv(dc, &tgsreq)?;
    check_error(&resp)?;
    parse_tgs_rep(&resp, sess, spn, altservice)
}

fn do_s4u2self(dc: &str, auth: &AuthInfo, tgt: &[u8], sess: &crate::crypto::Key, imp: &str) -> Result<Ticket2> {
    let pa_fu = build_pa_for_user(auth, imp, sess)?;
    // S4U2Self: sname = NT_UNKNOWN(0) with [username] — impacket convention
    let tgsreq = build_s4u2self_req(auth, tgt, sess, &[pa_fu])?;
    let resp = kdc_send_recv(dc, &tgsreq)?;
    check_error(&resp)?;
    let spn_label = auth.username.clone();
    parse_tgs_rep(&resp, sess, &spn_label, None)
}

fn build_s4u2self_req(auth: &AuthInfo, tgt: &[u8], sess: &crate::crypto::Key, extra_pa: &[Vec<u8>]) -> Result<Vec<u8>> {
    use crate::asn1::*;
    let nonce: u32 = rand::thread_rng().gen::<u32>() & 0x7FFF_FFFF;
    // impacket uses now+1day for till in S4U2Self, not far future
    let till = (Utc::now() + chrono::Duration::hours(24)).format("%Y%m%d%H%M%SZ").to_string();
    let realm = auth.domain.to_uppercase();
    // impacket S4U2Self uses etypes [18, 23] (AES256 + RC4, no AES128)
    let etypes = [18i32, 23];
    let etype_seq: Vec<Vec<u8>> = etypes.iter().map(|e| int(*e as i64)).collect();

    // sname = NT_UNKNOWN(0) [username] — matches impacket (name-type=0 in debug output)
    let sname = {
        let strs: Vec<Vec<u8>> = vec![gstr(&auth.username)];
        let mut inner = ctx(0, &int(0i64));
        inner.extend(ctx(1, &seq_of(&strs)));
        seq(&inner)
    };

    // impacket uses FORWARDABLE|RENEWABLE|CANONICALIZE (0x40810000) for TGS-REQ
    // rtime is included when RENEWABLE is set
    let mut body = ctx(0, &bitstr(&0x40810000u32.to_be_bytes(), 0));
    // No [1] cname in TGS-REQ req-body (only AS-REQ has cname)
    body.extend(ctx(2, &gstr(&realm)));
    body.extend(ctx(3, &sname));
    body.extend(ctx(5, &gentime(&till)));
    body.extend(ctx(6, &gentime(&till)));  // rtime = same as till (RENEWABLE is set)
    body.extend(ctx(7, &int(nonce as i64)));
    body.extend(ctx(8, &seq_of(&etype_seq)));
    let req_body = seq(&body);

    let auth_data = build_authenticator(auth, sess, &req_body)?;
    // Use kerberos_crypto for authenticator encryption (same as impacket)
    let kc_key = crate::krb5::key_to_kerberos_key(sess)?;
    let enc_auth = crate::krb5::krb_encrypt_with_key(&kc_key, kerberos_constants::key_usages::KEY_USAGE_TGS_REQ_AUTHEN, &auth_data)?;
    let enc_auth_ed = enc_data(sess.etype, None, &enc_auth);

    let mut ap = ctx(0, &int(5));
    ap.extend(ctx(1, &int(14)));
    ap.extend(ctx(2, &bitstr(&[0,0,0,0], 0)));
    ap.extend(ctx(3, tgt));
    ap.extend(ctx(4, &enc_auth_ed));
    let ap_req = app(14, &seq(&ap));

    let pa_tgs = pa_data_tl(1, &ap_req);
    // PA-TGS-REQ first, then extra_pa (PA-FOR-USER) — matching impacket order
    let mut all_pa: Vec<u8> = Vec::new();
    all_pa.extend(pa_tgs);
    for p in extra_pa { all_pa.extend(p); }

    let mut req = ctx(1, &int(5));
    req.extend(ctx(2, &int(12)));
    req.extend(ctx(3, &seq(&all_pa)));
    req.extend(ctx(4, &req_body));
    Ok(app(12, &seq(&req)))
}

fn do_s4u2proxy(dc: &str, auth: &AuthInfo, tgt: &[u8], sess: &crate::crypto::Key, addl: &[u8], spn: &str, altservice: Option<&str>) -> Result<Ticket2> {
    let tgsreq = build_tgs_req(auth, tgt, sess, spn, &[], false, Some(addl))?;
    let resp = kdc_send_recv(dc, &tgsreq)?;
    check_error(&resp)?;
    parse_tgs_rep(&resp, sess, spn, altservice)
}

fn build_tgs_req(auth: &AuthInfo, tgt: &[u8], sess: &crate::crypto::Key, spn: &str, extra_pa: &[Vec<u8>], renew: bool, addl_tkt: Option<&[u8]>) -> Result<Vec<u8>> {
    use crate::asn1::*;
    let nonce: u32 = rand::thread_rng().gen::<u32>() & 0x7FFF_FFFF;
    let till = "20370913024805Z";
    let realm = auth.domain.to_uppercase();
    let spn_parts: Vec<&str> = spn.splitn(2,'/').collect();
    let etypes = [AES256_CTS_HMAC_SHA1_96, AES128_CTS_HMAC_SHA1_96, RC4_HMAC];
    let etype_seq: Vec<Vec<u8>> = etypes.iter().map(|e| int(*e as i64)).collect();
    let mut kdc_opts: u32 = 0x40810010;
    if renew { kdc_opts |= 0x02000000; }
    if addl_tkt.is_some() { kdc_opts |= 0x00020000; }  // CNAME-IN-ADDL-TKT (bit 14)

    let mut body = ctx(0, &bitstr(&kdc_opts.to_be_bytes(), 0));
    body.extend(ctx(2, &gstr(&realm)));
    let sname = if spn_parts.len()==2 {
        principal_name(NT_SRV_INST as i32, &[spn_parts[0], spn_parts[1]])
    } else {
        principal_name(NT_PRINCIPAL as i32, &[spn_parts[0]])
    };
    body.extend(ctx(3, &sname));
    body.extend(ctx(5, &gentime(till)));
    body.extend(ctx(6, &gentime(till)));
    body.extend(ctx(7, &int(nonce as i64)));
    body.extend(ctx(8, &seq_of(&etype_seq)));
    if let Some(at) = addl_tkt {
        body.extend(ctx(11, &seq(at)));
    }
    let req_body = seq(&body);

    let auth_data = build_authenticator(auth, sess, &req_body)?;
    let enc_auth = krb_enc_with_kerberos_crypto(sess, crate::crypto::KU_TGS_AUTH as i32, &auth_data)?;
    let enc_auth_ed = enc_data(sess.etype, None, &enc_auth);

    let mut ap = ctx(0, &int(5));
    ap.extend(ctx(1, &int(14)));
    ap.extend(ctx(2, &bitstr(&[0,0,0,0], 0)));
    ap.extend(ctx(3, tgt));
    ap.extend(ctx(4, &enc_auth_ed));
    let ap_req = app(14, &seq(&ap));

    let pa_tgs = pa_data_tl(1, &ap_req);
    let mut all_pa = pa_tgs;
    for p in extra_pa { all_pa.extend(p); }

    let mut req = ctx(1, &int(5));
    req.extend(ctx(2, &int(12)));
    req.extend(ctx(3, &seq(&all_pa)));
    req.extend(ctx(4, &req_body));
    Ok(app(12, &seq(&req)))
}

fn build_authenticator(auth: &AuthInfo, _key: &crate::crypto::Key, _req_body: &[u8]) -> Result<Vec<u8>> {
    use crate::asn1::*;
    let now = Utc::now();
    let ts = now.format("%Y%m%d%H%M%SZ").to_string();
    let usec = now.timestamp_subsec_micros();
    let realm = auth.domain.to_uppercase();

    // Authenticator ::= [APPLICATION 2] SEQUENCE { ... }
    // The Authenticator must have APPLICATION 2 tag (0x62) wrapper
    let mut a = ctx(0, &int(5));
    a.extend(ctx(1, &gstr(&realm)));
    a.extend(ctx(2, &principal_name(1, &[&auth.username])));
    a.extend(ctx(4, &int(usec as i64)));
    a.extend(ctx(5, &gentime(&ts)));
    Ok(app(2, &seq(&a)))
}

/// Encrypt data using kerberos_crypto library (same as AS-REQ uses)
fn krb_enc_with_kerberos_crypto(key: &crate::crypto::Key, usage: i32, pt: &[u8]) -> Result<Vec<u8>> {
    let etype = key.etype;
    let cipher = new_kerberos_cipher(etype)
        .map_err(|e| anyhow::anyhow!("cipher init: {}", e))?;
    let krb_key = match etype {
        18 => KcKey::AES256Key(key.key.clone().try_into()
            .map_err(|_| anyhow::anyhow!("AES256 key length"))?),
        17 => KcKey::AES128Key(key.key.clone().try_into()
            .map_err(|_| anyhow::anyhow!("AES128 key length"))?),
        _ => KcKey::RC4Key(key.key.clone().try_into()
            .map_err(|_| anyhow::anyhow!("RC4 key length"))?),
    };
    let raw_key = match &krb_key {
        KcKey::AES256Key(k) => k.to_vec(),
        KcKey::AES128Key(k) => k.to_vec(),
        KcKey::RC4Key(k) => k.to_vec(),
        KcKey::Secret(s) => s.as_bytes().to_vec(),
    };
    Ok(cipher.encrypt(&raw_key, usage, pt))
}

fn build_pa_for_user(auth: &AuthInfo, imp: &str, key: &crate::crypto::Key) -> Result<Vec<u8>> {
    use crate::asn1::*;
    // impacket always uses HMAC-MD5 (cksum-type=-138) for PA-FOR-USER checksum
    // regardless of session key etype.
    // S4UByteArray = LE_u32(1) + username + realm.lower() + "Kerberos"
    let realm_lower = auth.domain.to_lowercase();
    let mut s4u_data: Vec<u8> = Vec::new();
    s4u_data.extend_from_slice(&1u32.to_le_bytes());  // NT_PRINCIPAL = 1
    s4u_data.extend_from_slice(imp.as_bytes());
    s4u_data.extend_from_slice(realm_lower.as_bytes());
    s4u_data.extend_from_slice(b"Kerberos");
    // PA-FOR-USER checksum uses RFC 4757 HMAC-MD5 (KERB-CHECKSUM-HMAC-MD5):
    // 1. Ksign = HMAC-MD5(session_key, "signaturekey")
    // 2. tmp = MD5(LE_uint32(17) || S4UByteArray)   (17 = PA-FOR-USER usage)
    // 3. Signature = HMAC-MD5(Ksign, tmp)
    let ksign = crate::crypto::hmac_md5(&key.key, b"signaturekey\0");
    let mut md5_input: Vec<u8> = Vec::new();
    md5_input.extend_from_slice(&17u32.to_le_bytes());  // key_usage=17
    md5_input.extend_from_slice(&s4u_data);
    let tmp = {
        use md5::Digest;
        let mut h = md5::Md5::new();
        h.update(&md5_input);
        h.finalize().to_vec()
    };
    let ck_val = crate::crypto::hmac_md5(&ksign, &tmp);
    let cktype: i32 = -138;  // RSA-MD5 / HMAC-MD5 — hardcoded like impacket
    let mut cks = ctx(0, &int(cktype as i64));
    cks.extend(ctx(1, &ostr(&ck_val)));
    let mut items = ctx(0, &principal_name(1, &[imp]));
    items.extend(ctx(1, &gstr(&realm_lower)));  // impacket uses lowercase realm
    items.extend(ctx(2, &seq(&cks)));
    items.extend(ctx(3, &gstr("Kerberos")));
    Ok(pa_data_tl(129, &seq(&items)))
}
 
fn pa_data_tl(pa_type: i32, value: &[u8]) -> Vec<u8> {
    use crate::asn1::*;
    let mut b = ctx(1, &int(pa_type as i64));
    b.extend(ctx(2, &ostr(value)));
    seq(&b)
}
 
fn parse_tgs_rep(data: &[u8], sess: &crate::crypto::Key, spn: &str, altservice: Option<&str>) -> Result<Ticket2> {
    use crate::asn1::*;
    let inner = unwrap_app(data, 13)?;
    let mut r = Reader::new(inner); let (_,sd) = r.tlv()?;
    let mut s = Reader::new(sd);
    // TGS-REP: [0]pvno [1]msg-type [2]padata(opt) [3]crealm [4]cname [5]ticket [6]enc-part
    let _ = s.ctx(0)?;  // pvno
    let _ = s.ctx(1)?;  // msg-type
    if s.peek()==Some(0xA2) { let _ = s.ctx(2)?; }  // padata (optional)
    let _ = s.ctx(3)?;  // crealm
    let _ = s.ctx(4)?;  // cname
    let tkt_raw = s.ctx(5)?; let tkt = tkt_raw.to_vec();  // ticket
    let enc_raw = s.ctx(6)?;  // enc-part
    let (_, cipher) = parse_enc_data(enc_raw)?;
    // Use kerberos_crypto for decryption (same library as encryption)
    let decrypt_key = match sess.etype {
        18 => KcKey::AES256Key(sess.key.clone().try_into()
            .map_err(|_| anyhow!("key len"))?),
        17 => KcKey::AES128Key(sess.key.clone().try_into()
            .map_err(|_| anyhow!("key len"))?),
        _ => KcKey::RC4Key(sess.key.clone().try_into()
            .map_err(|_| anyhow!("key len"))?),
    };
    let raw_dk = match &decrypt_key {
        KcKey::AES256Key(k) => k.to_vec(),
        KcKey::AES128Key(k) => k.to_vec(),
        KcKey::RC4Key(k) => k.to_vec(),
        KcKey::Secret(s) => s.as_bytes().to_vec(),
    };
    let dc = kerberos_crypto::new_kerberos_cipher(sess.etype)
        .map_err(|e| anyhow!("cipher: {}", e))?;
    let pt = dc.decrypt(&raw_dk, 8, &cipher)  // KEY_USAGE_TGS_REP_ENC_PART_SESSION_KEY=8
        .or_else(|_| dc.decrypt(&raw_dk, 9, &cipher))  // KEY_USAGE_TGS_REP_ENC_PART_SUB_KEY=9
        .map_err(|e| anyhow!("TGS-REP decrypt: {}", e))?;
    let (sk, se) = parse_enc_rep_part(&pt)?;
    let now = Utc::now().timestamp() as u32;
    Ok(Ticket2 {
        service: altservice.unwrap_or(spn).to_string(),
        server_realm: None, ticket_data: tkt,
        session_key: sk, session_etype: se,
        flags: 0x40000000, auth_time: now, start_time: now,
        end_time: now + 10*3600, renew_till: now + 7*86400,
    })
}
 
fn parse_enc_rep_part(data: &[u8]) -> Result<(Vec<u8>, i32)> {
    use crate::asn1::*;
    let inner = if !data.is_empty() && (data[0]==0x79 || data[0]==0x7A) {
        unwrap_app(data, data[0] & 0x1F)?
    } else { data };
    let mut r = Reader::new(inner); let (_,sd) = r.tlv()?;
    let mut s = Reader::new(sd);
    // [0] key (EncryptionKey)
    let kd = s.ctx(0)?;
    let mut kr = Reader::new(kd); let (_,ks) = kr.tlv()?;
    let mut ksr = Reader::new(ks);
    let et = Reader::new(ksr.ctx(0)?).read_int()? as i32;
    let kv = Reader::new(ksr.ctx(1)?).read_ostr()?.to_vec();
    // Scan remaining fields for [3] flags
    while !s.done() {
        let tag = s.peek().unwrap_or(0);
        if tag == 0xA3 {  // ctx[3] = flags (TicketFlags BIT STRING)
            if let Ok(flags_raw) = s.ctx(3) {
                // BIT STRING: first byte = unused bits count, rest = flags
                if flags_raw.len() >= 2 && flags_raw[0] == 0x03 {
                    // Skip tag(1) + len(1) + unused(1) = 3 bytes
                    if flags_raw.len() >= 4 {
                        let flag_bytes = &flags_raw[3..];
                        let flags: u32 = if flag_bytes.len() >= 4 {
                            u32::from_be_bytes([flag_bytes[0], flag_bytes[1], flag_bytes[2], flag_bytes[3]])
                        } else {
                            let mut fb = [0u8;4];
                            fb[..flag_bytes.len()].copy_from_slice(flag_bytes);
                            u32::from_be_bytes(fb)
                        };
                        if crate::is_debug() { eprintln!("[*] TGT flags: 0x{:08X} FORWARDABLE={} RENEWABLE={}",
                            flags, (flags & 0x40000000) != 0, (flags & 0x20000000) != 0); }
                    }
                }
            }
            break;
        }
        let _ = s.tlv();
    }
    Ok((kv, et))
}
 
fn check_error(data: &[u8]) -> Result<()> {
    use crate::asn1::*;
    if data.is_empty() { bail!("Empty KDC response"); }
    if (data[0] & 0x1F) == 30 {
        if let Ok(inner) = unwrap_app(data, 30) {
            let mut r = Reader::new(inner);
            if let Ok((_,sd)) = r.tlv() {
                let mut s = Reader::new(sd);
                while !s.done() {
                    if s.peek() == Some(0xA6) {
                        if let Ok(ec) = s.ctx(6) {
                            if let Ok(code) = Reader::new(ec).read_int() {
                                bail!("KDC error: {} (code {})", krb_error_name(code as i32), code);
                            }
                        }
                        break;
                    }
                    let _ = s.tlv();
                }
            }
        }
        bail!("KDC error (unknown code)");
    }
    Ok(())
}
 
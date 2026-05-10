use anyhow::{anyhow, bail, Context, Result};
use ldap3::{Ldap, LdapConnAsync, LdapConnSettings, Scope, SearchEntry as Ldap3Entry};

use crate::ntlm::{
    encode_equality_filter, encode_present_filter, parse_nt_hash, RawLdapConn,
    SearchEntry as RawEntry,
};


#[derive(Debug, Clone)]
pub enum AuthMethod {
    Password(String),
    NtlmHash { lm_hash: String, nt_hash: String },
    Kerberos { aes_key: Option<String> },
}

#[derive(Debug, Clone)]
pub struct ConnConfig {
    pub host: String,
    pub port: u16,
    pub use_ldaps: bool,
    pub domain: String,
    pub username: String,
    pub auth: AuthMethod,
    pub debug: bool,
}


pub struct SearchResult {
    pub dn: String,
    pub attrs: std::collections::HashMap<String, Vec<String>>,
    pub bin_attrs: std::collections::HashMap<String, Vec<Vec<u8>>>,
}

impl From<Ldap3Entry> for SearchResult {
    fn from(e: Ldap3Entry) -> Self {
        SearchResult {
            dn: e.dn,
            attrs: e.attrs,
            bin_attrs: e.bin_attrs,
        }
    }
}

impl From<RawEntry> for SearchResult {
    fn from(e: RawEntry) -> Self {
        SearchResult {
            dn: e.dn,
            attrs: e.attrs.into_iter().collect(),
            bin_attrs: e.bin_attrs.into_iter().collect(),
        }
    }
}


pub enum LdapClient {
    Ldap3(Ldap3Client),
    Raw(RawLdapConn),
}

impl LdapClient {
    pub async fn connect(cfg: &ConnConfig) -> Result<Self> {
        match &cfg.auth {
            AuthMethod::NtlmHash { lm_hash: _, nt_hash } => {
                let hash = parse_nt_hash(nt_hash)?;
                if cfg.debug {
                    eprintln!("[DEBUG] NTLM bind to {}:{} as {}@{}",
                              cfg.host, cfg.port, cfg.username, cfg.domain);
                }
                let mut conn = RawLdapConn::connect(&cfg.host, cfg.port).await?;
                conn.ntlm_bind(&hash, &cfg.username, &cfg.domain).await?;
                if cfg.debug {
                    eprintln!("[DEBUG] NTLM bind succeeded");
                }
                Ok(LdapClient::Raw(conn))
            }

            AuthMethod::Kerberos { aes_key } => {
                if let Some(key) = aes_key {
                    if cfg.debug {
                        eprintln!("[DEBUG] -aesKey supplied ({} hex chars)", key.len());
                    }
                    eprintln!(
                        "[!] -aesKey: ensure a TGT obtained with this key is present \
                         in KRB5CCNAME before running."
                    );
                }
                let ccname = std::env::var("KRB5CCNAME").unwrap_or_default();
                if ccname.is_empty() {
                    bail!(
                        "Kerberos authentication (-k) requires a valid ccache.\n\
                         Set KRB5CCNAME to the path of your ccache file, e.g.:\n  \
                         export KRB5CCNAME=/tmp/krb5cc_$(id -u)"
                    );
                }
                if cfg.debug {
                    eprintln!("[DEBUG] GSSAPI bind, KRB5CCNAME={ccname}");
                }
                // GSSAPI requires the `gssapi` ldap3 feature which needs Rust ≥ 1.77.
                // Provide a clear error rather than silently connecting unauthenticated.
                bail!(
                    "Kerberos (-k) requires rebuilding with `features = [\"gssapi\"]` in ldap3\n\
                     and Rust ≥ 1.77.\n\
                     To use Kerberos:\n  \
                     1. kinit {username}@{domain}  (or use getTGT.py)\n  \
                     2. export KRB5CCNAME=<path>\n  \
                     3. Rebuild with the gssapi feature enabled",
                    username = cfg.username,
                    domain = cfg.domain,
                );
            }

            AuthMethod::Password(password) => {
                let client = Ldap3Client::connect(cfg, password).await?;
                Ok(LdapClient::Ldap3(client))
            }
        }
    }

    pub async fn get_default_naming_context(&mut self) -> Result<String> {
        match self {
            LdapClient::Ldap3(c) => c.get_default_naming_context().await,
            LdapClient::Raw(c)   => c.get_default_naming_context().await,
        }
    }

    pub async fn search(&mut self, base: &str, filter: &str,
                        attrs: &[&str]) -> Result<Vec<SearchResult>> {
        match self {
            LdapClient::Ldap3(c) => c.search(base, filter, attrs).await,
            LdapClient::Raw(c) => {
                let filter_bytes = parse_filter_str(filter)?;
                let entries = c.search(base, 2, &filter_bytes, attrs).await?;
                Ok(entries.into_iter().map(SearchResult::from).collect())
            }
        }
    }

    pub async fn search_base(&mut self, dn: &str, filter: &str,
                             attrs: &[&str]) -> Result<Vec<SearchResult>> {
        match self {
            LdapClient::Ldap3(c) => c.search_base(dn, filter, attrs).await,
            LdapClient::Raw(c) => {
                let filter_bytes = parse_filter_str(filter)?;
                let entries = c.search(dn, 0, &filter_bytes, attrs).await?;
                Ok(entries.into_iter().map(SearchResult::from).collect())
            }
        }
    }

    pub async fn modify_replace_binary(&mut self, dn: &str, attr: &str,
                                       value: &[u8]) -> Result<()> {
        match self {
            LdapClient::Ldap3(c) => c.modify_replace_binary(dn, attr, value).await,
            LdapClient::Raw(c)   => c.modify_replace(dn, attr, Some(value)).await,
        }
    }

    pub async fn modify_clear_attribute(&mut self, dn: &str, attr: &str) -> Result<()> {
        match self {
            LdapClient::Ldap3(c) => c.modify_clear_attribute(dn, attr).await,
            LdapClient::Raw(c)   => c.modify_replace(dn, attr, None).await,
        }
    }
}


fn parse_filter_str(filter: &str) -> Result<Vec<u8>> {
    let f = filter.trim();
    if !f.starts_with('(') || !f.ends_with(')') {
        bail!("Filter must be wrapped in parens: {f}");
    }
    let inner = &f[1..f.len()-1];

    if let Some(eq_pos) = inner.find('=') {
        let attr = &inner[..eq_pos];
        let val  = &inner[eq_pos+1..];
        if val == "*" {
            return Ok(encode_present_filter(attr));
        }
        // Decode RFC 4515 escape sequences (\HH)
        let val_bytes = decode_filter_value(val)?;
        return Ok(encode_equality_filter(attr, &val_bytes));
    }
    bail!("Unsupported filter: {f}");
}

fn decode_filter_value(s: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i+1..i+3])
                .map_err(|_| anyhow!("Invalid escape in filter"))?;
            let b = u8::from_str_radix(hex, 16)
                .map_err(|_| anyhow!("Invalid hex escape \\{hex} in filter"))?;
            out.push(b);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Ok(out)
}


pub struct Ldap3Client {
    ldap: Ldap,
}

impl Ldap3Client {
    async fn connect(cfg: &ConnConfig, password: &str) -> Result<Self> {
        let scheme = if cfg.use_ldaps { "ldaps" } else { "ldap" };
        let url = format!("{}://{}:{}", scheme, cfg.host, cfg.port);
        if cfg.debug { eprintln!("[DEBUG] ldap3 connecting to {url}"); }

        let settings = LdapConnSettings::new();
        let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &url)
            .await
            .with_context(|| format!("Failed to connect to {url}"))?;
        ldap3::drive!(conn);

        let upn = format!("{}@{}", cfg.username, cfg.domain);
        if cfg.debug { eprintln!("[DEBUG] Simple bind as {upn}"); }
        ldap.simple_bind(&upn, password)
            .await
            .context("Simple bind failed")?
            .success()
            .context("Simple bind returned non-success")?;

        Ok(Ldap3Client { ldap })
    }

    async fn get_default_naming_context(&mut self) -> Result<String> {
        let (entries, _) = self.ldap
            .search("", Scope::Base, "(objectClass=*)", vec!["defaultNamingContext"])
            .await.context("RootDSE query failed")?
            .success().context("RootDSE error")?;
        let entry = entries.into_iter().next()
            .ok_or_else(|| anyhow!("RootDSE empty"))?;
        let e = Ldap3Entry::construct(entry);
        e.attrs.get("defaultNamingContext")
            .and_then(|v| v.first()).cloned()
            .ok_or_else(|| anyhow!("defaultNamingContext missing"))
    }

    async fn search(&mut self, base: &str, filter: &str,
                    attrs: &[&str]) -> Result<Vec<SearchResult>> {
        let (entries, _) = self.ldap
            .search(base, Scope::Subtree, filter, attrs.to_vec())
            .await.with_context(|| format!("LDAP search failed (filter={filter})"))?
            .success().with_context(|| format!("LDAP search error (filter={filter})"))?;
        Ok(entries.into_iter().map(|e| SearchResult::from(Ldap3Entry::construct(e))).collect())
    }

    async fn search_base(&mut self, dn: &str, filter: &str,
                         attrs: &[&str]) -> Result<Vec<SearchResult>> {
        let (entries, _) = self.ldap
            .search(dn, Scope::Base, filter, attrs.to_vec())
            .await.with_context(|| format!("LDAP base search failed (dn={dn})"))?
            .success().with_context(|| format!("LDAP base search error (dn={dn})"))?;
        Ok(entries.into_iter().map(|e| SearchResult::from(Ldap3Entry::construct(e))).collect())
    }

    async fn modify_replace_binary(&mut self, dn: &str, attr: &str,
                                   value: &[u8]) -> Result<()> {
        use ldap3::Mod;
        use std::collections::HashSet;
        let mods: Vec<Mod<Vec<u8>>> = vec![
            Mod::Replace(attr.as_bytes().to_vec(), HashSet::from([value.to_vec()])),
        ];
        let res = self.ldap.modify(dn, mods).await
            .with_context(|| format!("LDAP modify failed (dn={dn})"))?;
        ldap_rc_to_result(res.rc, &res.text, dn)
    }

    async fn modify_clear_attribute(&mut self, dn: &str, attr: &str) -> Result<()> {
        use ldap3::Mod;
        use std::collections::HashSet;
        let mods: Vec<Mod<Vec<u8>>> = vec![
            Mod::Replace(attr.as_bytes().to_vec(), HashSet::<Vec<u8>>::new()),
        ];
        let res = self.ldap.modify(dn, mods).await
            .with_context(|| format!("LDAP modify/clear failed (dn={dn})"))?;
        ldap_rc_to_result(res.rc, &res.text, dn)
    }
}

fn ldap_rc_to_result(rc: u32, text: &str, dn: &str) -> Result<()> {
    match rc {
        0  => Ok(()),
        50 => bail!("Could not modify object, the server reports insufficient rights: {text}"),
        19 => bail!("Could not modify object, the server reports a constrained violation: {text}"),
        _  => bail!("The server returned an error modifying {dn} (code {rc}): {text}"),
    }
}


pub fn ldap_escape_binary(data: &[u8]) -> String {
    data.iter().map(|b| format!("\\{b:02x}")).collect()
}

pub fn ldap_escape_filter(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\5c"),
            '*'  => out.push_str("\\2a"),
            '('  => out.push_str("\\28"),
            ')'  => out.push_str("\\29"),
            '\0' => out.push_str("\\00"),
            c    => out.push(c),
        }
    }
    out
}


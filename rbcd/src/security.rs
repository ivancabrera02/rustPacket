/// Windows Security Descriptor structures for msDS-AllowedToActOnBehalfOfOtherIdentity.

use std::fmt;
use anyhow::{anyhow, bail, Result};


/// A Windows Security Identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sid {
    pub revision: u8,
    pub identifier_authority: [u8; 6],
    pub sub_authorities: Vec<u32>,
}

impl Sid {
    /// Parse a canonical SID string 
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        if !s.starts_with("S-") && !s.starts_with("s-") {
            bail!("SID must start with 'S-': {s}");
        }
        let parts: Vec<&str> = s[2..].split('-').collect();
        if parts.len() < 2 {
            bail!("Invalid SID (too few components): {s}");
        }
        let revision: u8 = parts[0].parse().map_err(|_| anyhow!("Bad revision in SID: {s}"))?;
        let authority: u64 = parts[1].parse().map_err(|_| anyhow!("Bad authority in SID: {s}"))?;

        let mut identifier_authority = [0u8; 6];
        identifier_authority[2] = ((authority >> 32) & 0xff) as u8;
        identifier_authority[3] = ((authority >> 24) & 0xff) as u8;
        identifier_authority[4] = ((authority >> 16) & 0xff) as u8;
        identifier_authority[5] = (authority & 0xff) as u8;
      

        let sub_authorities: Vec<u32> = parts[2..]
            .iter()
            .map(|p| p.parse::<u32>().map_err(|_| anyhow!("Bad sub-authority in SID: {s}")))
            .collect::<Result<_>>()?;

        Ok(Sid { revision, identifier_authority, sub_authorities })
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 8 {
            bail!("SID too short: {} bytes", data.len());
        }
        let revision = data[0];
        let count = data[1] as usize;
        let identifier_authority: [u8; 6] = data[2..8].try_into().unwrap();
        let expected = 8 + count * 4;
        if data.len() < expected {
            bail!("SID data truncated: need {expected}, have {}", data.len());
        }
        let sub_authorities: Vec<u32> = (0..count)
            .map(|i| u32::from_le_bytes(data[8 + i * 4..8 + i * 4 + 4].try_into().unwrap()))
            .collect();
        Ok(Sid { revision, identifier_authority, sub_authorities })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.sub_authorities.len() * 4);
        out.push(self.revision);
        out.push(self.sub_authorities.len() as u8);
        out.extend_from_slice(&self.identifier_authority);
        for &sa in &self.sub_authorities {
            out.extend_from_slice(&sa.to_le_bytes());
        }
        out
    }

    #[allow(dead_code)]
    pub fn byte_len(&self) -> usize {
        8 + self.sub_authorities.len() * 4
    }
}

impl fmt::Display for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let authority = ((self.identifier_authority[0] as u64) << 40)
            | ((self.identifier_authority[1] as u64) << 32)
            | ((self.identifier_authority[2] as u64) << 24)
            | ((self.identifier_authority[3] as u64) << 16)
            | ((self.identifier_authority[4] as u64) << 8)
            | (self.identifier_authority[5] as u64);
        write!(f, "S-{}-{}", self.revision, authority)?;
        for sa in &self.sub_authorities {
            write!(f, "-{}", sa)?;
        }
        Ok(())
    }
}


pub const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x00;
pub const FULL_CONTROL_MASK: u32 = 983551;

#[derive(Debug, Clone)]
pub struct Ace {
    pub ace_type: u8,
    pub ace_flags: u8,
    pub mask: u32,
    pub sid: Sid,
}

impl Ace {
    /// Create an ACCESS_ALLOWED ACE 
    pub fn new_allow(sid: Sid) -> Self {
        Ace { ace_type: ACCESS_ALLOWED_ACE_TYPE, ace_flags: 0x00, mask: FULL_CONTROL_MASK, sid }
    }

    pub fn from_bytes(data: &[u8]) -> Result<(Self, usize)> {
        if data.len() < 8 {
            bail!("ACE too short");
        }
        let ace_type = data[0];
        let ace_flags = data[1];
        let ace_size = u16::from_le_bytes([data[2], data[3]]) as usize;
        if data.len() < ace_size {
            bail!("ACE data truncated");
        }
        let mask = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let sid = Sid::from_bytes(&data[8..ace_size])?;
        Ok((Ace { ace_type, ace_flags, mask, sid }, ace_size))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let sid_bytes = self.sid.to_bytes();
        // header (4) + mask (4) + sid
        let size = 8 + sid_bytes.len();
        let mut out = Vec::with_capacity(size);
        out.push(self.ace_type);
        out.push(self.ace_flags);
        out.extend_from_slice(&(size as u16).to_le_bytes());
        out.extend_from_slice(&self.mask.to_le_bytes());
        out.extend_from_slice(&sid_bytes);
        out
    }
}


#[derive(Debug, Clone)]
pub struct Acl {
    pub acl_revision: u8,
    pub aces: Vec<Ace>,
}

impl Acl {
    pub fn new_empty() -> Self {
        Acl { acl_revision: 4, aces: vec![] }
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 8 {
            bail!("ACL too short");
        }
        let acl_revision = data[0];
        // data[1] = Sbz1
        let _acl_size = u16::from_le_bytes([data[2], data[3]]);
        let ace_count = u16::from_le_bytes([data[4], data[5]]) as usize;
        // data[6..8] = Sbz2
        let mut aces = Vec::with_capacity(ace_count);
        let mut offset = 8;
        for _ in 0..ace_count {
            let (ace, consumed) = Ace::from_bytes(&data[offset..])?;
            aces.push(ace);
            offset += consumed;
        }
        Ok(Acl { acl_revision, aces })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut aces_bytes: Vec<u8> = self.aces.iter().flat_map(|a| a.to_bytes()).collect();
        let total = 8 + aces_bytes.len();
        let mut out = Vec::with_capacity(total);
        out.push(self.acl_revision);
        out.push(0u8); // Sbz1
        out.extend_from_slice(&(total as u16).to_le_bytes()); // AclSize
        out.extend_from_slice(&(self.aces.len() as u16).to_le_bytes()); // AceCount
        out.extend_from_slice(&0u16.to_le_bytes()); // Sbz2
        out.append(&mut aces_bytes);
        out
    }
}


pub const SE_SELF_RELATIVE: u16 = 0x8000;
pub const SE_DACL_PRESENT: u16 = 0x0004;

#[derive(Debug, Clone)]
pub struct SecurityDescriptor {
    pub revision: u8,
    pub control: u16,
    pub owner: Option<Sid>,
    pub group: Option<Sid>,
    pub dacl: Option<Acl>,
}

impl SecurityDescriptor {
    /// Create an empty SD 
    pub fn new_empty() -> Self {
        let owner = Sid::parse("S-1-5-32-544").expect("hardcoded SID is valid");
        SecurityDescriptor {
            revision: 1,
            control: SE_SELF_RELATIVE | SE_DACL_PRESENT | 0x0800, // 0x8804 — matches impacket's 32772
            owner: Some(owner),
            group: None,
            dacl: Some(Acl::new_empty()),
        }
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 20 {
            bail!("Security descriptor too short: {} bytes", data.len());
        }
        let revision = data[0];
        let control = u16::from_le_bytes([data[2], data[3]]);
        let offset_owner = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
        let offset_group = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
        let _offset_sacl = u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as usize;
        let offset_dacl = u32::from_le_bytes([data[16], data[17], data[18], data[19]]) as usize;

        let owner = if offset_owner > 0 && offset_owner < data.len() {
            Some(Sid::from_bytes(&data[offset_owner..])?)
        } else {
            None
        };

        let group = if offset_group > 0 && offset_group < data.len() {
            Some(Sid::from_bytes(&data[offset_group..])?)
        } else {
            None
        };

        let dacl = if offset_dacl > 0 && offset_dacl < data.len() {
            Some(Acl::from_bytes(&data[offset_dacl..])?)
        } else {
            None
        };

        Ok(SecurityDescriptor { revision, control, owner, group, dacl })
    }

   
    pub fn to_bytes(&self) -> Vec<u8> {
        // Fixed header is 20 bytes.
        let header_size: usize = 20;

        let owner_bytes = self.owner.as_ref().map(|s| s.to_bytes()).unwrap_or_default();
        let dacl_bytes = self.dacl.as_ref().map(|a| a.to_bytes()).unwrap_or_default();

        let owner_offset: u32 = if owner_bytes.is_empty() {
            0
        } else {
            header_size as u32
        };

        let group_offset: u32 = 0;
        let sacl_offset: u32 = 0;

        let dacl_offset: u32 = if dacl_bytes.is_empty() {
            0
        } else {
            header_size as u32 + owner_bytes.len() as u32
        };

        let mut out = Vec::with_capacity(header_size + owner_bytes.len() + dacl_bytes.len());
        out.push(self.revision);
        out.push(0u8); // Sbz1
        out.extend_from_slice(&self.control.to_le_bytes());
        out.extend_from_slice(&owner_offset.to_le_bytes());
        out.extend_from_slice(&group_offset.to_le_bytes());
        out.extend_from_slice(&sacl_offset.to_le_bytes());
        out.extend_from_slice(&dacl_offset.to_le_bytes());
        out.extend_from_slice(&owner_bytes);
        out.extend_from_slice(&dacl_bytes);
        out
    }
}


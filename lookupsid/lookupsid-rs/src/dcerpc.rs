/// DCE/RPC over SMB2 named pipes — MS-RPCE, MS-LSAT, MS-LSAD
use anyhow::{anyhow, Result};
use crate::smb2::Smb2Session;

const PDU_REQUEST: u8   = 0x00;
const PDU_RESPONSE: u8  = 0x02;
const PDU_FAULT: u8     = 0x03;
const PDU_BIND: u8      = 0x0B;
const PDU_BIND_ACK: u8  = 0x0C;
const PFC_FIRST_LAST: u8 = 0x03;

// LSARPC: 12345778-1234-ABCD-EF00-0123456789AB v0.0
const LSARPC_UUID: [u8;16] = [0x78,0x57,0x34,0x12,0x34,0x12,0xCD,0xAB,0xEF,0x00,0x01,0x23,0x45,0x67,0x89,0xAB];
// NDR: 8a885d04-1ceb-11c9-9fe8-08002b104860 v2.0
const NDR_UUID: [u8;16] = [0x04,0x5d,0x88,0x8a,0xeb,0x1c,0xc9,0x11,0x9f,0xe8,0x08,0x00,0x2b,0x10,0x48,0x60];

const OP_OPEN_POLICY2: u16   = 44;
const OP_QUERY_INFO2: u16    = 46;
const OP_LOOKUP_SIDS: u16    = 15;

pub const INFO_ACCOUNT_DOMAIN: u32 = 5;
pub const INFO_PRIMARY_DOMAIN: u32 = 3;

#[derive(Debug, Clone, PartialEq)]
pub enum SidType { User, Group, Domain, Alias, WellKnown, Deleted, Invalid, Unknown, Computer, Label }
impl SidType {
    pub fn from_u16(v: u16) -> Self {
        match v { 1=>Self::User, 2=>Self::Group, 3=>Self::Domain, 4=>Self::Alias,
            5=>Self::WellKnown, 6=>Self::Deleted, 7=>Self::Invalid, 9=>Self::Computer, 10=>Self::Label, _=>Self::Unknown }
    }
    pub fn name(&self) -> &'static str {
        match self { Self::User=>"SidTypeUser", Self::Group=>"SidTypeGroup", Self::Domain=>"SidTypeDomain",
            Self::Alias=>"SidTypeAlias", Self::WellKnown=>"SidTypeWellKnownGroup", Self::Deleted=>"SidTypeDeletedAccount",
            Self::Invalid=>"SidTypeInvalid", Self::Unknown=>"SidTypeUnknown", Self::Computer=>"SidTypeComputer", Self::Label=>"SidTypeLabel" }
    }
}

pub struct LookupResult {
    pub domains: Vec<String>,
    pub names: Vec<(u32, String, u16)>, // domain_idx, name, use
}

pub struct DceRpc { call_id: u32, fid: [u8;16], max_frag: u16 }

impl DceRpc {
    pub fn new(fid: [u8;16]) -> Self { Self { call_id: 1, fid, max_frag: 4280 } }

    fn next_id(&mut self) -> u32 { let i = self.call_id; self.call_id += 1; i }

    fn rpc_hdr(&self, pt: u8, cid: u32, blen: usize) -> Vec<u8> {
        let tl = (16 + blen) as u16;
        let mut h = Vec::with_capacity(16);
        h.push(5); h.push(0); h.push(pt); h.push(PFC_FIRST_LAST);
        h.extend_from_slice(&[0x10,0x00,0x00,0x00]); // LE NDR
        h.extend_from_slice(&tl.to_le_bytes());
        h.extend_from_slice(&0u16.to_le_bytes());
        h.extend_from_slice(&cid.to_le_bytes());
        h
    }

    pub async fn bind(&mut self, smb: &mut Smb2Session) -> Result<()> {
        let mut b = Vec::new();
        b.extend_from_slice(&0xFFFFu16.to_le_bytes()); // MaxXmitFrag = 65535
        b.extend_from_slice(&0xFFFFu16.to_le_bytes()); // MaxRecvFrag = 65535
        b.extend_from_slice(&0u32.to_le_bytes());
        b.push(1); b.extend_from_slice(&[0u8;3]);
        b.extend_from_slice(&0u16.to_le_bytes()); // ctx 0
        b.extend_from_slice(&1u16.to_le_bytes());
        b.extend_from_slice(&LSARPC_UUID); b.extend_from_slice(&0u16.to_le_bytes()); b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&NDR_UUID); b.extend_from_slice(&2u16.to_le_bytes()); b.extend_from_slice(&0u16.to_le_bytes());
        let cid = self.next_id();
        let h = self.rpc_hdr(PDU_BIND, cid, b.len());
        let r = smb.ioctl_transceive(&self.fid, &[h,b].concat()).await?;
        if r.len() < 16 || r[2] != PDU_BIND_ACK { return Err(anyhow!("bind failed")); }
        // Parse bind_ack: offset 16 = max_xmit_frag(2) + max_recv_frag(2)
        if r.len() >= 20 {
            self.max_frag = u16::from_le_bytes(r[16..18].try_into().unwrap_or([0xFF, 0xFF]));
            tracing::debug!("DCE/RPC bind OK, server max_frag={}", self.max_frag);
        } else {
            tracing::debug!("DCE/RPC bind OK");
        }
        Ok(())
    }

    async fn call(&mut self, smb: &mut Smb2Session, opnum: u16, stub: &[u8]) -> Result<Vec<u8>> {
        let cid = self.next_id();
        let mut b = Vec::new();
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&opnum.to_le_bytes());
        b.extend_from_slice(stub);
        let h = self.rpc_hdr(PDU_REQUEST, cid, b.len());
        let r = smb.ioctl_transceive(&self.fid, &[h,b].concat()).await?;
        if r.len() < 24 { return Err(anyhow!("rpc resp short")); }
        if r[2] == PDU_FAULT {
            let st = if r.len()>=20 { u32::from_le_bytes(r[16..20].try_into().unwrap_or([0;4])) } else {0};
            return Err(anyhow!("rpc fault: 0x{:08X}", st));
        }
        if r[2] != PDU_RESPONSE { return Err(anyhow!("expected response, got 0x{:02X}", r[2])); }
        Ok(r[24..].to_vec())
    }

    pub async fn open_policy2(&mut self, smb: &mut Smb2Session, target: &str) -> Result<Vec<u8>> {
        let mut s = Vec::new();

        // SystemName: [in, unique, string] wchar_t*
        // NDR encoding for a unique pointer to a conformant string:
        //   ReferentId (4 bytes) — non-zero means pointer is present
        //   MaximumCount (4 bytes) — number of wchar_t elements including null terminator
        //   Offset (4 bytes) = 0
        //   ActualCount (4 bytes) — same as MaximumCount for strings
        //   StringData (ActualCount * 2 bytes) — UTF-16LE with null terminator
        let tu: Vec<u8> = target.encode_utf16().chain(std::iter::once(0u16))
            .flat_map(|c| c.to_le_bytes()).collect();
        let char_count = (tu.len() / 2) as u32;

        s.extend_from_slice(&0x00020000u32.to_le_bytes()); // ReferentId (non-null)
        s.extend_from_slice(&char_count.to_le_bytes());     // MaximumCount
        s.extend_from_slice(&0u32.to_le_bytes());           // Offset
        s.extend_from_slice(&char_count.to_le_bytes());     // ActualCount
        s.extend_from_slice(&tu);                            // String data (with null term)
        // Pad to 4-byte boundary
        let pad = (4 - (tu.len() % 4)) % 4;
        s.extend_from_slice(&vec![0u8; pad]);

        // ObjectAttributes: LSAPR_OBJECT_ATTRIBUTES
        // NDR layout:
        //   Length (4 bytes) = 24
        //   RootDirectory (pointer, 4 bytes) = NULL (0)
        //   ObjectName (pointer, 4 bytes) = NULL (0)
        //   Attributes (4 bytes) = 0
        //   SecurityDescriptor (pointer, 4 bytes) = NULL (0)
        //   SecurityQualityOfService (pointer, 4 bytes) = NULL (0)
        s.extend_from_slice(&24u32.to_le_bytes());  // Length
        s.extend_from_slice(&0u32.to_le_bytes());   // RootDirectory (NULL ptr)
        s.extend_from_slice(&0u32.to_le_bytes());   // ObjectName (NULL ptr)
        s.extend_from_slice(&0u32.to_le_bytes());   // Attributes
        s.extend_from_slice(&0u32.to_le_bytes());   // SecurityDescriptor (NULL ptr)
        s.extend_from_slice(&0u32.to_le_bytes());   // SecurityQualityOfService (NULL ptr)

        // DesiredAccess: MAXIMUM_ALLOWED | POLICY_LOOKUP_NAMES
        s.extend_from_slice(&0x02000800u32.to_le_bytes());

        let r = self.call(smb, OP_OPEN_POLICY2, &s).await?;
        if r.len() < 24 { return Err(anyhow!("OpenPolicy2 resp short")); }
        let st = u32::from_le_bytes(r[r.len()-4..].try_into()?);
        if st != 0 { return Err(anyhow!("OpenPolicy2: 0x{:08X}", st)); }
        Ok(r[..20].to_vec())
    }

    pub async fn query_info_policy2(&mut self, smb: &mut Smb2Session, ph: &[u8], ic: u32) -> Result<String> {
        let mut s = Vec::new();
        s.extend_from_slice(ph);
        // InformationClass is a POLICY_INFORMATION_CLASS enum — NDR encodes enums as u32
        s.extend_from_slice(&ic.to_le_bytes());
        let r = self.call(smb, OP_QUERY_INFO2, &s).await?;
        tracing::debug!("QueryInfoPolicy2 response: {} bytes", r.len());
        if r.len() >= 80 {
            tracing::debug!("  hex[0..80]: {}", hex::encode(&r[..80]));
        }
        parse_domain_sid(&r)
    }

    pub async fn lookup_sids(&mut self, smb: &mut Smb2Session, ph: &[u8], sids: &[String]) -> Result<LookupResult> {
        let mut s = Vec::new();

        // PolicyHandle (20 bytes context handle)
        s.extend_from_slice(ph);

        // SidEnumBuffer: LSAPR_SID_ENUM_BUFFER (embedded, top-level [in])
        //   Entries (u32) 
        //   SidInfo: PLSAPR_SID_INFORMATION (unique pointer to conformant array)
        let n = sids.len() as u32;
        s.extend_from_slice(&n.to_le_bytes());                     // Entries
        s.extend_from_slice(&0x00020000u32.to_le_bytes());          // SidInfo ptr (referent)

        // Deferred data for SidInfo: conformant array of LSAPR_SID_INFORMATION
        //   MaxCount (u32) — conformant array header
        //   Elements: each is PRPC_SID (unique pointer, 4 bytes referent id)
        s.extend_from_slice(&n.to_le_bytes());                      // MaxCount
        for i in 0..n {
            s.extend_from_slice(&(0x00020004u32 + i * 4).to_le_bytes()); // SID ptr referent
        }

        // Deferred data for each SID pointer: RPC_SID
        for sid in sids {
            s.extend_from_slice(&sid_to_ndr(sid)?);
        }

        // TranslatedNames: LSAPR_TRANSLATED_NAMES (embedded, top-level [in,out] ref pointer)
        //   Entries (u32)
        //   Names: PLSAPR_TRANSLATED_NAME (unique pointer to conformant array)
        s.extend_from_slice(&0u32.to_le_bytes());                   // Entries = 0
        s.extend_from_slice(&0u32.to_le_bytes());                   // Names ptr = NULL

        // LookupLevel: LSAP_LOOKUP_LEVEL enum — NDR enums are u32 in MS-RPC
        s.extend_from_slice(&1u32.to_le_bytes());  // LsapLookupWksta = 1

        // MappedCount: [in, out] unsigned long (u32, ref pointer = embedded)
        s.extend_from_slice(&0u32.to_le_bytes());

        tracing::debug!("LookupSids stub: {} bytes, {} SIDs", s.len(), n);
        tracing::debug!("  stub hex[0..min(120,len)]: {}", hex::encode(&s[..s.len().min(120)]));

        let r = self.call(smb, OP_LOOKUP_SIDS, &s).await?;
        tracing::debug!("LookupSids response: {} bytes", r.len());
        tracing::debug!("  resp hex: {}", hex::encode(&r[..r.len().min(300)]));
        parse_lookup_resp(&r)
    }
}

fn sid_to_ndr(s: &str) -> Result<Vec<u8>> {
    let p: Vec<&str> = s.split('-').collect();
    if p.len() < 3 || p[0] != "S" { return Err(anyhow!("bad SID")); }
    let rev: u8 = p[1].parse()?;
    let auth: u64 = p[2].parse()?;
    let subs: Vec<u32> = p[3..].iter().map(|x| x.parse::<u32>()).collect::<std::result::Result<_,_>>()?;
    let sc = subs.len() as u8;
    let mut sid = Vec::with_capacity(8 + sc as usize * 4);
    sid.push(rev); sid.push(sc);
    sid.extend_from_slice(&[(auth>>40)as u8,(auth>>32)as u8,(auth>>24)as u8,(auth>>16)as u8,(auth>>8)as u8,auth as u8]);
    for sa in &subs { sid.extend_from_slice(&sa.to_le_bytes()); }
    let mut ndr = Vec::new();
    ndr.extend_from_slice(&(sc as u32).to_le_bytes());
    ndr.extend_from_slice(&sid);
    let pad = (4 - (sid.len() % 4)) % 4;
    ndr.extend_from_slice(&vec![0u8; pad]);
    Ok(ndr)
}

fn parse_domain_sid(r: &[u8]) -> Result<String> {
    // The response ends with NTSTATUS (last 4 bytes)
    if r.len() < 8 { return Err(anyhow!("QueryInfo resp short")); }
    let st = u32::from_le_bytes(r[r.len()-4..].try_into()?);
    if st != 0 { return Err(anyhow!("QueryInfoPolicy2: 0x{:08X}", st)); }

    // Response layout for POLICY_ACCOUNT_DOMAIN_INFO (info class 5):
    //   [0..4]   InfoClass pointer (referent id) — non-zero
    //   [4..8]   Union switch value (= info_class)
    //   [8..10]  DomainName.Length (u16)
    //   [10..12] DomainName.MaximumLength (u16)
    //   [12..16] DomainName.Buffer (pointer, referent id)
    //   [16..20] DomainSid (pointer, referent id)
    //   -- deferred pointers start here --
    //   [20..]   DomainName.Buffer data: MaxCount(4) + Offset(4) + ActualCount(4) + wchars + pad
    //   [..]     DomainSid data: MaxSubAuthCount(4) + Revision(1) + SubAuthCount(1) + Authority(6) + SubAuth[n]
    //   [last 4] NTSTATUS

    let data = &r[..r.len()-4]; // exclude trailing NTSTATUS

    if data.len() < 20 { return Err(anyhow!("response too short for POLICY_x_DOMAIN_INFO")); }

    let _info_ptr = u32::from_le_bytes(data[0..4].try_into()?);
    let _switch = u32::from_le_bytes(data[4..8].try_into()?);
    let _name_len = u16::from_le_bytes(data[8..10].try_into()?);
    let _name_maxlen = u16::from_le_bytes(data[10..12].try_into()?);
    let name_ptr = u32::from_le_bytes(data[12..16].try_into()?);
    let sid_ptr = u32::from_le_bytes(data[16..20].try_into()?);

    tracing::debug!("  name_ptr=0x{:08X}, sid_ptr=0x{:08X}", name_ptr, sid_ptr);

    let mut o = 20usize;

    // Skip domain name string if pointer is non-null
    if name_ptr != 0 {
        if o + 12 > data.len() { return Err(anyhow!("name string header truncated")); }
        let _mc = u32::from_le_bytes(data[o..o+4].try_into()?); o += 4;
        let _ofs = u32::from_le_bytes(data[o..o+4].try_into()?); o += 4;
        let ac = u32::from_le_bytes(data[o..o+4].try_into()?) as usize; o += 4;
        let sb = ac * 2;
        if o + sb > data.len() { return Err(anyhow!("name string data truncated")); }

        let domain_name = crate::ntlm::utf16le_decode(&data[o..o+sb]);
        tracing::debug!("  domain_name = '{}'", domain_name);

        o += sb;
        o += (4 - (sb % 4)) % 4; // pad to 4
    }

    // Parse SID
    if sid_ptr == 0 { return Err(anyhow!("DomainSid is NULL")); }

    if o + 4 > data.len() { return Err(anyhow!("SID MaxSubAuthCount truncated")); }
    let _max_sub = u32::from_le_bytes(data[o..o+4].try_into()?); o += 4;

    if o + 8 > data.len() { return Err(anyhow!("SID header truncated")); }
    let revision = data[o];
    let sub_count = data[o+1] as usize;
    let authority = &data[o+2..o+8];
    o += 8;

    if o + sub_count * 4 > data.len() { return Err(anyhow!("SID sub-authorities truncated")); }

    let id_auth: u64 = (authority[0] as u64) << 40
        | (authority[1] as u64) << 32
        | (authority[2] as u64) << 24
        | (authority[3] as u64) << 16
        | (authority[4] as u64) << 8
        | authority[5] as u64;

    let mut sid = format!("S-{}-{}", revision, id_auth);
    for i in 0..sub_count {
        let sa = u32::from_le_bytes(data[o..o+4].try_into()?);
        sid.push_str(&format!("-{}", sa));
        o += 4;
    }

    tracing::debug!("  parsed SID = {}", sid);
    Ok(sid)
}

fn parse_lookup_resp(r: &[u8]) -> Result<LookupResult> {
    if r.len() < 8 { return Err(anyhow!("LookupSids resp short")); }
    let st = u32::from_le_bytes(r[r.len()-4..].try_into()?);
    match st { 0|0x107 => {}, 0xC0000073 => return Err(anyhow!("STATUS_NONE_MAPPED")),
        _ => return Err(anyhow!("LookupSids: 0x{:08X}", st)) }

    let mut o = 0usize;

    // PLSAPR_REFERENCED_DOMAIN_LIST (unique pointer)
    let dp = r4(r,&mut o)?;  // referent id
    let mut doms = Vec::new();

    if dp != 0 {
        // LSAPR_REFERENCED_DOMAIN_LIST:
        //   Entries (u32)
        //   Domains: PLSAPR_TRUST_INFORMATION [size_is(Entries)] — pointer (u32 referent)
        //   MaxEntries (u32)
        let entries = r4(r,&mut o)? as usize;
        let _domains_ptr = r4(r,&mut o)?;  // referent id for Domains array
        let _max_entries = r4(r,&mut o)?;   // MaxEntries

        // Deferred: conformant array of LSAPR_TRUST_INFORMATION
        //   MaxCount (u32) — conformant array header
        let _arr_max_count = r4(r,&mut o)?;

        // Each LSAPR_TRUST_INFORMATION:
        //   Name: RPC_UNICODE_STRING = Length(2) + MaxLength(2) + BufferPtr(4) = 8 bytes
        //   Sid: PRPC_SID = pointer(4) = 4 bytes
        //   Total = 12 bytes per entry
        let hstart = o;
        o += entries * 12;  // skip past all headers

        // Now read deferred data for each domain
        for i in 0..entries {
            let ho = hstart + i * 12;
            let nl = u16::from_le_bytes(r[ho..ho+2].try_into().unwrap_or([0,0])) as usize;
            let np = u32::from_le_bytes(r[ho+4..ho+8].try_into().unwrap_or([0;4]));

            // Read name string (deferred pointer data)
            if np != 0 && nl > 0 {
                doms.push(read_unistr(r,&mut o)?);
            } else {
                doms.push(String::new());
            }

            // Read SID (deferred pointer data)
            let sid_ptr = u32::from_le_bytes(r[ho+8..ho+12].try_into().unwrap_or([0;4]));
            if sid_ptr != 0 {
                skip_sid(r, &mut o);
            }
        }
    }

    // LSAPR_TRANSLATED_NAMES:
    //   Entries (u32)
    //   Names: PLSAPR_TRANSLATED_NAME [size_is(Entries)] — pointer (u32 referent)
    let nc = r4(r,&mut o)? as usize;
    let names_ptr = r4(r,&mut o)?;

    let mut nhdrs = Vec::new();
    if nc > 0 && names_ptr != 0 {
        // Deferred: conformant array
        let _arr_max = r4(r,&mut o)?;  // MaxCount

        // Each LSAPR_TRANSLATED_NAME:
        //   Use (u16) + padding(u16) = 4 bytes
        //   Name: RPC_UNICODE_STRING = Length(2) + MaxLength(2) + BufferPtr(4) = 8 bytes
        //   DomainIndex (u32) = 4 bytes
        //   Total = 16 bytes
        for _ in 0..nc {
            if o+16 > r.len() { break; }
            let ut = u16::from_le_bytes(r[o..o+2].try_into()?); o+=2;
            o+=2; // padding
            let _nl = u16::from_le_bytes(r[o..o+2].try_into()?); o+=2;
            let _ml = u16::from_le_bytes(r[o..o+2].try_into()?); o+=2;
            let np = u32::from_le_bytes(r[o..o+4].try_into()?); o+=4;
            let di = u32::from_le_bytes(r[o..o+4].try_into()?); o+=4;
            nhdrs.push((ut, np, di));
        }
    }

    // Read deferred name strings
    let mut names = Vec::new();
    for (ut, np, di) in nhdrs {
        if np != 0 {
            names.push((di, read_unistr(r,&mut o).unwrap_or_default(), ut));
        } else {
            names.push((di, String::new(), ut));
        }
    }

    Ok(LookupResult { domains: doms, names })
}

fn r4(r: &[u8], o: &mut usize) -> Result<u32> {
    if *o+4 > r.len() { return Err(anyhow!("truncated at {}", o)); }
    let v = u32::from_le_bytes(r[*o..*o+4].try_into()?); *o += 4; Ok(v)
}

fn read_unistr(r: &[u8], o: &mut usize) -> Result<String> {
    if *o+12 > r.len() { return Err(anyhow!("unistr hdr truncated")); }
    let _mc = r4(r,o)?;
    let _ofs = r4(r,o)?;
    let ac = r4(r,o)? as usize;
    let sb = ac*2;
    if *o+sb > r.len() { return Err(anyhow!("unistr data truncated")); }
    let s = crate::ntlm::utf16le_decode(&r[*o..*o+sb]);
    *o += sb;
    *o += (4 - (sb%4))%4;
    Ok(s)
}

fn skip_sid(r: &[u8], o: &mut usize) {
    if *o+4 > r.len() { return; }
    let mc = u32::from_le_bytes(r[*o..*o+4].try_into().unwrap_or([0;4])) as usize;
    *o += 4;
    if *o+8 > r.len() { return; }
    let sc = r[*o+1] as usize;
    *o += 8;
    *o += sc * 4;
    let pad = (4 - (((sc*4+8)%4)%4))%4; // pad to 4
    *o += pad;
}

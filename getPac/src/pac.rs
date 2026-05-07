// pac.rs — PAC (Privilege Attribute Certificate) parser
//
// Implements [MS-PAC] structures

use anyhow::{bail, Result};
use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{Cursor, Read};

// PAC buffer type constants
const PAC_LOGON_INFO: u32 = 1;
const PAC_CREDENTIALS_INFO: u32 = 2;
const PAC_SERVER_CHECKSUM_TYPE: u32 = 6;
const PAC_PRIVSVR_CHECKSUM_TYPE: u32 = 7;
const PAC_CLIENT_INFO_TYPE: u32 = 10;
const PAC_S4U_DELEGATION_INFO: u32 = 11;
const PAC_UPN_DNS_INFO_TYPE: u32 = 12;
const PAC_TICKET_CHECKSUM_TYPE: u32 = 16;
const PAC_ATTRIBUTES_INFO_TYPE: u32 = 17;
const PAC_REQUESTOR_SID_TYPE: u32 = 18;

// UserAccountControl flags
const UF_ACCOUNTDISABLE: u32 = 0x0002;
const UF_LOCKOUT: u32 = 0x0010;
const UF_PASSWD_NOTREQD: u32 = 0x0020;
const UF_NORMAL_ACCOUNT: u32 = 0x0200;
const UF_DONT_EXPIRE_PASSWD: u32 = 0x10000;
const UF_SMARTCARD_REQUIRED: u32 = 0x40000;
const UF_TRUSTED_FOR_DELEGATION: u32 = 0x80000;
const UF_NOT_DELEGATED: u32 = 0x100000;
const UF_USE_DES_KEY_ONLY: u32 = 0x200000;
const UF_DONT_REQUIRE_PREAUTH: u32 = 0x400000;
const UF_PASSWORD_EXPIRED: u32 = 0x800000;
const UF_TRUSTED_TO_AUTH_FOR_DELEGATION: u32 = 0x1000000;
const UF_NO_AUTH_DATA_REQUIRED: u32 = 0x2000000;

// ────────────────────────────────────────────────────────────────────────

pub fn parse_and_display_pac(data: &[u8]) -> Result<()> {
    if data.len() < 8 {
        bail!("PAC data too short ({} bytes)", data.len());
    }

    let mut cursor = Cursor::new(data);
    let c_buffers = cursor.read_u32::<LittleEndian>()?;
    let version = cursor.read_u32::<LittleEndian>()?;

    println!("  PAC: {} buffer(s), version {}", c_buffers, version);
    println!();

    let mut buffers = Vec::new();
    for _ in 0..c_buffers {
        let ul_type = cursor.read_u32::<LittleEndian>()?;
        let cb_size = cursor.read_u32::<LittleEndian>()?;
        let offset = cursor.read_u64::<LittleEndian>()?;
        buffers.push((ul_type, cb_size as usize, offset as usize));
    }

    for (ul_type, size, offset) in &buffers {
        if *offset + *size > data.len() {
            println!("  [!] Buffer 0x{:x} overflows, skipping", ul_type);
            continue;
        }
        let buf = &data[*offset..*offset + *size];

        match *ul_type {
            PAC_LOGON_INFO => {
                println!("--- LOGON INFORMATION (Type 1) ---");
                parse_logon_info(buf);
                println!();
            }
            PAC_CLIENT_INFO_TYPE => {
                println!("--- CLIENT INFO (Type 10) ---");
                parse_client_info(buf);
                println!();
            }
            PAC_UPN_DNS_INFO_TYPE => {
                println!("--- UPN / DNS INFO (Type 12) ---");
                parse_upn_dns_info(buf);
                println!();
            }
            PAC_SERVER_CHECKSUM_TYPE => {
                println!("--- SERVER CHECKSUM (Type 6) ---");
                parse_signature(buf, "Server");
                println!();
            }
            PAC_PRIVSVR_CHECKSUM_TYPE => {
                println!("--- KDC CHECKSUM (Type 7) ---");
                parse_signature(buf, "KDC");
                println!();
            }
            PAC_TICKET_CHECKSUM_TYPE => {
                println!("--- TICKET CHECKSUM (Type 16) ---");
                parse_signature(buf, "Ticket");
                println!();
            }
            PAC_S4U_DELEGATION_INFO => {
                println!("--- S4U DELEGATION INFO (Type 11) ---");
                println!("  ({} bytes)", size);
                println!();
            }
            PAC_ATTRIBUTES_INFO_TYPE => {
                println!("--- PAC ATTRIBUTES (Type 17) ---");
                parse_attributes_info(buf);
                println!();
            }
            PAC_REQUESTOR_SID_TYPE => {
                println!("--- REQUESTOR SID (Type 18) ---");
                parse_requestor_sid(buf);
                println!();
            }
            PAC_CREDENTIALS_INFO => {
                println!("--- CREDENTIALS INFO (Type 2) ---");
                println!("  (encrypted, {} bytes)", size);
                println!();
            }
            _ => {
                println!("--- UNKNOWN TYPE 0x{:x} ({} bytes) ---", ul_type, size);
                println!();
            }
        }
    }
    Ok(())
}

// ─── LOGON INFO (NDR-encoded KERB_VALIDATION_INFO) ─────────────────────

fn parse_logon_info(data: &[u8]) {
    if data.len() < 20 {
        println!("  (too short for NDR header)");
        return;
    }
    let mut c = Cursor::new(data);

    // Type Serialization 1: Common Header (8) + Private Header (8) + ReferentID (4)
    let _version = c.read_u8().unwrap_or(0);
    let _endianness = c.read_u8().unwrap_or(0);
    let _common_len = c.read_u16::<LittleEndian>().unwrap_or(0);
    let _filler = c.read_u32::<LittleEndian>().unwrap_or(0);
    let _obj_len = c.read_u32::<LittleEndian>().unwrap_or(0);
    let _filler2 = c.read_u32::<LittleEndian>().unwrap_or(0);
    let _referent = c.read_u32::<LittleEndian>().unwrap_or(0);

    let pos = c.position() as usize;
    let ndr = &data[pos..];
    parse_kerb_validation_info(ndr);
}

fn parse_kerb_validation_info(data: &[u8]) {
    if data.len() < 120 {
        println!("  (KERB_VALIDATION_INFO too short: {} bytes)", data.len());
        return;
    }
    let mut c = Cursor::new(data);

    macro_rules! r64 { () => { c.read_u64::<LittleEndian>().unwrap_or(0) }; }
    macro_rules! r32 { () => { c.read_u32::<LittleEndian>().unwrap_or(0) }; }
    macro_rules! r16 { () => { c.read_u16::<LittleEndian>().unwrap_or(0) }; }

    let logon_time = r64!();
    println!("  LogonTime:           {}", filetime_str(logon_time));
    let logoff_time = r64!();
    println!("  LogoffTime:          {}", filetime_str(logoff_time));
    let kickoff = r64!();
    println!("  KickOffTime:         {}", filetime_str(kickoff));
    let pw_last = r64!();
    println!("  PasswordLastSet:     {}", filetime_str(pw_last));
    let pw_can = r64!();
    println!("  PasswordCanChange:   {}", filetime_str(pw_can));
    let pw_must = r64!();
    println!("  PasswordMustChange:  {}", filetime_str(pw_must));

    // RPC_UNICODE_STRING: Length(2) + MaxLength(2) + Pointer(4)
    let _eff_len = r16!();  let _eff_max = r16!();  let _eff_ptr = r32!();
    let _full_len = r16!(); let _full_max = r16!(); let _full_ptr = r32!();
    let _ls_len = r16!();   let _ls_max = r16!();   let _ls_ptr = r32!();
    let _pp_len = r16!();   let _pp_max = r16!();   let _pp_ptr = r32!();
    let _hd_len = r16!();   let _hd_max = r16!();   let _hd_ptr = r32!();
    let _hdr_len = r16!();  let _hdr_max = r16!();  let _hdr_ptr = r32!();

    let logon_count = r16!();
    println!("  LogonCount:          {}", logon_count);
    let bad_pw = r16!();
    println!("  BadPasswordCount:    {}", bad_pw);
    let user_id = r32!();
    println!("  UserId (RID):        {}", user_id);
    let primary_gid = r32!();
    println!("  PrimaryGroupId:      {}", primary_gid);
    let group_count = r32!();
    println!("  GroupCount:          {}", group_count);
    let _group_ptr = r32!();
    let user_flags = r32!();
    println!("  UserFlags:           0x{:08x}", user_flags);

    let mut _sess_key = [0u8; 16];
    let _ = c.read_exact(&mut _sess_key);

    let _svr_len = r16!(); let _svr_max = r16!(); let _svr_ptr = r32!();
    let _dom_len = r16!(); let _dom_max = r16!(); let _dom_ptr = r32!();
    let _dom_id_ptr = r32!();
    let _r1a = r32!(); let _r1b = r32!();

    let uac = r32!();
    println!("  UserAccountControl:  0x{:08x}", uac);
    print_uac_flags(uac);

    let _sub = r32!(); let _r3a = r32!(); let _r3b = r32!();

    let sid_count = r32!();
    println!("  ExtraSidCount:       {}", sid_count);
    let _extra_ptr = r32!();
    let _rg_dom_ptr = r32!();
    let rg_count = r32!();
    println!("  ResourceGroupCount:  {}", rg_count);

    // Deferred NDR strings
    let pos = c.position() as usize;
    let rest = &data[pos..];
    let mut sc = Cursor::new(rest);

    let labels = [
        "EffectiveName", "FullName", "LogonScript",
        "ProfilePath", "HomeDirectory", "HomeDirDrive",
    ];
    for label in &labels {
        if let Ok(s) = read_ndr_string(&mut sc) {
            if !s.is_empty() {
                println!("  {:22} {}", format!("{}:", label), s);
            }
        }
    }

    // Group memberships
    if group_count > 0 {
        if let Ok(max) = sc.read_u32::<LittleEndian>() {
            let n = (group_count as usize).min(max as usize).min(256);
            println!("  Groups ({}):", n);
            for _ in 0..n {
                let rid = sc.read_u32::<LittleEndian>().unwrap_or(0);
                let attrs = sc.read_u32::<LittleEndian>().unwrap_or(0);
                println!(
                    "    RID {:8}  Attrs 0x{:08x} ({})",
                    rid, attrs, group_attrs_str(attrs)
                );
            }
        }
    }

    if let Ok(s) = read_ndr_string(&mut sc) {
        if !s.is_empty() { println!("  LogonServer:         {}", s); }
    }
    if let Ok(s) = read_ndr_string(&mut sc) {
        if !s.is_empty() { println!("  LogonDomainName:     {}", s); }
    }

    if let Ok(sid) = read_ndr_sid(&mut sc) {
        println!("  LogonDomainId:       {}", sid);
    }

    if sid_count > 0 {
        println!("  Extra SIDs:");
        if let Ok(_max) = sc.read_u32::<LittleEndian>() {
            let mut entries = Vec::new();
            for _ in 0..sid_count.min(256) {
                let _ptr = sc.read_u32::<LittleEndian>().unwrap_or(0);
                let attrs = sc.read_u32::<LittleEndian>().unwrap_or(0);
                entries.push(attrs);
            }
            for attrs in entries {
                if let Ok(sid) = read_ndr_sid(&mut sc) {
                    println!("    {} (0x{:08x})", sid, attrs);
                }
            }
        }
    }
}

// ─── CLIENT INFO (Type 10) ─────────────────────────────────────────────

fn parse_client_info(data: &[u8]) {
    if data.len() < 10 { println!("  (too short)"); return; }
    let mut c = Cursor::new(data);
    let client_id = c.read_u64::<LittleEndian>().unwrap_or(0);
    println!("  ClientId:     {}", filetime_str(client_id));
    let name_len = c.read_u16::<LittleEndian>().unwrap_or(0) as usize;
    let pos = c.position() as usize;
    if name_len > 0 && pos + name_len <= data.len() {
        println!("  ClientName:   {}", utf16le(&data[pos..pos + name_len]));
    }
}

// ─── UPN/DNS INFO (Type 12) ───────────────────────────────────────────

fn parse_upn_dns_info(data: &[u8]) {
    if data.len() < 16 { println!("  (too short)"); return; }
    let mut c = Cursor::new(data);
    let upn_len = c.read_u16::<LittleEndian>().unwrap_or(0) as usize;
    let upn_off = c.read_u16::<LittleEndian>().unwrap_or(0) as usize;
    let dns_len = c.read_u16::<LittleEndian>().unwrap_or(0) as usize;
    let dns_off = c.read_u16::<LittleEndian>().unwrap_or(0) as usize;
    let flags = c.read_u32::<LittleEndian>().unwrap_or(0);

    if upn_off + upn_len <= data.len() {
        println!("  UPN:         {}", utf16le(&data[upn_off..upn_off + upn_len]));
    }
    if dns_off + dns_len <= data.len() {
        println!("  DNS Domain:  {}", utf16le(&data[dns_off..dns_off + dns_len]));
    }
    println!("  Flags:       0x{:08x}", flags);

    if data.len() >= 24 {
        let sam_len = c.read_u16::<LittleEndian>().unwrap_or(0) as usize;
        let sam_off = c.read_u16::<LittleEndian>().unwrap_or(0) as usize;
        let sid_len = c.read_u16::<LittleEndian>().unwrap_or(0) as usize;
        let sid_off = c.read_u16::<LittleEndian>().unwrap_or(0) as usize;
        if sam_len > 0 && sam_off + sam_len <= data.len() {
            println!("  SAM Name:    {}", utf16le(&data[sam_off..sam_off + sam_len]));
        }
        if sid_len > 0 && sid_off + sid_len <= data.len() {
            println!("  SID:         {}", parse_sid(&data[sid_off..sid_off + sid_len]));
        }
    }
}

// ─── SIGNATURE (Types 6, 7, 16) ───────────────────────────────────────

fn parse_signature(data: &[u8], label: &str) {
    if data.len() < 4 { println!("  (too short)"); return; }
    let mut c = Cursor::new(data);
    let sig_type = c.read_i32::<LittleEndian>().unwrap_or(0);
    let type_name = match sig_type {
        -138   => "HMAC_MD5",
        16     => "HMAC_SHA1_96_AES128",
        17     => "HMAC_SHA1_96_AES256",
        _      => "Unknown",
    };
    let pos = c.position() as usize;
    println!("  {} Type:  {} ({})", label, type_name, sig_type);
    println!("  Checksum:    {}", hex::encode(&data[pos..]));
}

// ─── ATTRIBUTES INFO (Type 17) ─────────────────────────────────────────

fn parse_attributes_info(data: &[u8]) {
    if data.len() < 8 { println!("  (too short)"); return; }
    let mut c = Cursor::new(data);
    let flags_len = c.read_u32::<LittleEndian>().unwrap_or(0);
    let flags = c.read_u32::<LittleEndian>().unwrap_or(0);
    println!("  FlagsLength: {}", flags_len);
    println!("  Flags:       0x{:08x}", flags);
    if flags & 1 != 0 { println!("    PAC_WAS_REQUESTED"); }
    if flags & 2 != 0 { println!("    PAC_WAS_GIVEN_IMPLICITLY"); }
}

// ─── REQUESTOR SID (Type 18) ──────────────────────────────────────────

fn parse_requestor_sid(data: &[u8]) {
    println!("  SID: {}", parse_sid(data));
}

// ═══════════════════════════════════════════════════════════════════════
// Utility functions
// ═══════════════════════════════════════════════════════════════════════

fn filetime_str(ft: u64) -> String {
    if ft == 0 || ft == 0x7FFFFFFFFFFFFFFF {
        return "(never)".into();
    }
    const EPOCH_DIFF: u64 = 116_444_736_000_000_000;
    if ft < EPOCH_DIFF {
        return format!("(pre-epoch 0x{:016x})", ft);
    }
    let unix_100ns = ft - EPOCH_DIFF;
    let secs = (unix_100ns / 10_000_000) as i64;
    let nanos = ((unix_100ns % 10_000_000) * 100) as u32;
    chrono::DateTime::from_timestamp(secs, nanos)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| format!("(invalid 0x{:016x})", ft))
}

fn parse_sid(data: &[u8]) -> String {
    if data.len() < 8 {
        return format!("(invalid SID, {} bytes)", data.len());
    }
    let rev = data[0];
    let sub_count = data[1] as usize;
    let auth = u48_be(&data[2..8]);
    let mut s = format!("S-{}-{}", rev, auth);
    for i in 0..sub_count {
        let off = 8 + i * 4;
        if off + 4 > data.len() { break; }
        let sub = u32::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3]]);
        s.push_str(&format!("-{}", sub));
    }
    s
}

fn u48_be(d: &[u8]) -> u64 {
    ((d[0] as u64) << 40) | ((d[1] as u64) << 32) | ((d[2] as u64) << 24)
    | ((d[3] as u64) << 16) | ((d[4] as u64) << 8) | (d[5] as u64)
}

fn utf16le(data: &[u8]) -> String {
    let u16s: Vec<u16> = data.chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&u16s)
}

fn read_ndr_string(c: &mut Cursor<&[u8]>) -> Result<String> {
    let _max = c.read_u32::<LittleEndian>()?;
    let _off = c.read_u32::<LittleEndian>()?;
    let actual = c.read_u32::<LittleEndian>()? as usize;
    let byte_count = actual * 2;
    let mut buf = vec![0u8; byte_count];
    c.read_exact(&mut buf)?;
    let total = 12 + byte_count;
    let pad = (4 - (total % 4)) % 4;
    if pad > 0 {
        let mut p = vec![0u8; pad];
        let _ = c.read_exact(&mut p);
    }
    Ok(utf16le(&buf))
}

fn read_ndr_sid(c: &mut Cursor<&[u8]>) -> Result<String> {
    let _max_count = c.read_u32::<LittleEndian>()?;
    let rev = c.read_u8()?;
    let sub_count = c.read_u8()? as usize;
    let mut auth_bytes = [0u8; 6];
    c.read_exact(&mut auth_bytes)?;
    let auth = u48_be(&auth_bytes);
    let mut s = format!("S-{}-{}", rev, auth);
    for _ in 0..sub_count.min(15) {
        let sub = c.read_u32::<LittleEndian>()?;
        s.push_str(&format!("-{}", sub));
    }
    Ok(s)
}

fn print_uac_flags(uac: u32) {
    let flags: &[(u32, &str)] = &[
        (UF_ACCOUNTDISABLE, "ACCOUNTDISABLE"),
        (UF_LOCKOUT, "LOCKOUT"),
        (UF_PASSWD_NOTREQD, "PASSWD_NOTREQD"),
        (UF_NORMAL_ACCOUNT, "NORMAL_ACCOUNT"),
        (UF_DONT_EXPIRE_PASSWD, "DONT_EXPIRE_PASSWD"),
        (UF_SMARTCARD_REQUIRED, "SMARTCARD_REQUIRED"),
        (UF_TRUSTED_FOR_DELEGATION, "TRUSTED_FOR_DELEGATION"),
        (UF_NOT_DELEGATED, "NOT_DELEGATED"),
        (UF_USE_DES_KEY_ONLY, "USE_DES_KEY_ONLY"),
        (UF_DONT_REQUIRE_PREAUTH, "DONT_REQUIRE_PREAUTH"),
        (UF_PASSWORD_EXPIRED, "PASSWORD_EXPIRED"),
        (UF_TRUSTED_TO_AUTH_FOR_DELEGATION, "TRUSTED_TO_AUTH_FOR_DELEGATION"),
        (UF_NO_AUTH_DATA_REQUIRED, "NO_AUTH_DATA_REQUIRED"),
    ];
    for (f, name) in flags {
        if uac & f != 0 {
            println!("                         | {}", name);
        }
    }
}

fn group_attrs_str(a: u32) -> String {
    let mut v = Vec::new();
    if a & 0x00000004 != 0 { v.push("ENABLED"); }
    if a & 0x00000020 != 0 { v.push("ENABLED_BY_DEFAULT"); }
    if a & 0x20000000 != 0 { v.push("MANDATORY"); }
    if v.is_empty() { format!("0x{:08x}", a) } else { v.join("|") }
}

//! DCE/RPC over SMB named pipe — enough to call NetrShareEnum (opnum 15)
//! on the \pipe\srvsvc interface.
//!
//! Wire format references:
//!   [MS-RPCE] — DCE/RPC Protocol Extension
//!   [MS-SRVS] — Server Service Remote Protocol
//!   [MS-DTYP] — Windows Data Types (NDR encoding)

use anyhow::{anyhow, bail, Result};

// ─── DCE/RPC constants ────────────────────────────────────────────────────────

const RPC_VERSION_MAJOR: u8 = 5;
const RPC_VERSION_MINOR: u8 = 0;
const PDU_TYPE_BIND:     u8 = 11;
const PDU_TYPE_BIND_ACK: u8 = 12;
const PDU_TYPE_REQUEST:  u8 = 0;
const PDU_TYPE_RESPONSE: u8 = 2;
const PDU_FLAGS_FIRST_LAST: u8 = 0x03;

/// SRVSVC interface UUID: {4B324FC8-1670-01D3-1278-5A47BF6EE188} v3.0
const SRVSVC_UUID: [u8; 16] = [
    0xC8, 0x4F, 0x32, 0x4B,  // Data1  (LE)
    0x70, 0x16,              // Data2  (LE)
    0xD3, 0x01,              // Data3  (LE)
    0x12, 0x78,              // Data4[0..2]
    0x5A, 0x47, 0xBF, 0x6E, 0xE1, 0x88, // Data4[2..8]
];
const SRVSVC_VER_MAJOR: u16 = 3;
const SRVSVC_VER_MINOR: u16 = 0;

/// NDR transfer syntax UUID: {8A885D04-1CEB-11C9-9FE8-08002B104860} v2.0
const NDR_UUID: [u8; 16] = [
    0x04, 0x5D, 0x88, 0x8A,
    0xEB, 0x1C, 0xC9, 0x11,
    0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60,
];
const NDR_VER_MAJOR: u16 = 2;
const NDR_VER_MINOR: u16 = 0;

// ─── Share type flags ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ShareInfo {
    pub name: String,
    pub comment: String,
    pub share_type: u32,
}

impl ShareInfo {
    pub fn type_str(&self) -> &'static str {
        match self.share_type & 0xFFFF {
            0x0000 => "Disk",
            0x0001 => "Printer",
            0x0002 => "Device",
            0x0003 => "IPC",
            _      => "Unknown",
        }
    }

    pub fn is_hidden(&self) -> bool {
        self.name.ends_with('$')
    }
}

// ─── Little-endian write helpers ──────────────────────────────────────────────

fn push_u16_le(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_le_bytes());
}
fn push_u32_le(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}
fn read_u16_le(buf: &[u8], off: usize) -> Result<u16> {
    buf.get(off..off+2)
        .ok_or_else(|| anyhow!("short read @{}", off))
        .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
}
fn read_u32_le(buf: &[u8], off: usize) -> Result<u32> {
    buf.get(off..off+4)
        .ok_or_else(|| anyhow!("short read @{}", off))
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
}

// ─── DCE/RPC Bind packet ──────────────────────────────────────────────────────

pub fn build_bind(call_id: u32) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::new();

    // max_xmit_frag / max_recv_frag
    push_u16_le(&mut body, 4280);
    push_u16_le(&mut body, 4280);
    // assoc_group
    push_u32_le(&mut body, 0);
    // p_context_elem: num_context_items = 1
    push_u16_le(&mut body, 1);
    push_u16_le(&mut body, 0); // reserved
    // context_id=0
    push_u16_le(&mut body, 0);
    // num_transfer_syntaxes=1
    push_u16_le(&mut body, 1);
    // abstract syntax: SRVSVC uuid + version
    body.extend_from_slice(&SRVSVC_UUID);
    push_u16_le(&mut body, SRVSVC_VER_MAJOR);
    push_u16_le(&mut body, SRVSVC_VER_MINOR);
    // transfer syntax: NDR uuid + version
    body.extend_from_slice(&NDR_UUID);
    push_u16_le(&mut body, NDR_VER_MAJOR);
    push_u16_le(&mut body, NDR_VER_MINOR);

    rpc_header(PDU_TYPE_BIND, call_id, &body)
}

// ─── NetrShareEnum request (opnum 15, Level 1) ────────────────────────────────

/// Build the NDR-encoded NetrShareEnum request for a given server name.
pub fn build_netshareenum(call_id: u32, server: &str) -> Vec<u8> {
    let mut stub: Vec<u8> = Vec::new();

    // ServerName: LPWSTR (unique pointer + conformant varying string)
    // Pointer referent ID (non-NULL)
    push_u32_le(&mut stub, 0x0002_0000);

    // NDR wide string: max_count, offset, actual_count, then UTF-16LE chars + null
    let wide: Vec<u16> = server.encode_utf16().chain(std::iter::once(0)).collect();
    let char_count = wide.len() as u32;
    push_u32_le(&mut stub, char_count); // MaxCount
    push_u32_le(&mut stub, 0);          // Offset
    push_u32_le(&mut stub, char_count); // ActualCount
    for w in &wide {
        push_u16_le(&mut stub, *w);
    }
    // Align to 4 bytes
    while stub.len() % 4 != 0 {
        stub.push(0);
    }

    // InfoStruct: Level=1
    push_u32_le(&mut stub, 1);
    // SHARE_ENUM_UNION tag = 1
    push_u32_le(&mut stub, 1);
    // Pointer to SHARE_INFO_1_CONTAINER (referent ID, non-NULL)
    push_u32_le(&mut stub, 0x0002_0004);
    // SHARE_INFO_1_CONTAINER.EntriesRead = 0
    push_u32_le(&mut stub, 0);
    // SHARE_INFO_1_CONTAINER.Buffer (NULL pointer)
    push_u32_le(&mut stub, 0);

    // PreferedMaximumLength = 0xFFFFFFFF
    push_u32_le(&mut stub, 0xFFFF_FFFF);

    // TotalEntries (out, send 0)
    push_u32_le(&mut stub, 0);

    // ResumeHandle: unique pointer (NULL = first call)
    push_u32_le(&mut stub, 0);

    rpc_request(call_id, 15, 0, &stub)
}

// ─── Build raw DCE/RPC header ─────────────────────────────────────────────────

fn rpc_header(pdu_type: u8, call_id: u32, body: &[u8]) -> Vec<u8> {
    let frag_len = (16 + body.len()) as u16;
    let mut pkt: Vec<u8> = Vec::with_capacity(frag_len as usize);
    pkt.push(RPC_VERSION_MAJOR);
    pkt.push(RPC_VERSION_MINOR);
    pkt.push(pdu_type);
    pkt.push(PDU_FLAGS_FIRST_LAST);
    // data representation: little-endian, ASCII
    pkt.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]);
    push_u16_le(&mut pkt, frag_len);
    push_u16_le(&mut pkt, 0); // auth_length
    push_u32_le(&mut pkt, call_id);
    pkt.extend_from_slice(body);
    pkt
}

fn rpc_request(call_id: u32, opnum: u16, context_id: u16, stub: &[u8]) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::new();
    push_u32_le(&mut body, stub.len() as u32); // alloc_hint
    push_u16_le(&mut body, context_id);
    push_u16_le(&mut body, opnum);
    body.extend_from_slice(stub);
    rpc_header(PDU_TYPE_REQUEST, call_id, &body)
}

// ─── Parse Bind-Ack ───────────────────────────────────────────────────────────

pub fn check_bind_ack(buf: &[u8]) -> Result<()> {
    if buf.len() < 16 { bail!("bind-ack too short"); }
    if buf[2] != PDU_TYPE_BIND_ACK {
        bail!("expected bind-ack (12), got PDU type {}", buf[2]);
    }
    Ok(())
}

// ─── Parse NetrShareEnum response ────────────────────────────────────────────

pub fn parse_netshareenum_response(buf: &[u8]) -> Result<Vec<ShareInfo>> {
    if buf.len() < 16 { bail!("response too short"); }
    if buf[2] != PDU_TYPE_RESPONSE {
        bail!("expected response PDU (2), got {}", buf[2]);
    }

    // Stub starts after 24-byte RPC response header
    // (16 base + 8: alloc_hint u32 + context_id u16 + cancel_count u8 + reserved u8)
    let mut off = 24;

    // Skip Level (u32) + Union tag (u32) + referent ID (u32) + EntriesRead (u32)
    off += 4 + 4 + 4;
    let entries_read = read_u32_le(buf, off)? as usize;
    off += 4;

    // Buffer pointer (referent ID for array)
    off += 4;

    if entries_read == 0 {
        return Ok(vec![]);
    }

    // Conformant array: MaxCount
    let max_count = read_u32_le(buf, off)? as usize;
    off += 4;

    // Array of SHARE_INFO_1: each entry is { ptr_netname u32, shi1_type u32, ptr_remark u32 }
    let count = max_count.min(entries_read);
    let mut types:   Vec<u32> = Vec::with_capacity(count);
    let mut name_ptrs:   Vec<u32> = Vec::with_capacity(count);
    let mut remark_ptrs: Vec<u32> = Vec::with_capacity(count);

    for _ in 0..count {
        let name_ptr   = read_u32_le(buf, off)?; off += 4;
        let shi1_type  = read_u32_le(buf, off)?; off += 4;
        let remark_ptr = read_u32_le(buf, off)?; off += 4;
        name_ptrs.push(name_ptr);
        types.push(shi1_type);
        remark_ptrs.push(remark_ptr);
    }

    // Now read the deferred wide-string pointers inline (conformant varying strings)
    let mut names:   Vec<String> = Vec::with_capacity(count);
    let mut remarks: Vec<String> = Vec::with_capacity(count);

    for _ in 0..count {
        names.push(read_wide_string(buf, &mut off)?);
    }
    for _ in 0..count {
        remarks.push(read_wide_string(buf, &mut off)?);
    }

    let shares = (0..count)
        .map(|i| ShareInfo {
            name:       names[i].clone(),
            comment:    remarks[i].clone(),
            share_type: types[i],
        })
        .collect();

    Ok(shares)
}

// ─── NDR wide-string decoder ──────────────────────────────────────────────────

fn read_wide_string(buf: &[u8], off: &mut usize) -> Result<String> {
    // MaxCount / Offset / ActualCount
    let _max   = read_u32_le(buf, *off)?; *off += 4;
    let _ofs   = read_u32_le(buf, *off)?; *off += 4;
    let actual = read_u32_le(buf, *off)? as usize; *off += 4;

    let byte_len = actual * 2;
    if buf.len() < *off + byte_len {
        bail!("wide string truncated");
    }
    let raw = &buf[*off..*off + byte_len];
    *off += byte_len;

    // Align to 4 bytes
    while *off % 4 != 0 { *off += 1; }

    let words: Vec<u16> = raw.chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    // Strip null terminator if present
    let end = words.iter().position(|&w| w == 0).unwrap_or(words.len());
    Ok(String::from_utf16_lossy(&words[..end]))
}

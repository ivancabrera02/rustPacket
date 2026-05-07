//! DCE/RPC PDU construction and parsing
//!
//! Implements the minimal DCE/RPC framing needed to transport SAMR calls
//! over a named pipe: BIND, BIND_ACK, REQUEST, and RESPONSE.

use crate::error::{SamrDumpError, SamrResult};

// PDU types
const PDU_BIND: u8 = 11;
const PDU_BIND_ACK: u8 = 12;
const PDU_REQUEST: u8 = 0;
const PDU_RESPONSE: u8 = 2;
const PDU_FAULT: u8 = 3;

// Flags
const PFC_FIRST_FRAG: u8 = 0x01;
const PFC_LAST_FRAG: u8 = 0x02;

/// NDR transfer syntax UUID (fixed)
const NDR_UUID: [u8; 16] = [
    0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11,
    0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60,
];

/// Build a DCE/RPC BIND PDU
pub fn build_bind(
    interface_uuid: &uuid::Uuid,
    version_major: u16,
    version_minor: u16,
) -> Vec<u8> {
    let uuid_bytes = uuid_to_dcerpc_bytes(interface_uuid);

    // Context item: presentation context (1 transfer syntax)
    let mut ctx_item = Vec::new();
    ctx_item.extend_from_slice(&0u16.to_le_bytes()); // context ID = 0
    ctx_item.extend_from_slice(&1u16.to_le_bytes()); // num_transfer_syntaxes = 1
    ctx_item.extend_from_slice(&uuid_bytes); // abstract syntax UUID
    ctx_item.extend_from_slice(&version_major.to_le_bytes());
    ctx_item.extend_from_slice(&version_minor.to_le_bytes());
    ctx_item.extend_from_slice(&NDR_UUID); // transfer syntax UUID
    ctx_item.extend_from_slice(&2u32.to_le_bytes()); // NDR version 2.0

    // Bind body
    let mut body = Vec::new();
    body.extend_from_slice(&4280u16.to_le_bytes()); // max_xmit_frag
    body.extend_from_slice(&4280u16.to_le_bytes()); // max_recv_frag
    body.extend_from_slice(&0u32.to_le_bytes()); // assoc_group
    body.extend_from_slice(&1u32.to_le_bytes()); // num_ctx_items (as u8 + 3 padding)
    // Actually: p_context_elem_t has num_context_items as u8
    // Let's re-do: num_ctx_items is actually 4 bytes in the bind: count(4)
    // Overwrite last 4 bytes
    let body_len = body.len();
    body[body_len - 4] = 1; // num items (1 byte) + 3 padding bytes
    body.extend_from_slice(&ctx_item);

    // Build header
    let total_len = 16 + body.len();
    let mut pdu = Vec::with_capacity(total_len);
    pdu.push(5); // rpc_vers
    pdu.push(0); // rpc_vers_minor
    pdu.push(PDU_BIND); // ptype
    pdu.push(PFC_FIRST_FRAG | PFC_LAST_FRAG); // pfc_flags
    pdu.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // data representation (LE, ASCII, IEEE)
    pdu.extend_from_slice(&(total_len as u16).to_le_bytes()); // frag_length
    pdu.extend_from_slice(&0u16.to_le_bytes()); // auth_length
    pdu.extend_from_slice(&0u32.to_le_bytes()); // call_id
    pdu.extend_from_slice(&body);

    pdu
}

/// Parse a BIND_ACK response
pub fn parse_bind_ack(data: &[u8]) -> SamrResult<()> {
    if data.len() < 16 {
        return Err(SamrDumpError::DceRpc("BIND_ACK too short".into()));
    }

    let ptype = data[2];
    if ptype == PDU_FAULT {
        return Err(SamrDumpError::DceRpc("BIND rejected (FAULT)".into()));
    }
    if ptype != PDU_BIND_ACK {
        return Err(SamrDumpError::DceRpc(format!(
            "Expected BIND_ACK (12), got {}",
            ptype
        )));
    }

    // Check result: after header(16) + max_xmit(2) + max_recv(2) + assoc_group(4) +
    // secondary_addr_len(2) + addr + padding + num_results(4) + result(2)
    // For now just accept if it parsed as BIND_ACK
    Ok(())
}

/// Build a DCE/RPC REQUEST PDU
pub fn build_request(opnum: u16, stub_data: &[u8]) -> Vec<u8> {
    let body_fixed_size = 8; // alloc_hint(4) + context_id(2) + opnum(2)
    let total_len = 16 + body_fixed_size + stub_data.len();

    let mut pdu = Vec::with_capacity(total_len);
    pdu.push(5);
    pdu.push(0);
    pdu.push(PDU_REQUEST);
    pdu.push(PFC_FIRST_FRAG | PFC_LAST_FRAG);
    pdu.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // LE
    pdu.extend_from_slice(&(total_len as u16).to_le_bytes());
    pdu.extend_from_slice(&0u16.to_le_bytes()); // auth_length
    pdu.extend_from_slice(&0u32.to_le_bytes()); // call_id

    // Request body
    pdu.extend_from_slice(&(stub_data.len() as u32).to_le_bytes()); // alloc_hint
    pdu.extend_from_slice(&0u16.to_le_bytes()); // context_id
    pdu.extend_from_slice(&opnum.to_le_bytes());
    pdu.extend_from_slice(stub_data);

    pdu
}

/// Parse a DCE/RPC RESPONSE, return the stub data
pub fn parse_response(data: &[u8]) -> SamrResult<Vec<u8>> {
    if data.len() < 24 {
        return Err(SamrDumpError::DceRpc("Response too short".into()));
    }

    let ptype = data[2];
    if ptype == PDU_FAULT {
        let fault_status = if data.len() >= 28 {
            u32::from_le_bytes([data[24], data[25], data[26], data[27]])
        } else {
            0
        };
        return Err(SamrDumpError::DceRpc(format!(
            "FAULT: status=0x{:08x}",
            fault_status
        )));
    }
    if ptype != PDU_RESPONSE {
        return Err(SamrDumpError::DceRpc(format!(
            "Expected RESPONSE (2), got {}",
            ptype
        )));
    }

    let frag_length = u16::from_le_bytes([data[8], data[9]]) as usize;
    let auth_length = u16::from_le_bytes([data[10], data[11]]) as usize;

    // Stub data starts at offset 24 (header=16, alloc_hint=4, context_id=2, cancel_count=1, reserved=1)
    let stub_offset = 24;
    let stub_end = frag_length - auth_length;

    if stub_offset <= stub_end && stub_end <= data.len() {
        Ok(data[stub_offset..stub_end].to_vec())
    } else {
        Ok(data[stub_offset.min(data.len())..].to_vec())
    }
}

/// Convert a UUID to DCE/RPC wire format (mixed-endian)
fn uuid_to_dcerpc_bytes(uuid: &uuid::Uuid) -> Vec<u8> {
    let bytes = uuid.as_bytes();
    let mut out = vec![0u8; 16];
    // First 4 bytes: little-endian u32
    out[0] = bytes[3];
    out[1] = bytes[2];
    out[2] = bytes[1];
    out[3] = bytes[0];
    // Next 2 bytes: little-endian u16
    out[4] = bytes[5];
    out[5] = bytes[4];
    // Next 2 bytes: little-endian u16
    out[6] = bytes[7];
    out[7] = bytes[6];
    // Last 8 bytes: as-is
    out[8..16].copy_from_slice(&bytes[8..16]);
    out
}

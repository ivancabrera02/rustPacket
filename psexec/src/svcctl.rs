#![allow(dead_code)]

use crate::error::{Error, Result};
use crate::ntlm::NtlmContext;
use crate::smb2::{Smb2Client, FileId};


const SVCCTL_UUID: [u8; 16] = [
    0x81, 0xBB, 0x7A, 0x36, 0x44, 0x98, 0xF1, 0x35,
    0xAD, 0x32, 0x98, 0xF0, 0x38, 0x00, 0x10, 0x03,
];

const NDR_UUID: [u8; 16] = [
    0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11,
    0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60,
];


const PDU_BIND:     u8 = 11;
const PDU_BIND_ACK: u8 = 12;
const PDU_REQUEST:  u8 = 0;
const PDU_RESPONSE: u8 = 2;


const OP_CLOSE_HANDLE:    u16 = 0;
const OP_CONTROL_SERVICE: u16 = 1;
const OP_DELETE_SERVICE:  u16 = 2;
const OP_CREATE_SERVICE:  u16 = 12;
const OP_OPEN_SCM:        u16 = 15;
const OP_START_SERVICE:   u16 = 19;


pub const SC_MANAGER_ALL_ACCESS: u32 = 0x000F_003F;
pub const SERVICE_ALL_ACCESS:    u32 = 0x000F_01FF;
pub const SERVICE_WIN32_OWN_PROCESS: u32 = 0x0000_0010;
pub const SERVICE_DEMAND_START:  u32 = 0x0000_0003;
pub const SERVICE_ERROR_IGNORE:  u32 = 0x0000_0000;
pub const SERVICE_CONTROL_STOP:  u32 = 0x0000_0001;


pub type ContextHandle = [u8; 20];


/// DCE-RPC SVCCTL client
pub struct SvcCtl {
    smb:     Smb2Client,
    tree_id: u32,
    fid:     FileId,
    call_id: u32,
}

impl SvcCtl {
    /// Open a new SMB2 session, connect to IPC$\svcctl, and perform DCE-RPC BIND
    pub fn connect(host: &str, port: u16, ntlm: &NtlmContext) -> Result<Self> {
        let mut smb = Smb2Client::connect(host, port, ntlm)?;
        let tree_id = smb.tree_connect("IPC$")?;
        let fid     = smb.create_pipe(tree_id, "svcctl", crate::smb2::FILE_GENERIC_READ | crate::smb2::FILE_GENERIC_WRITE)?;
        let mut s   = SvcCtl { smb, tree_id, fid, call_id: 1 };
        s.rpc_bind()?;
        Ok(s)
    }

    pub fn disconnect(mut self) -> Result<()> {
        self.smb.close(self.tree_id, self.fid)?;
        self.smb.tree_disconnect(self.tree_id)?;
        Ok(())
    }


    pub fn open_scm(&mut self, machine: &str) -> Result<ContextHandle> {
        let mut req = Vec::new();
        append_ndr_unique_str(&mut req, machine);
        req.extend_from_slice(&0u32.to_le_bytes());
        
        req.extend_from_slice(&SC_MANAGER_ALL_ACCESS.to_le_bytes());

        let resp = self.rpc_call(OP_OPEN_SCM, &req)?;
        parse_ctx_handle_response(&resp, "OpenSCManagerW")
    }

    /// CreateServiceW — returns a SERVICE context handle
    pub fn create_service(
        &mut self,
        scm:          ContextHandle,
        name:         &str,
        display_name: &str,
        bin_path:     &str,
    ) -> Result<ContextHandle> {
        let mut req = Vec::new();
        req.extend_from_slice(&scm);               // hSCManager [in]

        // lpServiceName [in, string]
        append_ndr_inline_str(&mut req, name);

        // lpDisplayName [in, unique, string]
        append_ndr_unique_str(&mut req, display_name);

        // dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl
        req.extend_from_slice(&SERVICE_ALL_ACCESS.to_le_bytes());
        req.extend_from_slice(&SERVICE_WIN32_OWN_PROCESS.to_le_bytes());
        req.extend_from_slice(&SERVICE_DEMAND_START.to_le_bytes());
        req.extend_from_slice(&SERVICE_ERROR_IGNORE.to_le_bytes());

        // lpBinaryPathName [in, string]
        append_ndr_inline_str(&mut req, bin_path);

        // lpLoadOrderGroup: NULL
        req.extend_from_slice(&0u32.to_le_bytes());

        // lpdwTagId: NULL
        req.extend_from_slice(&0u32.to_le_bytes());

        // lpDependencies: NULL byte array, dwDependSize=0
        req.extend_from_slice(&0u32.to_le_bytes()); // NULL ptr
        req.extend_from_slice(&0u32.to_le_bytes()); // dwDependSize

        // lpServiceStartName: NULL
        req.extend_from_slice(&0u32.to_le_bytes());

        // lpPassword: NULL byte array, dwPwSize=0
        req.extend_from_slice(&0u32.to_le_bytes()); // NULL ptr
        req.extend_from_slice(&0u32.to_le_bytes()); // dwPwSize

        let resp = self.rpc_call(OP_CREATE_SERVICE, &req)?;
        // Response: [lpdwTagId u32][lpServiceHandle ctx][return_code u32]
        if resp.len() < 28 {
            return Err(Error::Msg(format!("CreateServiceW response too short: {} bytes", resp.len())));
        }
        let ret = u32::from_le_bytes(resp[resp.len()-4..].try_into().unwrap());
        if ret != 0 {
            return Err(Error::Msg(format!("CreateServiceW failed: 0x{:08X}", ret)));
        }
        // Context handle at resp[4..24]
        let mut hdl = [0u8; 20];
        hdl.copy_from_slice(&resp[4..24]);
        Ok(hdl)
    }

  
    pub fn start_service(&mut self, svc: ContextHandle) -> Result<()> {
        let mut req = Vec::new();
        req.extend_from_slice(&svc);
        req.extend_from_slice(&0u32.to_le_bytes()); // dwNumServiceArgs = 0
        req.extend_from_slice(&0u32.to_le_bytes()); // lpServiceArgVectors = NULL

        let resp = self.rpc_call(OP_START_SERVICE, &req)?;
        check_rpc_return(&resp, "StartServiceW")
    }

    pub fn control_service(&mut self, svc: ContextHandle, control: u32) -> Result<()> {
        let mut req = Vec::new();
        req.extend_from_slice(&svc);
        req.extend_from_slice(&control.to_le_bytes());

        let resp = self.rpc_call(OP_CONTROL_SERVICE, &req)?;
        check_rpc_return(&resp, "ControlService")
    }

    pub fn delete_service(&mut self, svc: ContextHandle) -> Result<()> {
        let resp = self.rpc_call(OP_DELETE_SERVICE, &svc)?;
        check_rpc_return(&resp, "DeleteService")
    }

    pub fn close_handle(&mut self, hdl: ContextHandle) -> Result<()> {
        let resp = self.rpc_call(OP_CLOSE_HANDLE, &hdl)?;
        check_rpc_return(&resp, "CloseServiceHandle")
    }


    fn rpc_bind(&mut self) -> Result<()> {
        let mut body = Vec::new();
        body.extend_from_slice(&4280u16.to_le_bytes()); // max_xmit_frag
        body.extend_from_slice(&4280u16.to_le_bytes()); // max_recv_frag
        body.extend_from_slice(&0u32.to_le_bytes());    // assoc_group_id
        body.push(1);
        body.extend_from_slice(&[0u8; 3]);              // padding
        body.extend_from_slice(&0u16.to_le_bytes());    // context_id
        body.extend_from_slice(&1u16.to_le_bytes());    // num_transfer_syntaxes

        body.extend_from_slice(&SVCCTL_UUID);
        body.extend_from_slice(&2u16.to_le_bytes());    // version_major
        body.extend_from_slice(&0u16.to_le_bytes());    // version_minor
        body.extend_from_slice(&NDR_UUID);
        body.extend_from_slice(&2u16.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());

        let pkt = rpc_pdu(PDU_BIND, self.call_id, &body);
        self.call_id += 1;

        self.smb.write_pipe(self.tree_id, self.fid, &pkt)?;
        let resp = self.smb.read_pipe(self.tree_id, self.fid, 4096)?;

        if resp.len() < 16 {
            return Err("DCE-RPC BIND_ACK too short".into());
        }
        if resp[2] != PDU_BIND_ACK {
            return Err(Error::Msg(format!(
                "DCE-RPC BIND failed, ptype=0x{:02X}", resp[2]
            )));
        }
        Ok(())
    }

    fn rpc_call(&mut self, opnum: u16, body: &[u8]) -> Result<Vec<u8>> {
        let call_id = self.call_id;
        self.call_id += 1;

        let mut req_body = Vec::new();
        req_body.extend_from_slice(&(body.len() as u32).to_le_bytes()); // alloc_hint
        req_body.extend_from_slice(&0u16.to_le_bytes());                 // context_id
        req_body.extend_from_slice(&opnum.to_le_bytes());
        req_body.extend_from_slice(body);

        let pkt = rpc_pdu(PDU_REQUEST, call_id, &req_body);
        self.smb.write_pipe(self.tree_id, self.fid, &pkt)?;

        let resp = self.smb.read_pipe(self.tree_id, self.fid, 65535)?;

        if resp.len() < 24 {
            return Err("DCE-RPC response too short".into());
        }
        if resp[2] != PDU_RESPONSE {
            return Err(Error::Msg(format!("DCE-RPC unexpected ptype: 0x{:02X}", resp[2])));
        }

        // Skip 16-byte common header + 8-byte response header
        Ok(resp[24..].to_vec())
    }
}


fn rpc_pdu(ptype: u8, call_id: u32, body: &[u8]) -> Vec<u8> {
    let frag_len = (16 + body.len()) as u16;
    let mut pdu = Vec::new();
    pdu.push(5);                                        
    pdu.push(0);                                        
    pdu.push(ptype);
    pdu.push(0x03);                                     
    pdu.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]);  
    pdu.extend_from_slice(&frag_len.to_le_bytes());
    pdu.extend_from_slice(&0u16.to_le_bytes());         
    pdu.extend_from_slice(&call_id.to_le_bytes());
    pdu.extend_from_slice(body);
    pdu
}


fn append_ndr_inline_str(v: &mut Vec<u8>, s: &str) {
    let wide: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
    let chars = wide.len() as u32;
    v.extend_from_slice(&chars.to_le_bytes()); // MaxCount
    v.extend_from_slice(&0u32.to_le_bytes());  // Offset
    v.extend_from_slice(&chars.to_le_bytes()); // ActualCount
    for c in &wide { v.extend_from_slice(&c.to_le_bytes()); }
    while v.len() % 4 != 0 { v.push(0); }
}


fn append_ndr_unique_str(v: &mut Vec<u8>, s: &str) {
    // Non-null referent ID
    v.extend_from_slice(&0x0002_0000u32.to_le_bytes()); // arbitrary non-zero referent ID
    append_ndr_inline_str(v, s);
}

 
fn parse_ctx_handle_response(resp: &[u8], op: &str) -> Result<ContextHandle> {
    if resp.len() < 24 {
        return Err(Error::Msg(format!("{} response too short: {} bytes", op, resp.len())));
    }
    let ret_code = u32::from_le_bytes(resp[resp.len()-4..].try_into().unwrap());
    if ret_code != 0 {
        return Err(Error::Msg(format!("{} failed: 0x{:08X}", op, ret_code)));
    }
    let mut hdl = [0u8; 20];
    hdl.copy_from_slice(&resp[..20]);
    Ok(hdl)
}

fn check_rpc_return(resp: &[u8], op: &str) -> Result<()> {
    if resp.len() < 4 {
        return Err(Error::Msg(format!("{} response too short", op)));
    }
    let ret = u32::from_le_bytes(resp[resp.len()-4..].try_into().unwrap());
    if ret == 0 { Ok(()) } else { Err(Error::Msg(format!("{} failed: 0x{:08X}", op, ret))) }
}

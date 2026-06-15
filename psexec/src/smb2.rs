#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

use rand::Rng;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use cmac::Cmac;
use aes::Aes128;

type HmacSha256 = Hmac<Sha256>;

use crate::error::{Error, Result};
use crate::ntlm::{NtlmContext, spnego_wrap_negotiate, spnego_wrap_authenticate};


const SMB2_MAGIC: &[u8; 4] = b"\xFESMB";

const SMB2_NEGOTIATE:        u16 = 0x0000;
const SMB2_SESSION_SETUP:    u16 = 0x0001;
const SMB2_TREE_CONNECT:     u16 = 0x0003;
const SMB2_TREE_DISCONNECT:  u16 = 0x0004;
const SMB2_CREATE:           u16 = 0x0005;
const SMB2_CLOSE:            u16 = 0x0006;
const SMB2_WRITE:            u16 = 0x0009;
const SMB2_READ:             u16 = 0x0008;
const SMB2_IOCTL:            u16 = 0x000B;

const STATUS_SUCCESS:                  u32 = 0x0000_0000;
const STATUS_MORE_PROCESSING_REQUIRED: u32 = 0xC000_0016;

const SMB2_FLAGS_SIGNED: u32 = 0x0000_0008;

const SMB2_DIALECT_202: u16 = 0x0202;
const SMB2_DIALECT_210: u16 = 0x0210;
const SMB2_DIALECT_300: u16 = 0x0300;
const SMB2_DIALECT_302: u16 = 0x0302;

const SMB2_NEGOTIATE_SIGNING_ENABLED: u16 = 0x0001;

const SMB2_SESSION_FLAG_ENCRYPT_DATA: u16 = 0x0004;

const SMB2_SHARE_TYPE_DISK: u8 = 0x01;
const SMB2_SHARE_TYPE_PIPE: u8 = 0x02;

const FILE_OVERWRITE_IF:  u32 = 0x0000_0005;
const FILE_OPEN:          u32 = 0x0000_0001;
const FILE_OPEN_IF:       u32 = 0x0000_0003;

const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;

pub const FILE_GENERIC_READ:  u32 = 0x0012_0089;
pub const FILE_GENERIC_WRITE: u32 = 0x0012_0116;
const FILE_GENERIC_ALL:   u32 = 0x001F_01FF;

const IMPERSONATION_IMPERSONATION: u32 = 0x0000_0002;

const FILE_SHARE_READ:   u32 = 0x0000_0001;
const FILE_SHARE_WRITE:  u32 = 0x0000_0002;
const FILE_SHARE_DELETE: u32 = 0x0000_0004;

const DELETE_ACCESS:          u32 = 0x0001_0000;
const FILE_DELETE_ON_CLOSE:   u32 = 0x0000_1000;


#[derive(Clone, Copy, Default)]
pub struct FileId(pub [u8; 16]);


pub struct Smb2Client {
    stream:      TcpStream,
    session_id:  u64,
    msg_id:      u64,
    host:        String,
    dialect:     u16,
    signing_key: Option<[u8; 16]>,
    read_timeout: Option<Duration>, // set for relay connections to avoid infinite blocking
}

impl Smb2Client {
    pub fn connect_relay(host: &str, port: u16, ntlm: &NtlmContext) -> Result<Self> {
        let mut c = Self::connect(host, port, ntlm)?;
        c.read_timeout = Some(Duration::from_secs(2));
        c.stream.set_read_timeout(c.read_timeout)
            .map_err(|e| Error::Msg(format!("set_read_timeout: {}", e)))?;
        Ok(c)
    }

    /// Establish an authenticated SMB2 session.
    pub fn connect(host: &str, port: u16, ntlm: &NtlmContext) -> Result<Self> {
        let addr = format!("{}:{}", host, port);
        let stream = TcpStream::connect(&addr)
            .map_err(|e| Error::Msg(format!("TCP connect {}: {}", addr, e)))?;
       -
        stream.set_write_timeout(Some(Duration::from_secs(30)))
            .map_err(|e| Error::Msg(format!("set_write_timeout: {}", e)))?;

        let mut c = Smb2Client {
            stream,
            session_id: 0,
            msg_id: 0,
            host: host.to_string(),
            dialect: 0,
            signing_key: None,
            read_timeout: None,
        };
        c.smb1_negotiate()?;
        c.smb2_session_setup(ntlm)?;
        Ok(c)
    }


    fn smb2_negotiate(&mut self) -> Result<()> {
        
        const DIALECTS: &[u16] = &[
            SMB2_DIALECT_202, // 2.0.2 — baseline
            SMB2_DIALECT_210, // 2.1
            SMB2_DIALECT_300, // 3.0
            SMB2_DIALECT_302, // 3.0.2
        ];

        let mut body = Vec::new();
        body.extend_from_slice(&36u16.to_le_bytes());  // StructureSize (always 36)
        body.extend_from_slice(&(DIALECTS.len() as u16).to_le_bytes()); // DialectCount
        body.extend_from_slice(&SMB2_NEGOTIATE_SIGNING_ENABLED.to_le_bytes()); // SecurityMode
        body.extend_from_slice(&0u16.to_le_bytes());   // Reserved
        body.extend_from_slice(&0u32.to_le_bytes());   // Capabilities
        body.extend_from_slice(&rand_guid());           // ClientGuid (16 bytes)
        body.extend_from_slice(&0u64.to_le_bytes());   // ClientStartTime
        for &d in DIALECTS { body.extend_from_slice(&d.to_le_bytes()); }

        self.send_msg(SMB2_NEGOTIATE, 0, 0, &body)?;
        let resp = self.recv_msg()
            .map_err(|e| Error::Msg(format!("NEGOTIATE recv: {}", e)))?;

        let (status, payload) = parse_smb2_header(&resp)?;
        if status != STATUS_SUCCESS {
            return Err(Error::Msg(format!("NEGOTIATE failed: 0x{:08X}", status)));
        }
        if payload.len() >= 6 {
            self.dialect = u16::from_le_bytes(payload[4..6].try_into().unwrap());
        }
        Ok(())
    }

    fn smb1_negotiate(&mut self) -> Result<()> {
        // Standard dialect list; "SMB 2.???" triggers the SMB2 upgrade path.
        const DIALECTS: &[&[u8]] = &[
            b"\x02PC NETWORK PROGRAM 1.0\x00",
            b"\x02LANMAN1.0\x00",
            b"\x02Windows for Workgroups 3.1a\x00",
            b"\x02LM1.2X002\x00",
            b"\x02LANMAN2.1\x00",
            b"\x02NT LM 0.12\x00",
            b"\x02SMB 2.002\x00",
            b"\x02SMB 2.???\x00",
        ];
        let mut dialect_bytes: Vec<u8> = Vec::new();
        for d in DIALECTS { dialect_bytes.extend_from_slice(d); }

        // Build SMB1 NEGOTIATE request 
        let mut smb1: Vec<u8> = Vec::new();
        smb1.extend_from_slice(&[0xFF, b'S', b'M', b'B']); // ProtocolID
        smb1.push(0x72);                                     // Command: SMB_COM_NEGOTIATE
        smb1.extend_from_slice(&[0x00; 4]);                  // Status
        smb1.push(0x18);                                     // Flags
        smb1.extend_from_slice(&0x4863u16.to_le_bytes());    // Flags2 (unicode, ext-sec, long names)
        smb1.extend_from_slice(&[0x00; 2]);                  // PIDHigh
        smb1.extend_from_slice(&[0x00; 8]);                  // SecuritySignature
        smb1.extend_from_slice(&[0x00; 2]);                  // Reserved
        smb1.extend_from_slice(&0xFFFFu16.to_le_bytes());    // TID
        smb1.extend_from_slice(&0xFEFFu16.to_le_bytes());    // PID
        smb1.extend_from_slice(&0x0000u16.to_le_bytes());    // UID
        smb1.extend_from_slice(&0x0000u16.to_le_bytes());    // MID
        smb1.push(0u8);                                       // WordCount = 0
        smb1.extend_from_slice(&(dialect_bytes.len() as u16).to_le_bytes()); // ByteCount
        smb1.extend_from_slice(&dialect_bytes);

        // NetBIOS framing
        let len = smb1.len() as u32;
        let mut framed = vec![
            0x00,
            ((len >> 16) & 0xFF) as u8,
            ((len >>  8) & 0xFF) as u8,
            ( len        & 0xFF) as u8,
        ];
        framed.extend_from_slice(&smb1);

        self.stream.write_all(&framed)
            .map_err(|e| Error::Msg(format!("SMB1 NEGOTIATE send: {}", e)))?;

        let resp = self.recv_msg()
            .map_err(|e| Error::Msg(format!("NEGOTIATE recv: {}", e)))?;

        if resp.len() < 4 {
            return Err("NEGOTIATE response too short".into());
        }

     
        if &resp[0..4] == SMB2_MAGIC {
            let (status, payload) = parse_smb2_header(&resp)?;
            if status != STATUS_SUCCESS {
                return Err(Error::Msg(format!("NEGOTIATE failed: 0x{:08X}", status)));
            }
            // Server consumed MessageId=0; our next message must use 1.
            self.msg_id = 1;
            if payload.len() >= 6 {
                let dialect = u16::from_le_bytes(payload[4..6].try_into().unwrap());
                if dialect == 0x02FF {
                    return self.smb2_negotiate();
                }
                self.dialect = dialect;
            }
            return Ok(());
        }

        // SMB1-only or older server: replied with SMB1 NEGOTIATE response.
        // SMB1 header is 32 bytes; WordCount at [32], DialectIndex at [33..35].
        if resp[0] == 0xFF && resp.len() >= 35 && &resp[1..4] == b"SMB" {
            let idx = u16::from_le_bytes(resp[33..35].try_into().unwrap());
            if idx >= 6 {
                // Selected "SMB 2.002" or "SMB 2.???" → send proper SMB2 NEGOTIATE.
                return self.smb2_negotiate();
            }
            return Err(Error::Msg(format!(
                "Server only supports SMB1 (dialect index {})", idx
            )));
        }

        Err("Unexpected NEGOTIATE response (neither SMB1 nor SMB2)".into())
    }


    fn smb2_session_setup(&mut self, ntlm: &NtlmContext) -> Result<()> {
        let mut rng = rand::thread_rng();
        let client_nonce: [u8; 8] = rng.gen();

        let ntlm_neg  = ntlm.negotiate();
        let spnego1   = spnego_wrap_negotiate(&ntlm_neg);
        let body1     = build_session_setup_req(&spnego1);

        self.send_msg(SMB2_SESSION_SETUP, 0, 0, &body1)?;
        let resp1 = self.recv_msg()
            .map_err(|e| Error::Msg(format!("SESSION_SETUP[1] recv: {}", e)))?;

        let (status1, payload1) = parse_smb2_header(&resp1)?;
        if status1 != STATUS_MORE_PROCESSING_REQUIRED {
            return Err(Error::Msg(format!(
                "SESSION_SETUP[1] unexpected status: 0x{:08X}", status1
            )));
        }

        // Extract SessionId from response header (bytes 40..48 of the full SMB2 pkt)
        if resp1.len() < 48 { return Err("SESSION_SETUP[1] resp too short".into()); }
        let session_id = u64::from_le_bytes(resp1[40..48].try_into().unwrap());
        self.session_id = session_id;

        // Extract NTLM Type2 challenge from server's SPNEGO response
        let type2 = spnego_extract_token(&payload1)
            .ok_or("SESSION_SETUP[1]: could not extract NTLM Type2 from SPNEGO")?;

        let (ntlm_auth, exported_session_key) = ntlm.authenticate(&type2, &client_nonce)?;
        let spnego2  = spnego_wrap_authenticate(&ntlm_auth);
        let body2    = build_session_setup_req(&spnego2);

        // signing_key is still None here — SESSION_SETUP must not be signed
        self.send_msg(SMB2_SESSION_SETUP, session_id, 0, &body2)?;
        let resp2 = self.recv_msg()
            .map_err(|e| Error::Msg(format!("SESSION_SETUP[2] recv: {}", e)))?;

        let (status2, payload2) = parse_smb2_header(&resp2)?;
        if status2 != STATUS_SUCCESS {
            return Err(Error::Msg(format!(
                "SESSION_SETUP[2] authentication failed: 0x{:08X}\n\
                 Hint: 0xC000006D = wrong credentials/hash  \
                 0xC000015B = logon type not granted  \
                 0xC0000022 = access denied",
                status2
            )));
        }
        self.signing_key = Some(derive_signing_key(&exported_session_key, self.dialect));
        Ok(())
    }


    pub fn tree_connect(&mut self, share: &str) -> Result<u32> {
        // Path = \\<host>\<share>  UTF-16LE
        let path = format!("\\\\{}\\{}", self.host, share);
        let path_w: Vec<u8> = path.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();

        let mut body = Vec::new();
        body.extend_from_slice(&(9u16).to_le_bytes());            // StructureSize
        body.extend_from_slice(&0u16.to_le_bytes());              // Flags
        body.extend_from_slice(&(72u16).to_le_bytes());           // PathOffset (64 hdr + 8 body so far)
        body.extend_from_slice(&(path_w.len() as u16).to_le_bytes()); // PathLength
        body.extend_from_slice(&path_w);

        self.send_msg(SMB2_TREE_CONNECT, self.session_id, 0, &body)?;
        let resp = self.recv_msg()?;
        let (status, _) = parse_smb2_header(&resp)?;
        if status != STATUS_SUCCESS {
            return Err(Error::Msg(format!("TREE_CONNECT '{}' failed: 0x{:08X}", share, status)));
        }
        // TreeId is at bytes 36..40 of SMB2 header
        if resp.len() < 40 { return Err("TREE_CONNECT resp too short".into()); }
        let tree_id = u32::from_le_bytes(resp[36..40].try_into().unwrap());
        Ok(tree_id)
    }

    pub fn tree_disconnect(&mut self, tree_id: u32) -> Result<()> {
        let body: &[u8] = &[4, 0, 0, 0]; // StructureSize=4, reserved=0
        self.send_msg(SMB2_TREE_DISCONNECT, self.session_id, tree_id, body)?;
        let resp = self.recv_msg()?;
        let (status, _) = parse_smb2_header(&resp)?;
        if status != STATUS_SUCCESS {
            return Err(Error::Msg(format!("TREE_DISCONNECT failed: 0x{:08X}", status)));
        }
        Ok(())
    }


    /// Create or open a file on a disk share
    pub fn create_file(&mut self, tree_id: u32, filename: &str) -> Result<FileId> {
        let name_w: Vec<u8> = filename.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        self.smb2_create(tree_id, &name_w,
            FILE_GENERIC_WRITE, 0, 0,
            FILE_OVERWRITE_IF, FILE_NON_DIRECTORY_FILE)
    }

    /// Open a named pipe on IPC$ with the specified access mask
    pub fn create_pipe(&mut self, tree_id: u32, pipe_name: &str, desired_access: u32) -> Result<FileId> {
        let name_w: Vec<u8> = pipe_name.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        self.smb2_create(tree_id, &name_w,
            desired_access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            0,
            FILE_OPEN, FILE_NON_DIRECTORY_FILE)
    }

    fn smb2_create(
        &mut self, tree_id: u32, name_bytes: &[u8],
        desired_access: u32, share_access: u32, file_attrs: u32,
        create_disp: u32, create_opts: u32,
    ) -> Result<FileId> {
        
        let name_off: u16 = 64 + 56; // = 120
        let name_len = name_bytes.len() as u16;

        let mut body = Vec::new();
        body.extend_from_slice(&57u16.to_le_bytes());                // StructureSize
        body.push(0);                                                  // SecurityFlags
        body.push(0);                                                  // RequestedOplockLevel (NONE)
        body.extend_from_slice(&IMPERSONATION_IMPERSONATION.to_le_bytes());
        body.extend_from_slice(&[0u8; 8]);                            // SmbCreateFlags
        body.extend_from_slice(&[0u8; 8]);                            // Reserved
        body.extend_from_slice(&desired_access.to_le_bytes());
        body.extend_from_slice(&file_attrs.to_le_bytes());
        body.extend_from_slice(&share_access.to_le_bytes());
        body.extend_from_slice(&create_disp.to_le_bytes());
        body.extend_from_slice(&create_opts.to_le_bytes());
        body.extend_from_slice(&name_off.to_le_bytes());
        body.extend_from_slice(&name_len.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());                  // CreateContextsOffset
        body.extend_from_slice(&0u32.to_le_bytes());                  // CreateContextsLength
        body.extend_from_slice(name_bytes);
    
        while body.len() % 8 != 0 { body.push(0); }

        self.send_msg(SMB2_CREATE, self.session_id, tree_id, &body)?;
        let resp = self.recv_msg()?;
        let (status, payload) = parse_smb2_header(&resp)?;
        if status != STATUS_SUCCESS {
            return Err(Error::Msg(format!("SMB2 CREATE failed: 0x{:08X}", status)));
        }
        // FileId at offset 64 (8 persistent + 8 volatile) in response body
        if payload.len() < 88 { return Err("CREATE response too short".into()); }
        let mut fid = FileId::default();
        fid.0.copy_from_slice(&payload[64..80]);
        Ok(fid)
    }


    pub fn write_file(&mut self, tree_id: u32, fid: FileId, data: &[u8]) -> Result<()> {
        const CHUNK: usize = 65_535;
        let mut offset = 0u64;
        for chunk in data.chunks(CHUNK) {
            self.smb2_write(tree_id, fid, offset, chunk)?;
            offset += chunk.len() as u64;
        }
        Ok(())
    }

    fn smb2_write(&mut self, tree_id: u32, fid: FileId, offset: u64, data: &[u8]) -> Result<()> {
        // DataOffset = 64 (SMB2 header) + 48 (fixed body fields) = 112 = 0x70.
        // Fixed body breakdown (bytes):
        //   StructureSize(2) DataOffset(2) Length(4) Offset(8) FileId(16)
        //   Channel(4) RemainingBytes(4) WriteChannelInfoOffset(2)
        //   WriteChannelInfoLength(2) Flags(4)  → total 48 bytes, no padding needed.
        const DATA_OFFSET: u16 = 0x0070;

        let mut body = Vec::new();
        body.extend_from_slice(&49u16.to_le_bytes());                 // StructureSize
        body.extend_from_slice(&DATA_OFFSET.to_le_bytes());           // DataOffset
        body.extend_from_slice(&(data.len() as u32).to_le_bytes());   // Length
        body.extend_from_slice(&offset.to_le_bytes());                 // Offset
        body.extend_from_slice(&fid.0);                                // FileId (16 bytes)
        body.extend_from_slice(&0u32.to_le_bytes());                   // Channel
        body.extend_from_slice(&0u32.to_le_bytes());                   // RemainingBytes
        body.extend_from_slice(&0u16.to_le_bytes());                   // WriteChannelInfoOffset
        body.extend_from_slice(&0u16.to_le_bytes());                   // WriteChannelInfoLength
        body.extend_from_slice(&0u32.to_le_bytes());                   // Flags
        // data starts at exactly DATA_OFFSET bytes from the SMB2 header — no padding.
        body.extend_from_slice(data);

        self.send_msg(SMB2_WRITE, self.session_id, tree_id, &body)?;
        let status = loop {
            let resp = self.recv_msg()?;
            let (s, _) = parse_smb2_header(&resp)?;
            if s != 0x0000_0103 { break s; }
        };
        if status != STATUS_SUCCESS {
            return Err(Error::Msg(format!("SMB2 WRITE failed: 0x{:08X}", status)));
        }
        Ok(())
    }


    pub fn read_pipe(&mut self, tree_id: u32, fid: FileId, max_len: u32) -> Result<Vec<u8>> {
        let mut body = Vec::new();
        body.extend_from_slice(&49u16.to_le_bytes());    // StructureSize
        body.push(0);                                     // Padding
        body.push(0);                                     // Reserved
        body.extend_from_slice(&max_len.to_le_bytes());
        body.extend_from_slice(&0u64.to_le_bytes());      // Offset
        body.extend_from_slice(&fid.0);
        body.extend_from_slice(&0u32.to_le_bytes());      // MinimumCount
        body.extend_from_slice(&0u32.to_le_bytes());      // Channel
        body.extend_from_slice(&0u32.to_le_bytes());      // RemainingBytes
        body.extend_from_slice(&0u16.to_le_bytes());      // ReadChannelInfoOffset
        body.extend_from_slice(&0u16.to_le_bytes());      // ReadChannelInfoLength
        body.push(0);                                     // Buffer[1]

        self.send_msg(SMB2_READ, self.session_id, tree_id, &body)?;
        // Loop past STATUS_PENDING async interim responses
        // If a read_timeout is set (relay mode) and recv_msg times out, the async response will never arrive 
            match self.recv_msg() {
                Ok(resp) => {
                    let (s, p) = parse_smb2_header(&resp)?;
                    if s != 0x0000_0103 { break (s, p); } // not STATUS_PENDING — done
                }
                Err(ref e) if self.read_timeout.is_some() && is_timeout_error(e) => {
                    return Ok(Vec::new()); 
                }
                Err(e) => return Err(e),
            }
        };
        if status != STATUS_SUCCESS {
            return Err(Error::Msg(format!("SMB2 READ failed: 0x{:08X}", status)));
        }
        // DataOffset at payload[2..4]
        // DataLength at payload[4..8]
        if payload.len() < 8 { return Err("SMB2 READ response too short".into()); }
        let data_off  = u16::from_le_bytes(payload[2..4].try_into().unwrap()) as usize;
        let data_len  = u32::from_le_bytes(payload[4..8].try_into().unwrap()) as usize;
        let abs_off   = data_off.saturating_sub(64); // relative to payload
        let end       = abs_off + data_len;
        if payload.len() < end { return Err("SMB2 READ data out of bounds".into()); }
        Ok(payload[abs_off..end].to_vec())
    }


    pub fn write_pipe(&mut self, tree_id: u32, fid: FileId, data: &[u8]) -> Result<()> {
        self.smb2_write(tree_id, fid, 0, data)
    }


    pub fn close(&mut self, tree_id: u32, fid: FileId) -> Result<()> {
        let mut body = Vec::new();
        body.extend_from_slice(&24u16.to_le_bytes()); // StructureSize
        body.extend_from_slice(&0u16.to_le_bytes());  // Flags
        body.extend_from_slice(&0u32.to_le_bytes());  // Reserved
        body.extend_from_slice(&fid.0);

        self.send_msg(SMB2_CLOSE, self.session_id, tree_id, &body)?;
        let resp = self.recv_msg()?;
        let (status, _) = parse_smb2_header(&resp)?;
        if status != STATUS_SUCCESS {
            return Err(Error::Msg(format!("SMB2 CLOSE failed: 0x{:08X}", status)));
        }
        Ok(())
    }

    /// Delete a file on a disk share 
    pub fn delete_file(&mut self, tree_id: u32, filename: &str) -> Result<()> {
        let name_w: Vec<u8> = filename.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let fid = self.smb2_create(
            tree_id, &name_w,
            DELETE_ACCESS,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            0,
            FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE,
        )?;
        self.close(tree_id, fid)
    }

    /// Open a named pipe, retrying until it appears or timeout_ms expires
    pub fn wait_pipe(&mut self, tree_id: u32, pipe_name: &str, timeout_ms: u64, desired_access: u32) -> Result<FileId> {
        let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
        loop {
            match self.create_pipe(tree_id, pipe_name, desired_access) {
                Ok(fid) => return Ok(fid),
                Err(_) if std::time::Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(500));
                }
                Err(e) => return Err(e),
            }
        }
    }


    fn next_msg_id(&mut self) -> u64 {
        let id = self.msg_id;
        self.msg_id += 1;
        id
    }

    fn send_msg(&mut self, cmd: u16, session_id: u64, tree_id: u32, body: &[u8]) -> Result<()> {
        let msg_id = self.next_msg_id();
        let mut pkt = smb2_header(cmd, msg_id, session_id, tree_id);
        pkt.extend_from_slice(body);

        // Sign all session-bearing messages once we have a key
        if session_id != 0 {
            if let Some(ref key) = self.signing_key {
                sign_message(&mut pkt, key, self.dialect);
            }
        }

        // NetBIOS SSN service prefix: type=0x00, length=3 bytes big-endian
        let pkt_len = pkt.len() as u32;
        let mut framed = vec![0x00];
        framed.push(((pkt_len >> 16) & 0xFF) as u8);
        framed.push(((pkt_len >>  8) & 0xFF) as u8);
        framed.push( (pkt_len        & 0xFF) as u8);
        framed.extend_from_slice(&pkt);

        self.stream.write_all(&framed)
            .map_err(|e| Error::Msg(format!("TCP write: {}", e)))?;
        Ok(())
    }

    fn recv_msg(&mut self) -> Result<Vec<u8>> {
        // Read NetBIOS header (4 bytes)
        let mut hdr = [0u8; 4];
        self.stream.read_exact(&mut hdr)
            .map_err(|e| Error::Msg(format!("TCP read (NetBIOS hdr): {}", e)))?;
        let len = ((hdr[1] as usize) << 16) | ((hdr[2] as usize) << 8) | (hdr[3] as usize);

        let mut buf = vec![0u8; len];
        self.stream.read_exact(&mut buf)
            .map_err(|e| Error::Msg(format!("TCP read ({} bytes): {}", len, e)))?;
        Ok(buf)
    }
}


/// Derive the SMB2 signing key from the NTLM ExportedSessionKey.
fn derive_signing_key(exported_session_key: &[u8; 16], dialect: u16) -> [u8; 16] {
    if dialect >= 0x0300 {
        // HMAC-SHA256(K, 0x00000001 || "SMB2AESCMAC\0" || 0x00 || "SmbSign\0" || 0x00000080)
        let mut data = Vec::with_capacity(32);
        data.extend_from_slice(&1u32.to_be_bytes());
        data.extend_from_slice(b"SMB2AESCMAC\x00");
        data.push(0x00);
        data.extend_from_slice(b"SmbSign\x00");
        data.extend_from_slice(&128u32.to_be_bytes());
        let mut mac = HmacSha256::new_from_slice(exported_session_key)
            .expect("HMAC-SHA256 key length");
        mac.update(&data);
        mac.finalize().into_bytes()[..16].try_into().unwrap()
    } else {
        *exported_session_key
    }
}

fn sign_message(pkt: &mut Vec<u8>, key: &[u8; 16], dialect: u16) {
    // Set the SIGNED flag
    let flags = u32::from_le_bytes(pkt[16..20].try_into().unwrap());
    pkt[16..20].copy_from_slice(&(flags | SMB2_FLAGS_SIGNED).to_le_bytes());

    let sig: [u8; 16] = if dialect >= 0x0300 {
        let mut mac = Cmac::<Aes128>::new_from_slice(key).expect("AES-CMAC key");
        mac.update(pkt);
        mac.finalize().into_bytes()[..16].try_into().unwrap()
    } else {
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 signing key");
        mac.update(pkt);
        mac.finalize().into_bytes()[..16].try_into().unwrap()
    };
    pkt[48..64].copy_from_slice(&sig);
}


fn smb2_header(cmd: u16, msg_id: u64, session_id: u64, tree_id: u32) -> Vec<u8> {
    let mut h = Vec::with_capacity(64);
    h.extend_from_slice(SMB2_MAGIC);            // [0..4]  ProtocolId
    h.extend_from_slice(&64u16.to_le_bytes());  // [4..6]  StructureSize
    h.extend_from_slice(&0u16.to_le_bytes());   // [6..8]  CreditCharge
    h.extend_from_slice(&0u32.to_le_bytes());   // [8..12] Status (for requests)
    h.extend_from_slice(&cmd.to_le_bytes());    // [12..14] Command
    h.extend_from_slice(&1u16.to_le_bytes());   // [14..16] CreditRequest
    h.extend_from_slice(&0u32.to_le_bytes());   // [16..20] Flags
    h.extend_from_slice(&0u32.to_le_bytes());   // [20..24] NextCommand
    h.extend_from_slice(&msg_id.to_le_bytes()); // [24..32] MessageId
    h.extend_from_slice(&0u32.to_le_bytes());   // [32..36] Reserved / ProcessId
    h.extend_from_slice(&tree_id.to_le_bytes());// [36..40] TreeId
    h.extend_from_slice(&session_id.to_le_bytes()); // [40..48] SessionId
    h.extend_from_slice(&[0u8; 16]);            // [48..64] Signature (zeros = no signing)
    h
}

fn build_session_setup_req(security_blob: &[u8]) -> Vec<u8> {
    let sec_buf_off: u16 = 64 + 24; // = 88
    let sec_buf_len = security_blob.len() as u16;

    let mut body = Vec::new();
    body.extend_from_slice(&25u16.to_le_bytes());     // StructureSize
    body.push(0);                                      // Flags
    body.push(0);                                      // SecurityMode: NONE (or SIGNING_ENABLED=1)
    body.extend_from_slice(&0u32.to_le_bytes());       // Capabilities
    body.extend_from_slice(&0u32.to_le_bytes());       // Channel
    body.extend_from_slice(&sec_buf_off.to_le_bytes());
    body.extend_from_slice(&sec_buf_len.to_le_bytes());
    body.extend_from_slice(&0u64.to_le_bytes());       // PreviousSessionId
    body.extend_from_slice(security_blob);
    body
}

fn parse_smb2_header(pkt: &[u8]) -> Result<(u32, Vec<u8>)> {
    if pkt.len() < 64 {
        return Err(Error::Msg(format!("SMB2 packet too short: {} bytes", pkt.len())));
    }
    if &pkt[0..4] != SMB2_MAGIC {
        return Err("SMB2 magic mismatch".into());
    }
    let status = u32::from_le_bytes(pkt[8..12].try_into().unwrap());
    let payload = pkt[64..].to_vec();
    Ok((status, payload))
}


fn spnego_extract_token(payload: &[u8]) -> Option<Vec<u8>> {
    // SESSION_SETUP response: SecurityBufferOffset at payload[4..6], Length at payload[6..8]
    if payload.len() < 8 { return None; }
    let sec_off = u16::from_le_bytes(payload[4..6].try_into().ok()?) as usize;
    let sec_len = u16::from_le_bytes(payload[6..8].try_into().ok()?) as usize;
    let abs_off = sec_off.checked_sub(64)?; // relative to payload
    let spnego = payload.get(abs_off..abs_off + sec_len)?;

    // Walk ASN.1: skip outer tags to find octet-string (0x04) with NTLMSSP signature
    find_ntlmssp(spnego)
}

fn find_ntlmssp(data: &[u8]) -> Option<Vec<u8>> {
    let mut i = 0;
    while i < data.len() {
        let tag = data[i]; i += 1;
        let (len, skip) = asn1_read_len(data.get(i..)?)?;
        i += skip;
        let content = data.get(i..i + len)?;
        if tag == 0x04 {
            if content.starts_with(b"NTLMSSP\0") {
                return Some(content.to_vec());
            }
        }
        // Recurse into constructed types
        if tag & 0x20 != 0 || (tag & 0xC0 != 0) {
            if let Some(v) = find_ntlmssp(content) { return Some(v); }
        }
        i += len;
    }
    None
}

fn asn1_read_len(data: &[u8]) -> Option<(usize, usize)> {
    let b = *data.first()?;
    if b & 0x80 == 0 {
        Some((b as usize, 1))
    } else {
        let n = (b & 0x7F) as usize;
        if n == 0 || n > 4 || data.len() < 1 + n { return None; }
        let mut len = 0usize;
        for i in 0..n { len = (len << 8) | (data[1 + i] as usize); }
        Some((len, 1 + n))
    }
}


fn rand_guid() -> [u8; 16] {
    rand::thread_rng().gen()
}

fn is_timeout_error(e: &Error) -> bool {
    match e {
        Error::Msg(s) => s.contains("timed out") || s.contains("WouldBlock"),
        _ => false,
    }
}

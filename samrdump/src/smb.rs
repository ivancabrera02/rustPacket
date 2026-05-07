//! SMB2 client implementation
//!
//! Handles SMB2 NEGOTIATE, SESSION_SETUP (with NTLM), TREE_CONNECT,
//! CREATE (named pipe), READ, WRITE, and IOCTL (for DCE/RPC transport).

use crate::dcerpc;
use crate::error::{SamrDumpError, SamrResult};
use crate::ntlm;
use byteorder::{LittleEndian, ReadBytesExt};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::io::{Cursor, Read, Write};
use std::net::TcpStream;
use tracing::debug;

type HmacSha256 = Hmac<Sha256>;

// SMB2 Flags
const SMB2_FLAGS_SIGNED: u32 = 0x0000_0008;

// SMB2 commands
#[allow(dead_code)]
const SMB2_NEGOTIATE: u16 = 0x0000;
#[allow(dead_code)]
const SMB2_SESSION_SETUP: u16 = 0x0001;
#[allow(dead_code)]
const SMB2_TREE_CONNECT: u16 = 0x0003;
#[allow(dead_code)]
const SMB2_CREATE: u16 = 0x0005;
#[allow(dead_code)]
const SMB2_CLOSE: u16 = 0x0006;
#[allow(dead_code)]
const SMB2_READ: u16 = 0x0008;
#[allow(dead_code)]
const SMB2_WRITE: u16 = 0x0009;
#[allow(dead_code)]
const SMB2_IOCTL: u16 = 0x000B;

// SMB2 header size
const SMB2_HEADER_SIZE: usize = 64;

pub struct SmbSession {
    stream: TcpStream,
    session_id: u64,
    tree_id: u32,
    file_id: [u8; 16], // SMB2 file ID for the named pipe
    message_id: u64,
    dialect: u16,
    max_read_size: u32,
    max_write_size: u32,
    signing_required: bool,
    signing_key: Vec<u8>, // Session signing key (from NTLM)
}

impl SmbSession {
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            session_id: 0,
            tree_id: 0,
            file_id: [0; 16],
            message_id: 0,
            dialect: 0,
            max_read_size: 65536,
            max_write_size: 65536,
            signing_required: false,
            signing_key: Vec::new(),
        }
    }

    /// Send raw bytes with NetBIOS session header (4-byte length prefix).
    /// If signing is active, signs the packet before sending.
    fn send_raw(&mut self, data: &[u8]) -> SamrResult<()> {
        let data = if self.signing_required && !self.signing_key.is_empty() && data.len() >= SMB2_HEADER_SIZE {
            self.sign_packet(data)
        } else {
            data.to_vec()
        };

        let len = data.len() as u32;
        let mut header = [0u8; 4];
        header[0] = 0; // NetBIOS session message
        header[1] = ((len >> 16) & 0xFF) as u8;
        header[2] = ((len >> 8) & 0xFF) as u8;
        header[3] = (len & 0xFF) as u8;

        self.stream.write_all(&header)?;
        self.stream.write_all(&data)?;
        self.stream.flush()?;
        Ok(())
    }

    /// Sign an SMB2 packet: set FLAGS_SIGNED, zero signature field, compute
    /// HMAC-SHA256 over the entire message, write first 16 bytes as signature.
    fn sign_packet(&self, data: &[u8]) -> Vec<u8> {
        let mut pkt = data.to_vec();

        // Set the SIGNED flag (offset 16, 4 bytes LE)
        let flags = u32::from_le_bytes([pkt[16], pkt[17], pkt[18], pkt[19]]);
        let flags = flags | SMB2_FLAGS_SIGNED;
        pkt[16..20].copy_from_slice(&flags.to_le_bytes());

        // Zero out the signature field (offset 48, 16 bytes)
        pkt[48..64].fill(0);

        // HMAC-SHA256(SigningKey, entire packet)
        let mut mac = HmacSha256::new_from_slice(&self.signing_key)
            .expect("HMAC-SHA256 accepts any key size");
        mac.update(&pkt);
        let result = mac.finalize().into_bytes();

        // Write first 16 bytes of HMAC as signature
        pkt[48..64].copy_from_slice(&result[..16]);

        pkt
    }

    /// Receive a NetBIOS-framed SMB2 response
    fn recv_raw(&mut self) -> SamrResult<Vec<u8>> {
        let mut header = [0u8; 4];
        self.stream.read_exact(&mut header)?;
        let len = ((header[1] as usize) << 16) | ((header[2] as usize) << 8) | header[3] as usize;

        let mut buf = vec![0u8; len];
        self.stream.read_exact(&mut buf)?;
        Ok(buf)
    }

    /// Build an SMB2 header
    fn build_header(&mut self, command: u16, extra_flags: u32) -> Vec<u8> {
        let mut hdr = Vec::with_capacity(SMB2_HEADER_SIZE);
        hdr.extend_from_slice(&[0xFE, b'S', b'M', b'B']); // ProtocolId
        hdr.extend_from_slice(&64u16.to_le_bytes()); // StructureSize
        // CreditCharge: 0 for SMB 2.0.2, 1 for SMB 2.1+
        let credit_charge: u16 = if self.dialect >= 0x0210 { 1 } else { 0 };
        hdr.extend_from_slice(&credit_charge.to_le_bytes()); // CreditCharge
        hdr.extend_from_slice(&0u32.to_le_bytes()); // Status
        hdr.extend_from_slice(&command.to_le_bytes()); // Command
        hdr.extend_from_slice(&31u16.to_le_bytes()); // CreditRequest (request more credits)
        hdr.extend_from_slice(&extra_flags.to_le_bytes()); // Flags
        hdr.extend_from_slice(&0u32.to_le_bytes()); // NextCommand
        hdr.extend_from_slice(&self.message_id.to_le_bytes()); // MessageId
        self.message_id += 1;
        hdr.extend_from_slice(&0u32.to_le_bytes()); // Reserved (ProcessId)
        hdr.extend_from_slice(&self.tree_id.to_le_bytes()); // TreeId
        hdr.extend_from_slice(&self.session_id.to_le_bytes()); // SessionId
        hdr.extend_from_slice(&[0u8; 16]); // Signature
        hdr
    }

    /// Parse the SMB2 response header, return (status, command, body)
    fn parse_response(&self, data: &[u8]) -> SamrResult<(u32, u16, Vec<u8>)> {
        if data.len() < SMB2_HEADER_SIZE {
            return Err(SamrDumpError::Smb("Response too short".into()));
        }
        if &data[0..4] != &[0xFE, b'S', b'M', b'B'] {
            return Err(SamrDumpError::Smb("Invalid SMB2 signature".into()));
        }

        // Status at offset 8
        let status = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        // Command at offset 12
        let command = u16::from_le_bytes([data[12], data[13]]);

        debug!(
            "SMB2 response: cmd=0x{:04x} status=0x{:08x} len={}",
            command, status, data.len()
        );

        let body = data[SMB2_HEADER_SIZE..].to_vec();
        Ok((status, command, body))
    }

    /// Extract SessionId from an SMB2 response (offset 40..48)
    fn extract_session_id(data: &[u8]) -> u64 {
        if data.len() >= 48 {
            u64::from_le_bytes([
                data[40], data[41], data[42], data[43],
                data[44], data[45], data[46], data[47],
            ])
        } else {
            0
        }
    }

    /// SMB2 NEGOTIATE
    pub fn negotiate(&mut self) -> SamrResult<()> {
        let mut pkt = self.build_header(SMB2_NEGOTIATE, 0);

        // Negotiate request body
        let mut body = Vec::new();
        body.extend_from_slice(&36u16.to_le_bytes()); // StructureSize
        body.extend_from_slice(&2u16.to_le_bytes()); // DialectCount
        body.extend_from_slice(&1u16.to_le_bytes()); // SecurityMode (signing enabled)
        body.extend_from_slice(&0u16.to_le_bytes()); // Reserved
        body.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
        body.extend_from_slice(&[0u8; 16]); // ClientGuid
        body.extend_from_slice(&0u32.to_le_bytes()); // NegotiateContextOffset
        body.extend_from_slice(&0u16.to_le_bytes()); // NegotiateContextCount
        body.extend_from_slice(&0u16.to_le_bytes()); // Reserved2
        // Dialects: SMB 2.0.2, SMB 2.1
        body.extend_from_slice(&0x0202u16.to_le_bytes());
        body.extend_from_slice(&0x0210u16.to_le_bytes());

        pkt.extend_from_slice(&body);
        self.send_raw(&pkt)?;

        let resp = self.recv_raw()?;
        let (status, _cmd, resp_body) = self.parse_response(&resp)?;

        if status != 0 {
            return Err(SamrDumpError::Smb(format!(
                "NEGOTIATE failed: 0x{:08x}",
                status
            )));
        }

        if resp_body.len() < 64 {
            return Err(SamrDumpError::Smb("NEGOTIATE response too short".into()));
        }

        let mut c = Cursor::new(resp_body.as_slice());
        let _struct_size = c.read_u16::<LittleEndian>()?;
        let security_mode = c.read_u16::<LittleEndian>()?;
        self.dialect = c.read_u16::<LittleEndian>()?;

        // SecurityMode bit 0x02 = NEGOTIATE_SIGNING_REQUIRED
        self.signing_required = (security_mode & 0x02) != 0;
        debug!(
            "Negotiated dialect: 0x{:04x}, security_mode: 0x{:04x}, signing_required: {}",
            self.dialect, security_mode, self.signing_required
        );

        // Skip to MaxReadSize (offset 28 from body start) and MaxWriteSize (offset 32)
        // But we need to jump past several fields
        // StructSize(2) + SecurityMode(2) + Dialect(2) + NegContextCount(2) + ServerGuid(16)
        // + Capabilities(4) + MaxTransactSize(4) + MaxReadSize(4) + MaxWriteSize(4) ...
        if resp_body.len() >= 36 {
            let mut c2 = Cursor::new(&resp_body[24..]);
            let _caps = c2.read_u32::<LittleEndian>()?;
            let _max_transact = c2.read_u32::<LittleEndian>()?;
            self.max_read_size = c2.read_u32::<LittleEndian>()?;
            self.max_write_size = c2.read_u32::<LittleEndian>()?;
        }

        Ok(())
    }

    /// SMB2 SESSION_SETUP with NTLM authentication
    pub fn session_setup(
        &mut self,
        domain: &str,
        username: &str,
        password: &str,
        nt_hash_override: &[u8],
    ) -> SamrResult<()> {
        // --- Round 1: Send NTLM NEGOTIATE ---
        let negotiate_msg = ntlm::build_negotiate_message();
        let spnego_init = build_spnego_init(&negotiate_msg);

        let pkt = self.build_session_setup_packet(&spnego_init)?;
        self.send_raw(&pkt)?;

        let resp = self.recv_raw()?;
        let (status, _cmd, resp_body) = self.parse_response(&resp)?;

        // STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016
        if status != 0xC000_0016 && status != 0 {
            return Err(SamrDumpError::Smb(format!(
                "SESSION_SETUP round 1 failed: 0x{:08x}",
                status
            )));
        }

        // Extract session ID from response header (offset 40 in SMB2 header)
        self.session_id = Self::extract_session_id(&resp);
        debug!("Session ID after round 1: 0x{:016x}", self.session_id);

        // Extract NTLM CHALLENGE from SPNEGO response
        // SESSION_SETUP response body:
        //   StructureSize(2) + SessionFlags(2) + SecurityBufferOffset(2) + SecurityBufferLength(2)
        if resp_body.len() < 8 {
            return Err(SamrDumpError::Smb("SESSION_SETUP response too short".into()));
        }
        let sec_buf_offset = u16::from_le_bytes([resp_body[4], resp_body[5]]) as usize;
        let sec_buf_len = u16::from_le_bytes([resp_body[6], resp_body[7]]) as usize;

        // SecurityBufferOffset is from the start of the SMB2 header
        let sec_buf_start = sec_buf_offset.saturating_sub(SMB2_HEADER_SIZE);
        let challenge_spnego = if sec_buf_start + sec_buf_len <= resp_body.len() {
            &resp_body[sec_buf_start..sec_buf_start + sec_buf_len]
        } else {
            // Fallback: skip the 8-byte fixed header
            &resp_body[8.min(resp_body.len())..]
        };

        let ntlm_challenge = extract_ntlm_from_spnego(challenge_spnego)
            .map_err(|e| SamrDumpError::Ntlm(format!("Failed to extract challenge: {}", e)))?;

        let (server_challenge, _flags, target_info) =
            ntlm::parse_challenge_message(&ntlm_challenge)
                .map_err(|e| SamrDumpError::Ntlm(e))?;

        debug!("Server challenge: {:02x?}", server_challenge);
        debug!("Target info length: {} bytes", target_info.len());

        // --- Round 2: Send NTLM AUTHENTICATE ---
        let nt_hash_bytes = if !nt_hash_override.is_empty() {
            nt_hash_override.to_vec()
        } else {
            ntlm::nt_hash(password)
        };

        let (auth_msg, session_key) = ntlm::build_authenticate_message(
            domain,
            username,
            &nt_hash_bytes,
            &server_challenge,
            &target_info,
        );
        let spnego_auth = build_spnego_auth(&auth_msg);

        let pkt2 = self.build_session_setup_packet(&spnego_auth)?;
        self.send_raw(&pkt2)?;

        let resp2 = self.recv_raw()?;
        let (status2, _cmd2, _) = self.parse_response(&resp2)?;

        if status2 != 0 {
            return Err(SamrDumpError::Smb(format!(
                "Authentication failed: 0x{:08x} — check credentials",
                status2
            )));
        }

        // Update session ID from final response
        self.session_id = Self::extract_session_id(&resp2);

        // Store the session key for signing
        // For SMB2 (2.0.2, 2.1) the signing key IS the session key
        self.signing_key = session_key;
        debug!("Signing key stored ({} bytes), signing_required={}", self.signing_key.len(), self.signing_required);
        debug!("Authenticated session ID: 0x{:016x}", self.session_id);

        Ok(())
    }

    /// Build a SESSION_SETUP request packet with the given security buffer.
    ///
    /// MS-SMB2 §2.2.5 SMB2 SESSION_SETUP Request:
    ///   StructureSize(2) = 25
    ///   Flags(1) = 0
    ///   SecurityMode(1) = 1 (signing enabled)
    ///   Capabilities(4) = 0
    ///   Channel(4) = 0
    ///   SecurityBufferOffset(2) = 88 (64 header + 24 body fixed)
    ///   SecurityBufferLength(2)
    ///   PreviousSessionId(8) = 0
    ///   Buffer(variable)
    fn build_session_setup_packet(&mut self, security_buffer: &[u8]) -> SamrResult<Vec<u8>> {
        let mut pkt = self.build_header(SMB2_SESSION_SETUP, 0);

        // Fixed body: 24 bytes
        let sec_offset = (SMB2_HEADER_SIZE + 24) as u16; // = 88
        let sec_length = security_buffer.len() as u16;

        let mut body = Vec::with_capacity(24 + security_buffer.len());
        body.extend_from_slice(&25u16.to_le_bytes());   // StructureSize (2)
        body.push(0);                                     // Flags (1)
        body.push(1);                                     // SecurityMode (1)
        body.extend_from_slice(&0u32.to_le_bytes());     // Capabilities (4)
        body.extend_from_slice(&0u32.to_le_bytes());     // Channel (4)
        body.extend_from_slice(&sec_offset.to_le_bytes()); // SecurityBufferOffset (2)
        body.extend_from_slice(&sec_length.to_le_bytes()); // SecurityBufferLength (2)
        body.extend_from_slice(&0u64.to_le_bytes());     // PreviousSessionId (8)
        // Total fixed = 2+1+1+4+4+2+2+8 = 24 bytes ✓

        // Variable: security buffer
        body.extend_from_slice(security_buffer);

        pkt.extend_from_slice(&body);
        Ok(pkt)
    }

    /// SMB2 TREE_CONNECT
    pub fn tree_connect(&mut self, share: &str) -> SamrResult<()> {
        let share_utf16: Vec<u8> = share
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();

        let mut pkt = self.build_header(SMB2_TREE_CONNECT, 0);
        let mut body = Vec::new();
        body.extend_from_slice(&9u16.to_le_bytes()); // StructureSize
        body.extend_from_slice(&0u16.to_le_bytes()); // Reserved/Flags
        let path_offset = (SMB2_HEADER_SIZE + 8) as u16;
        body.extend_from_slice(&path_offset.to_le_bytes());
        body.extend_from_slice(&(share_utf16.len() as u16).to_le_bytes());
        // Pad to 8 bytes
        while body.len() < 8 {
            body.push(0);
        }
        body.extend_from_slice(&share_utf16);

        pkt.extend_from_slice(&body);
        self.send_raw(&pkt)?;

        let resp = self.recv_raw()?;
        let (status, _cmd, _resp_body) = self.parse_response(&resp)?;

        if status != 0 {
            return Err(SamrDumpError::Smb(format!(
                "TREE_CONNECT failed: 0x{:08x}",
                status
            )));
        }

        // Extract TreeId from response header
        self.tree_id = u32::from_le_bytes([resp[36], resp[37], resp[38], resp[39]]);
        debug!("Tree ID: 0x{:08x}", self.tree_id);

        Ok(())
    }

    /// SMB2 CREATE — open a named pipe
    pub fn create_pipe(&mut self, pipe_name: &str) -> SamrResult<()> {
        let name_utf16: Vec<u8> = pipe_name
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();

        let mut pkt = self.build_header(SMB2_CREATE, 0);
        let mut body = Vec::new();
        body.extend_from_slice(&57u16.to_le_bytes()); // StructureSize

        body.push(0); // SecurityFlags
        body.push(0); // RequestedOplockLevel = SMB2_OPLOCK_LEVEL_NONE

        // ImpersonationLevel: Impersonation(2)
        body.extend_from_slice(&2u32.to_le_bytes());

        body.extend_from_slice(&[0u8; 8]); // SmbCreateFlags
        body.extend_from_slice(&[0u8; 8]); // Reserved

        // DesiredAccess: GENERIC_READ | GENERIC_WRITE
        let access: u32 = 0x8000_0000 | 0x4000_0000 | 0x0012_019F;
        body.extend_from_slice(&access.to_le_bytes());

        // FileAttributes: Normal
        body.extend_from_slice(&0x80u32.to_le_bytes());

        // ShareAccess: Read | Write
        body.extend_from_slice(&3u32.to_le_bytes());

        // CreateDisposition: FILE_OPEN (1)
        body.extend_from_slice(&1u32.to_le_bytes());

        // CreateOptions: 0
        body.extend_from_slice(&0u32.to_le_bytes());

        // NameOffset: 64 + 56 = 120
        let name_offset = (SMB2_HEADER_SIZE + 56) as u16;
        body.extend_from_slice(&name_offset.to_le_bytes());

        // NameLength
        body.extend_from_slice(&(name_utf16.len() as u16).to_le_bytes());

        // CreateContextsOffset, CreateContextsLength
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());

        // Pad body to 56 bytes
        while body.len() < 56 {
            body.push(0);
        }
        body.extend_from_slice(&name_utf16);

        pkt.extend_from_slice(&body);
        self.send_raw(&pkt)?;

        let resp = self.recv_raw()?;
        let (status, _cmd, resp_body) = self.parse_response(&resp)?;

        if status != 0 {
            return Err(SamrDumpError::Smb(format!(
                "CREATE pipe failed: 0x{:08x}",
                status
            )));
        }

        // FileId is at offset 64 in the CREATE response body (after StructureSize(2) + OplockLevel(1)
        // + Flags(1) + CreateAction(4) + CreationTime(8) + LastAccessTime(8) + LastWriteTime(8)
        // + ChangeTime(8) + AllocationSize(8) + EndOfFile(8) + FileAttributes(4) + Reserved2(4)
        // = 2+1+1+4+8+8+8+8+8+8+4+4 = 64)
        if resp_body.len() >= 80 {
            self.file_id.copy_from_slice(&resp_body[64..80]);
            debug!("File ID: {:02x?}", self.file_id);
        } else {
            return Err(SamrDumpError::Smb("CREATE response too short for FileId".into()));
        }

        Ok(())
    }

    /// Write to the named pipe (used for DCE/RPC)
    pub fn write_pipe(&mut self, data: &[u8]) -> SamrResult<()> {
        let mut pkt = self.build_header(SMB2_WRITE, 0);
        let mut body = Vec::new();
        body.extend_from_slice(&49u16.to_le_bytes()); // StructureSize
        let data_offset = (SMB2_HEADER_SIZE + 48) as u16;
        body.extend_from_slice(&data_offset.to_le_bytes()); // DataOffset
        body.extend_from_slice(&(data.len() as u32).to_le_bytes()); // Length
        body.extend_from_slice(&0u64.to_le_bytes()); // Offset
        body.extend_from_slice(&self.file_id); // FileId (16 bytes)
        body.extend_from_slice(&0u32.to_le_bytes()); // Channel
        body.extend_from_slice(&0u32.to_le_bytes()); // RemainingBytes
        body.extend_from_slice(&0u16.to_le_bytes()); // WriteChannelInfoOffset
        body.extend_from_slice(&0u16.to_le_bytes()); // WriteChannelInfoLength
        body.extend_from_slice(&0u32.to_le_bytes()); // Flags
        debug_assert_eq!(body.len(), 48);
        body.extend_from_slice(data);

        pkt.extend_from_slice(&body);
        debug!("WRITE pkt total {} bytes, body {} bytes, data {} bytes",
            pkt.len(), body.len(), data.len());
        self.send_raw(&pkt)?;

        let resp = self.recv_raw()?;
        let (status, _cmd, _) = self.parse_response(&resp)?;

        if status != 0 {
            return Err(SamrDumpError::Smb(format!(
                "WRITE failed: 0x{:08x}",
                status
            )));
        }

        Ok(())
    }

    /// Read from the named pipe
    pub fn read_pipe(&mut self, max_len: u32) -> SamrResult<Vec<u8>> {
        let mut pkt = self.build_header(SMB2_READ, 0);

        let mut body = Vec::with_capacity(49);
        body.extend_from_slice(&49u16.to_le_bytes());          // StructureSize (2)
        body.push(0x50);                                        // Padding (1)
        body.push(0);                                           // Flags (1)
        body.extend_from_slice(&max_len.to_le_bytes());        // Length (4)
        body.extend_from_slice(&0u64.to_le_bytes());           // Offset (8) - 0 for pipes
        body.extend_from_slice(&self.file_id);                  // FileId (16)
        body.extend_from_slice(&0u32.to_le_bytes());           // MinimumCount (4)
        body.extend_from_slice(&0u32.to_le_bytes());           // Channel (4)
        body.extend_from_slice(&0u32.to_le_bytes());           // RemainingBytes (4)
        body.extend_from_slice(&0u16.to_le_bytes());           // ReadChannelInfoOffset (2)
        body.extend_from_slice(&0u16.to_le_bytes());           // ReadChannelInfoLength (2)
        body.push(0);                                           // Buffer (1)
        debug_assert_eq!(body.len(), 49);

        pkt.extend_from_slice(&body);

        debug!("READ request: pkt={} bytes, body={} bytes, max_len={}, file_id={:02x?}",
            pkt.len(), body.len(), max_len, &self.file_id);
        debug!("READ body hex: {:02x?}", &body);

        self.send_raw(&pkt)?;

        let resp = self.recv_raw()?;
        let (status, _cmd, resp_body) = self.parse_response(&resp)?;

        if status != 0 {
            return Err(SamrDumpError::Smb(format!(
                "READ failed: 0x{:08x}",
                status
            )));
        }

        if resp_body.len() < 16 {
            return Err(SamrDumpError::Smb("READ response too short".into()));
        }

        let data_offset = resp_body[2] as usize;
        let data_len = u32::from_le_bytes([
            resp_body[4], resp_body[5], resp_body[6], resp_body[7],
        ]) as usize;

        let body_offset = data_offset.saturating_sub(SMB2_HEADER_SIZE);

        if body_offset + data_len <= resp_body.len() {
            Ok(resp_body[body_offset..body_offset + data_len].to_vec())
        } else if data_len > 0 && 16 + data_len <= resp_body.len() {
            Ok(resp_body[16..16 + data_len].to_vec())
        } else {
            Ok(resp_body[16.min(resp_body.len())..].to_vec())
        }
    }

    /// IOCTL FSCTL_PIPE_TRANSCEIVE — write data to pipe and read response in one roundtrip.
    /// This is the preferred method for DCE/RPC over named pipes.
    pub fn transact_pipe(&mut self, data: &[u8]) -> SamrResult<Vec<u8>> {
        const FSCTL_PIPE_TRANSCEIVE: u32 = 0x0011C017;

        let mut pkt = self.build_header(SMB2_IOCTL, 0);

        // MS-SMB2 §2.2.31 IOCTL Request
        // StructureSize(2) = 57
        // Reserved(2)
        // CtlCode(4)
        // FileId(16)
        // InputOffset(4)  — from start of SMB2 header
        // InputCount(4)
        // MaxInputResponse(4)
        // OutputOffset(4)
        // OutputCount(4)
        // MaxOutputResponse(4)
        // Flags(4)
        // Reserved2(4)
        // Buffer(variable)

        let input_offset = (SMB2_HEADER_SIZE + 56) as u32; // Fixed body = 56 bytes
        let max_output: u32 = 4280; // Reasonable pipe response size

        let mut body = Vec::new();
        body.extend_from_slice(&57u16.to_le_bytes());  // StructureSize
        body.extend_from_slice(&0u16.to_le_bytes());   // Reserved
        body.extend_from_slice(&FSCTL_PIPE_TRANSCEIVE.to_le_bytes()); // CtlCode
        body.extend_from_slice(&self.file_id);          // FileId (16)
        body.extend_from_slice(&input_offset.to_le_bytes()); // InputOffset
        body.extend_from_slice(&(data.len() as u32).to_le_bytes()); // InputCount
        body.extend_from_slice(&0u32.to_le_bytes());   // MaxInputResponse
        body.extend_from_slice(&0u32.to_le_bytes());   // OutputOffset (server fills)
        body.extend_from_slice(&0u32.to_le_bytes());   // OutputCount
        body.extend_from_slice(&max_output.to_le_bytes()); // MaxOutputResponse
        body.extend_from_slice(&1u32.to_le_bytes());   // Flags = SMB2_0_IOCTL_IS_FSCTL
        body.extend_from_slice(&0u32.to_le_bytes());   // Reserved2
        // body should be 56 bytes now
        while body.len() < 56 {
            body.push(0);
        }
        body.extend_from_slice(data);                   // Buffer (input data)

        pkt.extend_from_slice(&body);
        self.send_raw(&pkt)?;

        let resp = self.recv_raw()?;
        let (status, _cmd, resp_body) = self.parse_response(&resp)?;

        // STATUS_BUFFER_OVERFLOW (0x80000005) means partial data — still valid
        if status != 0 && status != 0x8000_0005 {
            return Err(SamrDumpError::Smb(format!(
                "IOCTL (TRANSCEIVE) failed: 0x{:08x}",
                status
            )));
        }

        // MS-SMB2 §2.2.32 IOCTL Response
        //   StructureSize(2)  [0..2]    = 49
        //   Reserved(2)       [2..4]
        //   CtlCode(4)        [4..8]
        //   FileId(16)        [8..24]
        //   InputOffset(4)    [24..28]
        //   InputCount(4)     [28..32]
        //   OutputOffset(4)   [32..36]
        //   OutputCount(4)    [36..40]
        //   Flags(4)          [40..44]
        //   Reserved2(4)      [44..48]
        //   Buffer            [48..]
        if resp_body.len() < 48 {
            return Err(SamrDumpError::Smb(format!(
                "IOCTL response too short: {} bytes", resp_body.len()
            )));
        }

        let output_offset = u32::from_le_bytes([
            resp_body[32], resp_body[33], resp_body[34], resp_body[35],
        ]) as usize;
        let output_count = u32::from_le_bytes([
            resp_body[36], resp_body[37], resp_body[38], resp_body[39],
        ]) as usize;

        debug!("IOCTL response: status=0x{:08x} output_offset={} output_count={} body_len={}",
            status, output_offset, output_count, resp_body.len());

        let body_output_offset = output_offset.saturating_sub(SMB2_HEADER_SIZE);

        if output_count > 0 && body_output_offset + output_count <= resp_body.len() {
            Ok(resp_body[body_output_offset..body_output_offset + output_count].to_vec())
        } else if resp_body.len() > 48 {
            // Fallback: assume data starts right after the 48-byte fixed header
            debug!("IOCTL: using fallback extraction from offset 48, {} bytes available",
                resp_body.len() - 48);
            Ok(resp_body[48..].to_vec())
        } else {
            Ok(vec![])
        }
    }

    /// DCE/RPC bind to a specific interface
    pub fn dcerpc_bind(
        &mut self,
        interface_uuid: &uuid::Uuid,
        version_major: u16,
        version_minor: u16,
    ) -> SamrResult<()> {
        let bind_pdu = dcerpc::build_bind(interface_uuid, version_major, version_minor);
        debug!("DCE/RPC BIND PDU ({} bytes): {:02x?}", bind_pdu.len(), &bind_pdu[..bind_pdu.len().min(64)]);

        // Try IOCTL FSCTL_PIPE_TRANSCEIVE first (most compatible)
        match self.transact_pipe(&bind_pdu) {
            Ok(resp) => {
                debug!("BIND_ACK via IOCTL ({} bytes)", resp.len());
                return dcerpc::parse_bind_ack(&resp);
            }
            Err(e) => {
                debug!("IOCTL TRANSCEIVE failed ({}), falling back to WRITE+READ", e);
            }
        }

        // Fallback: separate WRITE + READ
        self.write_pipe(&bind_pdu)?;
        let resp = self.read_pipe(4280)?;
        debug!("BIND_ACK via READ ({} bytes)", resp.len());
        dcerpc::parse_bind_ack(&resp)
    }

    /// Send a DCE/RPC request and receive the response
    pub fn dcerpc_call(&mut self, opnum: u16, stub_data: &[u8]) -> SamrResult<Vec<u8>> {
        let request_pdu = dcerpc::build_request(opnum, stub_data);
        debug!("DCE/RPC REQUEST opnum={} stub={} bytes, pdu={} bytes",
            opnum, stub_data.len(), request_pdu.len());

        // Try IOCTL first
        match self.transact_pipe(&request_pdu) {
            Ok(resp) => {
                debug!("DCE/RPC response via IOCTL: {} bytes, first 32: {:02x?}",
                    resp.len(), &resp[..resp.len().min(32)]);
                let stub = dcerpc::parse_response(&resp)?;
                return Ok(stub);
            }
            Err(e) => {
                debug!("IOCTL TRANSCEIVE failed ({}), falling back to WRITE+READ", e);
            }
        }

        // Fallback
        self.write_pipe(&request_pdu)?;
        let resp = self.read_pipe(4280)?;
        debug!("DCE/RPC response via READ: {} bytes", resp.len());
        let stub = dcerpc::parse_response(&resp)?;
        Ok(stub)
    }

    /// Close the pipe and disconnect
    pub fn disconnect(&mut self) {
        // Best-effort close
        let mut pkt = self.build_header(SMB2_CLOSE, 0);
        let mut body = Vec::new();
        body.extend_from_slice(&24u16.to_le_bytes()); // StructureSize
        body.extend_from_slice(&0u16.to_le_bytes()); // Flags
        body.extend_from_slice(&[0u8; 4]); // Reserved
        body.extend_from_slice(&self.file_id);
        pkt.extend_from_slice(&body);
        let _ = self.send_raw(&pkt);
        let _ = self.recv_raw();
    }
}

// --- SPNEGO helpers (minimal ASN.1 / GSS-API wrapping for NTLM) ---

/// Wrap NTLM negotiate in SPNEGO initiator token
fn build_spnego_init(ntlm_token: &[u8]) -> Vec<u8> {
    // OID for NTLMSSP: 1.3.6.1.4.1.311.2.2.10
    let ntlmssp_oid: &[u8] = &[0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];

    // MechType sequence
    let mech_types = asn1_sequence(&[ntlmssp_oid]);
    let mech_types_ctx0 = asn1_context_tag(0, &mech_types);

    // mechToken [2]
    let mech_token = asn1_context_tag(2, &asn1_octet_string(ntlm_token));

    // NegotiateToken SEQUENCE
    let neg_token = asn1_sequence(&[&mech_types_ctx0, &mech_token]);

    // Context [0] for NegTokenInit
    let neg_init = asn1_context_tag(0, &neg_token);

    // GSS-API wrapping: APPLICATION [0] { OID spnego, NegTokenInit }
    let spnego_oid: &[u8] = &[0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
    let inner = [spnego_oid, &neg_init].concat();

    asn1_application_tag(0, &inner)
}

/// Wrap NTLM authenticate in SPNEGO response token
fn build_spnego_auth(ntlm_token: &[u8]) -> Vec<u8> {
    // responseToken [2]
    let resp_token = asn1_context_tag(2, &asn1_octet_string(ntlm_token));

    // NegTokenResp SEQUENCE
    let neg_resp = asn1_sequence(&[&resp_token]);

    // Context [1] for NegTokenResp
    asn1_context_tag(1, &neg_resp)
}

/// Extract the NTLM token from SPNEGO challenge
fn extract_ntlm_from_spnego(data: &[u8]) -> Result<Vec<u8>, String> {
    // Look for NTLMSSP signature in the blob
    if let Some(pos) = find_subsequence(data, b"NTLMSSP\x00") {
        Ok(data[pos..].to_vec())
    } else {
        Err("NTLMSSP signature not found in SPNEGO token".to_string())
    }
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

// Minimal ASN.1 DER helpers
fn asn1_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
    }
}

fn asn1_sequence(items: &[&[u8]]) -> Vec<u8> {
    let content: Vec<u8> = items.iter().flat_map(|i| i.iter().copied()).collect();
    let mut out = vec![0x30];
    out.extend_from_slice(&asn1_len(content.len()));
    out.extend_from_slice(&content);
    out
}

fn asn1_context_tag(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![0xA0 | tag];
    out.extend_from_slice(&asn1_len(content.len()));
    out.extend_from_slice(content);
    out
}

fn asn1_application_tag(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![0x60 | tag];
    out.extend_from_slice(&asn1_len(content.len()));
    out.extend_from_slice(content);
    out
}

fn asn1_octet_string(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x04];
    out.extend_from_slice(&asn1_len(data.len()));
    out.extend_from_slice(data);
    out
}

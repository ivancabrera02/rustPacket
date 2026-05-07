/// SMB2 Protocol with message signing — MS-SMB2
use anyhow::{anyhow, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

type HmacSha256 = Hmac<Sha256>;

pub const SMB2_NEGOTIATE: u16     = 0x0000;
pub const SMB2_SESSION_SETUP: u16 = 0x0001;
pub const SMB2_TREE_CONNECT: u16  = 0x0003;
pub const SMB2_CREATE: u16        = 0x0005;
pub const SMB2_CLOSE: u16         = 0x0006;
pub const SMB2_IOCTL: u16         = 0x000B;

pub const STATUS_SUCCESS: u32                  = 0x00000000;
pub const STATUS_MORE_PROCESSING_REQUIRED: u32 = 0xC0000016;

pub const SMB2_MAGIC: &[u8] = b"\xFESMB";
pub const SMB2_DIALECT_202: u16 = 0x0202;
pub const SMB2_DIALECT_210: u16 = 0x0210;
const HDR_SIZE: usize = 64;

/// SMB2 header flag: message is signed
const SMB2_FLAGS_SIGNED: u32 = 0x00000008;

pub struct Smb2Session {
    pub stream: TcpStream,
    pub session_id: u64,
    pub tree_id: u32,
    pub message_id: u64,
    pub dialect: u16,
    pub server_security_mode: u16,
    pub require_signing: bool,
    /// Session key for SMB2 signing (set after successful auth)
    pub signing_key: Option<Vec<u8>>,
}

impl Smb2Session {
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream, session_id: 0, tree_id: 0, message_id: 0,
            dialect: SMB2_DIALECT_202, server_security_mode: 0,
            require_signing: false, signing_key: None,
        }
    }

    fn next_msg_id(&mut self) -> u64 { let i = self.message_id; self.message_id += 1; i }

    async fn send(&mut self, data: &[u8]) -> Result<()> {
        let len = (data.len() as u32).to_be_bytes();
        self.stream.write_all(&len).await?;
        self.stream.write_all(data).await?;
        self.stream.flush().await?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<Vec<u8>> {
        let mut lb = [0u8; 4];
        self.stream.read_exact(&mut lb).await?;
        let len = u32::from_be_bytes(lb) as usize;
        if len == 0 || len > 10_000_000 { return Err(anyhow!("bad length {}", len)); }
        let mut buf = vec![0u8; len];
        self.stream.read_exact(&mut buf).await?;
        Ok(buf)
    }

    /// Build SMB2 header. If signing is active and command is not NEGOTIATE/SESSION_SETUP,
    /// the caller must call sign_message() before sending.
    fn build_header(&mut self, command: u16, extra_flags: u32) -> Vec<u8> {
        let mid = self.next_msg_id();
        let cc: u16 = if command == SMB2_NEGOTIATE { 0 } else { 1 };

        // Set SIGNED flag if we have a key and this isn't a session-setup leg
        let mut flags = extra_flags;
        if self.signing_key.is_some() && command != SMB2_SESSION_SETUP {
            flags |= SMB2_FLAGS_SIGNED;
        }

        let mut h = Vec::with_capacity(HDR_SIZE);
        h.extend_from_slice(SMB2_MAGIC);
        h.extend_from_slice(&64u16.to_le_bytes());          // StructureSize
        h.extend_from_slice(&cc.to_le_bytes());              // CreditCharge
        h.extend_from_slice(&0u32.to_le_bytes());            // Status
        h.extend_from_slice(&command.to_le_bytes());         // Command
        h.extend_from_slice(&1u16.to_le_bytes());            // CreditRequest
        h.extend_from_slice(&flags.to_le_bytes());           // Flags
        h.extend_from_slice(&0u32.to_le_bytes());            // NextCommand
        h.extend_from_slice(&mid.to_le_bytes());             // MessageId
        h.extend_from_slice(&0u32.to_le_bytes());            // Reserved
        h.extend_from_slice(&self.tree_id.to_le_bytes());    // TreeId
        h.extend_from_slice(&self.session_id.to_le_bytes()); // SessionId
        h.extend_from_slice(&[0u8; 16]);                     // Signature (placeholder)
        debug_assert_eq!(h.len(), HDR_SIZE);
        h
    }

    /// Sign an SMB2 message in-place using HMAC-SHA256.
    /// Signature field is at bytes 48..64 of the message.
    fn sign_message(&self, msg: &mut [u8]) {
        if let Some(ref key) = self.signing_key {
            // Clear signature field first
            msg[48..64].fill(0);
            let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key");
            mac.update(msg);
            let sig = mac.finalize().into_bytes();
            // Only first 16 bytes of the HMAC-SHA256 are used
            msg[48..64].copy_from_slice(&sig[..16]);
        }
    }

    /// Build message, sign it, send it.
    async fn send_signed(&mut self, hdr: Vec<u8>, body: Vec<u8>) -> Result<()> {
        let mut msg = [hdr, body].concat();
        self.sign_message(&mut msg);
        self.send(&msg).await
    }

    fn parse_resp(data: &[u8]) -> Result<(u32, u64, u32, Vec<u8>)> {
        if data.len() < HDR_SIZE { return Err(anyhow!("resp too short")); }
        if &data[0..4] != SMB2_MAGIC { return Err(anyhow!("bad magic")); }
        Ok((
            u32::from_le_bytes(data[8..12].try_into()?),
            u64::from_le_bytes(data[40..48].try_into()?),
            u32::from_le_bytes(data[36..40].try_into()?),
            data[HDR_SIZE..].to_vec(),
        ))
    }

    // ── NEGOTIATE ──────────────────────────────────────────────────────────

    pub async fn negotiate(&mut self) -> Result<()> {
        let dialects = [SMB2_DIALECT_202, SMB2_DIALECT_210];
        let mut body = Vec::new();
        body.extend_from_slice(&36u16.to_le_bytes());
        body.extend_from_slice(&(dialects.len() as u16).to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes());  // SecurityMode: signing enabled
        body.extend_from_slice(&0u16.to_le_bytes());  // Reserved
        body.extend_from_slice(&0u32.to_le_bytes());  // Capabilities
        body.extend_from_slice(&[0u8; 16]);            // ClientGuid
        body.extend_from_slice(&0u64.to_le_bytes());  // ClientStartTime
        for d in &dialects { body.extend_from_slice(&d.to_le_bytes()); }

        let hdr = self.build_header(SMB2_NEGOTIATE, 0);
        self.send(&[hdr, body].concat()).await?;

        let resp = self.recv().await?;
        let (status, _, _, body) = Self::parse_resp(&resp)?;
        if status != STATUS_SUCCESS { return Err(anyhow!("negotiate: 0x{:08X}", status)); }

        if body.len() >= 6 {
            self.server_security_mode = u16::from_le_bytes(body[2..4].try_into()?);
            self.dialect = u16::from_le_bytes(body[4..6].try_into()?);
            self.require_signing = (self.server_security_mode & 0x0002) != 0;
            tracing::debug!("SecurityMode: 0x{:04X} (signing {})", self.server_security_mode,
                if self.require_signing { "REQUIRED" } else { "enabled" });
        }
        tracing::debug!("negotiate OK, dialect 0x{:04X}", self.dialect);
        Ok(())
    }

    // ── SESSION SETUP ──────────────────────────────────────────────────────

    fn session_setup_body(&self, spnego: &[u8], prev_sid: u64) -> Vec<u8> {
        let fixed = 24usize;
        let off = (HDR_SIZE + fixed) as u16;
        let mut b = Vec::with_capacity(fixed + spnego.len());
        b.extend_from_slice(&25u16.to_le_bytes());
        b.push(0); // Flags
        b.push(1); // SecurityMode
        b.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
        b.extend_from_slice(&0u32.to_le_bytes()); // Channel
        b.extend_from_slice(&off.to_le_bytes());
        b.extend_from_slice(&(spnego.len() as u16).to_le_bytes());
        b.extend_from_slice(&prev_sid.to_le_bytes());
        debug_assert_eq!(b.len(), fixed);
        b.extend_from_slice(spnego);
        b
    }

    pub async fn session_setup_1(&mut self, ntlm_neg: &[u8]) -> Result<Vec<u8>> {
        let sp = build_spnego_neg(ntlm_neg);
        let body = self.session_setup_body(&sp, 0);
        let hdr = self.build_header(SMB2_SESSION_SETUP, 0);
        self.send(&[hdr, body].concat()).await?;

        let resp = self.recv().await?;
        let (st, sid, _, body) = Self::parse_resp(&resp)?;
        if st != STATUS_MORE_PROCESSING_REQUIRED {
            return Err(anyhow!("setup1: 0x{:08X}", st));
        }
        self.session_id = sid;

        if body.len() < 8 { return Err(anyhow!("setup1 resp short")); }
        let so = u16::from_le_bytes(body[4..6].try_into()?) as usize;
        let sl = u16::from_le_bytes(body[6..8].try_into()?) as usize;
        let bo = so.saturating_sub(HDR_SIZE);
        if bo + sl > body.len() { return Err(anyhow!("sec buf OOB")); }
        extract_ntlm_from_spnego(&body[bo..bo+sl])
    }

    pub async fn session_setup_2(&mut self, ntlm_auth: &[u8]) -> Result<()> {
        let sp = build_spnego_auth(ntlm_auth);
        let body = self.session_setup_body(&sp, 0);
        let hdr = self.build_header(SMB2_SESSION_SETUP, 0);
        self.send(&[hdr, body].concat()).await?;

        let resp = self.recv().await?;
        let (st, sid, _, body) = Self::parse_resp(&resp)?;
        if st != STATUS_SUCCESS { return Err(anyhow!("setup2: 0x{:08X}", st)); }
        if sid != 0 { self.session_id = sid; }

        if body.len() >= 4 {
            let sf = u16::from_le_bytes(body[2..4].try_into().unwrap_or([0,0]));
            if sf & 0x0001 != 0 { eprintln!("[!] WARNING: session is GUEST"); }
            if sf & 0x0002 != 0 { eprintln!("[!] WARNING: session is NULL"); }
            tracing::debug!("SessionFlags: 0x{:04X}", sf);
        }
        tracing::debug!("session OK, id=0x{:016X}", self.session_id);
        Ok(())
    }

    /// Call this after session_setup_2 to enable signing on subsequent messages.
    pub fn enable_signing(&mut self, session_key: Vec<u8>) {
        tracing::debug!("SMB2 signing enabled (key len={})", session_key.len());
        self.signing_key = Some(session_key);
    }

    // ── TREE CONNECT ───────────────────────────────────────────────────────

    pub async fn tree_connect(&mut self, target: &str) -> Result<()> {
        let path = format!("\\\\{}\\IPC$", target);
        let pu: Vec<u8> = path.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let fixed = 8usize;
        let po = (HDR_SIZE + fixed) as u16;
        let mut body = Vec::new();
        body.extend_from_slice(&9u16.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&po.to_le_bytes());
        body.extend_from_slice(&(pu.len() as u16).to_le_bytes());
        body.extend_from_slice(&pu);

        let hdr = self.build_header(SMB2_TREE_CONNECT, 0);
        self.send_signed(hdr, body).await?;

        let resp = self.recv().await?;
        let (st, _, tid, _) = Self::parse_resp(&resp)?;
        if st != STATUS_SUCCESS { return Err(anyhow!("tree connect: 0x{:08X}", st)); }
        self.tree_id = tid;
        tracing::debug!("tree connected, tid=0x{:X}", tid);
        Ok(())
    }

    // ── CREATE (named pipe) ────────────────────────────────────────────────

    pub async fn create_pipe(&mut self, name: &str) -> Result<[u8; 16]> {
        let nu: Vec<u8> = name.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let fixed = 56usize;
        let no = (HDR_SIZE + fixed) as u16;
        let mut body = Vec::with_capacity(fixed + nu.len());
        body.extend_from_slice(&57u16.to_le_bytes());
        body.push(0); // SecurityFlags
        body.push(0); // OplockLevel
        body.extend_from_slice(&2u32.to_le_bytes());        // ImpersonationLevel
        body.extend_from_slice(&0u64.to_le_bytes());        // SmbCreateFlags
        body.extend_from_slice(&0u64.to_le_bytes());        // Reserved
        body.extend_from_slice(&0x0012019Fu32.to_le_bytes()); // DesiredAccess
        body.extend_from_slice(&0u32.to_le_bytes());        // FileAttributes
        body.extend_from_slice(&7u32.to_le_bytes());        // ShareAccess
        body.extend_from_slice(&1u32.to_le_bytes());        // CreateDisposition=FILE_OPEN
        body.extend_from_slice(&0x00000040u32.to_le_bytes()); // CreateOptions
        body.extend_from_slice(&no.to_le_bytes());
        body.extend_from_slice(&(nu.len() as u16).to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        debug_assert_eq!(body.len(), fixed);
        body.extend_from_slice(&nu);

        let hdr = self.build_header(SMB2_CREATE, 0);
        self.send_signed(hdr, body).await?;

        let resp = self.recv().await?;
        let (st, _, _, body) = Self::parse_resp(&resp)?;
        if st != STATUS_SUCCESS { return Err(anyhow!("create '{}': 0x{:08X}", name, st)); }
        if body.len() < 80 { return Err(anyhow!("create resp short")); }
        let mut fid = [0u8; 16];
        fid.copy_from_slice(&body[64..80]);
        tracing::debug!("pipe '{}' opened", name);
        Ok(fid)
    }

    // ── IOCTL ──────────────────────────────────────────────────────────────

    pub async fn ioctl_transceive(&mut self, fid: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
        const FSCTL: u32 = 0x0011C017;
        let fixed = 56usize;
        let io = (HDR_SIZE + fixed) as u32;
        let mut body = Vec::with_capacity(fixed + data.len());
        body.extend_from_slice(&57u16.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&FSCTL.to_le_bytes());
        body.extend_from_slice(fid);
        body.extend_from_slice(&io.to_le_bytes());
        body.extend_from_slice(&(data.len() as u32).to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0x00010000u32.to_le_bytes());
        body.extend_from_slice(&1u32.to_le_bytes()); // IS_FSCTL
        body.extend_from_slice(&0u32.to_le_bytes());
        debug_assert_eq!(body.len(), fixed);
        body.extend_from_slice(data);

        let hdr = self.build_header(SMB2_IOCTL, 0);
        self.send_signed(hdr, body).await?;

        let resp = self.recv().await?;
        let (st, _, _, body) = Self::parse_resp(&resp)?;
        if st != STATUS_SUCCESS { return Err(anyhow!("ioctl: 0x{:08X}", st)); }
        if body.len() < 48 { return Err(anyhow!("ioctl resp short")); }
        let oo = u32::from_le_bytes(body[32..36].try_into()?) as usize;
        let oc = u32::from_le_bytes(body[36..40].try_into()?) as usize;
        let bo = oo.saturating_sub(HDR_SIZE);
        if bo + oc > body.len() { return Err(anyhow!("ioctl output OOB")); }
        Ok(body[bo..bo+oc].to_vec())
    }

    // ── CLOSE ──────────────────────────────────────────────────────────────

    pub async fn close(&mut self, fid: &[u8; 16]) -> Result<()> {
        let mut body = Vec::new();
        body.extend_from_slice(&24u16.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(fid);
        let hdr = self.build_header(SMB2_CLOSE, 0);
        self.send_signed(hdr, body).await?;
        let _ = self.recv().await?;
        Ok(())
    }
}

// ── SPNEGO helpers ─────────────────────────────────────────────────────────

pub fn build_spnego_neg(ntlm: &[u8]) -> Vec<u8> {
    let soid: &[u8] = &[0x06,0x06,0x2b,0x06,0x01,0x05,0x05,0x02];
    let noid: &[u8] = &[0x06,0x0a,0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a];
    let mt = aw(0xa0, &aw(0x30, noid));
    let mk = aw(0xa2, &aw(0x04, ntlm));
    let ni = aw(0xa0, &aw(0x30, &[mt, mk].concat()));
    aw(0x60, &[soid, &ni].concat())
}

pub fn build_spnego_auth(ntlm: &[u8]) -> Vec<u8> {
    aw(0xa1, &aw(0x30, &aw(0xa2, &aw(0x04, ntlm))))
}

pub fn extract_ntlm_from_spnego(data: &[u8]) -> Result<Vec<u8>> {
    let sig = b"NTLMSSP\x00";
    data.windows(8).position(|w| w == sig)
        .map(|p| Ok(data[p..].to_vec()))
        .unwrap_or_else(|| Err(anyhow!("NTLMSSP not found in SPNEGO")))
}

fn al(l: usize) -> Vec<u8> {
    if l < 0x80 { vec![l as u8] }
    else if l <= 0xFF { vec![0x81, l as u8] }
    else { vec![0x82, (l>>8) as u8, (l&0xFF) as u8] }
}
fn aw(t: u8, d: &[u8]) -> Vec<u8> {
    let mut o = vec![t]; o.extend(al(d.len())); o.extend_from_slice(d); o
}

//! Error types for samrdump-rs

use thiserror::Error;

#[derive(Error, Debug)]
pub enum SamrDumpError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("SMB error: {0}")]
    Smb(String),

    #[error("DCE/RPC error: {0}")]
    DceRpc(String),

    #[error("SAMR error: status=0x{0:08x}")]
    Samr(u32),

    #[error("NTLM error: {0}")]
    Ntlm(String),

    #[error("Protocol error: {0}")]
    Protocol(String),
}

pub type SamrResult<T> = std::result::Result<T, SamrDumpError>;

/// Well-known NT status codes
#[allow(dead_code)]
pub mod ntstatus {
    pub const STATUS_SUCCESS: u32 = 0x0000_0000;
    pub const STATUS_MORE_ENTRIES: u32 = 0x0000_0105;
    pub const STATUS_NO_MORE_ENTRIES: u32 = 0x8000_001A;
    pub const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
    pub const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
    pub const STATUS_NO_SUCH_DOMAIN: u32 = 0xC000_0078;
}

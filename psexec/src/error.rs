use std::fmt;


#[derive(Debug)]
pub enum Error {
    Win32(u32),
    Msg(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Win32(code) => {
                write!(f, "Win32 error 0x{:08X} — {}", code, format_win32(*code))
            }
            Error::Msg(s) => f.write_str(s),
        }
    }
}

impl From<String> for Error {
    fn from(s: String) -> Self { Error::Msg(s) }
}
impl From<&str> for Error {
    fn from(s: &str) -> Self { Error::Msg(s.to_string()) }
}

/// Capture GetLastError() as Error::Win32.
pub fn last_err() -> Error {
    Error::Win32(unsafe { windows_sys::Win32::Foundation::GetLastError() })
}

/// Turn a Win32 error code into a human-readable string via FormatMessageW.
pub fn format_win32(code: u32) -> String {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::System::Diagnostics::Debug::{
        FormatMessageW,
        FORMAT_MESSAGE_ALLOCATE_BUFFER,
        FORMAT_MESSAGE_FROM_SYSTEM,
        FORMAT_MESSAGE_IGNORE_INSERTS,
    };

    unsafe {
        let mut buf: *mut u16 = std::ptr::null_mut();
        let len = FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER
                | FORMAT_MESSAGE_FROM_SYSTEM
                | FORMAT_MESSAGE_IGNORE_INSERTS,
            std::ptr::null(),
            code,
            0,
            &mut buf as *mut *mut u16 as *mut u16,
            0,
            std::ptr::null(),
        );
        if len == 0 || buf.is_null() {
            return "(unknown error)".to_string();
        }
        let slice = std::slice::from_raw_parts(buf, len as usize);
        let msg = String::from_utf16_lossy(slice)
            .trim_end_matches(|c: char| c.is_whitespace())
            .to_string();
        LocalFree(buf as *mut _);
        msg
    }
}

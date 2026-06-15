use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::SC_HANDLE;
use windows_sys::Win32::System::Services::CloseServiceHandle;


#[inline]
pub fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}


pub fn wide_arr<const N: usize>(s: &str) -> [u16; N] {
    let mut arr = [0u16; N];
    for (i, c) in OsStr::new(s).encode_wide().enumerate() {
        if i + 1 >= N { break; }
        arr[i] = c;
    }
    arr
}


/// Owns a Windows HANDLE calls CloseHandle on drop.
pub struct OwnedHandle(pub HANDLE);

impl OwnedHandle {
    pub fn get(&self) -> HANDLE { self.0 }

    pub fn is_valid(&self) -> bool {
        self.0 != 0 && self.0 != INVALID_HANDLE_VALUE
    }

    /// Move the raw handle out.
    pub fn into_raw(mut self) -> HANDLE {
        let h = self.0;
        self.0 = 0; // prevent Drop
        h
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if self.0 != 0 && self.0 != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(self.0); }
        }
    }
}


/// Owns an SC_HANDLE, then calls CloseServiceHandle on drop
pub struct OwnedSc(pub SC_HANDLE);

impl OwnedSc {
    pub fn get(&self) -> SC_HANDLE { self.0 }
}

impl Drop for OwnedSc {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe { CloseServiceHandle(self.0); }
        }
    }
}

/// Run a closure when the guard drops (defer-style cleanup)
pub struct Defer<F: FnOnce()>(Option<F>);

impl<F: FnOnce()> Drop for Defer<F> {
    fn drop(&mut self) {
        if let Some(f) = self.0.take() { f(); }
    }
}

pub fn defer<F: FnOnce()>(f: F) -> Defer<F> { Defer(Some(f)) }

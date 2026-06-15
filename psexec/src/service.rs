#![allow(non_snake_case, dead_code)]

use std::mem;
use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
use std::sync::OnceLock;
use std::thread;

use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::System::Pipes::*;
use windows_sys::Win32::System::Services::*;
use windows_sys::Win32::System::Threading::*;
use windows_sys::Win32::Storage::FileSystem::*;

use crate::util::{wide, OwnedHandle};

const PIPE_ACCESS_INBOUND:  u32 = 0x0000_0001;
const PIPE_ACCESS_OUTBOUND: u32 = 0x0000_0002;
const PIPE_ACCESS_DUPLEX:   u32 = 0x0000_0003;

// FILE_FLAG_FIRST_PIPE_INSTANCE (winbase.h 0x00080000) ensures only one server instance exists
const FIRST_PIPE_INSTANCE:  u32 = 0x0008_0000;

// PIPE_TYPE / PIPE_READMODE / PIPE_WAIT are all 0 for byte-stream blocking pipes
const PIPE_BYTE_BLOCKING:   u32 = 0x0000_0000;

/// Compute the per-run communication pipe name from the service name
/// Using a unique name per invocation avoids FIRST_PIPE_INSTANCE conflicts when a previous service instance hasn't fully cleaned up yet.
pub fn comm_pipe_name(svc_name: &str) -> String {
    format!("RemCom_{}", svc_name)
}

pub const STDIN_PREFIX:  &str = "RemCom_stdin";
pub const STDOUT_PREFIX: &str = "RemCom_stdout";
pub const STDERR_PREFIX: &str = "RemCom_stderr";

/// Sent controller to service over the communication pipe.
/// Must match RemCom.h exactly (RemComMessage class layout).
#[repr(C)]
pub struct RemComMessage {
    pub szCommand:    [u16; 0x1000],  
    pub szWorkingDir: [u16; 260],     
    pub dwPriority:   u32,            
    pub dwProcessId:  u32,            
    pub szMachine:    [u16; 260],     
    pub bNoWait:      i32,          
}

/// Sent service to controller once the process exits
#[repr(C)]
pub struct RemComResponse {
    pub dwErrorCode:  u32,
    pub dwReturnCode: u32,
}

impl RemComMessage {
    pub fn new(command: &str, workdir: &str, machine: &str, pid: u32) -> Self {
        let mut m: Self = unsafe { mem::zeroed() };
        copy_wide_to(command, &mut m.szCommand);
        copy_wide_to(workdir, &mut m.szWorkingDir);
        copy_wide_to(machine, &mut m.szMachine);
        m.dwPriority  = NORMAL_PRIORITY_CLASS;
        m.dwProcessId = pid;
        m.bNoWait     = 0;
        m
    }

    pub fn machine_str(&self) -> String { wide_field(&self.szMachine) }
    pub fn command_str(&self) -> String { wide_field(&self.szCommand) }
    pub fn workdir_str(&self) -> String { wide_field(&self.szWorkingDir) }
}

fn wide_field(arr: &[u16]) -> String {
    let end = arr.iter().position(|&c| c == 0).unwrap_or(arr.len());
    String::from_utf16_lossy(&arr[..end])
}

fn copy_wide_to(src: &str, dst: &mut [u16]) {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    for (i, c) in OsStr::new(src).encode_wide().enumerate() {
        if i + 1 >= dst.len() { break; }
        dst[i] = c;
    }
}


static G_STATUS_HANDLE: AtomicIsize  = AtomicIsize::new(0);
static G_STOP:          AtomicBool   = AtomicBool::new(false);
static G_SVC_NAME_W:    OnceLock<Vec<u16>> = OnceLock::new();
static G_COMM_PIPE:     OnceLock<String>   = OnceLock::new();


pub fn run(svc_name: String) {
    G_COMM_PIPE.set(comm_pipe_name(&svc_name)).ok();
    G_SVC_NAME_W.set(wide(&svc_name)).ok();

    let tbl = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: G_SVC_NAME_W.get().unwrap().as_ptr() as *mut _,
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: std::ptr::null_mut(),
            lpServiceProc: None,
        },
    ];
    unsafe { StartServiceCtrlDispatcherW(tbl.as_ptr()); }
}

// ── SCM callbacks ─────────────────────────────────────────────────────────────

unsafe extern "system" fn service_ctrl(ctrl: u32) {
    if ctrl == SERVICE_CONTROL_STOP || ctrl == SERVICE_CONTROL_SHUTDOWN {
        G_STOP.store(true, Ordering::SeqCst);
        set_status(SERVICE_STOP_PENDING, 5_000);
    }
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
    let name_ptr = G_SVC_NAME_W
        .get()
        .map(|v| v.as_ptr())
        .unwrap_or(std::ptr::null());

    let h = RegisterServiceCtrlHandlerW(name_ptr, Some(service_ctrl));
    G_STATUS_HANDLE.store(h, Ordering::SeqCst);

    set_status(SERVICE_RUNNING, 0);

    let _ = do_work(); // errors are intentionally swallowed in service context

    set_status(SERVICE_STOPPED, 0);
}

fn set_status(state: u32, wait_hint: u32) {
    let h = G_STATUS_HANDLE.load(Ordering::SeqCst);
    if h == 0 { return; }
    let accepted = if state == SERVICE_RUNNING {
        SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
    } else { 0 };
    let mut ss = SERVICE_STATUS {
        dwServiceType:             SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState:            state,
        dwControlsAccepted:        accepted,
        dwWin32ExitCode:           NO_ERROR,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint:              0,
        dwWaitHint:                wait_hint,
    };
    unsafe { SetServiceStatus(h, &mut ss); }
}


fn do_work() -> crate::error::Result<()> {
    let pipe_name = G_COMM_PIPE.get()
        .map(|s| s.as_str())
        .unwrap_or("RemCom_communicaton");

    let h_comm = make_named_pipe(
        &format!("\\\\.\\pipe\\{}", pipe_name),
        PIPE_ACCESS_DUPLEX | FIRST_PIPE_INSTANCE,
    )?;
    connect_pipe(h_comm.get())?;

    let msg = read_message(h_comm.get())?;
    let machine = msg.machine_str();
    let pid     = msg.dwProcessId;
    let command = msg.command_str();
    let workdir = msg.workdir_str();

    // 3. I/O named pipes (remote-accessible via \\controller\pipe\...)
    let h_stdin_named  = make_named_pipe(
        &format!("\\\\.\\pipe\\{}{}{}", STDIN_PREFIX,  machine, pid),
        PIPE_ACCESS_INBOUND | FIRST_PIPE_INSTANCE,
    )?;
    let h_stdout_named = make_named_pipe(
        &format!("\\\\.\\pipe\\{}{}{}", STDOUT_PREFIX, machine, pid),
        PIPE_ACCESS_OUTBOUND | FIRST_PIPE_INSTANCE,
    )?;
    let h_stderr_named = make_named_pipe(
        &format!("\\\\.\\pipe\\{}{}{}", STDERR_PREFIX, machine, pid),
        PIPE_ACCESS_OUTBOUND | FIRST_PIPE_INSTANCE,
    )?;

    //  anon_stdin:  child reads from READ end  | parent (service) writes to WRITE end
    //  anon_stdout: child writes to WRITE end  | parent reads from READ end
    //  anon_stderr: same as stdout
    let (h_stdin_r,  h_stdin_w)  = anon_pipe()?;
    let (h_stdout_r, h_stdout_w) = anon_pipe()?;
    let (h_stderr_r, h_stderr_w) = anon_pipe()?;

    // The parent-side handles must NOT be inherited by the child.
    non_inherit(h_stdin_w.get())?;
    non_inherit(h_stdout_r.get())?;
    non_inherit(h_stderr_r.get())?;

    let h_proc = spawn_child(
        &command,
        if workdir.is_empty() { None } else { Some(&workdir) },
        h_stdin_r.get(),
        h_stdout_w.get(),
        h_stderr_w.get(),
    )?;

    // Parent no longer needs the child-side handles
    drop(h_stdin_r);
    drop(h_stdout_w);
    drop(h_stderr_w);

    connect_pipe(h_stdin_named.get())?;
    connect_pipe(h_stdout_named.get())?;
    connect_pipe(h_stderr_named.get())?;

    // named stdin  to anon stdin_w   (controller types to child reads)
    // anon stdout_r →to named stdout  (child output to controller sees)
    // anon stderr_r to named stderr
    let raw_stdin_named  = h_stdin_named.into_raw();
    let raw_stdout_named = h_stdout_named.into_raw();
    let raw_stderr_named = h_stderr_named.into_raw();
    let raw_stdin_w  = h_stdin_w.into_raw();
    let raw_stdout_r = h_stdout_r.into_raw();
    let raw_stderr_r = h_stderr_r.into_raw();

    let ta = thread::spawn(move || {
        pipe_relay(raw_stdin_named, raw_stdin_w);
        unsafe { CloseHandle(raw_stdin_named); CloseHandle(raw_stdin_w); }
    });
    let tb = thread::spawn(move || {
        pipe_relay(raw_stdout_r, raw_stdout_named);
        unsafe { CloseHandle(raw_stdout_r); CloseHandle(raw_stdout_named); }
    });
    let tc = thread::spawn(move || {
        pipe_relay(raw_stderr_r, raw_stderr_named);
        unsafe { CloseHandle(raw_stderr_r); CloseHandle(raw_stderr_named); }
    });

    unsafe { WaitForSingleObject(h_proc.get(), INFINITE); }
    let mut exit_code = 0u32;
    unsafe { GetExitCodeProcess(h_proc.get(), &mut exit_code); }

    let _ = ta.join();
    let _ = tb.join();
    let _ = tc.join();

    let resp = RemComResponse { dwErrorCode: 0, dwReturnCode: exit_code };
    let resp_bytes = unsafe {
        std::slice::from_raw_parts(
            &resp as *const RemComResponse as *const u8,
            mem::size_of::<RemComResponse>(),
        )
    };
    let mut w = 0u32;
    unsafe {
        WriteFile(
            h_comm.get(),
            resp_bytes.as_ptr() as *const _,
            resp_bytes.len() as u32,
            &mut w,
            std::ptr::null_mut(),
        );
    }
    Ok(())
}


fn make_named_pipe(name: &str, access: u32) -> crate::error::Result<OwnedHandle> {
    let nw = wide(name);
    let h = unsafe {
        CreateNamedPipeW(
            nw.as_ptr(),
            access,
            PIPE_BYTE_BLOCKING,  // PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT
            1,       // max instances
            65_536,  // out-buf
            65_536,  // in-buf
            0,       // default timeout
            std::ptr::null(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        Err(crate::error::last_err())
    } else {
        Ok(OwnedHandle(h))
    }
}

fn connect_pipe(h: HANDLE) -> crate::error::Result<()> {
    let ok = unsafe { ConnectNamedPipe(h, std::ptr::null_mut()) };
    if ok != 0 {
        return Ok(());
    }
    let e = unsafe { GetLastError() };
    if e == ERROR_PIPE_CONNECTED { Ok(()) } else { Err(crate::error::Error::Win32(e)) }
}

fn anon_pipe() -> crate::error::Result<(OwnedHandle, OwnedHandle)> {
    let sa = SECURITY_ATTRIBUTES {
        nLength:              mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle:       TRUE,
    };
    let mut r = 0isize;
    let mut w = 0isize;
    let ok = unsafe { CreatePipe(&mut r, &mut w, &sa, 0) };
    if ok != 0 {
        Ok((OwnedHandle(r), OwnedHandle(w)))
    } else {
        Err(crate::error::last_err())
    }
}

fn non_inherit(h: HANDLE) -> crate::error::Result<()> {
    // HANDLE_FLAG_INHERIT = 1
    let ok = unsafe { SetHandleInformation(h, HANDLE_FLAG_INHERIT, 0) };
    if ok != 0 { Ok(()) } else { Err(crate::error::last_err()) }
}

fn spawn_child(
    command: &str,
    workdir: Option<&str>,
    h_stdin:  HANDLE,
    h_stdout: HANDLE,
    h_stderr: HANDLE,
) -> crate::error::Result<OwnedHandle> {
    let mut cmd_w = wide(command);
    let wdir_w: Option<Vec<u16>> = workdir.map(wide);

    let mut si: STARTUPINFOW = unsafe { mem::zeroed() };
    si.cb          = mem::size_of::<STARTUPINFOW>() as u32;
    si.dwFlags     = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = 0; // SW_HIDE
    si.hStdInput   = h_stdin;
    si.hStdOutput  = h_stdout;
    si.hStdError   = h_stderr;

    let mut pi: PROCESS_INFORMATION = unsafe { mem::zeroed() };

    let ok = unsafe {
        CreateProcessW(
            std::ptr::null(),
            cmd_w.as_mut_ptr(),
            std::ptr::null(),   // process security
            std::ptr::null(),   // thread security
            TRUE,               // bInheritHandles
            CREATE_NO_WINDOW,
            std::ptr::null(),   // inherit environment
            wdir_w.as_ref().map_or(std::ptr::null(), |v| v.as_ptr()),
            &si,
            &mut pi,
        )
    };

    if ok == 0 {
        return Err(crate::error::last_err());
    }

    // Close the thread handle immediately
    unsafe { CloseHandle(pi.hThread); }
    Ok(OwnedHandle(pi.hProcess))
}

fn pipe_relay(src: HANDLE, dst: HANDLE) {
    let mut buf = [0u8; 8192];
    loop {
        let mut n = 0u32;
        let ok = unsafe {
            ReadFile(src, buf.as_mut_ptr() as *mut _, buf.len() as u32, &mut n, std::ptr::null_mut())
        };
        if ok == 0 || n == 0 { break; }
        let mut w = 0u32;
        let ok = unsafe {
            WriteFile(dst, buf.as_ptr() as *const _, n, &mut w, std::ptr::null_mut())
        };
        if ok == 0 { break; }
    }
}

fn read_message(h: HANDLE) -> crate::error::Result<RemComMessage> {
    let mut msg: RemComMessage = unsafe { mem::zeroed() };
    let total = mem::size_of::<RemComMessage>() as u32;
    let mut done = 0u32;
    while done < total {
        let ptr = unsafe { (&mut msg as *mut RemComMessage as *mut u8).add(done as usize) };
        let mut n = 0u32;
        let ok = unsafe {
            ReadFile(h, ptr as *mut _, total - done, &mut n, std::ptr::null_mut())
        };
        if ok == 0 || n == 0 { return Err(crate::error::last_err()); }
        done += n;
    }
    Ok(msg)
}

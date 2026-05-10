// smbclient-rs — Interactive SMB2/3 client in pure Rust
// Similar to impacket's smbclient.py — no C deps, no libsmbclient.
//
// Usage:
//   smbclient-rs //192.168.1.10/share -u Administrator -p Password123
//   smbclient-rs //192.168.1.10/IPC$ -u user -p pass -c "shares"

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use colored::Colorize;
use futures_util::StreamExt;
use rustyline::DefaultEditor;
use smb::{
    Client, ClientConfig, Directory, FileAccessMask, FileCreateArgs, ReadAt, UncPath, WriteAt,
};
use smb_rpc::interface::ShareKind;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

// ─── CLI ─────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "smbclient-rs",
    about = "Interactive SMB2/3 client — like impacket's smbclient but in pure Rust",
    version = "0.1.0"
)]
struct Args {
    /// SMB target: //HOST/SHARE  or  \\HOST\SHARE
    target: String,

    /// Username
    #[arg(short, long, default_value = "")]
    username: String,

    /// Password
    #[arg(short, long, default_value = "")]
    password: String,

    /// Run a single command and exit (non-interactive)
    #[arg(short, long, value_name = "CMD")]
    command: Option<String>,

    /// Port (default: 445)
    #[arg(long, default_value_t = 445)]
    port: u16,
}

// ─── Session ─────────────────────────────────────────────────────────────────

struct Session {
    client:     Client,
    share_root: UncPath,
    host:       String,
    username:   String,
    password:   String,
    cwd:        String,
    local_dir:  PathBuf,
}

impl Session {
    fn resolve(&self, remote: &str) -> UncPath {
        let remote = remote.replace('\\', "/");
        let path = if remote.is_empty() {
            self.cwd.clone()
        } else if remote.starts_with('/') {
            remote.trim_start_matches('/').to_string()
        } else if self.cwd.is_empty() {
            remote
        } else {
            format!("{}/{}", self.cwd, remote)
        };
        if path.is_empty() {
            self.share_root.clone()
        } else {
            self.share_root.clone().with_path(&path)
        }
    }

    fn prompt(&self) -> String {
        let host  = self.share_root.server();
        let share = self.share_root.share().unwrap_or("");
        let cwd   = if self.cwd.is_empty() { String::new() }
                    else { format!("/{}", self.cwd) };
        format!("{}{}{}{}",
            "smb://".cyan(),
            host.bright_cyan().bold(),
            format!("/{}", share).cyan(),
            format!("{} > ", cwd).yellow())
    }
}

// ─── Banner / Help ────────────────────────────────────────────────────────────

fn print_banner() {
    println!("{}", r#"
  ╔═══════════════════════════════════════════════════════╗
  ║   ███████╗███╗   ███╗██████╗      ██████╗███████╗    ║
  ║   ██╔════╝████╗ ████║██╔══██╗    ██╔════╝██╔════╝    ║
  ║   ███████╗██╔████╔██║██████╔╝    ██║     ███████╗    ║
  ║   ╚════██║██║╚██╔╝██║██╔══██╗    ██║     ╚════██║    ║
  ║   ███████║██║ ╚═╝ ██║██████╔╝    ╚██████╗███████║    ║
  ║   ╚══════╝╚═╝     ╚═╝╚═════╝      ╚═════╝╚══════╝    ║
  ║         SMB2/3 interactive client in pure Rust         ║
  ╚═══════════════════════════════════════════════════════╝"#.cyan().bold());
    println!();
}

fn print_help() {
    println!("{}", "┌─ Commands ──────────────────────────────────────────────────────────┐".bright_black());
    let cmds: &[(&str, &str)] = &[
        ("shares",                "List all shares on the server  (NetrShareEnum)"),
        ("ls [path]",             "List files and directories"),
        ("cd <path>",             "Change remote directory  (.. to go up)"),
        ("pwd",                   "Print current remote path"),
        ("get <remote> [local]",  "Download a file"),
        ("put <local> [remote]",  "Upload a file"),
        ("mkdir <path>",          "Create a remote directory"),
        ("rm <file>",             "Delete a remote file"),
        ("rmdir <dir>",           "Delete a remote directory"),
        ("cat <file>",            "Print remote file to stdout"),
        ("lcd [path]",            "Change local working directory"),
        ("lpwd",                  "Print local working directory"),
        ("info",                  "Show connection info"),
        ("help / ?",              "Show this help"),
        ("exit / quit",           "Disconnect and exit"),
    ];
    for (cmd, desc) in cmds {
        println!("│  {:<30} {}", cmd.cyan(), desc);
    }
    println!("{}", "└─────────────────────────────────────────────────────────────────────┘".bright_black());
}

// ─── Share enumeration via built-in RPC ──────────────────────────────────────

async fn cmd_shares(sess: &Session) -> Result<()> {
    println!("  Connecting to IPC$ and calling NetrShareEnum ...");

    sess.client
        .ipc_connect(&sess.host, &sess.username, sess.password.clone())
        .await
        .with_context(|| format!("Cannot connect to IPC$ on {}", sess.host))?;

    let shares = sess.client
        .list_shares(&sess.host)
        .await
        .with_context(|| "NetrShareEnum failed")?;

    println!();
    println!(
        "  {:<30} {:<12} {}",
        "Share Name".bold().underline(),
        "Type".bold().underline(),
        "Comment".bold().underline()
    );
    println!("{}", "  ".to_string() + &"─".repeat(60).bright_black().to_string());

    let mut disk_cnt = 0;
    for s in &shares {
        let name = (*s.netname).as_ref().map_or(String::new(), |n| n.to_string());
        let comment = (*s.remark).as_ref().map_or(String::new(), |n| n.to_string());
        let is_hidden = name.ends_with('$');
        let kind = s.share_type.kind();

        let type_str: &str = match kind {
            ShareKind::Disk    => "Disk",
            ShareKind::PrintQ  => "Printer",
            ShareKind::Device  => "Device",
            ShareKind::IPC     => "IPC",
        };

        let name_styled = if is_hidden {
            name.bright_black().bold().to_string()
        } else {
            match type_str {
                "Disk"    => name.bright_green().bold().to_string(),
                "IPC"     => name.bright_yellow().to_string(),
                "Printer" => name.bright_magenta().to_string(),
                _         => name.normal().to_string(),
            }
        };
        let type_styled = match type_str {
            "Disk"    => { disk_cnt += 1; type_str.bright_green().to_string() }
            "IPC"     => type_str.bright_yellow().to_string(),
            "Printer" => type_str.bright_magenta().to_string(),
            other     => other.normal().to_string(),
        };
        println!("  {:<38} {:<20} {}", name_styled, type_styled, comment.bright_black());
    }

    println!("{}", "  ".to_string() + &"─".repeat(60).bright_black().to_string());
    println!(
        "  {} share(s) total  ({} disk, {} IPC/system)",
        shares.len().to_string().bold(),
        disk_cnt.to_string().bright_green(),
        (shares.len() - disk_cnt).to_string().bright_yellow()
    );
    println!();
    println!("  {} Connect with: {}", "→".cyan(),
        format!("smbclient-rs //{}/<SHARE> -u {} -p ***", sess.host, sess.username).yellow());

    Ok(())
}

// ─── Other commands ───────────────────────────────────────────────────────────

async fn cmd_ls(sess: &Session, path: &str) -> Result<()> {
    use smb::DirAccessMask;
    use smb::FileDirectoryInformation;

    let unc = sess.resolve(path);
    let resource = sess.client
        .create_file(
            &unc,
            &FileCreateArgs::make_open_existing(
                DirAccessMask::new()
                    .with_list_directory(true)
                    .with_synchronize(true)
                    .into(),
            ),
        )
        .await
        .with_context(|| format!("Cannot open directory '{}'", unc))?;

    let dir = Arc::new(resource.unwrap_dir());

    let entries: Vec<FileDirectoryInformation> = {
        let mut stream = Directory::query_with_options::<FileDirectoryInformation>(
            &dir, "*", 0x10000,
        )
        .await?;
        let mut v = Vec::new();
        while let Some(item) = stream.next().await {
            v.push(item?);
        }
        v
    };

    dir.close().await?;

    println!(
        "  {:<44} {:>12}  {}",
        "Name".bold().underline(),
        "Size".bold().underline(),
        "Attr".bold().underline()
    );
    println!("{}", "  ".to_string() + &"─".repeat(62).bright_black().to_string());

    let (mut dirs, mut files) = (0usize, 0usize);
    for e in &entries {
        let name = e.file_name.to_string();
        if name == "." || name == ".." { continue; }
        if e.file_attributes.directory() {
            println!("  {:<44} {:>12}  {}", name.bright_blue().bold(), "<DIR>".bright_blue(), "d".bright_blue());
            dirs += 1;
        } else {
            println!("  {:<44} {:>12}  {}", name, format_size(e.end_of_file), "-".bright_black());
            files += 1;
        }
    }
    println!("{}", "  ".to_string() + &"─".repeat(62).bright_black().to_string());
    println!("  {} dir(s), {} file(s)", dirs.to_string().bright_blue(), files.to_string().bright_green());
    Ok(())
}

fn cmd_cd(sess: &mut Session, path: &str) -> Result<()> {
    match path {
        "" | "." => {}
        ".." => {
            if let Some(pos) = sess.cwd.rfind('/') { sess.cwd.truncate(pos); }
            else { sess.cwd.clear(); }
        }
        p if p.starts_with('/') || p.starts_with('\\') => {
            sess.cwd = p.trim_matches(|c| c == '/' || c == '\\').replace('\\', "/");
        }
        p => {
            sess.cwd = if sess.cwd.is_empty() { p.replace('\\', "/") }
                       else { format!("{}/{}", sess.cwd, p.replace('\\', "/")) };
        }
    }
    let display = if sess.cwd.is_empty() {
        format!("\\\\{}\\{}", sess.share_root.server(), sess.share_root.share().unwrap_or(""))
    } else {
        format!("\\\\{}\\{}\\{}", sess.share_root.server(), sess.share_root.share().unwrap_or(""), sess.cwd.replace('/', "\\"))
    };
    println!("  cwd → {}", display.cyan());
    Ok(())
}

fn cmd_pwd(sess: &Session) {
    let display = if sess.cwd.is_empty() {
        format!("\\\\{}\\{}", sess.share_root.server(), sess.share_root.share().unwrap_or(""))
    } else {
        format!("\\\\{}\\{}\\{}", sess.share_root.server(), sess.share_root.share().unwrap_or(""), sess.cwd.replace('/', "\\"))
    };
    println!("  {}", display.cyan());
}

fn cmd_lcd(sess: &mut Session, path: &str) -> Result<()> {
    let canonical = sess.local_dir.join(path).canonicalize()
        .with_context(|| format!("Local path '{}' not accessible", path))?;
    sess.local_dir = canonical;
    println!("  local dir → {}", sess.local_dir.display().to_string().cyan());
    Ok(())
}

async fn cmd_get(sess: &Session, remote: &str, local_hint: &str) -> Result<()> {
    let unc = sess.resolve(remote);
    let basename = std::path::Path::new(remote)
        .file_name().map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| remote.to_string());
    let local_name = if local_hint.is_empty() { &basename } else { local_hint };
    let local_path = sess.local_dir.join(local_name);

    println!("  {} {} → {}", "↓".bright_green(), remote.cyan(), local_path.display().to_string().yellow());

    let open_args = FileCreateArgs::make_open_existing(FileAccessMask::new().with_generic_read(true));
    let resource = sess.client.create_file(&unc, &open_args).await
        .with_context(|| format!("Cannot open remote file '{}'", remote))?;
    let file = resource.unwrap_file();
    let mut out = std::fs::File::create(&local_path)
        .with_context(|| format!("Cannot create '{}'", local_path.display()))?;
    let mut offset = 0u64;
    loop {
        let mut buf = vec![0u8; 65536];
        let n = file.read_at(&mut buf, offset).await?;
        if n == 0 { break; }
        out.write_all(&buf[..n])?;
        offset += n as u64;
    }
    file.close().await?;
    println!("  {} '{}' saved ({} bytes)", "✓".green().bold(), local_name.green(), offset);
    Ok(())
}

async fn cmd_put(sess: &Session, local: &str, remote_hint: &str) -> Result<()> {
    use smb::{CreateOptions, FileAttributes};

    let local_path = sess.local_dir.join(local);
    let basename = std::path::Path::new(local)
        .file_name().map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| local.to_string());
    let remote_name = if remote_hint.is_empty() { &basename } else { remote_hint };
    let unc = sess.resolve(remote_name);

    println!("  {} {} → {}", "↑".bright_yellow(), local_path.display().to_string().yellow(), remote_name.cyan());

    let mut src = std::fs::File::open(&local_path)
        .with_context(|| format!("Cannot open '{}'", local_path.display()))?;
    let open_args = FileCreateArgs::make_create_new(
        FileAttributes::new(),
        CreateOptions::new(),
    );
    let resource = sess.client.create_file(&unc, &open_args).await
        .with_context(|| format!("Cannot create remote file '{}'", remote_name))?;
    let file = resource.unwrap_file();
    let mut offset = 0u64;
    let mut buf = vec![0u8; 65536];
    loop {
        let n = src.read(&mut buf)?;
        if n == 0 { break; }
        file.write_at(&buf[..n], offset).await?;
        offset += n as u64;
    }
    file.close().await?;
    println!("  {} '{}' uploaded ({} bytes)", "✓".green().bold(), remote_name.green(), offset);
    Ok(())
}

async fn cmd_mkdir(sess: &Session, path: &str) -> Result<()> {
    use smb::{CreateOptions, FileAttributes};

    let unc = sess.resolve(path);
    let open_args = FileCreateArgs::make_create_new(
        FileAttributes::new().with_directory(true),
        CreateOptions::new().with_directory_file(true),
    );
    let resource = sess.client.create_file(&unc, &open_args).await
        .with_context(|| format!("Cannot create directory '{}'", path))?;
    resource.unwrap_dir().close().await?;
    println!("  {} Directory '{}' created", "✓".green().bold(), path.green());
    Ok(())
}

async fn cmd_rm(sess: &Session, path: &str) -> Result<()> {
    use smb::FileDispositionInformation;

    let unc = sess.resolve(path);
    let open_args = FileCreateArgs::make_open_existing(FileAccessMask::new().with_delete(true));
    let resource = sess.client.create_file(&unc, &open_args).await
        .with_context(|| format!("Cannot open '{}' for deletion", path))?;
    let file = resource.unwrap_file();
    file.set_info(FileDispositionInformation::default()).await
        .with_context(|| format!("Cannot mark '{}' for deletion", path))?;
    file.close().await?;
    println!("  {} '{}' deleted", "✓".green().bold(), path.green());
    Ok(())
}

async fn cmd_rmdir(sess: &Session, path: &str) -> Result<()> {
    use smb::FileDispositionInformation;

    let unc = sess.resolve(path);
    let open_args = FileCreateArgs::make_open_existing(FileAccessMask::new().with_delete(true));
    let resource = sess.client.create_file(&unc, &open_args).await
        .with_context(|| format!("Cannot open directory '{}' for deletion", path))?;
    let dir = resource.unwrap_dir();
    dir.set_info(FileDispositionInformation::default()).await
        .with_context(|| format!("Cannot mark directory '{}' for deletion", path))?;
    dir.close().await?;
    println!("  {} Directory '{}' removed", "✓".green().bold(), path.green());
    Ok(())
}

async fn cmd_cat(sess: &Session, path: &str) -> Result<()> {
    let unc = sess.resolve(path);
    let open_args = FileCreateArgs::make_open_existing(FileAccessMask::new().with_generic_read(true));
    let resource = sess.client.create_file(&unc, &open_args).await
        .with_context(|| format!("Cannot open '{}'", path))?;
    let file = resource.unwrap_file();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mut offset = 0u64;
    loop {
        let mut buf = vec![0u8; 4096];
        let n = file.read_at(&mut buf, offset).await?;
        if n == 0 { break; }
        out.write_all(&buf[..n])?;
        offset += n as u64;
    }
    file.close().await?;
    println!();
    Ok(())
}

fn cmd_info(sess: &Session) {
    println!("{}", "┌─ Connection Info ──────────────────────────────────────┐".bright_black());
    println!("│  Host:    {}", sess.host.cyan());
    println!("│  Share:   {}", sess.share_root.share().unwrap_or("").cyan());
    println!("│  Remote:  \\{}", sess.cwd.replace('/', "\\").yellow());
    println!("│  Local:   {}", sess.local_dir.display().to_string().yellow());
    println!("│  User:    {}", if sess.username.is_empty() { "anonymous" } else { &sess.username }.yellow());
    println!("{}", "└────────────────────────────────────────────────────────┘".bright_black());
}

// ─── Dispatcher ───────────────────────────────────────────────────────────────

async fn dispatch(sess: &mut Session, line: &str) -> Result<bool> {
    let parts: Vec<&str> = line.trim().splitn(3, ' ').collect();
    let cmd = match parts.first() {
        Some(c) if !c.is_empty() => c.to_lowercase(),
        _ => return Ok(false),
    };
    let arg1 = parts.get(1).copied().unwrap_or("").trim();
    let arg2 = parts.get(2).copied().unwrap_or("").trim();

    match cmd.as_str() {
        "help" | "?"                => print_help(),
        "exit" | "quit" | "bye"    => return Ok(true),
        "shares"                    => cmd_shares(sess).await?,
        "ls" | "dir"                => cmd_ls(sess, arg1).await?,
        "cd"                        => cmd_cd(sess, arg1)?,
        "pwd"                       => cmd_pwd(sess),
        "lcd"                       => cmd_lcd(sess, if arg1.is_empty() { "." } else { arg1 })?,
        "lpwd"                      => println!("  {}", sess.local_dir.display().to_string().cyan()),
        "info"                      => cmd_info(sess),

        "get"   => if arg1.is_empty() { eprintln!("{}", "  Usage: get <remote> [local]".red()) }
                   else { cmd_get(sess, arg1, arg2).await? },
        "put"   => if arg1.is_empty() { eprintln!("{}", "  Usage: put <local> [remote]".red()) }
                   else { cmd_put(sess, arg1, arg2).await? },
        "mkdir" | "md"
                => if arg1.is_empty() { eprintln!("{}", "  Usage: mkdir <path>".red()) }
                   else { cmd_mkdir(sess, arg1).await? },
        "rm" | "del"
                => if arg1.is_empty() { eprintln!("{}", "  Usage: rm <file>".red()) }
                   else { cmd_rm(sess, arg1).await? },
        "rmdir" | "rd"
                => if arg1.is_empty() { eprintln!("{}", "  Usage: rmdir <dir>".red()) }
                   else { cmd_rmdir(sess, arg1).await? },
        "cat"   => if arg1.is_empty() { eprintln!("{}", "  Usage: cat <file>".red()) }
                   else { cmd_cat(sess, arg1).await? },

        other => eprintln!("  {} '{}' — type {} for commands",
            "Unknown command:".red(), other, "help".yellow()),
    }
    Ok(false)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn format_size(bytes: u64) -> String {
    const KB: u64 = 1_024;
    const MB: u64 = KB * 1_024;
    const GB: u64 = MB * 1_024;
    if bytes >= GB      { format!("{:.2} GB", bytes as f64 / GB as f64) }
    else if bytes >= MB { format!("{:.2} MB", bytes as f64 / MB as f64) }
    else if bytes >= KB { format!("{:.1} KB", bytes as f64 / KB as f64) }
    else                { format!("{} B",     bytes) }
}

fn normalise_unc(raw: &str) -> String {
    let cleaned = raw.replace('/', "\\").trim_start_matches('\\').to_string();
    format!("\\\\{}", cleaned)
}

// ─── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    print_banner();

    let unc_str = normalise_unc(&args.target);
    let share_path = UncPath::from_str(&unc_str)
        .map_err(|e| anyhow!("Invalid target '{}': {}", args.target, e))?;

    let host = share_path.server().to_string();
    let user_display = if args.username.is_empty() { "anonymous" } else { &args.username };
    println!("  Connecting to {}  (user: {}) ...",
        unc_str.cyan(), user_display.yellow());

    let client = Client::new(ClientConfig::default());
    client
        .share_connect(&share_path, &args.username, args.password.clone())
        .await
        .with_context(|| format!("Connection to '{}' failed", unc_str))?;

    println!("  {} Connected!\n", "✓".green().bold());

    let mut sess = Session {
        client,
        host,
        username:   args.username.clone(),
        password:   args.password.clone(),
        share_root: share_path,
        cwd:        String::new(),
        local_dir:  std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
    };

    // Non-interactive mode
    if let Some(cmd) = args.command {
        dispatch(&mut sess, &cmd).await?;
        return Ok(());
    }

    // Interactive REPL
    println!("  Type {} for available commands.\n", "help".yellow());
    let mut rl = DefaultEditor::new()?;

    loop {
        let prompt = sess.prompt();
        match rl.readline(&prompt) {
            Ok(line) => {
                let trimmed = line.trim().to_string();
                if trimmed.is_empty() { continue; }
                let _ = rl.add_history_entry(&trimmed);
                match dispatch(&mut sess, &trimmed).await {
                    Ok(true)  => break,
                    Ok(false) => {}
                    Err(e)    => eprintln!("  {} {:#}", "Error:".red().bold(), e),
                }
            }
            Err(rustyline::error::ReadlineError::Interrupted)
            | Err(rustyline::error::ReadlineError::Eof) => break,
            Err(e) => { eprintln!("  Readline error: {}", e); break; }
        }
    }

    println!("\n  {} Goodbye!\n", "✓".green());
    Ok(())
}

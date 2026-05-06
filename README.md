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

> Please note, this is a beta version of the tools. We are aware that not all tools or functionalities are available, too many tokens have been spent :)

## Features

### Kerberos & Authentication
- **Kerberoasting** — Extract service account credentials via SPN enumeration
- **AS-REP Roasting** — Exploit users without Kerberos pre-authentication
- **getTGT** — Request and export Kerberos Ticket Granting Tickets (TGT)

### Active Directory Enumeration
- **GetADComputers** — Enumerate and retrieve computer objects from Active Directory
- **GetADUsers** — List AD users and extract detailed attribute information
- **GetNPUsers** — Identify users without Kerberos pre-authentication requirements
- **GetUsersSPN** — Enumerate Service Principal Names (SPNs) for user accounts
- **LDAPCheckStatus** — Verify LDAP service availability and connectivity

### Local & Remote Access
- **lookupsid** — Perform reverse SID lookups to resolve usernames and group names
- **samrdump** — Extract local account information via SAM-R protocol
- **smbclient** — SMB client for file sharing enumeration and lateral movement

### Privilege Escalation & Exploitation
- **RBCD** — Exploit Resource-Based Constrained Delegation misconfigurations
- **mssqclient** — SQL Server client for database interaction and privilege escalation

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

| Tool | Description |
|---|---|
| rustPacket-GetADComputers | Enumerates and retrieves information about computers in Active Directory |
| rustPacket-GetADUsers | Lists Active Directory users and their attributes |
| rustPacket-GetNPUsers | Identifies AD users without Kerberos pre-authentication requirement |
| rustPacket-GetUsersSPN | Searches and enumerates Service Principal Names (SPNs) for AD users |
| rustPacket-lookupsid | Performs reverse SID lookups to obtain usernames and group names |
| rustPacket-samrdump | Extracts local account information using the SAM-R protocol |
| rustPacket-smbclient | SMB client for enumerating network shares and resources |
| rustPacket-getTGT | Obtains Kerberos Ticket Granting Tickets (TGT) |
| rustPacket-rbcd | Exploits Resource-Based Constrained Delegation (RBCD) configurations |
| rustPacket-mssqclient | Client for interacting with SQL Server databases |
| rustPacket-LDAPCheckStatus | Verifies the status and availability of LDAP services |

## Contributing

Contributions are welcome! If you'd like to add a new tool or improve an existing one:

1. Fork the repository
2. Create your feature branch
3. Write your code and tests
4. Commit your changes (`git commit -m 'Add new-tool'`)
5. Push to the branch (`git push origin feature/new-tool`)
6. Open a Pull Request

//! MS-SAMR client operations
//!
//! Implements the SAMR RPC calls needed to enumerate domains, users, groups
//! and aliases on a remote Windows host. Each method constructs the NDR-encoded
//! stub data, sends it via DCE/RPC REQUEST, and parses the NDR response.
//!
//! Reference: [MS-SAMR] — Security Account Manager (SAM) Remote Protocol

use crate::error::{ntstatus, SamrDumpError, SamrResult};
use crate::smb::SmbSession;
use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{Cursor, Read};
use tracing::debug;

// SAMR operation numbers (opcodes)
#[allow(dead_code)]
const SAMR_CONNECT: u16 = 0;        // SamrConnect
const SAMR_CLOSE_HANDLE: u16 = 1;   // SamrCloseHandle
const SAMR_ENUM_DOMAINS: u16 = 6;   // SamrEnumerateDomainsInSamServer
const SAMR_LOOKUP_DOMAIN: u16 = 5;  // SamrLookupDomainInSamServer
const SAMR_OPEN_DOMAIN: u16 = 7;    // SamrOpenDomain
const SAMR_ENUM_USERS: u16 = 13;    // SamrEnumerateUsersInDomain
const SAMR_ENUM_GROUPS: u16 = 11;   // SamrEnumerateGroupsInDomain
const SAMR_ENUM_ALIASES: u16 = 15;  // SamrEnumerateAliasesInDomain
const SAMR_OPEN_USER: u16 = 34;     // SamrOpenUser
const SAMR_QUERY_USER_INFO: u16 = 36; // SamrQueryInformationUser
#[allow(dead_code)]
const SAMR_QUERY_DISPLAY_INFO: u16 = 40; // SamrQueryDisplayInformation
const SAMR_CONNECT2: u16 = 57;      // SamrConnect2

/// A 20-byte SAMR context handle
pub type SamrHandle = [u8; 20];

/// User information retrieved from SamrQueryInformationUser
#[derive(Debug, Clone)]
pub struct UserInfo {
    pub full_name: String,
    pub description: String,
    pub last_logon: String,
    pub last_pwd_set: String,
    pub pwd_never_expires: bool,
    pub account_disabled: bool,
}

pub struct SamrClient<'a> {
    session: &'a mut SmbSession,
}

impl<'a> SamrClient<'a> {
    pub fn new(session: &'a mut SmbSession) -> Self {
        Self { session }
    }

    // ---------------------------------------------------------------
    // SamrConnect2 (opnum 57)
    //
    // This is the standard connect method used by impacket.
    // Wire format (MS-SAMR §3.1.5.1.1):
    //   [in, string, unique] PSAMPR_SERVER_NAME ServerName
    //   [in] unsigned long DesiredAccess
    //   [out] SAMPR_HANDLE *ServerHandle
    //   [out] NTSTATUS return
    // ---------------------------------------------------------------
    pub fn connect(&mut self, server_name: &str) -> SamrResult<SamrHandle> {
        let server_utf16: Vec<u16> = format!("\\\\{}", server_name)
            .encode_utf16()
            .chain(std::iter::once(0)) // null terminator
            .collect();

        let mut stub = Vec::new();

        // Pointer referent ID (non-null)
        stub.extend_from_slice(&0x0002_0000u32.to_le_bytes());

        // Conformant varying string:
        //   MaximumCount(4) + Offset(4) + ActualCount(4) + data
        let char_count = server_utf16.len() as u32;
        stub.extend_from_slice(&char_count.to_le_bytes()); // MaximumCount
        stub.extend_from_slice(&0u32.to_le_bytes());       // Offset
        stub.extend_from_slice(&char_count.to_le_bytes()); // ActualCount

        // String data in UTF-16LE
        for ch in &server_utf16 {
            stub.extend_from_slice(&ch.to_le_bytes());
        }

        // Pad to 4-byte alignment
        while stub.len() % 4 != 0 {
            stub.push(0);
        }

        // DesiredAccess: only what we need
        // SAM_SERVER_CONNECT(0x01) | SAM_SERVER_ENUMERATE_DOMAINS(0x10) |
        // SAM_SERVER_LOOKUP_DOMAIN(0x20)
        let access: u32 = 0x0000_0031;
        stub.extend_from_slice(&access.to_le_bytes());

        let resp = self.session.dcerpc_call(SAMR_CONNECT2, &stub)?;
        self.parse_handle_response(&resp)
    }

    // ---------------------------------------------------------------
    // SamrEnumerateDomainsInSamServer (opnum 6)
    // ---------------------------------------------------------------
    pub fn enumerate_domains(&mut self, server_handle: &SamrHandle) -> SamrResult<Vec<String>> {
        let mut all_names = Vec::new();
        let mut enum_context: u32 = 0;

        loop {
            let mut stub = Vec::new();
            stub.extend_from_slice(server_handle);
            stub.extend_from_slice(&enum_context.to_le_bytes());
            stub.extend_from_slice(&0xFFFFu32.to_le_bytes()); // PreferedMaximumLength

            let resp = self.session.dcerpc_call(SAMR_ENUM_DOMAINS, &stub)?;

            // The Windows NDR implementation serializes the response as:
            //
            //   EnumerationContext(4)
            //   Buffer referent(4)
            //   [deferred SAMPR_ENUMERATION_BUFFER immediately:]
            //     EntriesRead(4)
            //     Array referent(4)
            //     [deferred conformant array:]
            //       MaxCount(4)
            //       entries × { RID(4), Name{len(2),max(2),ptr(4)} }
            //       [deferred string data per entry]
            //   CountReturned(4)
            //   NTSTATUS(4)             ← return value at the very end

            let resp_len = resp.len();
            if resp_len < 8 {
                break;
            }

            let mut c = Cursor::new(resp.as_slice());

            enum_context = c.read_u32::<LittleEndian>()?;
            let buf_ptr = c.read_u32::<LittleEndian>()?;

            if buf_ptr != 0 && resp_len > 16 {
                // Deferred: SAMPR_ENUMERATION_BUFFER
                let entries_read = c.read_u32::<LittleEndian>()?;
                let array_ptr = c.read_u32::<LittleEndian>()?;

                debug!("EnumDomains: entries_read={} array_ptr=0x{:08x}", entries_read, array_ptr);

                if array_ptr != 0 && entries_read > 0 {
                    // Deferred: conformant array
                    let _max_count = c.read_u32::<LittleEndian>()?;

                    let mut entries = Vec::new();
                    for _ in 0..entries_read {
                        let rid = c.read_u32::<LittleEndian>()?;
                        let _name_len = c.read_u16::<LittleEndian>()?;
                        let _name_max = c.read_u16::<LittleEndian>()?;
                        let name_ptr = c.read_u32::<LittleEndian>()?;
                        entries.push((rid, name_ptr));
                    }

                    for (_rid, name_ptr) in &entries {
                        if *name_ptr == 0 {
                            all_names.push(String::new());
                            continue;
                        }
                        match read_ndr_unicode_string(&mut c) {
                            Ok(name) => {
                                debug!("  Domain: '{}'", name);
                                all_names.push(name);
                            }
                            Err(e) => {
                                debug!("  Failed to read domain name: {}", e);
                                break;
                            }
                        }
                    }
                }
            }

            // CountReturned + NTSTATUS are at the end of the stub
            let status = read_trailing_status(&resp);
            debug!("EnumDomains: found {} names, trailing status=0x{:08x}", all_names.len(), status);

            if status != ntstatus::STATUS_MORE_ENTRIES {
                break;
            }
        }

        Ok(all_names)
    }

    // ---------------------------------------------------------------
    // SamrLookupDomainInSamServer (opnum 5)
    // Returns the SID for a domain name
    // ---------------------------------------------------------------
    pub fn lookup_domain(
        &mut self,
        server_handle: &SamrHandle,
        domain_name: &str,
    ) -> SamrResult<Vec<u8>> {
        let name_utf16: Vec<u16> = domain_name
            .encode_utf16()
            .collect();

        let mut stub = Vec::new();
        stub.extend_from_slice(server_handle);

        // RPC_UNICODE_STRING (inline, not a pointer)
        let byte_len = (name_utf16.len() * 2) as u16;
        stub.extend_from_slice(&byte_len.to_le_bytes());       // Length
        stub.extend_from_slice(&byte_len.to_le_bytes());       // MaximumLength
        stub.extend_from_slice(&1u32.to_le_bytes());           // Pointer referent

        // Conformant/varying array
        let char_count = name_utf16.len() as u32;
        stub.extend_from_slice(&char_count.to_le_bytes());     // MaximumCount
        stub.extend_from_slice(&0u32.to_le_bytes());           // Offset
        stub.extend_from_slice(&char_count.to_le_bytes());     // ActualCount
        for ch in &name_utf16 {
            stub.extend_from_slice(&ch.to_le_bytes());
        }
        // Pad to 4-byte boundary
        while stub.len() % 4 != 0 {
            stub.push(0);
        }

        let resp = self.session.dcerpc_call(SAMR_LOOKUP_DOMAIN, &stub)?;

        // Response: Pointer(4) + SID data + NTSTATUS(4)
        let status = read_trailing_status(&resp);
        if status != ntstatus::STATUS_SUCCESS {
            return Err(SamrDumpError::Samr(status));
        }

        // Parse SID: pointer(4) + SubAuthorityCount(4 as part of SID) + ...
        if resp.len() < 12 {
            return Err(SamrDumpError::Protocol("LookupDomain response too short".into()));
        }

        let mut c = Cursor::new(resp.as_slice());
        let ptr = c.read_u32::<LittleEndian>()?;
        if ptr == 0 {
            return Err(SamrDumpError::Protocol("NULL SID pointer".into()));
        }

        // The SID is encoded as:
        //   SubAuthorityCount (4 bytes, conformant max)
        //   Revision (1)
        //   SubAuthorityCount (1)
        //   IdentifierAuthority (6)
        //   SubAuthority[] (4 * count)
        let sub_auth_count_max = c.read_u32::<LittleEndian>()? as usize;
        let revision = c.read_u8()?;
        let sub_auth_count = c.read_u8()? as usize;

        let mut sid = Vec::new();
        sid.push(revision);
        sid.push(sub_auth_count as u8);

        // IdentifierAuthority (6 bytes)
        let mut auth = [0u8; 6];
        c.read_exact(&mut auth)?;
        sid.extend_from_slice(&auth);

        // SubAuthorities
        for _ in 0..sub_auth_count {
            let sub = c.read_u32::<LittleEndian>()?;
            sid.extend_from_slice(&sub.to_le_bytes());
        }

        Ok(sid)
    }

    // ---------------------------------------------------------------
    // SamrOpenDomain (opnum 7)
    // ---------------------------------------------------------------
    pub fn open_domain(
        &mut self,
        server_handle: &SamrHandle,
        domain_sid: &[u8],
    ) -> SamrResult<SamrHandle> {
        let mut stub = Vec::new();
        stub.extend_from_slice(server_handle);

        // DesiredAccess: MAXIMUM_ALLOWED — let the server grant what it can
        let access: u32 = 0x0200_0000;
        stub.extend_from_slice(&access.to_le_bytes());

        // SID: SubAuthorityCount (conformant max) + raw SID
        let sub_auth_count = domain_sid[1] as u32;
        stub.extend_from_slice(&sub_auth_count.to_le_bytes());
        stub.extend_from_slice(domain_sid);

        // Pad to 4-byte alignment
        while stub.len() % 4 != 0 {
            stub.push(0);
        }

        let resp = self.session.dcerpc_call(SAMR_OPEN_DOMAIN, &stub)?;
        self.parse_handle_response(&resp)
    }

    // ---------------------------------------------------------------
    // SamrEnumerateUsersInDomain (opnum 13)
    // ---------------------------------------------------------------
    pub fn enumerate_users(
        &mut self,
        domain_handle: &SamrHandle,
    ) -> SamrResult<Vec<(u32, String)>> {
        self.enumerate_entries(domain_handle, SAMR_ENUM_USERS, 0)
    }

    // ---------------------------------------------------------------
    // SamrEnumerateGroupsInDomain (opnum 11)
    // ---------------------------------------------------------------
    pub fn enumerate_groups(
        &mut self,
        domain_handle: &SamrHandle,
    ) -> SamrResult<Vec<(u32, String)>> {
        self.enumerate_entries(domain_handle, SAMR_ENUM_GROUPS, 0)
    }

    // ---------------------------------------------------------------
    // SamrEnumerateAliasesInDomain (opnum 15)
    // ---------------------------------------------------------------
    pub fn enumerate_aliases(
        &mut self,
        domain_handle: &SamrHandle,
    ) -> SamrResult<Vec<(u32, String)>> {
        self.enumerate_entries(domain_handle, SAMR_ENUM_ALIASES, 0)
    }

    /// Generic enumerate for users/groups/aliases (same wire format)
    fn enumerate_entries(
        &mut self,
        handle: &SamrHandle,
        opnum: u16,
        user_account_control: u32,
    ) -> SamrResult<Vec<(u32, String)>> {
        let mut all_entries = Vec::new();
        let mut enum_context: u32 = 0;

        for iteration in 0..100 {
            let mut stub = Vec::new();
            stub.extend_from_slice(handle);
            stub.extend_from_slice(&enum_context.to_le_bytes());

            if opnum == SAMR_ENUM_USERS {
                stub.extend_from_slice(&user_account_control.to_le_bytes());
            }

            stub.extend_from_slice(&0xFFFFu32.to_le_bytes());

            let resp = self.session.dcerpc_call(opnum, &stub)?;

            let resp_len = resp.len();
            if resp_len < 8 {
                break;
            }

            let mut c = Cursor::new(resp.as_slice());
            let new_enum_context = c.read_u32::<LittleEndian>()?;
            let buf_ptr = c.read_u32::<LittleEndian>()?;

            let entries_before = all_entries.len();

            if buf_ptr != 0 && resp_len > 16 {
                let entries_read = c.read_u32::<LittleEndian>()?;
                let array_ptr = c.read_u32::<LittleEndian>()?;

                if array_ptr != 0 && entries_read > 0 {
                    let _max_count = c.read_u32::<LittleEndian>()?;

                    let mut entries_meta = Vec::new();
                    for _ in 0..entries_read {
                        let rid = c.read_u32::<LittleEndian>()?;
                        let _name_len = c.read_u16::<LittleEndian>()?;
                        let _name_max = c.read_u16::<LittleEndian>()?;
                        let name_ptr = c.read_u32::<LittleEndian>()?;
                        entries_meta.push((rid, name_ptr));
                    }

                    for (rid, name_ptr) in &entries_meta {
                        if *name_ptr == 0 {
                            all_entries.push((*rid, String::new()));
                            continue;
                        }
                        match read_ndr_unicode_string(&mut c) {
                            Ok(name) => all_entries.push((*rid, name)),
                            Err(e) => {
                                debug!("Failed to read name for RID {}: {}", rid, e);
                                break;
                            }
                        }
                    }
                }
            }

            let status = read_trailing_status(&resp);
            debug!("enumerate opnum={}: iter={} ctx={}→{} new={} status=0x{:08x}",
                opnum, iteration, enum_context, new_enum_context,
                all_entries.len() - entries_before, status);

            enum_context = new_enum_context;

            // Exit if not MORE_ENTRIES, or if no progress was made
            if status != ntstatus::STATUS_MORE_ENTRIES {
                break;
            }
            if all_entries.len() == entries_before {
                debug!("No new entries, breaking to avoid infinite loop");
                break;
            }
        }

        Ok(all_entries)
    }

    // ---------------------------------------------------------------
    // SamrOpenUser (opnum 34) + SamrQueryInformationUser (opnum 36)
    //
    // Opens a user by RID, queries info level 21 (UserAllInformation),
    // and closes the handle.
    // ---------------------------------------------------------------
    pub fn query_user_info(
        &mut self,
        domain_handle: &SamrHandle,
        rid: u32,
    ) -> SamrResult<UserInfo> {
        // --- Open User ---
        let mut stub = Vec::new();
        stub.extend_from_slice(domain_handle);
        // DesiredAccess: MAXIMUM_ALLOWED
        let access: u32 = 0x0200_0000;
        stub.extend_from_slice(&access.to_le_bytes());
        stub.extend_from_slice(&rid.to_le_bytes());

        let resp = self.session.dcerpc_call(SAMR_OPEN_USER, &stub)?;
        let user_handle = self.parse_handle_response(&resp)?;

        // --- Query Information (level 21 = UserAllInformation) ---
        let mut stub2 = Vec::new();
        stub2.extend_from_slice(&user_handle);
        stub2.extend_from_slice(&21u16.to_le_bytes()); // UserAllInformation
        // Pad
        stub2.extend_from_slice(&0u16.to_le_bytes());

        let info = match self.session.dcerpc_call(SAMR_QUERY_USER_INFO, &stub2) {
            Ok(resp2) => self.parse_user_all_info(&resp2),
            Err(e) => {
                // Try with a simpler info level (1 = UserGeneralInformation)
                debug!("Level 21 failed ({}), trying level 1", e);
                let mut stub3 = Vec::new();
                stub3.extend_from_slice(&user_handle);
                stub3.extend_from_slice(&1u16.to_le_bytes());
                stub3.extend_from_slice(&0u16.to_le_bytes());

                match self.session.dcerpc_call(SAMR_QUERY_USER_INFO, &stub3) {
                    Ok(resp3) => self.parse_user_general_info(&resp3),
                    Err(_) => Ok(UserInfo {
                        full_name: String::new(),
                        description: String::new(),
                        last_logon: "N/A".to_string(),
                        last_pwd_set: "N/A".to_string(),
                        pwd_never_expires: false,
                        account_disabled: false,
                    }),
                }
            }
        };

        // Close user handle
        let _ = self.close_handle(&user_handle);

        info
    }

    /// SamrCloseHandle (opnum 1)
    pub fn close_handle(&mut self, handle: &SamrHandle) -> SamrResult<()> {
        let mut stub = Vec::new();
        stub.extend_from_slice(handle);
        let _ = self.session.dcerpc_call(SAMR_CLOSE_HANDLE, &stub);
        Ok(())
    }

    // ---------------------------------------------------------------
    // Response parsers
    // ---------------------------------------------------------------

    /// Parse a response that returns a 20-byte handle + NTSTATUS
    fn parse_handle_response(&self, resp: &[u8]) -> SamrResult<SamrHandle> {
        if resp.len() < 24 {
            return Err(SamrDumpError::Protocol(format!(
                "Handle response too short: {} bytes",
                resp.len()
            )));
        }

        let mut handle = [0u8; 20];
        handle.copy_from_slice(&resp[0..20]);

        let status = u32::from_le_bytes([resp[20], resp[21], resp[22], resp[23]]);
        if status != ntstatus::STATUS_SUCCESS {
            return Err(SamrDumpError::Samr(status));
        }

        Ok(handle)
    }

    /// Parse UserAllInformation (level 21) response
    fn parse_user_all_info(&self, data: &[u8]) -> SamrResult<UserInfo> {
        // This is a complex NDR structure. We do a best-effort parse:
        // The response starts with a pointer + info level switch, then the
        // SAMPR_USER_ALL_INFORMATION structure.
        //
        // Layout (simplified):
        //   Pointer(4) + Level(2+2 pad)
        //   LastLogon(8) + LastLogoff(8) + PasswordLastSet(8) + AccountExpires(8)
        //   PasswordCanChange(8) + PasswordMustChange(8)
        //   UserName(RPC_UNICODE_STRING 8) + FullName(8) + HomeDirectory(8) +
        //   HomeDirectoryDrive(8) + ScriptPath(8) + ProfilePath(8) +
        //   AdminComment(8) + WorkStations(8) + UserComment(8) +
        //   Parameters(8) + LmOwfPassword(18+pad) + NtOwfPassword(18+pad) +
        //   PrivateData(8) + SecurityDescriptor(8+4) +
        //   UserId(4) + PrimaryGroupId(4) + UserAccountControl(4) +
        //   WhichFields(4) + LogonHours(12) + BadPasswordCount(2) +
        //   LogonCount(2) + CountryCode(2) + CodePage(2) +
        //   LmPasswordPresent(1) + NtPasswordPresent(1) +
        //   PasswordExpired(1) + PrivateDataSensitive(1)

        if data.len() < 48 {
            return Ok(UserInfo {
                full_name: String::new(),
                description: String::new(),
                last_logon: "N/A".to_string(),
                last_pwd_set: "N/A".to_string(),
                pwd_never_expires: false,
                account_disabled: false,
            });
        }

        let mut c = Cursor::new(data);

        // Skip pointer + level
        let _ptr = c.read_u32::<LittleEndian>()?;
        let _level = c.read_u16::<LittleEndian>()?;
        let _pad = c.read_u16::<LittleEndian>()?;

        // Timestamps (FILETIME = u64, 100ns intervals since 1601-01-01)
        let last_logon = c.read_u64::<LittleEndian>()?;
        let _last_logoff = c.read_u64::<LittleEndian>()?;
        let pwd_last_set = c.read_u64::<LittleEndian>()?;
        let _account_expires = c.read_u64::<LittleEndian>()?;
        let _pwd_can_change = c.read_u64::<LittleEndian>()?;
        let _pwd_must_change = c.read_u64::<LittleEndian>()?;

        // RPC_UNICODE_STRING fields: each is 8 bytes (len(2) + maxlen(2) + ptr(4))
        let _username_rpc = read_rpc_unicode_string_header(&mut c)?;
        let full_name_rpc = read_rpc_unicode_string_header(&mut c)?;
        let _home_dir = read_rpc_unicode_string_header(&mut c)?;
        let _home_drive = read_rpc_unicode_string_header(&mut c)?;
        let _script_path = read_rpc_unicode_string_header(&mut c)?;
        let _profile_path = read_rpc_unicode_string_header(&mut c)?;
        let admin_comment_rpc = read_rpc_unicode_string_header(&mut c)?;
        let _workstations = read_rpc_unicode_string_header(&mut c)?;
        let _user_comment = read_rpc_unicode_string_header(&mut c)?;
        let _parameters = read_rpc_unicode_string_header(&mut c)?;

        // Skip LM/NT password (18 bytes each + padding), PrivateData, SecurityDescriptor...
        // Jump ahead to UserAccountControl
        // This is fragile — the exact offset depends on many variable-length fields.
        // We'll try to find UserAccountControl by skipping known fixed parts.

        // For a simpler approach, try to read deferred string data for FullName and AdminComment
        // We need to find where the actual string data lives. With NDR, the deferred pointers
        // come after all the fixed fields. This is hard to do precisely, so we attempt
        // a heuristic: scan for the strings in the trailing data.

        let last_logon_str = filetime_to_string(last_logon);
        let pwd_last_set_str = filetime_to_string(pwd_last_set);

        // Try to extract full_name and description from deferred pointer data
        let full_name = extract_deferred_string(data, full_name_rpc)
            .unwrap_or_default();
        let description = extract_deferred_string(data, admin_comment_rpc)
            .unwrap_or_default();

        // Try to find UserAccountControl in the data
        // UAC flags: ACCOUNTDISABLE=0x0002, DONT_EXPIRE_PASSWORD=0x10000
        let (account_disabled, pwd_never_expires) = find_uac_flags(data);

        Ok(UserInfo {
            full_name,
            description,
            last_logon: last_logon_str,
            last_pwd_set: pwd_last_set_str,
            pwd_never_expires,
            account_disabled,
        })
    }

    /// Parse UserGeneralInformation (level 1) response — simpler fallback
    fn parse_user_general_info(&self, data: &[u8]) -> SamrResult<UserInfo> {
        // Level 1: UserName + FullName + PrimaryGroupId + AdminComment + UserComment
        if data.len() < 12 {
            return Ok(UserInfo {
                full_name: String::new(),
                description: String::new(),
                last_logon: "N/A".to_string(),
                last_pwd_set: "N/A".to_string(),
                pwd_never_expires: false,
                account_disabled: false,
            });
        }

        let mut c = Cursor::new(data);
        let _ptr = c.read_u32::<LittleEndian>()?;
        let _level = c.read_u16::<LittleEndian>()?;
        let _pad = c.read_u16::<LittleEndian>()?;

        let _username_rpc = read_rpc_unicode_string_header(&mut c)?;
        let _full_name_rpc = read_rpc_unicode_string_header(&mut c)?;
        let _primary_group = c.read_u32::<LittleEndian>().unwrap_or(0);
        let _admin_comment_rpc = read_rpc_unicode_string_header(&mut c)?;
        let _user_comment_rpc = read_rpc_unicode_string_header(&mut c)?;

        // Read deferred strings
        let _username = read_ndr_unicode_string(&mut c).unwrap_or_default();
        let full_name = read_ndr_unicode_string(&mut c).unwrap_or_default();

        // Try to read description from remaining data
        let description = read_ndr_unicode_string(&mut c).unwrap_or_default();

        Ok(UserInfo {
            full_name,
            description,
            last_logon: "N/A".to_string(),
            last_pwd_set: "N/A".to_string(),
            pwd_never_expires: false,
            account_disabled: false,
        })
    }
}

// ---------------------------------------------------------------
// NDR helper functions
// ---------------------------------------------------------------

/// RPC_UNICODE_STRING header: Length(2) + MaximumLength(2) + Pointer(4)
#[allow(dead_code)]
struct RpcUnicodeStringHeader {
    length: u16,
    maximum_length: u16,
    pointer: u32,
}

fn read_rpc_unicode_string_header(c: &mut Cursor<&[u8]>) -> SamrResult<RpcUnicodeStringHeader> {
    Ok(RpcUnicodeStringHeader {
        length: c.read_u16::<LittleEndian>()?,
        maximum_length: c.read_u16::<LittleEndian>()?,
        pointer: c.read_u32::<LittleEndian>()?,
    })
}

/// Read a deferred NDR conformant/varying unicode string
fn read_ndr_unicode_string(c: &mut Cursor<&[u8]>) -> SamrResult<String> {
    let _max_count = c.read_u32::<LittleEndian>()?;
    let _offset = c.read_u32::<LittleEndian>()?;
    let actual_count = c.read_u32::<LittleEndian>()?;

    let char_count = actual_count as usize;
    let mut chars = Vec::with_capacity(char_count);
    for _ in 0..char_count {
        let ch = c.read_u16::<LittleEndian>()?;
        chars.push(ch);
    }

    // Pad to 4-byte alignment
    let bytes_read = char_count * 2;
    let padding = (4 - (bytes_read % 4)) % 4;
    for _ in 0..padding {
        let _ = c.read_u8();
    }

    // Trim null terminator
    if chars.last() == Some(&0) {
        chars.pop();
    }

    Ok(String::from_utf16_lossy(&chars))
}

/// Try to extract a deferred string from the data blob using the header info
fn extract_deferred_string(_data: &[u8], header: RpcUnicodeStringHeader) -> Option<String> {
    if header.pointer == 0 || header.length == 0 {
        return Some(String::new());
    }
    // We can't precisely locate the deferred data without tracking pointer positions,
    // so we return None and let the caller handle it
    None
}

/// Convert Windows FILETIME to human-readable string
fn filetime_to_string(ft: u64) -> String {
    if ft == 0 || ft == 0x7FFFFFFFFFFFFFFF || ft == 0x8000000000000000 {
        return "Never".to_string();
    }

    // FILETIME: 100-nanosecond intervals since 1601-01-01
    // Unix epoch offset: 116444736000000000 (in 100-ns units)
    let unix_100ns = ft as i128 - 116_444_736_000_000_000i128;
    let unix_secs = unix_100ns / 10_000_000;

    if unix_secs < 0 || unix_secs > i64::MAX as i128 {
        return "Never".to_string();
    }

    match chrono::DateTime::from_timestamp(unix_secs as i64, 0) {
        Some(dt) => dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        None => "Never".to_string(),
    }
}

/// Attempt to find UAC flags in the response data
fn find_uac_flags(data: &[u8]) -> (bool, bool) {
    // UserAccountControl is a DWORD. Known flag values:
    // ACCOUNTDISABLE = 0x0002
    // DONT_EXPIRE_PASSWORD = 0x10000
    // NORMAL_ACCOUNT = 0x0200
    //
    // Heuristic: look for a DWORD that has NORMAL_ACCOUNT set (common for real users)
    for i in (0..data.len().saturating_sub(4)).step_by(4) {
        let val = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        if val & 0x0200 != 0 && val < 0x01000000 {
            // Likely a UAC value
            let disabled = val & 0x0002 != 0;
            let no_expire = val & 0x10000 != 0;
            return (disabled, no_expire);
        }
    }
    (false, false)
}

/// Read the NTSTATUS from the last 4 bytes of a response
fn read_trailing_status(data: &[u8]) -> u32 {
    if data.len() >= 4 {
        u32::from_le_bytes([
            data[data.len() - 4],
            data[data.len() - 3],
            data[data.len() - 2],
            data[data.len() - 1],
        ])
    } else {
        0xFFFFFFFF
    }
}

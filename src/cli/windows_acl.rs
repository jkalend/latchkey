//! Windows plaintext-file access enforcement at creation time (SEC-02).
//!
//! Plaintext exports hold every stored secret unencrypted. On Unix the CLI
//! opens them with mode 0o600; Windows has no umask equivalent — a file
//! created with plain `OpenOptions::create_new` inherits the destination
//! directory's DACL, which can grant read access to other users (shared
//! project/team folders). The fix creates the file with a protected DACL
//! built before the handle exists: user full control + SYSTEM/Administrators
//! full control, with inheritance from the parent directory disabled so
//! broad reader ACEs cannot reach the file.
//!
//! Encrypted vault writes keep the default inherited ACL: their content is
//! AEAD-protected and the parent profile directory is the documented
//! storage policy (ADR-0002). This module is only for the plaintext path.
#![allow(clippy::wildcard_imports)]

use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows::core::Result as WResult;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{
    self, AddAccessAllowedAce, AllocateAndInitializeSid, GetTokenInformation, InitializeAcl,
    InitializeSecurityDescriptor, SetSecurityDescriptorDacl, SetSecurityDescriptorGroup,
    SetSecurityDescriptorOwner, TokenUser, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR,
    SECURITY_NT_AUTHORITY, SECURITY_WORLD_SID_AUTHORITY, TOKEN_ACCESS_MASK, TOKEN_QUERY,
    TOKEN_USER,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_CREATION_DISPOSITION, FILE_FLAGS_AND_ATTRIBUTES,
    FILE_SHARE_MODE, FILE_SHARE_READ,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

// Well-known SID subauthorities (Windows/Win32/System/SystemServices).
const SECURITY_LOCAL_SYSTEM_RID: u32 = 18;
const SECURITY_BUILTIN_DOMAIN_RID: u32 = 32;
const DOMAIN_ALIAS_RID_ADMINS: u32 = 544;
const SECURITY_WORLD_RID: u32 = 0;

// Everyone SID has no read grant in this DACL by construction; the owner and
// system/administrator principals get file rights equivalent to a private file.
const FILE_RIGHTS_FULL: u32 = 0x000F_01FF; // FILE_ALL_ACCESS minus SYNCHRONIZE quirk parity

#[derive(Debug)]
pub struct GuardedFile {
    handle: HANDLE,
}

impl GuardedFile {
    pub fn into_std_file(self) -> io::Result<std::fs::File> {
        let handle = self.handle;
        std::mem::forget(self);
        // -1 is the invalid pseudo-handle; anything else converts directly.
        if handle.0 as isize == -1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid file handle",
            ));
        }
        // SAFETY: handle is a freshly created, exclusively owned file handle
        // from CreateFileW; taking ownership in a std::fs::File is correct.
        unsafe {
            Ok(std::os::windows::io::FromRawHandle::from_raw_handle(
                handle.0,
            ))
        }
    }
}

impl Drop for GuardedFile {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

#[repr(C)]
struct SidTriple {
    user: [u8; 68],
    system: [u8; 16],
    admins: [u8; 32],
    user_len: usize,
    system_len: usize,
    admins_len: usize,
}

/// Read the process user SID into a fixed buffer (TOKEN_USER is one SID).
/// Returns the actual SID length in bytes.
fn current_user_sid(buf: &mut [u8; 68]) -> WResult<u32> {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ACCESS_MASK(TOKEN_QUERY.0),
            &mut token,
        )?;
        let mut len = 0u32;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut len);
        let mut data = vec![0u8; len as usize];
        let user = data.as_mut_ptr() as *mut TOKEN_USER;
        GetTokenInformation(token, TokenUser, Some(user.cast()), len, &mut len)?;
        let sid = (*user).User.Sid;
        let size = Security::GetLengthSid(sid);
        assert!(size <= 68, "unexpectedly large user SID");
        std::ptr::copy_nonoverlapping(sid.0 as *const u8, buf.as_mut_ptr(), size as usize);
        let _ = CloseHandle(token);
        Ok(size)
    }
}

// The ACL byte buffer must outlive the SECURITY_DESCRIPTOR until
// CreateFileW consumes it; a thread-local keeps it alive across the two
// functions without unsafe lifetime gymnastics.
thread_local! {
    static ACL_STORAGE: std::cell::RefCell<Option<Vec<u8>>> = const { std::cell::RefCell::new(None) };
}

/// Build the protected self-relative SECURITY_DESCRIPTOR bytes.
fn protected_descriptor(
    user: &[u8],
    user_len: usize,
    system: &[u8],
    system_len: usize,
    admins: &[u8],
    admins_len: usize,
) -> WResult<SECURITY_DESCRIPTOR> {
    unsafe {
        let mut sd = SECURITY_DESCRIPTOR::default();
        let sd_ptr = Security::PSECURITY_DESCRIPTOR(
            &mut sd as *mut SECURITY_DESCRIPTOR as *mut core::ffi::c_void,
        );
        InitializeSecurityDescriptor(sd_ptr, 1u32)?; // SECURITY_DESCRIPTOR_REVISION
                                                     // ACL: user full + SYSTEM full + Administrators full. Everyone gets
                                                     // nothing; parent inheritance is disabled, so broad reader ACEs from
                                                     // the destination directory cannot appear.
        let ace_len = |sid_len: usize| std::mem::size_of::<Security::ACE_HEADER>() + 4 + sid_len;
        let acl_len = core::mem::size_of::<Security::ACL>()
            + ace_len(user_len)
            + ace_len(system_len)
            + ace_len(admins_len);
        // Zero-initialized + aligned: NTFS requires the ACL pointer to be
        // 4-byte aligned (Vec<u8> is not guaranteed aligned). Keep the buffer
        // alive until the descriptor has been consumed by CreateFileW.
        let mut acl_bytes = vec![0u8; acl_len + 4];
        let aligned = acl_bytes
            .as_mut_ptr()
            .byte_offset(acl_bytes.as_ptr().align_offset(4) as isize);
        let acl = aligned as *mut Security::ACL;
        InitializeAcl(acl, acl_len as u32, Security::ACL_REVISION)?;

        let user_ptr = Security::PSID(user.as_ptr() as *mut core::ffi::c_void);
        AddAccessAllowedAce(acl, Security::ACL_REVISION, FILE_RIGHTS_FULL, user_ptr)?;
        let system_ptr = Security::PSID(system.as_ptr() as *mut core::ffi::c_void);
        AddAccessAllowedAce(acl, Security::ACL_REVISION, FILE_RIGHTS_FULL, system_ptr)?;
        let admins_ptr = Security::PSID(admins.as_ptr() as *mut core::ffi::c_void);
        AddAccessAllowedAce(acl, Security::ACL_REVISION, FILE_RIGHTS_FULL, admins_ptr)?;

        SetSecurityDescriptorOwner(sd_ptr, Some(user_ptr), false)?;
        SetSecurityDescriptorGroup(sd_ptr, Some(user_ptr), false)?;
        SetSecurityDescriptorDacl(sd_ptr, true, Some(acl), false)?;
        // Move the buffer into the descriptor struct's shadow so it outlives
        // this function until the file is created.
        ACL_STORAGE.with(|cell| *cell.borrow_mut() = Some(acl_bytes));
        Ok(sd)
    }
}

fn to_wide(path: &Path) -> Vec<u16> {
    let mut wide: Vec<_> = path.as_os_str().encode_wide().collect();
    wide.push(0);
    wide
}

/// Create a new plaintext file at `path` with a protected DACL. Fails if the
/// path exists (create_new semantics preserved for the export path).
pub fn create_new_protected(path: &Path) -> io::Result<GuardedFile> {
    let mut sids = SidTriple {
        user: [0u8; 68],
        system: [0u8; 16],
        admins: [0u8; 32],
        user_len: 0,
        system_len: 0,
        admins_len: 0,
    };
    sids.user_len = current_user_sid(&mut sids.user).map_err(win_to_io)? as usize;
    unsafe {
        let mut system_sid = Security::PSID::default();
        AllocateAndInitializeSid(
            &SECURITY_NT_AUTHORITY,
            1,
            SECURITY_LOCAL_SYSTEM_RID,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            &mut system_sid,
        )
        .map_err(win_to_io)?;
        let mut admins_sid = Security::PSID::default();
        AllocateAndInitializeSid(
            &SECURITY_NT_AUTHORITY,
            2,
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0,
            0,
            0,
            0,
            0,
            0,
            &mut admins_sid,
        )
        .map_err(win_to_io)?;
        // SIDs stay alive in raw form; we pass raw byte copies.
        sids.system_len = sid_to_bytes(system_sid, &mut sids.system);
        sids.admins_len = sid_to_bytes(admins_sid, &mut sids.admins);
        let _ = Security::FreeSid(system_sid);
        let _ = Security::FreeSid(admins_sid);
    }

    let mut sd = protected_descriptor(
        &sids.user,
        sids.user_len,
        &sids.system,
        sids.system_len,
        &sids.admins,
        sids.admins_len,
    )
    .map_err(win_to_io)?;
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: &mut sd as *mut SECURITY_DESCRIPTOR as *mut core::ffi::c_void,
        bInheritHandle: windows::core::BOOL::default(),
    };
    let wide = to_wide(path);
    let handle = unsafe {
        CreateFileW(
            windows::core::PCWSTR::from_raw(wide.as_ptr()),
            (windows::Win32::Storage::FileSystem::FILE_GENERIC_WRITE
                | windows::Win32::Storage::FileSystem::DELETE)
                .0,
            FILE_SHARE_MODE(FILE_SHARE_READ.0),
            Some(&sa),
            FILE_CREATION_DISPOSITION(1), // CREATE_NEW
            FILE_FLAGS_AND_ATTRIBUTES(FILE_ATTRIBUTE_NORMAL.0),
            None,
        )
    }
    .map_err(win_to_io)?;
    Ok(GuardedFile { handle })
}

fn sid_to_bytes(sid: Security::PSID, buf: &mut [u8]) -> usize {
    unsafe {
        let len = Security::GetLengthSid(sid) as usize;
        std::ptr::copy_nonoverlapping(sid.0 as *const u8, buf.as_mut_ptr(), len);
        len
    }
}

fn win_to_io(e: windows::core::Error) -> io::Error {
    io::Error::other(e.to_string())
}

/// Best-effort verification that the effective rights of the Everyone
/// well-known SID on the created file contain no read bits.
#[cfg(windows)]
pub fn everyone_read_granted(path: &Path) -> io::Result<bool> {
    use windows::Win32::Security::Authorization::{
        GetEffectiveRightsFromAclW, GetNamedSecurityInfoW, SE_FILE_OBJECT, TRUSTEE_IS_SID,
        TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W,
    };
    use windows::Win32::Security::{GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION};
    unsafe {
        let mut sd = Security::PSECURITY_DESCRIPTOR::default();
        let err = GetNamedSecurityInfoW(
            windows::core::PCWSTR::from_raw(to_wide(path).as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            &mut sd,
        );
        if err.is_err() {
            return Err(io::Error::other(format!("GetNamedSecurityInfoW: {err:?}")));
        }
        let mut dacl_present = windows::core::BOOL::default();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut defaulted = windows::core::BOOL::default();
        GetSecurityDescriptorDacl(sd, &mut dacl_present, &mut dacl, &mut defaulted)?;
        let mut world = Security::PSID::default();
        AllocateAndInitializeSid(
            &SECURITY_WORLD_SID_AUTHORITY,
            1,
            SECURITY_WORLD_RID,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            &mut world,
        )?;
        let trustee = TRUSTEE_W {
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
            ptstrName: windows::core::PWSTR(world.0 as *mut u16),
            ..TRUSTEE_W::default()
        };
        let mut rights: u32 = 0;
        let err = GetEffectiveRightsFromAclW(dacl, &trustee, &mut rights);
        let _ = Security::FreeSid(world);
        if err.is_err() {
            return Err(io::Error::other(format!(
                "GetEffectiveRightsFromAclW: {err:?}"
            )));
        }
        const READ_BITS: u32 = 0x0000_001F; // FILE_READ_DATA..FILE_READ_ATTRIBUTES|READ_CONTROL|SYNCHRONIZE subset
        Ok(rights & READ_BITS != 0)
    }
}

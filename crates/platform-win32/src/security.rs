/*
 * Copyright 2026 Julien Bombled
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::ffi::c_void;
use std::path::Path;
use thiserror::Error;
use windows_sys::Win32::Foundation::{
    GetLastError, LocalFree, ERROR_INSUFFICIENT_BUFFER, ERROR_NOT_ALL_ASSIGNED,
    ERROR_SUCCESS, HANDLE, LUID,
};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, LookupAccountSidW, LookupPrivilegeValueW,
    DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    SE_PRIVILEGE_ENABLED, SID_NAME_USE, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_PRIVILEGES, TOKEN_QUERY, UNPROTECTED_DACL_SECURITY_INFORMATION,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSidToSidW, SetNamedSecurityInfoW,
    TreeResetNamedSecurityInfoW, SE_FILE_OBJECT,
};
use windows_sys::Win32::Storage::FileSystem::{
    GetFileAttributesW, FILE_ATTRIBUTE_REPARSE_POINT, INVALID_FILE_ATTRIBUTES,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::handles::OwnedHandle;
use crate::registry::to_wide_null;

pub type PSID = *mut c_void;

#[derive(Error, Debug)]
pub enum SecurityError {
    #[error("Security operation failed with Win32 error code: {0}")]
    Win32Error(u32),
    #[error("Privilege '{0}' could not be adjusted or assigned")]
    PrivilegeNotAssigned(String),
    #[error("Failed to resolve SID: {0}")]
    SidResolutionError(String),
    #[error("Path is a reparse point or junction: {0}")]
    ReparsePointEncountered(String),
    #[error("Invalid path")]
    InvalidPath,
}

pub type SecResult<T> = Result<T, SecurityError>;

/// Standard Windows Privilege Names
pub const SE_TAKE_OWNERSHIP_NAME: &str = "SeTakeOwnershipPrivilege";
pub const SE_RESTORE_NAME: &str = "SeRestorePrivilege";
pub const SE_BACKUP_NAME: &str = "SeBackupPrivilege";
pub const SE_DEBUG_NAME: &str = "SeDebugPrivilege";
pub const SE_IMPERSONATE_NAME: &str = "SeImpersonatePrivilege";
pub const SE_TCB_NAME: &str = "SeTcbPrivilege";

/// RAII Privilege Guard that enables a set of privileges on the current process token
/// and automatically restores the original token privileges state on drop.
pub struct PrivilegeGuard {
    token: OwnedHandle,
    previous_state: TOKEN_PRIVILEGES,
    has_previous: bool,
}

impl PrivilegeGuard {
    /// Acquires and enables the requested privilege names for the current process.
    pub fn new(privilege_names: &[&str]) -> SecResult<Self> {
        let mut raw_token: HANDLE = std::ptr::null_mut();
        let success = unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &mut raw_token,
            )
        };

        if success == 0 {
            return Err(SecurityError::Win32Error(unsafe { GetLastError() }));
        }

        let token = OwnedHandle::from_raw(raw_token)
            .ok_or_else(|| SecurityError::Win32Error(unsafe { GetLastError() }))?;

        let mut previous_state: TOKEN_PRIVILEGES = unsafe { std::mem::zeroed() };
        let mut return_length: u32 = 0;

        for &priv_name in privilege_names {
            let wide_name = to_wide_null(priv_name);
            let mut luid: LUID = unsafe { std::mem::zeroed() };

            let luid_success = unsafe {
                LookupPrivilegeValueW(std::ptr::null(), wide_name.as_ptr(), &mut luid)
            };

            if luid_success == 0 {
                return Err(SecurityError::PrivilegeNotAssigned(priv_name.to_string()));
            }

            let mut tp: TOKEN_PRIVILEGES = unsafe { std::mem::zeroed() };
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            let adjust_success = unsafe {
                AdjustTokenPrivileges(
                    token.as_raw(),
                    0,
                    &tp,
                    std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
                    &mut previous_state,
                    &mut return_length,
                )
            };

            let last_err = unsafe { GetLastError() };
            if adjust_success == 0 || last_err == ERROR_NOT_ALL_ASSIGNED {
                tracing::warn!(privilege = priv_name, err = last_err, "Could not enable privilege");
            }
        }

        Ok(Self {
            token,
            previous_state,
            has_previous: return_length > 0,
        })
    }
}

impl Drop for PrivilegeGuard {
    fn drop(&mut self) {
        if self.has_previous {
            unsafe {
                AdjustTokenPrivileges(
                    self.token.as_raw(),
                    0,
                    &self.previous_state,
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                );
            }
        }
    }
}

/// Checks if a filesystem path is a Reparse Point (Junction, Symlink, or OneDrive placeholder).
pub fn is_reparse_point(path: &Path) -> bool {
    let wide_path = to_wide_null(path.as_os_str());
    let attributes = unsafe { GetFileAttributesW(wide_path.as_ptr()) };
    if attributes == INVALID_FILE_ATTRIBUTES {
        return false;
    }
    (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
}

/// Converts a binary PSID to a canonical SDDL string (e.g., "S-1-5-21-...").
pub fn sid_to_string(psid: PSID) -> SecResult<String> {
    if psid.is_null() {
        return Err(SecurityError::SidResolutionError("PSID is null".into()));
    }

    let mut str_ptr: *mut u16 = std::ptr::null_mut();
    let success = unsafe { ConvertSidToStringSidW(psid, &mut str_ptr) };

    if success == 0 || str_ptr.is_null() {
        return Err(SecurityError::Win32Error(unsafe { GetLastError() }));
    }

    let mut len = 0;
    while unsafe { *str_ptr.add(len) } != 0 {
        len += 1;
    }

    let slice = unsafe { std::slice::from_raw_parts(str_ptr, len) };
    let result = String::from_utf16(slice).map_err(|_| SecurityError::SidResolutionError("Invalid UTF-16".into()));

    unsafe {
        LocalFree(str_ptr as *mut c_void);
    }

    result
}

/// Resolves a Security Identifier (SID) string to its Account and Domain Name.
pub fn lookup_account_by_sid_string(sid_str: &str) -> SecResult<(String, String)> {
    let wide_sid = to_wide_null(sid_str);
    let mut psid: PSID = std::ptr::null_mut();

    let conv_success = unsafe { ConvertStringSidToSidW(wide_sid.as_ptr(), &mut psid) };
    if conv_success == 0 || psid.is_null() {
        return Err(SecurityError::SidResolutionError(sid_str.to_string()));
    }

    let mut name_len = 0u32;
    let mut domain_len = 0u32;
    let mut sid_type: SID_NAME_USE = 0;

    // First call to determine buffer sizes
    unsafe {
        LookupAccountSidW(
            std::ptr::null(),
            psid,
            std::ptr::null_mut(),
            &mut name_len,
            std::ptr::null_mut(),
            &mut domain_len,
            &mut sid_type,
        );
    }

    let err = unsafe { GetLastError() };
    if err != ERROR_INSUFFICIENT_BUFFER && err != ERROR_SUCCESS {
        unsafe { LocalFree(psid as *mut c_void) };
        return Err(SecurityError::SidResolutionError(format!("LookupAccountSidW error: {err}")));
    }

    let mut name_buf = vec![0u16; name_len as usize];
    let mut domain_buf = vec![0u16; domain_len as usize];

    let lookup_success = unsafe {
        LookupAccountSidW(
            std::ptr::null(),
            psid,
            name_buf.as_mut_ptr(),
            &mut name_len,
            domain_buf.as_mut_ptr(),
            &mut domain_len,
            &mut sid_type,
        )
    };

    unsafe { LocalFree(psid as *mut c_void) };

    if lookup_success == 0 {
        return Err(SecurityError::SidResolutionError(format!("LookupAccountSidW failed: {}", unsafe { GetLastError() })));
    }

    let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
    let domain = String::from_utf16_lossy(&domain_buf[..domain_len as usize]);

    Ok((domain, name))
}

/// Reassigns ownership and recursively resets NTFS DACL model on a directory tree,
/// safeguarding against traversing reparse points (symlinks/junctions/OneDrive).
pub fn reset_tree_security_safe(root_path: &Path, owner_sid_str: &str) -> SecResult<()> {
    if is_reparse_point(root_path) {
        return Err(SecurityError::ReparsePointEncountered(root_path.to_string_lossy().to_string()));
    }

    let _privs = PrivilegeGuard::new(&[
        SE_TAKE_OWNERSHIP_NAME,
        SE_RESTORE_NAME,
        SE_BACKUP_NAME,
    ])?;

    let wide_sid = to_wide_null(owner_sid_str);
    let mut psid: PSID = std::ptr::null_mut();

    let conv_res = unsafe { ConvertStringSidToSidW(wide_sid.as_ptr(), &mut psid) };
    if conv_res == 0 || psid.is_null() {
        return Err(SecurityError::SidResolutionError(owner_sid_str.to_string()));
    }

    let wide_path = to_wide_null(root_path.as_os_str());

    // 1. Set Ownership on root
    let owner_status = unsafe {
        SetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            psid,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };

    if owner_status != ERROR_SUCCESS {
        unsafe { LocalFree(psid as *mut c_void) };
        return Err(SecurityError::Win32Error(owner_status));
    }

    // 2. Tree reset DACL propagation
    let tree_status = unsafe {
        TreeResetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
            psid,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0, // Keep explicit ACEs
            None,
            0,
            std::ptr::null_mut(),
        )
    };

    unsafe { LocalFree(psid as *mut c_void) };

    if tree_status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(SecurityError::Win32Error(tree_status))
    }
}

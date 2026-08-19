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
use std::time::Duration;
use thiserror::Error;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_SERVICE_ALREADY_RUNNING,
    HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::{
    DuplicateTokenEx, SetTokenInformation,
    SecurityImpersonation, TokenPrimary, TokenSessionId,
    TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_QUERY,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
    PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Environment::CreateEnvironmentBlock;
use windows_sys::Win32::System::RemoteDesktop::WTSGetActiveConsoleSessionId;
use windows_sys::Win32::System::Services::{
    OpenSCManagerW, OpenServiceW, QueryServiceStatusEx,
    StartServiceW, SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO,
    SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START,
    SERVICE_STATUS_PROCESS,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessAsUserW, OpenProcess, OpenProcessToken, PROCESS_INFORMATION,
    PROCESS_QUERY_INFORMATION, STARTUPINFOW,
};

use crate::handles::{OwnedEnvironmentBlock, OwnedHandle, OwnedScHandle};
use crate::registry::to_wide_null;
use crate::security::{PrivilegeGuard, SE_DEBUG_NAME, SE_IMPERSONATE_NAME, SE_TCB_NAME};

pub const MAXIMUM_ALLOWED: u32 = 0x02000000;

#[derive(Error, Debug)]
pub enum TokenError {
    #[error("Token operation failed with Win32 error code: {0}")]
    Win32Error(u32),
    #[error("Process '{0}' not found")]
    ProcessNotFound(String),
    #[error("Service '{0}' failed to start")]
    ServiceStartFailed(String),
    #[error("Security or privilege error: {0}")]
    SecurityError(#[from] crate::security::SecurityError),
}

pub type TokenResult<T> = Result<T, TokenError>;

/// Returns the active console interactive session ID.
pub fn get_active_console_session() -> u32 {
    unsafe { WTSGetActiveConsoleSessionId() }
}

/// Finds a running process ID by its executable image name (case-insensitive).
pub fn find_process_id_by_name(image_name: &str) -> TokenResult<u32> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(TokenError::Win32Error(unsafe { GetLastError() }));
    }
    let owned_snapshot = OwnedHandle::from_raw(snapshot)
        .ok_or_else(|| TokenError::Win32Error(unsafe { GetLastError() }))?;

    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

    let mut success = unsafe { Process32FirstW(owned_snapshot.as_raw(), &mut entry) };
    while success != 0 {
        let name_len = entry
            .szExeFile
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(entry.szExeFile.len());
        let current_name = String::from_utf16_lossy(&entry.szExeFile[..name_len]);

        if current_name.eq_ignore_ascii_case(image_name) {
            return Ok(entry.th32ProcessID);
        }

        success = unsafe { Process32NextW(owned_snapshot.as_raw(), &mut entry) };
    }

    Err(TokenError::ProcessNotFound(image_name.to_string()))
}

/// Starts the TrustedInstaller service via SCM and waits until it is in the RUNNING state.
pub fn ensure_trustedinstaller_service_running() -> TokenResult<u32> {
    let scm_handle = unsafe {
        OpenSCManagerW(
            std::ptr::null(),
            std::ptr::null(),
            SC_MANAGER_CONNECT,
        )
    };
    if scm_handle.is_null() {
        return Err(TokenError::Win32Error(unsafe { GetLastError() }));
    }
    let owned_scm = OwnedScHandle::from_raw(scm_handle)
        .ok_or_else(|| TokenError::Win32Error(unsafe { GetLastError() }))?;

    let wide_service_name = to_wide_null("TrustedInstaller");
    let service_handle = unsafe {
        OpenServiceW(
            owned_scm.as_raw(),
            wide_service_name.as_ptr(),
            SERVICE_START | SERVICE_QUERY_STATUS,
        )
    };
    if service_handle.is_null() {
        return Err(TokenError::Win32Error(unsafe { GetLastError() }));
    }
    let owned_service = OwnedScHandle::from_raw(service_handle)
        .ok_or_else(|| TokenError::Win32Error(unsafe { GetLastError() }))?;

    // Try to start service
    let start_res = unsafe { StartServiceW(owned_service.as_raw(), 0, std::ptr::null()) };
    let start_err = unsafe { GetLastError() };
    if start_res == 0 && start_err != ERROR_SERVICE_ALREADY_RUNNING {
        tracing::warn!(err = start_err, "Service start returned non-zero code");
    }

    // Wait until RUNNING
    let mut status: SERVICE_STATUS_PROCESS = unsafe { std::mem::zeroed() };
    let mut bytes_needed = 0;

    for _ in 0..20 {
        let query_res = unsafe {
            QueryServiceStatusEx(
                owned_service.as_raw(),
                SC_STATUS_PROCESS_INFO,
                &mut status as *mut SERVICE_STATUS_PROCESS as *mut u8,
                std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
                &mut bytes_needed,
            )
        };

        if query_res != 0 && status.dwCurrentState == SERVICE_RUNNING {
            return Ok(status.dwProcessId);
        }

        std::thread::sleep(Duration::from_millis(150));
    }

    // Fallback: search process by name
    find_process_id_by_name("TrustedInstaller.exe")
}

/// Captures and duplicates the primary token from the TrustedInstaller process,
/// configuring the token session ID for interactive display on target session.
pub fn duplicate_trustedinstaller_token(target_session_id: u32) -> TokenResult<OwnedHandle> {
    let _privs = PrivilegeGuard::new(&[SE_DEBUG_NAME, SE_IMPERSONATE_NAME, SE_TCB_NAME])?;

    let pid = ensure_trustedinstaller_service_running()?;

    let process_handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid) };
    if process_handle.is_null() {
        return Err(TokenError::Win32Error(unsafe { GetLastError() }));
    }
    let owned_process = OwnedHandle::from_raw(process_handle)
        .ok_or_else(|| TokenError::Win32Error(unsafe { GetLastError() }))?;

    let mut token_handle: HANDLE = std::ptr::null_mut();
    let tok_res = unsafe {
        OpenProcessToken(
            owned_process.as_raw(),
            TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY,
            &mut token_handle,
        )
    };
    if tok_res == 0 {
        return Err(TokenError::Win32Error(unsafe { GetLastError() }));
    }
    let owned_token = OwnedHandle::from_raw(token_handle)
        .ok_or_else(|| TokenError::Win32Error(unsafe { GetLastError() }))?;

    let mut dup_token: HANDLE = std::ptr::null_mut();
    let dup_res = unsafe {
        DuplicateTokenEx(
            owned_token.as_raw(),
            MAXIMUM_ALLOWED,
            std::ptr::null(),
            SecurityImpersonation,
            TokenPrimary,
            &mut dup_token,
        )
    };
    if dup_res == 0 {
        return Err(TokenError::Win32Error(unsafe { GetLastError() }));
    }
    let owned_dup = OwnedHandle::from_raw(dup_token)
        .ok_or_else(|| TokenError::Win32Error(unsafe { GetLastError() }))?;

    // Assign session ID for interactive launch
    let mut session_id = target_session_id;
    let set_sess_res = unsafe {
        SetTokenInformation(
            owned_dup.as_raw(),
            TokenSessionId,
            &mut session_id as *mut u32 as *mut c_void,
            std::mem::size_of::<u32>() as u32,
        )
    };
    if set_sess_res == 0 {
        tracing::warn!(err = unsafe { GetLastError() }, "SetTokenInformation(TokenSessionId) warning");
    }

    Ok(owned_dup)
}

/// Spawns a process under a duplicated token with interactive station/desktop setup.
pub fn launch_process_with_token(
    token: &OwnedHandle,
    cmd_line: &str,
    desktop: Option<&str>,
) -> TokenResult<u32> {
    let mut env_block: *mut c_void = std::ptr::null_mut();
    let env_res = unsafe { CreateEnvironmentBlock(&mut env_block, token.as_raw(), 0) };
    let _owned_env = if env_res != 0 && !env_block.is_null() {
        OwnedEnvironmentBlock::from_raw(env_block)
    } else {
        None
    };

    let desktop_name = desktop.unwrap_or("winsta0\\default");
    let mut wide_desktop = to_wide_null(desktop_name);
    let mut wide_cmd = to_wide_null(cmd_line);

    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    si.lpDesktop = wide_desktop.as_mut_ptr();

    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    let flags = 0x00000400; // CREATE_UNICODE_ENVIRONMENT

    let proc_res = unsafe {
        CreateProcessAsUserW(
            token.as_raw(),
            std::ptr::null(),
            wide_cmd.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            flags,
            env_block,
            std::ptr::null(),
            &si,
            &mut pi,
        )
    };

    if proc_res == 0 {
        return Err(TokenError::Win32Error(unsafe { GetLastError() }));
    }

    if !pi.hProcess.is_null() {
        unsafe { CloseHandle(pi.hProcess) };
    }
    if !pi.hThread.is_null() {
        unsafe { CloseHandle(pi.hThread) };
    }

    Ok(pi.dwProcessId)
}

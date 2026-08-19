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

use thiserror::Error;
use windows_sys::Win32::Foundation::{
    GetLastError, LocalFree, ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY,
    GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    RevertToSelf, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_ATTRIBUTE_NORMAL, OPEN_EXISTING,
};
use windows_sys::Win32::System::Pipes::{
    CreateNamedPipeW, ImpersonateNamedPipeClient, WaitNamedPipeW,
    PIPE_READMODE_MESSAGE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_MESSAGE,
    PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};

use platform_win32::{to_wide_null, OwnedHandle};
use crate::messages::{BrokerRequest, BrokerResponse};

pub const SECURE_PIPE_NAME: &str = r"\\.\pipe\WinProfileBrokerSecure";
pub const SECURE_PIPE_SDDL: &str = "D:(A;;GA;;;BA)(A;;GA;;;SY)";
pub const PIPE_ACCESS_DUPLEX: u32 = 0x00000003;

#[derive(Error, Debug)]
pub enum PipeError {
    #[error("Named pipe Win32 error: {0}")]
    Win32Error(u32),
    #[error("Serialization / Deserialization error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Named pipe communication timed out or broker offline")]
    BrokerUnavailable,
    #[error("Client identity could not be verified (impersonation failed)")]
    UnauthorizedClient,
}

pub type PipeResult<T> = Result<T, PipeError>;

/// Client-side function: Sends a typed request to the Broker service over the secure Named Pipe.
pub fn send_broker_request(request: &BrokerRequest) -> PipeResult<BrokerResponse> {
    let wide_pipe = to_wide_null(SECURE_PIPE_NAME);

    // Wait for pipe availability if busy
    let wait_res = unsafe { WaitNamedPipeW(wide_pipe.as_ptr(), 2000) };
    if wait_res == 0 {
        let last_err = unsafe { GetLastError() };
        if last_err == ERROR_FILE_NOT_FOUND || last_err == ERROR_PIPE_BUSY {
            return Err(PipeError::BrokerUnavailable);
        }
    }

    let raw_handle = unsafe {
        CreateFileW(
            wide_pipe.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };

    if raw_handle == INVALID_HANDLE_VALUE || raw_handle.is_null() {
        return Err(PipeError::BrokerUnavailable);
    }
    let pipe_handle = OwnedHandle::from_raw(raw_handle)
        .ok_or(PipeError::BrokerUnavailable)?;

    // Serialize request
    let payload = serde_json::to_vec(request)?;
    let len = payload.len() as u32;

    // Send length prefix (4 bytes) + JSON payload
    let mut bytes_written = 0u32;
    let write_len_res = unsafe {
        WriteFile(
            pipe_handle.as_raw(),
            &len as *const u32 as *const u8,
            4,
            &mut bytes_written,
            std::ptr::null_mut(),
        )
    };
    if write_len_res == 0 {
        return Err(PipeError::Win32Error(unsafe { GetLastError() }));
    }

    let write_payload_res = unsafe {
        WriteFile(
            pipe_handle.as_raw(),
            payload.as_ptr(),
            len,
            &mut bytes_written,
            std::ptr::null_mut(),
        )
    };
    if write_payload_res == 0 {
        return Err(PipeError::Win32Error(unsafe { GetLastError() }));
    }

    // Read response length prefix
    let mut resp_len = 0u32;
    let mut bytes_read = 0u32;
    let read_len_res = unsafe {
        ReadFile(
            pipe_handle.as_raw(),
            &mut resp_len as *mut u32 as *mut u8,
            4,
            &mut bytes_read,
            std::ptr::null_mut(),
        )
    };
    if read_len_res == 0 || bytes_read < 4 {
        return Err(PipeError::Win32Error(unsafe { GetLastError() }));
    }

    // Read response payload
    let mut resp_buf = vec![0u8; resp_len as usize];
    let read_payload_res = unsafe {
        ReadFile(
            pipe_handle.as_raw(),
            resp_buf.as_mut_ptr(),
            resp_len,
            &mut bytes_read,
            std::ptr::null_mut(),
        )
    };
    if read_payload_res == 0 {
        return Err(PipeError::Win32Error(unsafe { GetLastError() }));
    }

    let response: BrokerResponse = serde_json::from_slice(&resp_buf[..bytes_read as usize])?;
    Ok(response)
}

/// Server-side helper to create a named pipe instance with strict SDDL and remote reject flags.
pub fn create_secure_pipe_server_instance() -> PipeResult<OwnedHandle> {
    let wide_pipe = to_wide_null(SECURE_PIPE_NAME);
    let wide_sddl = to_wide_null(SECURE_PIPE_SDDL);

    let mut sec_desc: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let sddl_res = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide_sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sec_desc,
            std::ptr::null_mut(),
        )
    };

    if sddl_res == 0 || sec_desc.is_null() {
        return Err(PipeError::Win32Error(unsafe { GetLastError() }));
    }

    let mut sa: SECURITY_ATTRIBUTES = unsafe { std::mem::zeroed() };
    sa.nLength = std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32;
    sa.lpSecurityDescriptor = sec_desc;
    sa.bInheritHandle = 0;

    let open_mode = PIPE_ACCESS_DUPLEX;
    let pipe_mode = PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;

    let raw_pipe = unsafe {
        CreateNamedPipeW(
            wide_pipe.as_ptr(),
            open_mode,
            pipe_mode,
            PIPE_UNLIMITED_INSTANCES,
            65536,
            65536,
            0,
            &sa,
        )
    };

    unsafe { LocalFree(sec_desc as _) };

    if raw_pipe == INVALID_HANDLE_VALUE || raw_pipe.is_null() {
        return Err(PipeError::Win32Error(unsafe { GetLastError() }));
    }

    OwnedHandle::from_raw(raw_pipe).ok_or_else(|| PipeError::Win32Error(unsafe { GetLastError() }))
}

/// Server-side helper: Verifies client identity using Impersonation.
pub fn verify_pipe_client_identity(pipe: &OwnedHandle) -> PipeResult<()> {
    let imp_res = unsafe { ImpersonateNamedPipeClient(pipe.as_raw()) };
    if imp_res == 0 {
        return Err(PipeError::UnauthorizedClient);
    }
    // Revert back immediately after identity assertion
    unsafe { RevertToSelf() };
    Ok(())
}

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

use std::path::Path;
use thiserror::Error;
use windows_sys::Win32::Foundation::{ERROR_MORE_DATA, ERROR_SUCCESS};
use windows_sys::Win32::System::RestartManager::{
    RmEndSession, RmForceShutdown, RmGetList, RmRegisterResources, RmShutdown, RmStartSession,
    RM_PROCESS_INFO,
};

use crate::registry::to_wide_null;

pub const RM_NORMAL_SHUTDOWN: u32 = 0;
pub const RM_FORCE_SHUTDOWN: u32 = 1;

#[derive(Error, Debug)]
pub enum RestartManagerError {
    #[error("Restart Manager failed with error code: {0}")]
    Win32Error(u32),
    #[error("Failed to register resource path: {0}")]
    InvalidPath(String),
}

pub type RmResult<T> = Result<T, RestartManagerError>;

/// Detailed information on a process holding a lock on a file resource.
#[derive(Debug, Clone)]
pub struct LockingProcessInfo {
    pub process_id: u32,
    pub app_name: String,
    pub service_short_name: String,
    pub app_type: u32,
    pub restartable: bool,
}

/// RAII wrapper for a Windows Restart Manager session.
pub struct RestartManagerSession {
    session_handle: u32,
    #[allow(dead_code)]
    session_key: [u16; 33],
}

impl RestartManagerSession {
    /// Starts a new Restart Manager session.
    pub fn new() -> RmResult<Self> {
        let mut session_handle: u32 = 0;
        let mut session_key = [0u16; 33];

        let status = unsafe { RmStartSession(&mut session_handle, 0, session_key.as_mut_ptr()) };

        if status == ERROR_SUCCESS {
            Ok(Self {
                session_handle,
                session_key,
            })
        } else {
            Err(RestartManagerError::Win32Error(status))
        }
    }

    /// Registers a file resource (such as NTUSER.DAT or UsrClass.dat) in the session.
    pub fn register_file(&self, file_path: &Path) -> RmResult<()> {
        let wide_path = to_wide_null(file_path.as_os_str());
        let file_ptrs = [wide_path.as_ptr()];

        let status = unsafe {
            RmRegisterResources(
                self.session_handle,
                1,
                file_ptrs.as_ptr(),
                0,
                std::ptr::null(),
                0,
                std::ptr::null(),
            )
        };

        if status == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(RestartManagerError::Win32Error(status))
        }
    }

    /// Retrieves the list of processes locking the registered resources.
    pub fn get_locking_processes(&self) -> RmResult<Vec<LockingProcessInfo>> {
        let mut proc_info_needed = 0u32;
        let mut proc_info_count = 0u32;
        let mut reboot_reasons = 0u32;

        // First call to determine array count needed
        let status = unsafe {
            RmGetList(
                self.session_handle,
                &mut proc_info_needed,
                &mut proc_info_count,
                std::ptr::null_mut(),
                &mut reboot_reasons,
            )
        };

        if status != ERROR_SUCCESS && status != ERROR_MORE_DATA {
            return Err(RestartManagerError::Win32Error(status));
        }

        if proc_info_needed == 0 {
            return Ok(Vec::new());
        }

        let mut proc_infos: Vec<RM_PROCESS_INFO> =
            vec![unsafe { std::mem::zeroed() }; proc_info_needed as usize];
        proc_info_count = proc_info_needed;

        let status = unsafe {
            RmGetList(
                self.session_handle,
                &mut proc_info_needed,
                &mut proc_info_count,
                proc_infos.as_mut_ptr(),
                &mut reboot_reasons,
            )
        };

        if status != ERROR_SUCCESS {
            return Err(RestartManagerError::Win32Error(status));
        }

        let mut results = Vec::new();
        for info in &proc_infos[..proc_info_count as usize] {
            let name_len = info
                .strAppName
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(info.strAppName.len());
            let app_name = String::from_utf16_lossy(&info.strAppName[..name_len]);

            let svc_len = info
                .strServiceShortName
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(info.strServiceShortName.len());
            let svc_name = String::from_utf16_lossy(&info.strServiceShortName[..svc_len]);

            results.push(LockingProcessInfo {
                process_id: info.Process.dwProcessId,
                app_name,
                service_short_name: svc_name,
                app_type: info.ApplicationType as u32,
                restartable: info.bRestartable != 0,
            });
        }

        Ok(results)
    }

    /// Requests a graceful shutdown of the locking processes.
    pub fn shutdown_locking_processes(&self, force: bool) -> RmResult<()> {
        let flags: u32 = if force {
            RmForceShutdown as u32
        } else {
            RM_NORMAL_SHUTDOWN
        };

        let status = unsafe { RmShutdown(self.session_handle, flags, None) };

        if status == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(RestartManagerError::Win32Error(status))
        }
    }
}

impl Drop for RestartManagerSession {
    fn drop(&mut self) {
        if self.session_handle != 0 {
            unsafe {
                RmEndSession(self.session_handle);
            }
        }
    }
}

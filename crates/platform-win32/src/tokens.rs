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

use std::ffi::{c_void, OsStr, OsString};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;
use windows_sys::Win32::Foundation::{
    GetLastError, ERROR_SERVICE_ALREADY_RUNNING, HANDLE, INVALID_HANDLE_VALUE, WAIT_FAILED,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::{
    DuplicateTokenEx, SecurityImpersonation, TokenPrimary, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE,
    TOKEN_QUERY,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Environment::CreateEnvironmentBlock;
use windows_sys::Win32::System::RemoteDesktop::{
    ProcessIdToSessionId, WTSActive, WTSConnectState, WTSConnected, WTSFreeMemory,
    WTSQuerySessionInformationW, WTS_CONNECTSTATE_CLASS, WTS_CURRENT_SERVER_HANDLE,
};
use windows_sys::Win32::System::Services::{
    OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, StartServiceW, SC_MANAGER_CONNECT,
    SC_STATUS_PROCESS_INFO, SERVICE_CONTINUE_PENDING, SERVICE_QUERY_STATUS, SERVICE_RUNNING,
    SERVICE_START, SERVICE_START_PENDING, SERVICE_STATUS_PROCESS,
};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows_sys::Win32::System::Threading::{
    CreateProcessWithTokenW, GetCurrentProcessId, OpenProcess, OpenProcessToken, TerminateProcess,
    WaitForSingleObject, CREATE_PROCESS_LOGON_FLAGS, CREATE_UNICODE_ENVIRONMENT,
    PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, STARTUPINFOW,
};

use crate::handles::{OwnedEnvironmentBlock, OwnedHandle, OwnedScHandle};
use crate::registry::to_wide_null;
use crate::security::{PrivilegeGuard, SecurityError, SE_DEBUG_NAME, SE_IMPERSONATE_NAME};

/// Generic Windows access-mask value retained for API compatibility. TrustedInstaller
/// token capture deliberately uses the exact masks below instead.
pub const MAXIMUM_ALLOWED: u32 = 0x02000000;
const TRUSTED_INSTALLER_SERVICE: &str = "TrustedInstaller";
const SERVICE_START_POLL_ATTEMPTS: usize = 20;
const SERVICE_START_POLL_INTERVAL: Duration = Duration::from_millis(150);
const SYSTEM_COMMAND_NAME: &str = "cmd.exe";
const TRUSTED_INSTALLER_CONSOLE_TITLE: &str = "TrustedInstaller Elevated Console";
const INITIAL_SYSTEM_DIRECTORY_CAPACITY: usize = 260;
const PROCESS_COMPENSATION_EXIT_CODE: u32 = 1;
const PROCESS_COMPENSATION_TIMEOUT: Duration = Duration::from_secs(5);
const TRUSTED_INSTALLER_PROCESS_ACCESS: u32 = PROCESS_QUERY_LIMITED_INFORMATION;
const TRUSTED_INSTALLER_SOURCE_TOKEN_ACCESS: u32 = TOKEN_DUPLICATE;
const TRUSTED_INSTALLER_LAUNCH_TOKEN_ACCESS: u32 =
    TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY;

#[derive(Error, Debug)]
pub enum TokenError {
    #[error("Token operation failed with Win32 error code: {0}")]
    Win32Error(u32),
    #[error("{operation} failed with Win32 error code: {code}")]
    Win32Operation { operation: &'static str, code: u32 },
    #[error("Process '{0}' not found")]
    ProcessNotFound(String),
    #[error(
        "TrustedInstaller did not reach RUNNING (state {state}, Win32 exit {win32_exit_code}, service exit {service_exit_code}, PID {process_id})"
    )]
    TrustedInstallerServiceState {
        state: u32,
        win32_exit_code: u32,
        service_exit_code: u32,
        process_id: u32,
    },
    #[error("Requesting process session {0} is not interactive")]
    NonInteractiveRequestSession(u32),
    #[error("Requesting process session {session_id} is not active or connected (state {state})")]
    RequestSessionNotConnected {
        session_id: u32,
        state: WTS_CONNECTSTATE_CLASS,
    },
    #[error(
        "WTS returned invalid connection-state data for session {session_id} ({bytes_returned} bytes)"
    )]
    InvalidSessionStateData {
        session_id: u32,
        bytes_returned: u32,
    },
    #[error("Windows system directory returned an invalid path: {0}")]
    InvalidSystemDirectory(String),
    #[error("Windows system executable is unavailable at {path}: {source}")]
    SystemExecutableUnavailable {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("Process termination wait timed out after {0} milliseconds")]
    ProcessWaitTimeout(u32),
    #[error("Process termination wait failed with Win32 error code: {0}")]
    ProcessWaitFailed(u32),
    #[error(
        "CreateProcessWithTokenW returned incomplete process information for PID {0}; child was terminated and reaped"
    )]
    InvalidProcessInformationCompensated(u32),
    #[error(
        "CreateProcessWithTokenW returned incomplete process information for PID {pid}; compensation failed: {compensation_error}"
    )]
    InvalidProcessInformationCompensationFailed {
        pid: u32,
        compensation_error: String,
    },
    #[error(
        "CreateProcessWithTokenW returned success without a process handle for PID {pid} (thread handle present: {thread_handle_present}); child cannot be compensated"
    )]
    InvalidProcessInformationMissingProcessHandle {
        pid: u32,
        thread_handle_present: bool,
    },
    #[error("Privileged operation failed: {operation_error}; privilege restoration also failed: {restore_error}")]
    OperationAndPrivilegeRestoreFailed {
        operation_error: String,
        restore_error: String,
    },
    #[error(
        "Privilege restoration failed after launching PID {pid}: {restore_error}; process was terminated and reaped"
    )]
    PrivilegeRestoreCompensated { pid: u32, restore_error: String },
    #[error(
        "Privilege restoration failed after launching PID {pid}: {restore_error}; process compensation failed: {compensation_error}"
    )]
    PrivilegeRestoreCompensationFailed {
        pid: u32,
        restore_error: String,
        compensation_error: String,
    },
    #[error("Security or privilege error: {0}")]
    SecurityError(#[from] crate::security::SecurityError),
}

pub type TokenResult<T> = Result<T, TokenError>;

/// Fully resolved, immutable inputs for a privileged process launch.
#[derive(Debug, Clone)]
pub struct ProcessLaunchSpec {
    application_path: PathBuf,
    working_directory: PathBuf,
    arguments: Vec<OsString>,
}

impl ProcessLaunchSpec {
    pub fn application_path(&self) -> &Path {
        &self.application_path
    }

    pub fn working_directory(&self) -> &Path {
        &self.working_directory
    }
}

/// Owns the process handle returned by `CreateProcessWithTokenW` until the caller
/// has durably audited success or completed compensating termination.
#[derive(Debug)]
pub struct LaunchedProcess {
    handle: OwnedHandle,
    pid: u32,
}

/// Owns the duplicated TrustedInstaller token and keeps SeImpersonatePrivilege
/// enabled until the launch attempt explicitly restores it.
pub struct TrustedInstallerLaunchToken {
    token: OwnedHandle,
    impersonate_privilege: PrivilegeGuard,
}

trait PrivilegeRestorer {
    fn restore(self) -> Result<(), SecurityError>;
}

impl PrivilegeRestorer for PrivilegeGuard {
    fn restore(self) -> Result<(), SecurityError> {
        PrivilegeGuard::restore(self)
    }
}

fn restore_after_operation<T, R: PrivilegeRestorer>(
    operation_result: TokenResult<T>,
    restorer: R,
) -> TokenResult<T> {
    match (operation_result, restorer.restore()) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(operation_error), Ok(())) => Err(operation_error),
        (Ok(_), Err(restore_error)) => Err(TokenError::SecurityError(restore_error)),
        (Err(operation_error), Err(restore_error)) => {
            Err(TokenError::OperationAndPrivilegeRestoreFailed {
                operation_error: operation_error.to_string(),
                restore_error: restore_error.to_string(),
            })
        }
    }
}

impl LaunchedProcess {
    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn terminate(&self, exit_code: u32) -> TokenResult<()> {
        let result = unsafe { TerminateProcess(self.handle.as_raw(), exit_code) };
        if result == 0 {
            return Err(TokenError::Win32Error(unsafe { GetLastError() }));
        }
        Ok(())
    }

    pub fn wait_for_exit(&self, timeout: Duration) -> TokenResult<()> {
        let timeout_ms = timeout.as_millis().min(u128::from(u32::MAX - 1)) as u32;
        let result = unsafe { WaitForSingleObject(self.handle.as_raw(), timeout_ms) };
        match result {
            WAIT_OBJECT_0 => Ok(()),
            WAIT_TIMEOUT => Err(TokenError::ProcessWaitTimeout(timeout_ms)),
            WAIT_FAILED => Err(TokenError::ProcessWaitFailed(unsafe { GetLastError() })),
            other => Err(TokenError::ProcessWaitFailed(other)),
        }
    }
}

/// Returns the interactive session that owns the requesting WinProfile process.
///
/// This intentionally does not use the physical console session, which can
/// belong to a different user when WinProfile is running through RDP.
pub fn get_requesting_process_session() -> TokenResult<u32> {
    get_requesting_process_session_with_api(&WindowsRequestSessionApi)
}

trait RequestSessionApi {
    fn current_process_id(&self) -> u32;
    fn process_session_id(&self, process_id: u32) -> TokenResult<u32>;
    fn session_connect_state(&self, session_id: u32) -> TokenResult<WTS_CONNECTSTATE_CLASS>;
}

struct WindowsRequestSessionApi;

impl RequestSessionApi for WindowsRequestSessionApi {
    fn current_process_id(&self) -> u32 {
        unsafe { GetCurrentProcessId() }
    }

    fn process_session_id(&self, process_id: u32) -> TokenResult<u32> {
        let mut session_id = 0u32;
        let result = unsafe { ProcessIdToSessionId(process_id, &mut session_id) };
        if result == 0 {
            return Err(TokenError::Win32Error(unsafe { GetLastError() }));
        }
        Ok(session_id)
    }

    fn session_connect_state(&self, session_id: u32) -> TokenResult<WTS_CONNECTSTATE_CLASS> {
        let mut buffer = std::ptr::null_mut::<u16>();
        let mut bytes_returned = 0u32;
        let result = unsafe {
            WTSQuerySessionInformationW(
                WTS_CURRENT_SERVER_HANDLE,
                session_id,
                WTSConnectState,
                &mut buffer,
                &mut bytes_returned,
            )
        };
        let memory = WtsMemory(buffer.cast());
        if result == 0 {
            return Err(TokenError::Win32Error(unsafe { GetLastError() }));
        }
        if memory.0.is_null()
            || bytes_returned < std::mem::size_of::<WTS_CONNECTSTATE_CLASS>() as u32
        {
            return Err(TokenError::InvalidSessionStateData {
                session_id,
                bytes_returned,
            });
        }
        Ok(unsafe { *(memory.0.cast::<WTS_CONNECTSTATE_CLASS>()) })
    }
}

struct WtsMemory(*mut c_void);

impl Drop for WtsMemory {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { WTSFreeMemory(self.0) };
        }
    }
}

fn get_requesting_process_session_with_api<A: RequestSessionApi>(api: &A) -> TokenResult<u32> {
    let process_id = api.current_process_id();
    let session_id = api.process_session_id(process_id)?;
    if session_id == 0 {
        return Err(TokenError::NonInteractiveRequestSession(session_id));
    }
    let state = api.session_connect_state(session_id)?;
    if state != WTSActive && state != WTSConnected {
        return Err(TokenError::RequestSessionNotConnected { session_id, state });
    }
    Ok(session_id)
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
    ensure_trustedinstaller_service_running_with_api(&WindowsTrustedInstallerServiceApi)
}

trait TrustedInstallerServiceApi {
    type Handle;

    fn open_manager(&self, desired_access: u32) -> Result<Self::Handle, u32>;
    fn open_service(
        &self,
        manager: &Self::Handle,
        service_name: &[u16],
        desired_access: u32,
    ) -> Result<Self::Handle, u32>;
    fn start_service(&self, service: &Self::Handle) -> Result<(), u32>;
    fn query_status(&self, service: &Self::Handle) -> Result<SERVICE_STATUS_PROCESS, u32>;
    fn wait(&self, interval: Duration);
}

struct WindowsTrustedInstallerServiceApi;

impl TrustedInstallerServiceApi for WindowsTrustedInstallerServiceApi {
    type Handle = OwnedScHandle;

    fn open_manager(&self, desired_access: u32) -> Result<Self::Handle, u32> {
        let handle = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), desired_access) };
        OwnedScHandle::from_raw(handle).ok_or_else(|| unsafe { GetLastError() })
    }

    fn open_service(
        &self,
        manager: &Self::Handle,
        service_name: &[u16],
        desired_access: u32,
    ) -> Result<Self::Handle, u32> {
        let handle =
            unsafe { OpenServiceW(manager.as_raw(), service_name.as_ptr(), desired_access) };
        OwnedScHandle::from_raw(handle).ok_or_else(|| unsafe { GetLastError() })
    }

    fn start_service(&self, service: &Self::Handle) -> Result<(), u32> {
        let result = unsafe { StartServiceW(service.as_raw(), 0, std::ptr::null()) };
        if result == 0 {
            Err(unsafe { GetLastError() })
        } else {
            Ok(())
        }
    }

    fn query_status(&self, service: &Self::Handle) -> Result<SERVICE_STATUS_PROCESS, u32> {
        let mut status: SERVICE_STATUS_PROCESS = unsafe { std::mem::zeroed() };
        let mut bytes_needed = 0;
        let result = unsafe {
            QueryServiceStatusEx(
                service.as_raw(),
                SC_STATUS_PROCESS_INFO,
                (&raw mut status).cast::<u8>(),
                std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
                &mut bytes_needed,
            )
        };
        if result == 0 {
            Err(unsafe { GetLastError() })
        } else {
            Ok(status)
        }
    }

    fn wait(&self, interval: Duration) {
        std::thread::sleep(interval);
    }
}

fn ensure_trustedinstaller_service_running_with_api<A: TrustedInstallerServiceApi>(
    api: &A,
) -> TokenResult<u32> {
    let manager =
        api.open_manager(SC_MANAGER_CONNECT)
            .map_err(|code| TokenError::Win32Operation {
                operation: "OpenSCManagerW for TrustedInstaller",
                code,
            })?;
    let service_name = to_wide_null(TRUSTED_INSTALLER_SERVICE);
    let service = api
        .open_service(
            &manager,
            &service_name,
            SERVICE_START | SERVICE_QUERY_STATUS,
        )
        .map_err(|code| TokenError::Win32Operation {
            operation: "OpenServiceW for TrustedInstaller",
            code,
        })?;
    if let Err(code) = api.start_service(&service) {
        if code != ERROR_SERVICE_ALREADY_RUNNING {
            return Err(TokenError::Win32Operation {
                operation: "StartServiceW for TrustedInstaller",
                code,
            });
        }
    }

    for attempt in 0..SERVICE_START_POLL_ATTEMPTS {
        let status = api
            .query_status(&service)
            .map_err(|code| TokenError::Win32Operation {
                operation: "QueryServiceStatusEx for TrustedInstaller",
                code,
            })?;
        if status.dwCurrentState == SERVICE_RUNNING && status.dwProcessId != 0 {
            return Ok(status.dwProcessId);
        }
        let transitional = matches!(
            status.dwCurrentState,
            SERVICE_START_PENDING | SERVICE_CONTINUE_PENDING
        );
        if !transitional || attempt + 1 == SERVICE_START_POLL_ATTEMPTS {
            return Err(service_state_error(status));
        }
        api.wait(SERVICE_START_POLL_INTERVAL);
    }

    unreachable!("the bounded service poll loop always returns")
}

fn service_state_error(status: SERVICE_STATUS_PROCESS) -> TokenError {
    TokenError::TrustedInstallerServiceState {
        state: status.dwCurrentState,
        win32_exit_code: status.dwWin32ExitCode,
        service_exit_code: status.dwServiceSpecificExitCode,
        process_id: status.dwProcessId,
    }
}

/// Captures and duplicates the TrustedInstaller primary token. SeDebugPrivilege
/// is restored immediately after capture; SeImpersonatePrivilege remains owned
/// by the returned launch token until process creation completes.
pub fn duplicate_trustedinstaller_token() -> TokenResult<TrustedInstallerLaunchToken> {
    let pid = ensure_trustedinstaller_service_running()?;
    let debug_privilege = PrivilegeGuard::new(&[SE_DEBUG_NAME])?;
    let capture_result = capture_trustedinstaller_token(pid);
    let owned_dup = restore_after_operation(capture_result, debug_privilege)?;
    let impersonate_privilege = PrivilegeGuard::new(&[SE_IMPERSONATE_NAME])?;

    Ok(TrustedInstallerLaunchToken {
        token: owned_dup,
        impersonate_privilege,
    })
}

fn capture_trustedinstaller_token(pid: u32) -> TokenResult<OwnedHandle> {
    capture_trustedinstaller_token_with_api(pid, &WindowsTrustedInstallerCaptureApi)
}

trait TrustedInstallerCaptureApi {
    type Handle;

    fn open_process(&self, pid: u32, desired_access: u32) -> Result<Self::Handle, u32>;
    fn open_process_token(
        &self,
        process: &Self::Handle,
        desired_access: u32,
    ) -> Result<Self::Handle, u32>;
    fn duplicate_primary_token(
        &self,
        source_token: &Self::Handle,
        desired_access: u32,
    ) -> Result<Self::Handle, u32>;
}

struct WindowsTrustedInstallerCaptureApi;

impl TrustedInstallerCaptureApi for WindowsTrustedInstallerCaptureApi {
    type Handle = OwnedHandle;

    fn open_process(&self, pid: u32, desired_access: u32) -> Result<Self::Handle, u32> {
        let handle = unsafe { OpenProcess(desired_access, 0, pid) };
        OwnedHandle::from_raw(handle).ok_or_else(|| unsafe { GetLastError() })
    }

    fn open_process_token(
        &self,
        process: &Self::Handle,
        desired_access: u32,
    ) -> Result<Self::Handle, u32> {
        let mut handle: HANDLE = std::ptr::null_mut();
        let result = unsafe { OpenProcessToken(process.as_raw(), desired_access, &mut handle) };
        if result == 0 {
            Err(unsafe { GetLastError() })
        } else {
            OwnedHandle::from_raw(handle).ok_or_else(|| unsafe { GetLastError() })
        }
    }

    fn duplicate_primary_token(
        &self,
        source_token: &Self::Handle,
        desired_access: u32,
    ) -> Result<Self::Handle, u32> {
        let mut handle: HANDLE = std::ptr::null_mut();
        let result = unsafe {
            DuplicateTokenEx(
                source_token.as_raw(),
                desired_access,
                std::ptr::null(),
                SecurityImpersonation,
                TokenPrimary,
                &mut handle,
            )
        };
        if result == 0 {
            Err(unsafe { GetLastError() })
        } else {
            OwnedHandle::from_raw(handle).ok_or_else(|| unsafe { GetLastError() })
        }
    }
}

fn capture_trustedinstaller_token_with_api<A: TrustedInstallerCaptureApi>(
    pid: u32,
    api: &A,
) -> TokenResult<A::Handle> {
    let process = api
        .open_process(pid, TRUSTED_INSTALLER_PROCESS_ACCESS)
        .map_err(|code| TokenError::Win32Operation {
            operation: "OpenProcess for TrustedInstaller",
            code,
        })?;
    let source_token = api
        .open_process_token(&process, TRUSTED_INSTALLER_SOURCE_TOKEN_ACCESS)
        .map_err(|code| TokenError::Win32Operation {
            operation: "OpenProcessToken for TrustedInstaller",
            code,
        })?;
    api.duplicate_primary_token(&source_token, TRUSTED_INSTALLER_LAUNCH_TOKEN_ACCESS)
        .map_err(|code| TokenError::Win32Operation {
            operation: "DuplicateTokenEx for TrustedInstaller",
            code,
        })
}

/// Resolves the Windows system command interpreter without consulting PATH,
/// the current working directory, or environment variables.
pub fn trustedinstaller_console_launch_spec() -> TokenResult<ProcessLaunchSpec> {
    let system_directory = system_directory()?;
    let unresolved_application = system_directory.join(SYSTEM_COMMAND_NAME);
    let application_path = std::fs::canonicalize(&unresolved_application).map_err(|source| {
        TokenError::SystemExecutableUnavailable {
            path: unresolved_application.display().to_string(),
            source,
        }
    })?;
    if !application_path.is_absolute() || !application_path.is_file() {
        return Err(TokenError::InvalidSystemDirectory(
            application_path.display().to_string(),
        ));
    }
    let working_directory = application_path
        .parent()
        .ok_or_else(|| TokenError::InvalidSystemDirectory(application_path.display().to_string()))?
        .to_path_buf();
    Ok(ProcessLaunchSpec {
        application_path,
        working_directory,
        arguments: vec![
            OsString::from("/k"),
            OsString::from("title"),
            OsString::from(TRUSTED_INSTALLER_CONSOLE_TITLE),
        ],
    })
}

/// Spawns a process under a duplicated token with explicit application and
/// working-directory paths. The returned process handle remains owned.
pub fn launch_process_with_token(
    launch_token: TrustedInstallerLaunchToken,
    spec: &ProcessLaunchSpec,
) -> TokenResult<LaunchedProcess> {
    let TrustedInstallerLaunchToken {
        token,
        impersonate_privilege,
    } = launch_token;
    let launch_result = (|| {
        let mut env_block: *mut c_void = std::ptr::null_mut();
        let env_res = unsafe { CreateEnvironmentBlock(&mut env_block, token.as_raw(), 0) };
        if env_res == 0 || env_block.is_null() {
            return Err(TokenError::Win32Operation {
                operation: "CreateEnvironmentBlock for TrustedInstaller",
                code: unsafe { GetLastError() },
            });
        }
        let _owned_env = OwnedEnvironmentBlock::from_raw(env_block)
            .ok_or_else(|| TokenError::Win32Error(unsafe { GetLastError() }))?;

        create_process_with_api(token.as_raw(), spec, env_block, &WindowsProcessCreationApi)
    })();

    finalize_process_privilege_restore(launch_result, impersonate_privilege)
}

fn system_directory() -> TokenResult<PathBuf> {
    let mut capacity = INITIAL_SYSTEM_DIRECTORY_CAPACITY;
    loop {
        let mut buffer = vec![0u16; capacity];
        let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
        if length == 0 {
            return Err(TokenError::Win32Error(unsafe { GetLastError() }));
        }
        if (length as usize) < buffer.len() {
            buffer.truncate(length as usize);
            let path = PathBuf::from(OsString::from_wide(&buffer));
            if !path.is_absolute() {
                return Err(TokenError::InvalidSystemDirectory(
                    path.display().to_string(),
                ));
            }
            return Ok(path);
        }
        capacity = (length as usize).saturating_add(1);
    }
}

trait ProcessCreationApi {
    #[allow(clippy::too_many_arguments)]
    fn create_process(
        &self,
        token: HANDLE,
        logon_flags: CREATE_PROCESS_LOGON_FLAGS,
        application_name: *const u16,
        command_line: *mut u16,
        creation_flags: PROCESS_CREATION_FLAGS,
        environment: *mut c_void,
        current_directory: *const u16,
        startup_info: *const STARTUPINFOW,
        process_information: *mut PROCESS_INFORMATION,
    ) -> i32;
}

struct WindowsProcessCreationApi;

impl ProcessCreationApi for WindowsProcessCreationApi {
    fn create_process(
        &self,
        token: HANDLE,
        logon_flags: CREATE_PROCESS_LOGON_FLAGS,
        application_name: *const u16,
        command_line: *mut u16,
        creation_flags: PROCESS_CREATION_FLAGS,
        environment: *mut c_void,
        current_directory: *const u16,
        startup_info: *const STARTUPINFOW,
        process_information: *mut PROCESS_INFORMATION,
    ) -> i32 {
        unsafe {
            CreateProcessWithTokenW(
                token,
                logon_flags,
                application_name,
                command_line,
                creation_flags,
                environment,
                current_directory,
                startup_info,
                process_information,
            )
        }
    }
}

fn create_process_with_api<A: ProcessCreationApi>(
    token: HANDLE,
    spec: &ProcessLaunchSpec,
    environment: *mut c_void,
    api: &A,
) -> TokenResult<LaunchedProcess> {
    let wide_application = wide_null(spec.application_path.as_os_str());
    let wide_working_directory = wide_null(spec.working_directory.as_os_str());
    let mut wide_command = build_windows_command_line(&spec.application_path, &spec.arguments);

    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;

    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    let proc_res = api.create_process(
        token,
        0,
        wide_application.as_ptr(),
        wide_command.as_mut_ptr(),
        CREATE_UNICODE_ENVIRONMENT,
        environment,
        wide_working_directory.as_ptr(),
        &si,
        &mut pi,
    );

    if proc_res == 0 {
        return Err(TokenError::Win32Operation {
            operation: "CreateProcessWithTokenW for TrustedInstaller",
            code: unsafe { GetLastError() },
        });
    }

    let process = OwnedHandle::from_raw(pi.hProcess);
    let thread = OwnedHandle::from_raw(pi.hThread);
    let thread_handle_present = thread.is_some();
    drop(thread);
    let process = process.map(|handle| LaunchedProcess {
        handle,
        pid: pi.dwProcessId,
    });
    validate_created_process_information(process, thread_handle_present, pi.dwProcessId)
}

trait CompensatableProcess {
    fn process_id(&self) -> u32;
    fn terminate_for_compensation(&self) -> TokenResult<()>;
    fn wait_for_compensation(&self) -> TokenResult<()>;
}

impl CompensatableProcess for LaunchedProcess {
    fn process_id(&self) -> u32 {
        self.pid()
    }

    fn terminate_for_compensation(&self) -> TokenResult<()> {
        self.terminate(PROCESS_COMPENSATION_EXIT_CODE)
    }

    fn wait_for_compensation(&self) -> TokenResult<()> {
        self.wait_for_exit(PROCESS_COMPENSATION_TIMEOUT)
    }
}

fn validate_created_process_information<P: CompensatableProcess>(
    process: Option<P>,
    thread_handle_present: bool,
    pid: u32,
) -> TokenResult<P> {
    match (process, thread_handle_present) {
        (Some(process), true) => Ok(process),
        (Some(process), false) => Err(match compensate_process(process) {
            Ok(pid) => TokenError::InvalidProcessInformationCompensated(pid),
            Err((pid, compensation_error)) => {
                TokenError::InvalidProcessInformationCompensationFailed {
                    pid,
                    compensation_error,
                }
            }
        }),
        (None, thread_handle_present) => {
            Err(TokenError::InvalidProcessInformationMissingProcessHandle {
                pid,
                thread_handle_present,
            })
        }
    }
}

fn finalize_process_privilege_restore<P, R>(
    process_result: TokenResult<P>,
    restorer: R,
) -> TokenResult<P>
where
    P: CompensatableProcess,
    R: PrivilegeRestorer,
{
    let restore_result = restorer.restore();
    match (process_result, restore_result) {
        (Ok(process), Ok(())) => Ok(process),
        (Err(launch_error), Ok(())) => Err(launch_error),
        (Err(launch_error), Err(restore_error)) => {
            Err(TokenError::OperationAndPrivilegeRestoreFailed {
                operation_error: launch_error.to_string(),
                restore_error: restore_error.to_string(),
            })
        }
        (Ok(process), Err(restore_error)) => {
            let restore_error = restore_error.to_string();
            match compensate_process(process) {
                Ok(pid) => Err(TokenError::PrivilegeRestoreCompensated { pid, restore_error }),
                Err((pid, compensation_error)) => {
                    Err(TokenError::PrivilegeRestoreCompensationFailed {
                        pid,
                        restore_error,
                        compensation_error,
                    })
                }
            }
        }
    }
}

fn compensate_process<P: CompensatableProcess>(process: P) -> Result<u32, (u32, String)> {
    let pid = process.process_id();
    let terminate_error = process.terminate_for_compensation().err();
    let wait_error = process.wait_for_compensation().err();
    drop(process);
    match (terminate_error, wait_error) {
        (None, None) => Ok(pid),
        (terminate_error, wait_error) => {
            let mut failures = Vec::new();
            if let Some(error) = terminate_error {
                failures.push(format!("terminate: {error}"));
            }
            if let Some(error) = wait_error {
                failures.push(format!("wait: {error}"));
            }
            Err((pid, failures.join("; ")))
        }
    }
}

fn wide_null(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

fn build_windows_command_line(application: &Path, arguments: &[OsString]) -> Vec<u16> {
    let mut command_line = Vec::new();
    append_quoted_argument(&mut command_line, application.as_os_str());
    for argument in arguments {
        command_line.push(b' ' as u16);
        append_quoted_argument(&mut command_line, argument);
    }
    command_line.push(0);
    command_line
}

fn append_quoted_argument(command_line: &mut Vec<u16>, argument: &OsStr) {
    let units = argument.encode_wide().collect::<Vec<_>>();
    let needs_quotes = units.is_empty()
        || units
            .iter()
            .any(|unit| *unit == b' ' as u16 || *unit == b'\t' as u16 || *unit == b'"' as u16);
    if !needs_quotes {
        command_line.extend(units);
        return;
    }

    command_line.push(b'"' as u16);
    let mut backslashes = 0usize;
    for unit in units {
        if unit == b'\\' as u16 {
            backslashes += 1;
            continue;
        }
        if unit == b'"' as u16 {
            command_line.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2 + 1));
            command_line.push(unit);
        } else {
            command_line.extend(std::iter::repeat_n(b'\\' as u16, backslashes));
            command_line.push(unit);
        }
        backslashes = 0;
    }
    command_line.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2));
    command_line.push(b'"' as u16);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::fs::File;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    static NEXT_TEMP_DIRECTORY: AtomicU64 = AtomicU64::new(0);
    static CURRENT_DIRECTORY_LOCK: Mutex<()> = Mutex::new(());

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let suffix = NEXT_TEMP_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "winprofile-{label}-{}-{suffix}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).expect("create test directory");
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    struct CurrentDirectoryGuard(PathBuf);

    impl Drop for CurrentDirectoryGuard {
        fn drop(&mut self) {
            std::env::set_current_dir(&self.0).expect("restore current directory");
        }
    }

    #[derive(Debug)]
    struct CapturedProcessCreation {
        logon_flags: CREATE_PROCESS_LOGON_FLAGS,
        application_name: OsString,
        command_line: OsString,
        creation_flags: PROCESS_CREATION_FLAGS,
        current_directory: OsString,
        desktop_is_null: bool,
    }

    struct CapturingProcessCreationApi {
        captured: Mutex<Option<CapturedProcessCreation>>,
    }

    impl CapturingProcessCreationApi {
        fn new() -> Self {
            Self {
                captured: Mutex::new(None),
            }
        }
    }

    impl ProcessCreationApi for CapturingProcessCreationApi {
        fn create_process(
            &self,
            _token: HANDLE,
            logon_flags: CREATE_PROCESS_LOGON_FLAGS,
            application_name: *const u16,
            command_line: *mut u16,
            creation_flags: PROCESS_CREATION_FLAGS,
            _environment: *mut c_void,
            current_directory: *const u16,
            startup_info: *const STARTUPINFOW,
            _process_information: *mut PROCESS_INFORMATION,
        ) -> i32 {
            assert!(!application_name.is_null());
            assert!(!command_line.is_null());
            assert!(!current_directory.is_null());
            assert!(!startup_info.is_null());
            let desktop = unsafe { (*startup_info).lpDesktop };
            assert!(desktop.is_null());
            let captured = CapturedProcessCreation {
                logon_flags,
                application_name: unsafe { os_string_from_wide_pointer(application_name) },
                command_line: unsafe { os_string_from_wide_pointer(command_line) },
                creation_flags,
                current_directory: unsafe { os_string_from_wide_pointer(current_directory) },
                desktop_is_null: desktop.is_null(),
            };
            *self.captured.lock().expect("capture lock") = Some(captured);
            0
        }
    }

    struct FakePrivilegeRestorer(Result<(), SecurityError>);

    impl PrivilegeRestorer for FakePrivilegeRestorer {
        fn restore(self) -> Result<(), SecurityError> {
            self.0
        }
    }

    struct FakeCompensatableProcess {
        pid: u32,
        terminate_calls: Arc<AtomicU64>,
        wait_calls: Arc<AtomicU64>,
        drop_calls: Arc<AtomicU64>,
        terminate_result: Result<(), u32>,
        wait_result: Result<(), u32>,
    }

    impl CompensatableProcess for FakeCompensatableProcess {
        fn process_id(&self) -> u32 {
            self.pid
        }

        fn terminate_for_compensation(&self) -> TokenResult<()> {
            self.terminate_calls.fetch_add(1, Ordering::SeqCst);
            self.terminate_result.map_err(TokenError::Win32Error)
        }

        fn wait_for_compensation(&self) -> TokenResult<()> {
            self.wait_calls.fetch_add(1, Ordering::SeqCst);
            self.wait_result.map_err(TokenError::Win32Error)
        }
    }

    impl Drop for FakeCompensatableProcess {
        fn drop(&mut self) {
            self.drop_calls.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum CaptureStage {
        OpenProcess,
        OpenProcessToken,
        DuplicateToken,
    }

    struct CapturingTrustedInstallerApi {
        fail_at: Option<CaptureStage>,
        calls: Mutex<Vec<(CaptureStage, u32, u32)>>,
    }

    impl CapturingTrustedInstallerApi {
        fn new(fail_at: Option<CaptureStage>) -> Self {
            Self {
                fail_at,
                calls: Mutex::new(Vec::new()),
            }
        }

        fn record(
            &self,
            stage: CaptureStage,
            handle_or_pid: u32,
            desired_access: u32,
        ) -> Result<u32, u32> {
            self.calls.lock().expect("capture calls lock").push((
                stage,
                handle_or_pid,
                desired_access,
            ));
            if self.fail_at == Some(stage) {
                Err(5)
            } else {
                Ok(match stage {
                    CaptureStage::OpenProcess => 101,
                    CaptureStage::OpenProcessToken => 102,
                    CaptureStage::DuplicateToken => 103,
                })
            }
        }
    }

    impl TrustedInstallerCaptureApi for CapturingTrustedInstallerApi {
        type Handle = u32;

        fn open_process(&self, pid: u32, desired_access: u32) -> Result<Self::Handle, u32> {
            self.record(CaptureStage::OpenProcess, pid, desired_access)
        }

        fn open_process_token(
            &self,
            process: &Self::Handle,
            desired_access: u32,
        ) -> Result<Self::Handle, u32> {
            self.record(CaptureStage::OpenProcessToken, *process, desired_access)
        }

        fn duplicate_primary_token(
            &self,
            source_token: &Self::Handle,
            desired_access: u32,
        ) -> Result<Self::Handle, u32> {
            self.record(CaptureStage::DuplicateToken, *source_token, desired_access)
        }
    }

    struct CapturingTrustedInstallerServiceApi {
        manager_result: Result<u32, u32>,
        service_result: Result<u32, u32>,
        start_result: Result<(), u32>,
        statuses: Mutex<VecDeque<Result<SERVICE_STATUS_PROCESS, u32>>>,
        calls: Mutex<Vec<(&'static str, u32)>>,
        waits: AtomicU64,
    }

    impl CapturingTrustedInstallerServiceApi {
        fn with_statuses(statuses: Vec<Result<SERVICE_STATUS_PROCESS, u32>>) -> Self {
            Self {
                manager_result: Ok(201),
                service_result: Ok(202),
                start_result: Ok(()),
                statuses: Mutex::new(statuses.into()),
                calls: Mutex::new(Vec::new()),
                waits: AtomicU64::new(0),
            }
        }
    }

    impl TrustedInstallerServiceApi for CapturingTrustedInstallerServiceApi {
        type Handle = u32;

        fn open_manager(&self, desired_access: u32) -> Result<Self::Handle, u32> {
            self.calls
                .lock()
                .expect("service calls lock")
                .push(("manager", desired_access));
            self.manager_result
        }

        fn open_service(
            &self,
            _manager: &Self::Handle,
            service_name: &[u16],
            desired_access: u32,
        ) -> Result<Self::Handle, u32> {
            assert_eq!(service_name, to_wide_null(TRUSTED_INSTALLER_SERVICE));
            self.calls
                .lock()
                .expect("service calls lock")
                .push(("service", desired_access));
            self.service_result
        }

        fn start_service(&self, _service: &Self::Handle) -> Result<(), u32> {
            self.calls
                .lock()
                .expect("service calls lock")
                .push(("start", 0));
            self.start_result
        }

        fn query_status(&self, _service: &Self::Handle) -> Result<SERVICE_STATUS_PROCESS, u32> {
            self.calls
                .lock()
                .expect("service calls lock")
                .push(("query", 0));
            self.statuses
                .lock()
                .expect("service statuses lock")
                .pop_front()
                .expect("configured service status")
        }

        fn wait(&self, interval: Duration) {
            self.waits.fetch_add(1, Ordering::SeqCst);
            self.calls
                .lock()
                .expect("service calls lock")
                .push(("wait", interval.as_millis() as u32));
        }
    }

    fn service_status(
        state: u32,
        process_id: u32,
        win32_exit_code: u32,
        service_exit_code: u32,
    ) -> SERVICE_STATUS_PROCESS {
        SERVICE_STATUS_PROCESS {
            dwServiceType: 0,
            dwCurrentState: state,
            dwControlsAccepted: 0,
            dwWin32ExitCode: win32_exit_code,
            dwServiceSpecificExitCode: service_exit_code,
            dwCheckPoint: 0,
            dwWaitHint: 0,
            dwProcessId: process_id,
            dwServiceFlags: 0,
        }
    }

    struct FakeRequestSessionApi {
        current_process_id: u32,
        session_result: Result<u32, u32>,
        state_result: Result<WTS_CONNECTSTATE_CLASS, u32>,
        observed_process_ids: Mutex<Vec<u32>>,
        observed_session_ids: Mutex<Vec<u32>>,
    }

    impl FakeRequestSessionApi {
        fn new(
            current_process_id: u32,
            session_result: Result<u32, u32>,
            state_result: Result<WTS_CONNECTSTATE_CLASS, u32>,
        ) -> Self {
            Self {
                current_process_id,
                session_result,
                state_result,
                observed_process_ids: Mutex::new(Vec::new()),
                observed_session_ids: Mutex::new(Vec::new()),
            }
        }
    }

    impl RequestSessionApi for FakeRequestSessionApi {
        fn current_process_id(&self) -> u32 {
            self.current_process_id
        }

        fn process_session_id(&self, process_id: u32) -> TokenResult<u32> {
            self.observed_process_ids
                .lock()
                .expect("process observations lock")
                .push(process_id);
            self.session_result.map_err(TokenError::Win32Error)
        }

        fn session_connect_state(&self, session_id: u32) -> TokenResult<WTS_CONNECTSTATE_CLASS> {
            self.observed_session_ids
                .lock()
                .expect("session observations lock")
                .push(session_id);
            self.state_result.map_err(TokenError::Win32Error)
        }
    }

    unsafe fn os_string_from_wide_pointer(pointer: *const u16) -> OsString {
        let length = (0..32_768)
            .find(|index| unsafe { *pointer.add(*index) } == 0)
            .expect("wide string terminator");
        OsString::from_wide(unsafe { std::slice::from_raw_parts(pointer, length) })
    }

    #[test]
    fn requesting_process_session_wins_when_physical_console_differs() {
        let physical_console_session = 1u32;
        let requesting_process_session = 9u32;
        let api = FakeRequestSessionApi::new(4242, Ok(requesting_process_session), Ok(WTSActive));

        let result = get_requesting_process_session_with_api(&api);

        assert_eq!(result.expect("request session"), requesting_process_session);
        assert_ne!(requesting_process_session, physical_console_session);
        assert_eq!(
            *api.observed_process_ids
                .lock()
                .expect("process observations lock"),
            vec![4242]
        );
        assert_eq!(
            *api.observed_session_ids
                .lock()
                .expect("session observations lock"),
            vec![requesting_process_session]
        );
    }

    #[test]
    fn requesting_process_session_zero_is_rejected_before_state_query() {
        let api = FakeRequestSessionApi::new(4242, Ok(0), Ok(WTSActive));

        let result = get_requesting_process_session_with_api(&api);

        assert!(matches!(
            result,
            Err(TokenError::NonInteractiveRequestSession(0))
        ));
        assert!(api
            .observed_session_ids
            .lock()
            .expect("session observations lock")
            .is_empty());
    }

    #[test]
    fn requesting_process_session_lookup_error_fails_closed() {
        let api = FakeRequestSessionApi::new(4242, Err(5), Ok(WTSActive));

        let result = get_requesting_process_session_with_api(&api);

        assert!(matches!(result, Err(TokenError::Win32Error(5))));
        assert!(api
            .observed_session_ids
            .lock()
            .expect("session observations lock")
            .is_empty());
    }

    #[test]
    fn disconnected_requesting_process_session_is_rejected() {
        let api = FakeRequestSessionApi::new(
            4242,
            Ok(9),
            Ok(windows_sys::Win32::System::RemoteDesktop::WTSDisconnected),
        );

        let result = get_requesting_process_session_with_api(&api);

        assert!(matches!(
            result,
            Err(TokenError::RequestSessionNotConnected {
                session_id: 9,
                state,
            }) if state == windows_sys::Win32::System::RemoteDesktop::WTSDisconnected
        ));
    }

    #[test]
    fn connected_requesting_process_session_is_accepted() {
        let api = FakeRequestSessionApi::new(4242, Ok(9), Ok(WTSConnected));

        assert_eq!(
            get_requesting_process_session_with_api(&api).expect("connected request session"),
            9
        );
    }

    #[test]
    fn requesting_process_session_state_query_error_fails_closed() {
        let api = FakeRequestSessionApi::new(4242, Ok(9), Err(1722));

        assert!(matches!(
            get_requesting_process_session_with_api(&api),
            Err(TokenError::Win32Error(1722))
        ));
    }

    #[test]
    fn command_resolver_is_absolute_and_ignores_fake_current_directory_cmd() {
        let test_directory = TestDirectory::new("fake-cmd");
        let fake_command = test_directory.0.join(SYSTEM_COMMAND_NAME);
        File::create(&fake_command).expect("create fake command");
        let canonical_fake = std::fs::canonicalize(&fake_command).expect("canonical fake command");
        let _current_directory_lock = CURRENT_DIRECTORY_LOCK
            .lock()
            .expect("current directory lock");
        let original_directory = std::env::current_dir().expect("read current directory");
        std::env::set_current_dir(&test_directory.0).expect("set fake current directory");
        let _current_directory_guard = CurrentDirectoryGuard(original_directory);

        let spec = trustedinstaller_console_launch_spec().expect("resolve system command");

        assert!(spec.application_path().is_absolute());
        assert!(spec.application_path().is_file());
        assert_eq!(
            spec.application_path().file_name(),
            Some(OsStr::new(SYSTEM_COMMAND_NAME))
        );
        assert_ne!(spec.application_path(), canonical_fake);
        assert_eq!(
            spec.application_path().parent(),
            Some(spec.working_directory())
        );
    }

    #[test]
    fn trustedinstaller_capture_uses_exact_minimum_access_masks() {
        let api = CapturingTrustedInstallerApi::new(None);

        let token = capture_trustedinstaller_token_with_api(7331, &api)
            .expect("capture TrustedInstaller token");

        assert_eq!(token, 103);
        assert_eq!(
            *api.calls.lock().expect("capture calls lock"),
            vec![
                (
                    CaptureStage::OpenProcess,
                    7331,
                    PROCESS_QUERY_LIMITED_INFORMATION,
                ),
                (CaptureStage::OpenProcessToken, 101, TOKEN_DUPLICATE),
                (
                    CaptureStage::DuplicateToken,
                    102,
                    TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY,
                ),
            ]
        );
    }

    #[test]
    fn trustedinstaller_capture_reports_the_exact_failing_stage() {
        let stages = [
            (
                CaptureStage::OpenProcess,
                "OpenProcess for TrustedInstaller",
            ),
            (
                CaptureStage::OpenProcessToken,
                "OpenProcessToken for TrustedInstaller",
            ),
            (
                CaptureStage::DuplicateToken,
                "DuplicateTokenEx for TrustedInstaller",
            ),
        ];

        for (stage, operation) in stages {
            let api = CapturingTrustedInstallerApi::new(Some(stage));
            let result = capture_trustedinstaller_token_with_api(7331, &api);
            assert!(matches!(
                result,
                Err(TokenError::Win32Operation {
                    operation: actual_operation,
                    code: 5,
                }) if actual_operation == operation
            ));
        }
    }

    #[test]
    fn trustedinstaller_scm_uses_exact_masks_and_returns_running_pid() {
        let api = CapturingTrustedInstallerServiceApi::with_statuses(vec![Ok(service_status(
            SERVICE_RUNNING,
            7331,
            0,
            0,
        ))]);

        let pid = ensure_trustedinstaller_service_running_with_api(&api)
            .expect("TrustedInstaller running");

        assert_eq!(pid, 7331);
        assert_eq!(
            *api.calls.lock().expect("service calls lock"),
            vec![
                ("manager", SC_MANAGER_CONNECT),
                ("service", SERVICE_START | SERVICE_QUERY_STATUS),
                ("start", 0),
                ("query", 0),
            ]
        );
        assert_eq!(api.waits.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn trustedinstaller_scm_accepts_already_running_and_polls_transitional_states() {
        let mut api = CapturingTrustedInstallerServiceApi::with_statuses(vec![
            Ok(service_status(SERVICE_START_PENDING, 0, 0, 0)),
            Ok(service_status(SERVICE_CONTINUE_PENDING, 0, 0, 0)),
            Ok(service_status(SERVICE_RUNNING, 7331, 0, 0)),
        ]);
        api.start_result = Err(ERROR_SERVICE_ALREADY_RUNNING);

        let pid = ensure_trustedinstaller_service_running_with_api(&api)
            .expect("already running service reaches RUNNING");

        assert_eq!(pid, 7331);
        assert_eq!(api.waits.load(Ordering::SeqCst), 2);
        assert_eq!(
            *api.calls.lock().expect("service calls lock"),
            vec![
                ("manager", SC_MANAGER_CONNECT),
                ("service", SERVICE_START | SERVICE_QUERY_STATUS),
                ("start", 0),
                ("query", 0),
                ("wait", SERVICE_START_POLL_INTERVAL.as_millis() as u32),
                ("query", 0),
                ("wait", SERVICE_START_POLL_INTERVAL.as_millis() as u32),
                ("query", 0),
            ]
        );
    }

    #[test]
    fn trustedinstaller_scm_reports_the_exact_open_and_start_stage() {
        let cases = [
            ("manager", "OpenSCManagerW for TrustedInstaller"),
            ("service", "OpenServiceW for TrustedInstaller"),
            ("start", "StartServiceW for TrustedInstaller"),
        ];

        for (failing_stage, expected_operation) in cases {
            let mut api = CapturingTrustedInstallerServiceApi::with_statuses(vec![]);
            match failing_stage {
                "manager" => api.manager_result = Err(5),
                "service" => api.service_result = Err(5),
                "start" => api.start_result = Err(5),
                _ => unreachable!("test stage is exhaustive"),
            }

            let result = ensure_trustedinstaller_service_running_with_api(&api);
            assert!(matches!(
                result,
                Err(TokenError::Win32Operation {
                    operation,
                    code: 5,
                }) if operation == expected_operation
            ));
        }
    }

    #[test]
    fn trustedinstaller_query_status_error_keeps_stage_and_win32_code() {
        let api = CapturingTrustedInstallerServiceApi::with_statuses(vec![Err(5)]);

        let result = ensure_trustedinstaller_service_running_with_api(&api);

        assert!(matches!(
            result,
            Err(TokenError::Win32Operation {
                operation: "QueryServiceStatusEx for TrustedInstaller",
                code: 5,
            })
        ));
        assert_eq!(api.waits.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn trustedinstaller_terminal_service_state_is_diagnostic_and_not_retried() {
        let api = CapturingTrustedInstallerServiceApi::with_statuses(vec![Ok(service_status(
            windows_sys::Win32::System::Services::SERVICE_STOPPED,
            0,
            1066,
            73,
        ))]);

        let result = ensure_trustedinstaller_service_running_with_api(&api);

        assert!(matches!(
            result,
            Err(TokenError::TrustedInstallerServiceState {
                state,
                win32_exit_code: 1066,
                service_exit_code: 73,
                process_id: 0,
            }) if state == windows_sys::Win32::System::Services::SERVICE_STOPPED
        ));
        assert_eq!(api.waits.load(Ordering::SeqCst), 0);
    }

    #[test]
    #[ignore = "requires an elevated Windows VM and may start the TrustedInstaller service"]
    fn live_elevated_trustedinstaller_capture_and_duplicate_without_launch() {
        assert!(
            crate::security::is_process_elevated().expect("query process elevation"),
            "run this ignored oracle from an elevated test process"
        );

        let launch_token =
            duplicate_trustedinstaller_token().expect("capture and duplicate TrustedInstaller");
        let TrustedInstallerLaunchToken {
            token,
            impersonate_privilege,
        } = launch_token;
        assert!(!token.as_raw().is_null());
        drop(token);
        impersonate_privilege
            .restore()
            .expect("restore SeImpersonatePrivilege explicitly");
    }

    #[test]
    fn process_creation_uses_with_token_contract_and_inherits_caller_desktop() {
        let spec = ProcessLaunchSpec {
            application_path: PathBuf::from(r"C:\System Root\cmd.exe"),
            working_directory: PathBuf::from(r"C:\System Root"),
            arguments: vec![
                OsString::from("/k"),
                OsString::from("title"),
                OsString::from(TRUSTED_INSTALLER_CONSOLE_TITLE),
            ],
        };
        let api = CapturingProcessCreationApi::new();

        let result =
            create_process_with_api(std::ptr::null_mut(), &spec, std::ptr::null_mut(), &api);

        assert!(matches!(
            result,
            Err(TokenError::Win32Operation {
                operation: "CreateProcessWithTokenW for TrustedInstaller",
                ..
            })
        ));
        let captured = api.captured.lock().expect("capture lock");
        let captured = captured.as_ref().expect("captured process call");
        assert_eq!(captured.logon_flags, 0);
        assert_eq!(captured.application_name, spec.application_path.as_os_str());
        assert_eq!(captured.creation_flags, CREATE_UNICODE_ENVIRONMENT);
        assert_eq!(
            captured.current_directory,
            spec.working_directory.as_os_str()
        );
        assert!(captured.desktop_is_null);
        assert_eq!(
            captured.command_line,
            OsString::from(
                r#""C:\System Root\cmd.exe" /k title "TrustedInstaller Elevated Console""#
            )
        );
    }

    #[test]
    fn privilege_restore_failure_after_process_creation_compensates_and_closes() {
        let terminate_calls = Arc::new(AtomicU64::new(0));
        let wait_calls = Arc::new(AtomicU64::new(0));
        let drop_calls = Arc::new(AtomicU64::new(0));
        let process = FakeCompensatableProcess {
            pid: 7331,
            terminate_calls: Arc::clone(&terminate_calls),
            wait_calls: Arc::clone(&wait_calls),
            drop_calls: Arc::clone(&drop_calls),
            terminate_result: Ok(()),
            wait_result: Ok(()),
        };

        let result = finalize_process_privilege_restore(
            Ok(process),
            FakePrivilegeRestorer(Err(SecurityError::Win32Error(1300))),
        );

        assert!(matches!(
            result,
            Err(TokenError::PrivilegeRestoreCompensated {
                pid: 7331,
                restore_error,
            }) if restore_error.contains("1300")
        ));
        assert_eq!(terminate_calls.load(Ordering::SeqCst), 1);
        assert_eq!(wait_calls.load(Ordering::SeqCst), 1);
        assert_eq!(drop_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn partial_process_information_is_compensated_before_error() {
        let terminate_calls = Arc::new(AtomicU64::new(0));
        let wait_calls = Arc::new(AtomicU64::new(0));
        let drop_calls = Arc::new(AtomicU64::new(0));
        let process = FakeCompensatableProcess {
            pid: 8123,
            terminate_calls: Arc::clone(&terminate_calls),
            wait_calls: Arc::clone(&wait_calls),
            drop_calls: Arc::clone(&drop_calls),
            terminate_result: Ok(()),
            wait_result: Ok(()),
        };

        let result = validate_created_process_information(Some(process), false, 8123);

        assert!(matches!(
            result,
            Err(TokenError::InvalidProcessInformationCompensated(8123))
        ));
        assert_eq!(terminate_calls.load(Ordering::SeqCst), 1);
        assert_eq!(wait_calls.load(Ordering::SeqCst), 1);
        assert_eq!(drop_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn partial_process_information_compensation_failure_is_explicit() {
        let terminate_calls = Arc::new(AtomicU64::new(0));
        let wait_calls = Arc::new(AtomicU64::new(0));
        let drop_calls = Arc::new(AtomicU64::new(0));
        let process = FakeCompensatableProcess {
            pid: 8124,
            terminate_calls: Arc::clone(&terminate_calls),
            wait_calls: Arc::clone(&wait_calls),
            drop_calls: Arc::clone(&drop_calls),
            terminate_result: Err(5),
            wait_result: Err(1460),
        };

        let result = validate_created_process_information(Some(process), false, 8124);

        assert!(matches!(
            result,
            Err(TokenError::InvalidProcessInformationCompensationFailed {
                pid: 8124,
                compensation_error,
            }) if compensation_error.contains("5") && compensation_error.contains("1460")
        ));
        assert_eq!(terminate_calls.load(Ordering::SeqCst), 1);
        assert_eq!(wait_calls.load(Ordering::SeqCst), 1);
        assert_eq!(drop_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn missing_process_handle_contract_violation_is_explicit() {
        let result =
            validate_created_process_information::<FakeCompensatableProcess>(None, true, 8125);

        assert!(matches!(
            result,
            Err(TokenError::InvalidProcessInformationMissingProcessHandle {
                pid: 8125,
                thread_handle_present: true,
            })
        ));
    }

    #[test]
    fn privileged_launch_has_no_session_token_or_tcb_path() {
        let source = include_str!("tokens.rs");
        let forbidden = [
            ["CreateProcess", "AsUserW"].concat(),
            ["SetToken", "Information"].concat(),
            ["Token", "SessionId"].concat(),
            ["SE_", "TCB_NAME"].concat(),
            ["winsta0", "\\default"].concat(),
        ];

        for pattern in forbidden {
            assert!(
                !source.contains(&pattern),
                "forbidden path remains: {pattern}"
            );
        }
        assert!(source.contains(&["CreateProcess", "WithTokenW"].concat()));
    }
}

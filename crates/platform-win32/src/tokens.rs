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
    SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START,
    SERVICE_STATUS_PROCESS,
};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows_sys::Win32::System::Threading::{
    CreateProcessWithTokenW, GetCurrentProcessId, OpenProcess, OpenProcessToken, TerminateProcess,
    WaitForSingleObject, CREATE_PROCESS_LOGON_FLAGS, CREATE_UNICODE_ENVIRONMENT,
    PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, PROCESS_QUERY_INFORMATION, STARTUPINFOW,
};

use crate::handles::{OwnedEnvironmentBlock, OwnedHandle, OwnedScHandle};
use crate::registry::to_wide_null;
use crate::security::{PrivilegeGuard, SecurityError, SE_DEBUG_NAME, SE_IMPERSONATE_NAME};

pub const MAXIMUM_ALLOWED: u32 = 0x02000000;
const TRUSTED_INSTALLER_SERVICE: &str = "TrustedInstaller";
const SERVICE_START_POLL_ATTEMPTS: usize = 20;
const SERVICE_START_POLL_INTERVAL: Duration = Duration::from_millis(150);
const SYSTEM_COMMAND_NAME: &str = "cmd.exe";
const TRUSTED_INSTALLER_CONSOLE_TITLE: &str = "TrustedInstaller Elevated Console";
const INITIAL_SYSTEM_DIRECTORY_CAPACITY: usize = 260;
const PROCESS_COMPENSATION_EXIT_CODE: u32 = 1;
const PROCESS_COMPENSATION_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Error, Debug)]
pub enum TokenError {
    #[error("Token operation failed with Win32 error code: {0}")]
    Win32Error(u32),
    #[error("Process '{0}' not found")]
    ProcessNotFound(String),
    #[error("Service '{0}' failed to start")]
    ServiceStartFailed(String),
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
    let scm_handle =
        unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
    if scm_handle.is_null() {
        return Err(TokenError::Win32Error(unsafe { GetLastError() }));
    }
    let owned_scm = OwnedScHandle::from_raw(scm_handle)
        .ok_or_else(|| TokenError::Win32Error(unsafe { GetLastError() }))?;

    let wide_service_name = to_wide_null(TRUSTED_INSTALLER_SERVICE);
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
        return Err(TokenError::Win32Error(start_err));
    }

    // Wait until RUNNING
    let mut status: SERVICE_STATUS_PROCESS = unsafe { std::mem::zeroed() };
    let mut bytes_needed = 0;

    for _ in 0..SERVICE_START_POLL_ATTEMPTS {
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

        std::thread::sleep(SERVICE_START_POLL_INTERVAL);
    }

    Err(TokenError::ServiceStartFailed(
        TRUSTED_INSTALLER_SERVICE.to_string(),
    ))
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
    Ok(owned_dup)
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
            return Err(TokenError::Win32Error(unsafe { GetLastError() }));
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
        return Err(TokenError::Win32Error(unsafe { GetLastError() }));
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

        assert!(matches!(result, Err(TokenError::Win32Error(_))));
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

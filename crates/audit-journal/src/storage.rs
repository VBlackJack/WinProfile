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

//! Protected, handle-rooted storage for audit and rollback artifacts.
//!
//! The production constructor is intentionally separate from trusted test
//! injection. Production resolves ProgramData through the Known Folder API,
//! creates the product root with one exact protected DACL, and rejects an
//! existing legacy root instead of attempting to repair it in place.

use std::ffi::{c_void, OsStr, OsString};
use std::fs::File;
use std::io;
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Path, PathBuf};
use std::ptr::{addr_of, null, null_mut};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use platform_win32::{SecureDirectory, SecureFsError};
use thiserror::Error;
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    NtCreateFile, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN,
    FILE_OPEN_IF, FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
};
use windows_sys::Win32::Foundation::{
    CloseHandle, DuplicateHandle, LocalFree, DUPLICATE_SAME_ACCESS, ERROR_ALREADY_EXISTS,
    ERROR_SUCCESS, HANDLE, INVALID_HANDLE_VALUE, STATUS_OBJECT_NAME_COLLISION,
    STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND, STATUS_SHARING_VIOLATION,
    UNICODE_STRING,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, ConvertStringSidToSidW, GetSecurityInfo,
    SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    AclSizeInformation, EqualSid, GetAce, GetAclInformation, GetSecurityDescriptorControl,
    ACCESS_ALLOWED_ACE, ACL_SIZE_INFORMATION, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION,
    OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_ATTRIBUTES, SE_DACL_PROTECTED,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, FileDispositionInfo, GetFileInformationByHandle, MoveFileExW,
    SetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, DELETE, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_DISPOSITION_INFO, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_TRAVERSE, MOVEFILE_WRITE_THROUGH, OPEN_EXISTING, READ_CONTROL,
    SYNCHRONIZE,
};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, SECURITY_DESCRIPTOR_REVISION,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
use windows_sys::Win32::UI::Shell::{FOLDERID_ProgramData, SHGetKnownFolderPath};

const PRODUCT_DIRECTORY: &str = "WinProfile";
const STORAGE_LOCK_FILE: &str = ".storage.lock";
const OPERATION_LOCK_FILE: &str = ".operation.lock";
const ROOT_SDDL: &str = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
const SYSTEM_SID: &str = "S-1-5-18";
const ADMINISTRATORS_SID: &str = "S-1-5-32-544";
const OBJ_CASE_INSENSITIVE: u32 = 0x40;
const DIRECTORY_SHARES: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE;
const DIRECTORY_ACCESS: u32 =
    FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;
const DEFAULT_LOCK_TIMEOUT: Duration = Duration::from_secs(2);
const LOCK_RETRY_DELAY: Duration = Duration::from_millis(10);

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("storage IO error during {operation} for {path}: {source}")]
    Io {
        operation: &'static str,
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("native storage operation {operation} failed for {path}: NTSTATUS {status:#010x}")]
    Native {
        operation: &'static str,
        path: String,
        status: i32,
    },
    #[error("legacy storage is insecure and was left unchanged: {0}")]
    LegacyStorageInsecure(String),
    #[error("storage lock timed out after {0:?}")]
    LockTimeout(Duration),
    #[error("invalid storage component: {0}")]
    InvalidComponent(String),
    #[error("secure filesystem validation failed: {0}")]
    SecureFs(#[from] SecureFsError),
    #[error("Known Folder ProgramData resolution failed with HRESULT {0:#010x}")]
    KnownFolder(i32),
    #[error("storage cleanup failed after {operation_error}: {cleanup_error}")]
    CleanupFailed {
        operation_error: String,
        cleanup_error: String,
    },
}

pub type StorageResult<T> = Result<T, StorageError>;

impl StorageError {
    pub(crate) fn is_not_found(&self) -> bool {
        matches!(
            self,
            Self::Native { status, .. }
                if *status == STATUS_OBJECT_NAME_NOT_FOUND || *status == STATUS_OBJECT_PATH_NOT_FOUND
        )
    }

    pub(crate) fn is_collision(&self) -> bool {
        matches!(
            self,
            Self::Native { status, .. } if *status == STATUS_OBJECT_NAME_COLLISION
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct FileIdentity {
    pub volume_serial: u32,
    pub file_index: u64,
}

#[derive(Debug)]
struct StorageHandle(HANDLE);

// Windows kernel handles may be used and closed from any thread. Access to
// mutable file content is separately serialized by the exclusive lock handle.
unsafe impl Send for StorageHandle {}
unsafe impl Sync for StorageHandle {}

impl StorageHandle {
    fn new(raw: HANDLE, operation: &'static str, path: &Path) -> StorageResult<Self> {
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            Err(io_error(operation, path))
        } else {
            Ok(Self(raw))
        }
    }

    fn raw(&self) -> HANDLE {
        self.0
    }

    fn duplicate(&self, operation: &'static str, path: &Path) -> StorageResult<Self> {
        let process = unsafe { GetCurrentProcess() };
        let mut duplicate = null_mut();
        let success = unsafe {
            DuplicateHandle(
                process,
                self.0,
                process,
                &mut duplicate,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        };
        if success == 0 {
            return Err(io_error(operation, path));
        }
        Self::new(duplicate, operation, path)
    }

    fn into_file(self) -> File {
        let raw = self.0;
        std::mem::forget(self);
        unsafe { File::from_raw_handle(raw.cast()) }
    }
}

impl Drop for StorageHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct StorageDirectory {
    handle: StorageHandle,
    path: PathBuf,
}

impl StorageDirectory {
    fn duplicate(&self) -> StorageResult<Self> {
        Ok(Self {
            handle: self
                .handle
                .duplicate("duplicate storage directory", &self.path)?,
            path: self.path.clone(),
        })
    }

    fn open_child(&self, name: &OsStr) -> StorageResult<Self> {
        let path = child_path(&self.path, name)?;
        let handle = nt_open_relative(
            self.handle.raw(),
            name,
            &path,
            DIRECTORY_ACCESS,
            DIRECTORY_SHARES,
            FILE_OPEN,
            FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
        )?;
        validate_kind(&handle, &path, true)?;
        Ok(Self { handle, path })
    }

    fn open_or_create_child(&self, name: &OsStr) -> StorageResult<Self> {
        match self.open_child(name) {
            Ok(directory) => Ok(directory),
            Err(StorageError::Native { status, .. })
                if status == STATUS_OBJECT_NAME_NOT_FOUND
                    || status == STATUS_OBJECT_PATH_NOT_FOUND =>
            {
                let path = child_path(&self.path, name)?;
                let handle = nt_open_relative(
                    self.handle.raw(),
                    name,
                    &path,
                    DIRECTORY_ACCESS,
                    DIRECTORY_SHARES,
                    FILE_CREATE,
                    FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                )?;
                validate_kind(&handle, &path, true)?;
                Ok(Self { handle, path })
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) fn open_file(&self, name: &OsStr, access: u32, share: u32) -> StorageResult<File> {
        let path = child_path(&self.path, name)?;
        let handle = nt_open_relative(
            self.handle.raw(),
            name,
            &path,
            access | SYNCHRONIZE,
            share,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
        )?;
        validate_kind(&handle, &path, false)?;
        Ok(handle.into_file())
    }

    pub(crate) fn create_file(
        &self,
        name: &OsStr,
        share: u32,
    ) -> StorageResult<CreatedStorageFile> {
        let path = child_path(&self.path, name)?;
        let handle = nt_open_relative(
            self.handle.raw(),
            name,
            &path,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE | SYNCHRONIZE,
            share,
            FILE_CREATE,
            FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
        )?;
        if let Err(error) = validate_kind(&handle, &path, false) {
            let _ = delete_by_handle(&handle, &path);
            return Err(error);
        }
        let cleanup_handle = match handle.duplicate("duplicate created file handle", &path) {
            Ok(handle) => handle,
            Err(operation_error) => {
                return match delete_by_handle(&handle, &path) {
                    Ok(()) => Err(operation_error),
                    Err(cleanup_error) => Err(StorageError::CleanupFailed {
                        operation_error: operation_error.to_string(),
                        cleanup_error: cleanup_error.to_string(),
                    }),
                };
            }
        };
        Ok(CreatedStorageFile {
            file: Some(handle.into_file()),
            cleanup_handle: Some(cleanup_handle),
            path,
        })
    }

    pub(crate) fn entries(&self) -> StorageResult<Vec<OsString>> {
        let secure = SecureDirectory::open_absolute_existing(&self.path)?;
        Ok(secure
            .entries()?
            .into_iter()
            .map(|entry| entry.name)
            .collect())
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn child_path(&self, name: &str) -> StorageResult<PathBuf> {
        child_path(&self.path, OsStr::new(name))
    }

    pub(crate) fn remove_file_if_exists(&self, name: &str) -> StorageResult<bool> {
        let path = child_path(&self.path, OsStr::new(name))?;
        let handle = match nt_open_relative(
            self.handle.raw(),
            OsStr::new(name),
            &path,
            DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            0,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
        ) {
            Ok(handle) => handle,
            Err(error) if error.is_not_found() => return Ok(false),
            Err(error) => return Err(error),
        };
        validate_kind(&handle, &path, false)?;
        delete_by_handle(&handle, &path)?;
        Ok(true)
    }
}

/// A create-new file which deletes the exact created object unless committed.
#[derive(Debug)]
pub(crate) struct CreatedStorageFile {
    file: Option<File>,
    cleanup_handle: Option<StorageHandle>,
    path: PathBuf,
}

impl CreatedStorageFile {
    pub(crate) fn file_mut(&mut self) -> &mut File {
        self.file.as_mut().expect("created file remains present")
    }

    pub(crate) fn commit(mut self) -> File {
        self.cleanup_handle.take();
        self.file.take().expect("created file remains present")
    }

    pub(crate) fn rollback(mut self) -> StorageResult<()> {
        let result = match self.cleanup_handle.take() {
            Some(handle) => delete_by_handle(&handle, &self.path),
            None => Ok(()),
        };
        self.file.take();
        result
    }
}

impl Drop for CreatedStorageFile {
    fn drop(&mut self) {
        if let Some(handle) = self.cleanup_handle.as_ref() {
            let _ = delete_by_handle(handle, &self.path);
        }
    }
}

#[derive(Debug)]
pub(crate) struct StorageLock {
    _handle: StorageHandle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StorageTrust {
    Production,
    TrustedInjection,
}

/// Shared storage anchor. The production root handle remains open for the
/// lifetime of every logger and snapshot engine built from it.
#[derive(Debug)]
pub(crate) struct StorageRoot {
    directory: StorageDirectory,
    trust: StorageTrust,
}

impl StorageRoot {
    pub(crate) fn production() -> StorageResult<Arc<Self>> {
        let program_data = resolve_program_data_with(&KnownFolderProgramData)?;
        Self::production_at(&program_data)
    }

    fn production_at(program_data: &Path) -> StorageResult<Arc<Self>> {
        let root_path = program_data.join(PRODUCT_DIRECTORY);
        create_protected_root_if_missing(&root_path)?;
        let directory = open_absolute_directory(&root_path)?;
        validate_production_root(&directory.handle, &root_path)?;
        Ok(Arc::new(Self {
            directory,
            trust: StorageTrust::Production,
        }))
    }

    /// Explicitly trusted injection for tests. It never participates in the
    /// production Known Folder path and still refuses every reparse component.
    pub(crate) fn trusted(path: &Path) -> StorageResult<Arc<Self>> {
        let (directory, created) = SecureDirectory::open_or_create_absolute(path)?;
        drop(directory);
        drop(created);
        let directory = open_absolute_directory(path)?;
        Ok(Arc::new(Self {
            directory,
            trust: StorageTrust::TrustedInjection,
        }))
    }

    pub(crate) fn root_directory(&self) -> StorageResult<StorageDirectory> {
        self.revalidate()?;
        self.directory.duplicate()
    }

    pub(crate) fn open_or_create_directory(&self, name: &str) -> StorageResult<StorageDirectory> {
        self.revalidate()?;
        self.directory.open_or_create_child(OsStr::new(name))
    }

    pub(crate) fn open_file(&self, name: &str, access: u32, share: u32) -> StorageResult<File> {
        self.revalidate()?;
        self.directory.open_file(OsStr::new(name), access, share)
    }

    pub(crate) fn create_file(&self, name: &str, share: u32) -> StorageResult<CreatedStorageFile> {
        self.revalidate()?;
        self.directory.create_file(OsStr::new(name), share)
    }

    pub(crate) fn child_path(&self, name: &str) -> StorageResult<PathBuf> {
        child_path(&self.directory.path, OsStr::new(name))
    }

    pub(crate) fn remove_file_if_exists(&self, name: &str) -> StorageResult<bool> {
        self.revalidate()?;
        self.directory.remove_file_if_exists(name)
    }

    pub(crate) fn durable_rename(&self, source: &str, target: &str) -> StorageResult<()> {
        self.revalidate()?;
        drop(self.directory.open_file(
            OsStr::new(source),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        )?);
        match self.directory.open_file(
            OsStr::new(target),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        ) {
            Ok(_) => {
                return Err(StorageError::Native {
                    operation: "durable rename target collision",
                    path: self.directory.child_path(target)?.display().to_string(),
                    status: STATUS_OBJECT_NAME_COLLISION,
                });
            }
            Err(error) if error.is_not_found() => {}
            Err(error) => return Err(error),
        }
        let source_path = self.directory.child_path(source)?;
        let target_path = self.directory.child_path(target)?;
        let source_wide = wide_null(source_path.as_os_str());
        let target_wide = wide_null(target_path.as_os_str());
        if unsafe {
            MoveFileExW(
                source_wide.as_ptr(),
                target_wide.as_ptr(),
                MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            return Err(io_error("durable storage rename", &source_path));
        }
        Ok(())
    }

    pub(crate) fn acquire_lock(&self) -> StorageResult<StorageLock> {
        self.acquire_named_lock(STORAGE_LOCK_FILE, DEFAULT_LOCK_TIMEOUT)
    }

    pub(crate) fn acquire_operation_lock(&self) -> StorageResult<StorageLock> {
        self.acquire_named_lock(OPERATION_LOCK_FILE, DEFAULT_LOCK_TIMEOUT)
    }

    #[cfg(test)]
    pub(crate) fn acquire_operation_lock_with_timeout(
        &self,
        timeout: Duration,
    ) -> StorageResult<StorageLock> {
        self.acquire_named_lock(OPERATION_LOCK_FILE, timeout)
    }

    fn acquire_named_lock(&self, name: &str, timeout: Duration) -> StorageResult<StorageLock> {
        self.revalidate()?;
        let start = Instant::now();
        loop {
            let path = child_path(&self.directory.path, OsStr::new(name))?;
            match nt_open_relative(
                self.directory.handle.raw(),
                OsStr::new(name),
                &path,
                FILE_GENERIC_READ | FILE_GENERIC_WRITE | SYNCHRONIZE,
                0,
                FILE_OPEN_IF,
                FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            ) {
                Ok(handle) => {
                    validate_kind(&handle, &path, false)?;
                    return Ok(StorageLock { _handle: handle });
                }
                Err(StorageError::Native { status, .. }) if status == STATUS_SHARING_VIOLATION => {
                    if start.elapsed() >= timeout {
                        return Err(StorageError::LockTimeout(timeout));
                    }
                    thread::sleep(LOCK_RETRY_DELAY.min(timeout.saturating_sub(start.elapsed())));
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn revalidate(&self) -> StorageResult<()> {
        validate_kind(&self.directory.handle, &self.directory.path, true)?;
        if self.trust == StorageTrust::Production {
            validate_production_root(&self.directory.handle, &self.directory.path)?;
        }
        Ok(())
    }
}

trait ProgramDataResolver {
    fn resolve(&self) -> StorageResult<PathBuf>;
}

struct KnownFolderProgramData;

impl ProgramDataResolver for KnownFolderProgramData {
    fn resolve(&self) -> StorageResult<PathBuf> {
        resolve_known_folder_program_data()
    }
}

fn resolve_program_data_with(resolver: &dyn ProgramDataResolver) -> StorageResult<PathBuf> {
    resolver.resolve()
}

fn resolve_known_folder_program_data() -> StorageResult<PathBuf> {
    let mut raw = null_mut();
    let status = unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramData, 0, null_mut(), &mut raw) };
    if status < 0 {
        if !raw.is_null() {
            unsafe { CoTaskMemFree(raw.cast()) };
        }
        return Err(StorageError::KnownFolder(status));
    }
    if raw.is_null() {
        return Err(StorageError::KnownFolder(0x8000_4005_u32 as i32));
    }
    let length = unsafe {
        let mut length = 0usize;
        while *raw.add(length) != 0 {
            length += 1;
        }
        length
    };
    let path = PathBuf::from(OsString::from_wide(unsafe {
        std::slice::from_raw_parts(raw, length)
    }));
    unsafe { CoTaskMemFree(raw.cast()) };
    Ok(path)
}

fn create_protected_root_if_missing(path: &Path) -> StorageResult<()> {
    let sddl = wide_null(OsStr::new(ROOT_SDDL));
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SECURITY_DESCRIPTOR_REVISION,
            &mut descriptor,
            null_mut(),
        )
    };
    if converted == 0 {
        return Err(io_error("parse protected root SDDL", path));
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let wide_path = wide_null(path.as_os_str());
    let created = unsafe { CreateDirectoryW(wide_path.as_ptr(), &attributes) };
    let error = io::Error::last_os_error();
    unsafe {
        LocalFree(descriptor.cast());
    }
    if created == 0 && error.raw_os_error() != Some(ERROR_ALREADY_EXISTS as i32) {
        return Err(StorageError::Io {
            operation: "create protected storage root",
            path: path.display().to_string(),
            source: error,
        });
    }
    Ok(())
}

fn open_absolute_directory(path: &Path) -> StorageResult<StorageDirectory> {
    let wide = wide_null(path.as_os_str());
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            DIRECTORY_ACCESS,
            DIRECTORY_SHARES,
            null(),
            OPEN_EXISTING,
            windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS
                | windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    let handle = StorageHandle::new(raw, "open storage root", path)?;
    validate_kind(&handle, path, true)?;
    Ok(StorageDirectory {
        handle,
        path: path.to_path_buf(),
    })
}

fn validate_production_root(handle: &StorageHandle, path: &Path) -> StorageResult<()> {
    let mut owner: PSID = null_mut();
    let mut dacl = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    let status = unsafe {
        GetSecurityInfo(
            handle.raw(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        if !descriptor.is_null() {
            unsafe {
                LocalFree(descriptor.cast());
            }
        }
        return Err(StorageError::Io {
            operation: "read storage root security descriptor",
            path: path.display().to_string(),
            source: io::Error::from_raw_os_error(status as i32),
        });
    }
    let validation = validate_descriptor(descriptor, owner, dacl, path);
    unsafe {
        LocalFree(descriptor.cast());
    }
    validation
}

fn validate_descriptor(
    descriptor: PSECURITY_DESCRIPTOR,
    owner: PSID,
    dacl: *mut windows_sys::Win32::Security::ACL,
    path: &Path,
) -> StorageResult<()> {
    if descriptor.is_null() || owner.is_null() || dacl.is_null() {
        return Err(legacy(path, "owner or DACL is missing"));
    }
    let mut control = 0u16;
    let mut revision = 0u32;
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
        return Err(io_error("inspect storage DACL control", path));
    }
    if control & SE_DACL_PROTECTED == 0 {
        return Err(legacy(path, "DACL inheritance is not protected"));
    }

    let system_sid = LocalSid::parse(SYSTEM_SID, path)?;
    let administrators_sid = LocalSid::parse(ADMINISTRATORS_SID, path)?;
    let owner_allowed = unsafe {
        EqualSid(owner, system_sid.raw()) != 0 || EqualSid(owner, administrators_sid.raw()) != 0
    };
    if !owner_allowed {
        return Err(legacy(path, "owner is neither SYSTEM nor Administrators"));
    }

    let mut information: ACL_SIZE_INFORMATION = unsafe { zeroed() };
    if unsafe {
        GetAclInformation(
            dacl,
            (&mut information as *mut ACL_SIZE_INFORMATION).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(io_error("inspect storage DACL", path));
    }
    if information.AceCount != 2 {
        return Err(legacy(
            path,
            "DACL must contain exactly SYSTEM and Administrators ACEs",
        ));
    }

    let mut system_seen = false;
    let mut administrators_seen = false;
    for index in 0..information.AceCount {
        let mut raw_ace = null_mut();
        if unsafe { GetAce(dacl, index, &mut raw_ace) } == 0 {
            return Err(io_error("read storage DACL ACE", path));
        }
        let ace = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
        if ace.Header.AceType != ACCESS_ALLOWED_ACE_TYPE as u8
            || ace.Mask != windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS
            || ace.Header.AceFlags != (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8
        {
            return Err(legacy(path, "DACL contains a non-canonical allow ACE"));
        }
        let sid = addr_of!(ace.SidStart).cast_mut().cast::<c_void>();
        if unsafe { EqualSid(sid, system_sid.raw()) } != 0 {
            system_seen = true;
        } else if unsafe { EqualSid(sid, administrators_sid.raw()) } != 0 {
            administrators_seen = true;
        } else {
            return Err(legacy(path, "DACL grants access to a third-party SID"));
        }
    }
    if !system_seen || !administrators_seen {
        return Err(legacy(path, "SYSTEM or Administrators ACE is missing"));
    }
    Ok(())
}

struct LocalSid(PSID);

impl LocalSid {
    fn parse(value: &str, path: &Path) -> StorageResult<Self> {
        let wide = wide_null(OsStr::new(value));
        let mut sid = null_mut();
        if unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut sid) } == 0 {
            return Err(io_error("parse expected storage SID", path));
        }
        Ok(Self(sid))
    }

    fn raw(&self) -> PSID {
        self.0
    }
}

impl Drop for LocalSid {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0.cast());
        }
    }
}

fn nt_open_relative(
    parent: HANDLE,
    name: &OsStr,
    path: &Path,
    desired_access: u32,
    share_access: u32,
    disposition: u32,
    options: u32,
) -> StorageResult<StorageHandle> {
    validate_component(name)?;
    let mut wide: Vec<u16> = name.encode_wide().collect();
    let byte_length = wide
        .len()
        .checked_mul(size_of::<u16>())
        .and_then(|length| u16::try_from(length).ok())
        .ok_or_else(|| StorageError::InvalidComponent(name.to_string_lossy().to_string()))?;
    let unicode = UNICODE_STRING {
        Length: byte_length,
        MaximumLength: byte_length,
        Buffer: wide.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent,
        ObjectName: &unicode,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: null(),
        SecurityQualityOfService: null(),
    };
    let mut raw = null_mut();
    let mut io_status: IO_STATUS_BLOCK = unsafe { zeroed() };
    let status = unsafe {
        NtCreateFile(
            &mut raw,
            desired_access,
            &attributes,
            &mut io_status,
            null(),
            0,
            share_access,
            disposition,
            options,
            null(),
            0,
        )
    };
    if status < 0 {
        return Err(StorageError::Native {
            operation: "open relative storage object",
            path: path.display().to_string(),
            status,
        });
    }
    StorageHandle::new(raw, "open relative storage object", path)
}

fn validate_kind(handle: &StorageHandle, path: &Path, directory: bool) -> StorageResult<()> {
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
    if unsafe { GetFileInformationByHandle(handle.raw(), &mut info) } == 0 {
        return Err(io_error("validate storage object by handle", path));
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(legacy(path, "reparse points are forbidden"));
    }
    let is_directory = info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
    if is_directory != directory {
        return Err(legacy(path, "storage object has the wrong type"));
    }
    Ok(())
}

pub(crate) fn file_identity(file: &File, path: &Path) -> StorageResult<FileIdentity> {
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &mut info) } == 0 {
        return Err(io_error("read storage file identity", path));
    }
    Ok(FileIdentity {
        volume_serial: info.dwVolumeSerialNumber,
        file_index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    })
}

pub(crate) fn delete_open_file(file: &File, path: &Path) -> StorageResult<()> {
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: 1 };
    if unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle().cast(),
            FileDispositionInfo,
            (&disposition as *const FILE_DISPOSITION_INFO).cast(),
            size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    } == 0
    {
        return Err(io_error("delete open storage file by handle", path));
    }
    Ok(())
}

fn delete_by_handle(handle: &StorageHandle, path: &Path) -> StorageResult<()> {
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: 1 };
    if unsafe {
        SetFileInformationByHandle(
            handle.raw(),
            FileDispositionInfo,
            (&disposition as *const FILE_DISPOSITION_INFO).cast(),
            size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    } == 0
    {
        return Err(io_error("delete storage object by handle", path));
    }
    Ok(())
}

fn child_path(parent: &Path, name: &OsStr) -> StorageResult<PathBuf> {
    validate_component(name)?;
    Ok(parent.join(name))
}

fn validate_component(name: &OsStr) -> StorageResult<()> {
    let text = name.to_string_lossy();
    if text.is_empty()
        || text == "."
        || text == ".."
        || text.contains(['\\', '/'])
        || text.contains(':')
        || text.contains('\0')
    {
        return Err(StorageError::InvalidComponent(text.to_string()));
    }
    Ok(())
}

fn wide_null(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

fn legacy(path: &Path, reason: &str) -> StorageError {
    StorageError::LegacyStorageInsecure(format!("{}: {reason}", path.display()))
}

fn io_error(operation: &'static str, path: &Path) -> StorageError {
    StorageError::Io {
        operation,
        path: path.display().to_string(),
        source: io::Error::last_os_error(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use windows_sys::Win32::Security::{
        AccessCheck, CheckTokenMembership, DuplicateToken, GetSecurityDescriptorDacl,
        GetSecurityDescriptorOwner, SecurityImpersonation, GENERIC_MAPPING, PRIVILEGE_SET,
        TOKEN_DUPLICATE, TOKEN_QUERY,
    };
    use windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_EXECUTE;
    use windows_sys::Win32::System::Threading::OpenProcessToken;

    struct FakeResolver(PathBuf);

    impl ProgramDataResolver for FakeResolver {
        fn resolve(&self) -> StorageResult<PathBuf> {
            Ok(self.0.clone())
        }
    }

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "winprofile-storage-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).expect("create temporary directory");
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn exclusive_lock_is_process_wide_and_released_on_drop() {
        let temp = TestDirectory::new();
        let first = StorageRoot::trusted(&temp.0).expect("first root");
        let second = StorageRoot::trusted(&temp.0).expect("second root");
        let held = first.acquire_lock().expect("first lock");
        assert!(matches!(
            second.acquire_named_lock(STORAGE_LOCK_FILE, Duration::from_millis(30)),
            Err(StorageError::LockTimeout(_))
        ));
        drop(held);
        second.acquire_lock().expect("lock after release");
    }

    #[test]
    fn anchored_root_and_child_cannot_be_deleted_while_handles_live() {
        let temp = TestDirectory::new();
        let root_path = temp.0.join("root");
        let storage = StorageRoot::trusted(&root_path).expect("root");
        let child = storage
            .open_or_create_directory("Snapshots")
            .expect("child");
        assert!(std::fs::remove_dir(child.path()).is_err());
        assert!(std::fs::remove_dir(&root_path).is_err());
        drop(child);
        std::fs::remove_dir(root_path.join("Snapshots")).expect("child after handle closes");
        drop(storage);
        std::fs::remove_dir(&root_path).expect("root after handle closes");
    }

    #[test]
    fn resolver_seam_ignores_hostile_program_data_environment() {
        let temp = TestDirectory::new();
        let hostile = temp.0.join("hostile");
        let expected = temp.0.join("known-folder-result");
        let previous = std::env::var_os("ProgramData");
        std::env::set_var("ProgramData", &hostile);
        let resolved =
            resolve_program_data_with(&FakeResolver(expected.clone())).expect("resolver result");
        match previous {
            Some(value) => std::env::set_var("ProgramData", value),
            None => std::env::remove_var("ProgramData"),
        }
        assert_eq!(resolved, expected);
        assert_ne!(resolved, hostile);
    }

    #[test]
    fn permissive_precreated_production_root_is_rejected_without_mutation() {
        let temp = TestDirectory::new();
        let root = temp.0.join(PRODUCT_DIRECTORY);
        std::fs::create_dir(&root).expect("legacy root");
        let sentinel = root.join("sentinel.bin");
        std::fs::write(&sentinel, b"unchanged").expect("sentinel");
        let result = StorageRoot::production_at(&temp.0);
        assert!(matches!(
            result,
            Err(StorageError::LegacyStorageInsecure(_))
        ));
        assert_eq!(
            std::fs::read(sentinel).expect("sentinel bytes"),
            b"unchanged"
        );
    }

    #[test]
    fn hostile_journal_inside_legacy_root_is_never_opened_or_changed() {
        let temp = TestDirectory::new();
        let root = temp.0.join(PRODUCT_DIRECTORY);
        std::fs::create_dir(&root).expect("legacy root");
        let hostile_log = root.join("audit_log.jsonl");
        std::fs::write(&hostile_log, b"forged\n").expect("hostile journal");
        assert!(matches!(
            StorageRoot::production_at(&temp.0),
            Err(StorageError::LegacyStorageInsecure(_))
        ));
        assert_eq!(
            std::fs::read(hostile_log).expect("journal bytes"),
            b"forged\n"
        );
    }

    #[test]
    fn root_and_child_junctions_are_refused_without_touching_target() {
        let temp = TestDirectory::new();
        let target = temp.0.join("target");
        std::fs::create_dir(&target).expect("junction target");
        let sentinel = target.join("sentinel.bin");
        std::fs::write(&sentinel, b"untouched").expect("sentinel");

        let root_junction = temp.0.join("root-junction");
        let root_status = std::process::Command::new("cmd.exe")
            .args([
                "/d",
                "/c",
                "mklink",
                "/J",
                &root_junction.display().to_string(),
                &target.display().to_string(),
            ])
            .status()
            .expect("create root junction");
        assert!(root_status.success());
        assert!(StorageRoot::trusted(&root_junction).is_err());
        std::fs::remove_dir(&root_junction).expect("remove root junction");

        let safe_root = temp.0.join("safe-root");
        let storage = StorageRoot::trusted(&safe_root).expect("safe root");
        let child_junction = safe_root.join("Snapshots");
        let child_status = std::process::Command::new("cmd.exe")
            .args([
                "/d",
                "/c",
                "mklink",
                "/J",
                &child_junction.display().to_string(),
                &target.display().to_string(),
            ])
            .status()
            .expect("create child junction");
        assert!(child_status.success());
        assert!(storage.open_or_create_directory("Snapshots").is_err());
        std::fs::remove_dir(&child_junction).expect("remove child junction");
        assert_eq!(
            std::fs::read(sentinel).expect("sentinel bytes"),
            b"untouched"
        );
    }

    #[test]
    fn canonical_sddl_passes_exact_parser() {
        let wide = wide_null(OsStr::new(ROOT_SDDL));
        let mut descriptor = null_mut();
        assert_ne!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    wide.as_ptr(),
                    SECURITY_DESCRIPTOR_REVISION,
                    &mut descriptor,
                    null_mut(),
                )
            },
            0
        );
        let mut owner = null_mut();
        let mut owner_defaulted = 0;
        let mut dacl = null_mut();
        let mut dacl_present = 0;
        let mut dacl_defaulted = 0;
        assert_ne!(
            unsafe { GetSecurityDescriptorOwner(descriptor, &mut owner, &mut owner_defaulted) },
            0
        );
        assert_ne!(
            unsafe {
                GetSecurityDescriptorDacl(
                    descriptor,
                    &mut dacl_present,
                    &mut dacl,
                    &mut dacl_defaulted,
                )
            },
            0
        );
        validate_descriptor(descriptor, owner, dacl, Path::new("test")).expect("exact DACL");
        unsafe {
            LocalFree(descriptor.cast());
        }
    }

    #[test]
    fn canonical_parser_rejects_inherit_only_and_no_propagate_flags() {
        for sddl in [
            "O:BAG:BAD:P(A;OICIIO;FA;;;SY)(A;OICI;FA;;;BA)",
            "O:BAG:BAD:P(A;OICINP;FA;;;SY)(A;OICI;FA;;;BA)",
        ] {
            let wide = wide_null(OsStr::new(sddl));
            let mut descriptor = null_mut();
            assert_ne!(
                unsafe {
                    ConvertStringSecurityDescriptorToSecurityDescriptorW(
                        wide.as_ptr(),
                        SECURITY_DESCRIPTOR_REVISION,
                        &mut descriptor,
                        null_mut(),
                    )
                },
                0
            );
            let mut owner = null_mut();
            let mut owner_defaulted = 0;
            let mut dacl = null_mut();
            let mut dacl_present = 0;
            let mut dacl_defaulted = 0;
            assert_ne!(
                unsafe { GetSecurityDescriptorOwner(descriptor, &mut owner, &mut owner_defaulted) },
                0
            );
            assert_ne!(
                unsafe {
                    GetSecurityDescriptorDacl(
                        descriptor,
                        &mut dacl_present,
                        &mut dacl,
                        &mut dacl_defaulted,
                    )
                },
                0
            );
            assert!(matches!(
                validate_descriptor(descriptor, owner, dacl, Path::new("test")),
                Err(StorageError::LegacyStorageInsecure(_))
            ));
            unsafe {
                LocalFree(descriptor.cast());
            }
        }
    }

    #[test]
    fn canonical_sddl_access_check_matches_admin_or_system_membership() {
        let wide = wide_null(OsStr::new(ROOT_SDDL));
        let mut descriptor = null_mut();
        assert_ne!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    wide.as_ptr(),
                    SECURITY_DESCRIPTOR_REVISION,
                    &mut descriptor,
                    null_mut(),
                )
            },
            0
        );
        let mut primary = null_mut();
        assert_ne!(
            unsafe {
                OpenProcessToken(
                    GetCurrentProcess(),
                    TOKEN_QUERY | TOKEN_DUPLICATE,
                    &mut primary,
                )
            },
            0
        );
        let primary = StorageHandle::new(primary, "test process token", Path::new("test"))
            .expect("primary token");
        let mut impersonation = null_mut();
        assert_ne!(
            unsafe { DuplicateToken(primary.raw(), SecurityImpersonation, &mut impersonation) },
            0
        );
        let impersonation =
            StorageHandle::new(impersonation, "test impersonation token", Path::new("test"))
                .expect("impersonation token");

        let system = LocalSid::parse(SYSTEM_SID, Path::new("test")).expect("system SID");
        let administrators =
            LocalSid::parse(ADMINISTRATORS_SID, Path::new("test")).expect("administrators SID");
        let mut system_member = 0;
        let mut administrators_member = 0;
        assert_ne!(
            unsafe { CheckTokenMembership(impersonation.raw(), system.raw(), &mut system_member) },
            0
        );
        assert_ne!(
            unsafe {
                CheckTokenMembership(
                    impersonation.raw(),
                    administrators.raw(),
                    &mut administrators_member,
                )
            },
            0
        );

        let mapping = GENERIC_MAPPING {
            GenericRead: FILE_GENERIC_READ,
            GenericWrite: FILE_GENERIC_WRITE,
            GenericExecute: FILE_GENERIC_EXECUTE,
            GenericAll: windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS,
        };
        let mut privileges: PRIVILEGE_SET = unsafe { zeroed() };
        let mut privilege_bytes = size_of::<PRIVILEGE_SET>() as u32;
        let mut granted = 0u32;
        let mut allowed = 0;
        assert_ne!(
            unsafe {
                AccessCheck(
                    descriptor,
                    impersonation.raw(),
                    FILE_READ_ATTRIBUTES,
                    &mapping,
                    &mut privileges,
                    &mut privilege_bytes,
                    &mut granted,
                    &mut allowed,
                )
            },
            0
        );
        assert_eq!(
            allowed != 0,
            system_member != 0 || administrators_member != 0
        );
        if allowed != 0 {
            assert_eq!(granted & FILE_READ_ATTRIBUTES, FILE_READ_ATTRIBUTES);
        }
        unsafe {
            LocalFree(descriptor.cast());
        }
    }
}

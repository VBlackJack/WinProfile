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

//! Handle-rooted filesystem primitives for privileged operations.
//!
//! Every path component after the volume/share root is opened relative to the
//! already verified parent handle. `FILE_OPEN_REPARSE_POINT` prevents the final
//! component from being followed, and the opened object is then checked by
//! handle before it can be used.

use std::ffi::{c_void, OsStr, OsString};
use std::fs::File;
use std::io;
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::FromRawHandle;
use std::path::{Component, Path, PathBuf};
use std::ptr::{addr_of, null, null_mut};

use thiserror::Error;
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    NtCreateFile, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN,
    FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
};
use windows_sys::Win32::Foundation::{
    HANDLE, STATUS_FILE_IS_A_DIRECTORY, STATUS_NOT_A_DIRECTORY, STATUS_OBJECT_NAME_COLLISION,
    STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND, UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FileAttributeTagInfo, FileDispositionInfo, FileIdBothDirectoryInfo,
    FileIdBothDirectoryRestartInfo, GetFileInformationByHandle, GetFileInformationByHandleEx,
    SetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, DELETE, FILE_ADD_FILE,
    FILE_ADD_SUBDIRECTORY, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO, FILE_DELETE_CHILD,
    FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_ID_BOTH_DIR_INFO, FILE_LIST_DIRECTORY,
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE,
    OPEN_EXISTING, SYNCHRONIZE,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

use crate::OwnedHandle;

const OBJ_CASE_INSENSITIVE: u32 = 0x40;
const DIRECTORY_BUFFER_BYTES: usize = 64 * 1024;
const ALL_FILE_SHARES: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
const DIRECTORY_READ_ACCESS: u32 =
    FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
const DIRECTORY_WRITE_ACCESS: u32 = DIRECTORY_READ_ACCESS
    | FILE_ADD_FILE
    | FILE_ADD_SUBDIRECTORY
    | FILE_DELETE_CHILD
    | FILE_GENERIC_WRITE;

#[derive(Error, Debug)]
pub enum SecureFsError {
    #[error("invalid absolute filesystem path: {0}")]
    InvalidPath(String),
    #[error("filesystem entry was not found: {0}")]
    NotFound(String),
    #[error("filesystem entry already exists: {0}")]
    AlreadyExists(String),
    #[error("reparse point refused on opened object: {0}")]
    ReparsePoint(String),
    #[error("Windows filesystem operation '{operation}' failed for {path}: {source}")]
    Io {
        operation: &'static str,
        path: String,
        #[source]
        source: io::Error,
    },
    #[error(
        "native filesystem operation '{operation}' failed for {path}: NTSTATUS {status:#010x}"
    )]
    Native {
        operation: &'static str,
        path: String,
        status: i32,
    },
    #[error("secure filesystem rollback failed after '{operation_error}': {rollback_error}")]
    Rollback {
        operation_error: String,
        rollback_error: String,
    },
}

pub type SecureFsResult<T> = Result<T, SecureFsError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureEntryKind {
    File,
    Directory,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureDirEntry {
    pub name: OsString,
    pub kind: SecureEntryKind,
}

/// A handle to the exact object created by a secure operation.
///
/// Rollback deletes this object by handle, so a later rename or path swap
/// cannot redirect cleanup to another filesystem entry.
#[derive(Debug)]
pub struct SecureCreatedEntry {
    handle: OwnedHandle,
    display_path: PathBuf,
}

/// Armed immediately after `FILE_CREATE`; deletes the exact opened object on
/// every early return until ownership has been transferred to the transaction.
struct PendingCreatedHandle {
    handle: Option<OwnedHandle>,
    display_path: PathBuf,
    armed: bool,
}

impl PendingCreatedHandle {
    fn new(handle: OwnedHandle, display_path: PathBuf) -> Self {
        Self {
            handle: Some(handle),
            display_path,
            armed: true,
        }
    }

    fn handle(&self) -> &OwnedHandle {
        self.handle
            .as_ref()
            .expect("pending created handle is always present while armed")
    }

    fn fail<T>(mut self, operation_error: SecureFsError) -> SecureFsResult<T> {
        let rollback = delete_open_handle(self.handle(), &self.display_path);
        self.armed = false;
        drop(self.handle.take());
        match rollback {
            Ok(()) => Err(operation_error),
            Err(rollback_error) => Err(SecureFsError::Rollback {
                operation_error: operation_error.to_string(),
                rollback_error: rollback_error.to_string(),
            }),
        }
    }

    fn commit(mut self) -> OwnedHandle {
        self.armed = false;
        self.handle
            .take()
            .expect("pending created handle is present at commit")
    }
}

impl Drop for PendingCreatedHandle {
    fn drop(&mut self) {
        if self.armed {
            if let Some(handle) = self.handle.as_ref() {
                let _ = delete_open_handle(handle, &self.display_path);
            }
        }
    }
}

impl SecureCreatedEntry {
    /// Marks the object for deletion and consumes the handle so it is closed
    /// before rollback proceeds to the parent directory.
    pub fn remove(self) -> SecureFsResult<()> {
        delete_open_handle(&self.handle, &self.display_path)
    }
}

#[derive(Debug)]
pub struct SecureDirectory {
    handle: OwnedHandle,
    display_path: PathBuf,
    ancestry: Vec<FileIdentity>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    volume_serial: u32,
    file_index: u64,
}

impl SecureDirectory {
    /// Opens an existing absolute directory one component at a time.
    pub fn open_absolute_existing(path: &Path) -> SecureFsResult<Self> {
        Self::open_absolute(path, false).map(|(directory, _)| directory)
    }

    /// Opens or creates an absolute destination one component at a time.
    ///
    /// Newly created components are returned as exact-object handles for the
    /// caller's transaction. If traversal fails, this function removes any
    /// components it created before returning the error.
    pub fn open_or_create_absolute(path: &Path) -> SecureFsResult<(Self, Vec<SecureCreatedEntry>)> {
        Self::open_absolute(path, true)
    }

    fn open_absolute(
        path: &Path,
        create_missing: bool,
    ) -> SecureFsResult<(Self, Vec<SecureCreatedEntry>)> {
        let (root_path, components) = split_absolute(path)?;
        let mut current = open_volume_or_share_root(&root_path)?;
        let mut created = Vec::new();

        for component in components {
            let next = if create_missing {
                current.open_or_create_directory(&component)
            } else {
                current
                    .open_directory(&component)
                    .map(|directory| (directory, None))
            };
            match next {
                Ok((directory, created_entry)) => {
                    if let Some(entry) = created_entry {
                        created.push(entry);
                    }
                    current = directory;
                }
                Err(error) => {
                    let operation_error = error.to_string();
                    drop(current);
                    if let Some(rollback_error) = rollback_created(created) {
                        return Err(SecureFsError::Rollback {
                            operation_error,
                            rollback_error,
                        });
                    }
                    return Err(error);
                }
            }
        }

        Ok((current, created))
    }

    pub fn open_directory(&self, name: &OsStr) -> SecureFsResult<Self> {
        let path = child_display_path(&self.display_path, name)?;
        let (handle, _) = nt_open_relative(
            self.handle.as_raw(),
            name,
            &path,
            DIRECTORY_READ_ACCESS,
            ALL_FILE_SHARES,
            FILE_OPEN,
            FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
        )?;
        reject_reparse_handle(&handle, &path)?;
        let mut ancestry = self.ancestry.clone();
        ancestry.push(file_identity(&handle, &path)?);
        Ok(Self {
            handle,
            display_path: path,
            ancestry,
        })
    }

    pub fn open_or_create_directory(
        &self,
        name: &OsStr,
    ) -> SecureFsResult<(Self, Option<SecureCreatedEntry>)> {
        let path = child_display_path(&self.display_path, name)?;
        match self.open_directory(name) {
            Ok(directory) => return Ok((directory, None)),
            Err(SecureFsError::NotFound(_)) => {}
            Err(error) => return Err(error),
        }

        let create_result = nt_open_relative(
            self.handle.as_raw(),
            name,
            &path,
            DIRECTORY_WRITE_ACCESS | DELETE,
            ALL_FILE_SHARES,
            FILE_CREATE,
            FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
        );
        let (handle, _) = match create_result {
            Ok(result) => result,
            Err(SecureFsError::AlreadyExists(_)) => {
                return match self.open_directory(name) {
                    Ok(_) => Err(SecureFsError::AlreadyExists(path.display().to_string())),
                    Err(error) => Err(error),
                };
            }
            Err(error) => return Err(error),
        };
        let pending = PendingCreatedHandle::new(handle, path.clone());
        let identity = match reject_reparse_handle(pending.handle(), &path)
            .and_then(|()| file_identity(pending.handle(), &path))
        {
            Ok(identity) => identity,
            Err(error) => return pending.fail(error),
        };
        let rollback_handle = match pending.handle().try_clone() {
            Ok(rollback_handle) => rollback_handle,
            Err(source) => {
                let error = SecureFsError::Io {
                    operation: "duplicate created directory handle",
                    path: path.display().to_string(),
                    source,
                };
                return pending.fail(error);
            }
        };
        let handle = pending.commit();
        let created = SecureCreatedEntry {
            handle: rollback_handle,
            display_path: path.clone(),
        };
        let mut ancestry = self.ancestry.clone();
        ancestry.push(identity);
        Ok((
            Self {
                handle,
                display_path: path,
                ancestry,
            },
            Some(created),
        ))
    }

    pub fn open_file(&self, name: &OsStr) -> SecureFsResult<File> {
        let path = child_display_path(&self.display_path, name)?;
        let (handle, _) = nt_open_relative(
            self.handle.as_raw(),
            name,
            &path,
            FILE_GENERIC_READ | SYNCHRONIZE,
            FILE_SHARE_READ,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
        )?;
        reject_reparse_handle(&handle, &path)?;
        Ok(handle_into_file(handle))
    }

    pub fn create_file(&self, name: &OsStr) -> SecureFsResult<(File, SecureCreatedEntry)> {
        let path = child_display_path(&self.display_path, name)?;
        let created = nt_open_relative(
            self.handle.as_raw(),
            name,
            &path,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE | SYNCHRONIZE,
            FILE_SHARE_READ,
            FILE_CREATE,
            FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
        );
        let (handle, _) = match created {
            Ok(result) => result,
            Err(SecureFsError::AlreadyExists(_)) => {
                match nt_open_relative(
                    self.handle.as_raw(),
                    name,
                    &path,
                    FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                    ALL_FILE_SHARES,
                    FILE_OPEN,
                    FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                ) {
                    Ok((existing, _)) => reject_reparse_handle(&existing, &path)?,
                    Err(SecureFsError::NotFound(_)) => {}
                    Err(error) => return Err(error),
                }
                return Err(SecureFsError::AlreadyExists(path.display().to_string()));
            }
            Err(error) => return Err(error),
        };
        let pending = PendingCreatedHandle::new(handle, path.clone());
        if let Err(error) = reject_reparse_handle(pending.handle(), &path) {
            return pending.fail(error);
        }
        let rollback_handle = match pending.handle().try_clone() {
            Ok(rollback_handle) => rollback_handle,
            Err(source) => {
                let error = SecureFsError::Io {
                    operation: "duplicate created file handle",
                    path: path.display().to_string(),
                    source,
                };
                return pending.fail(error);
            }
        };
        let handle = pending.commit();
        Ok((
            handle_into_file(handle),
            SecureCreatedEntry {
                handle: rollback_handle,
                display_path: path,
            },
        ))
    }

    /// Enumerates the directory represented by this handle, never by path.
    pub fn entries(&self) -> SecureFsResult<Vec<SecureDirEntry>> {
        let word_count = DIRECTORY_BUFFER_BYTES.div_ceil(size_of::<usize>());
        let mut entries = Vec::new();
        let mut restart = true;

        loop {
            let mut buffer = vec![0usize; word_count];
            let information_class = if restart {
                FileIdBothDirectoryRestartInfo
            } else {
                FileIdBothDirectoryInfo
            };
            let success = unsafe {
                GetFileInformationByHandleEx(
                    self.handle.as_raw(),
                    information_class,
                    buffer.as_mut_ptr().cast::<c_void>(),
                    DIRECTORY_BUFFER_BYTES as u32,
                )
            };
            if success == 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(18) {
                    break;
                }
                return Err(SecureFsError::Io {
                    operation: "enumerate directory by handle",
                    path: self.display_path.display().to_string(),
                    source: error,
                });
            }

            parse_directory_buffer(
                buffer.as_ptr().cast::<u8>(),
                DIRECTORY_BUFFER_BYTES,
                &self.display_path,
                &mut entries,
            )?;
            restart = false;
        }

        entries.sort_by_key(|entry| entry.name.to_string_lossy().to_lowercase());
        Ok(entries)
    }

    /// Compares the identity of each root against the securely opened ancestry
    /// of the other. This remains valid across DOS aliases and SUBST drives.
    pub fn overlaps(&self, other: &Self) -> bool {
        let self_identity = self.ancestry.last();
        let other_identity = other.ancestry.last();
        self_identity.is_some_and(|identity| other.ancestry.contains(identity))
            || other_identity.is_some_and(|identity| self.ancestry.contains(identity))
    }
}

fn split_absolute(path: &Path) -> SecureFsResult<(PathBuf, Vec<OsString>)> {
    let mut iter = path.components();
    let prefix = match iter.next() {
        Some(Component::Prefix(prefix)) => prefix,
        _ => return Err(SecureFsError::InvalidPath(path.display().to_string())),
    };
    if !matches!(iter.next(), Some(Component::RootDir)) {
        return Err(SecureFsError::InvalidPath(path.display().to_string()));
    }

    let mut root = PathBuf::from(prefix.as_os_str());
    root.push(Path::new(r"\"));
    let mut components = Vec::new();
    for component in iter {
        match component {
            Component::Normal(name) => components.push(name.to_os_string()),
            _ => return Err(SecureFsError::InvalidPath(path.display().to_string())),
        }
    }
    Ok((root, components))
}

fn open_volume_or_share_root(path: &Path) -> SecureFsResult<SecureDirectory> {
    let wide = wide_null(path.as_os_str());
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            DIRECTORY_READ_ACCESS,
            ALL_FILE_SHARES,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    let handle =
        OwnedHandle::from_raw(raw).ok_or_else(|| win32_error("open volume or share root", path))?;
    reject_reparse_handle(&handle, path)?;
    let identity = file_identity(&handle, path)?;
    Ok(SecureDirectory {
        handle,
        display_path: path.to_path_buf(),
        ancestry: vec![identity],
    })
}

fn nt_open_relative(
    parent: HANDLE,
    name: &OsStr,
    display_path: &Path,
    desired_access: u32,
    share_access: u32,
    disposition: u32,
    options: u32,
) -> SecureFsResult<(OwnedHandle, usize)> {
    validate_component(name, display_path)?;
    let mut wide: Vec<u16> = name.encode_wide().collect();
    let byte_length = wide
        .len()
        .checked_mul(size_of::<u16>())
        .and_then(|length| u16::try_from(length).ok())
        .ok_or_else(|| SecureFsError::InvalidPath(display_path.display().to_string()))?;
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
            FILE_ATTRIBUTE_NORMAL,
            share_access,
            disposition,
            options,
            null(),
            0,
        )
    };
    if status < 0 {
        return Err(nt_error(
            "open relative to directory handle",
            display_path,
            status,
        ));
    }
    let handle = OwnedHandle::from_raw(raw).ok_or_else(|| SecureFsError::Native {
        operation: "open relative to directory handle",
        path: display_path.display().to_string(),
        status,
    })?;
    Ok((handle, io_status.Information))
}

fn reject_reparse_handle(handle: &OwnedHandle, path: &Path) -> SecureFsResult<()> {
    let mut information: FILE_ATTRIBUTE_TAG_INFO = unsafe { zeroed() };
    let success = unsafe {
        GetFileInformationByHandleEx(
            handle.as_raw(),
            FileAttributeTagInfo,
            (&mut information as *mut FILE_ATTRIBUTE_TAG_INFO).cast::<c_void>(),
            size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    };
    if success == 0 {
        return Err(win32_error("inspect opened object attributes", path));
    }
    if information.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(SecureFsError::ReparsePoint(path.display().to_string()));
    }
    Ok(())
}

fn file_identity(handle: &OwnedHandle, path: &Path) -> SecureFsResult<FileIdentity> {
    let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
    let success = unsafe { GetFileInformationByHandle(handle.as_raw(), &mut information) };
    if success == 0 {
        return Err(win32_error("read opened object identity", path));
    }
    Ok(FileIdentity {
        volume_serial: information.dwVolumeSerialNumber,
        file_index: (u64::from(information.nFileIndexHigh) << 32)
            | u64::from(information.nFileIndexLow),
    })
}

fn parse_directory_buffer(
    buffer: *const u8,
    buffer_bytes: usize,
    directory: &Path,
    entries: &mut Vec<SecureDirEntry>,
) -> SecureFsResult<()> {
    let mut offset = 0usize;
    loop {
        if offset + size_of::<FILE_ID_BOTH_DIR_INFO>() > buffer_bytes {
            return Err(SecureFsError::InvalidPath(format!(
                "invalid directory enumeration for {}",
                directory.display()
            )));
        }
        let information = unsafe { &*buffer.add(offset).cast::<FILE_ID_BOTH_DIR_INFO>() };
        let name_pointer = addr_of!(information.FileName).cast::<u16>();
        let header_bytes = name_pointer as usize - (information as *const _ as usize);
        let name_bytes = information.FileNameLength as usize;
        if !name_bytes.is_multiple_of(size_of::<u16>())
            || offset + header_bytes + name_bytes > buffer_bytes
        {
            return Err(SecureFsError::InvalidPath(format!(
                "invalid directory entry returned for {}",
                directory.display()
            )));
        }
        let name_units =
            unsafe { std::slice::from_raw_parts(name_pointer, name_bytes / size_of::<u16>()) };
        let name = OsString::from_wide(name_units);
        if name != OsStr::new(".") && name != OsStr::new("..") {
            let path = directory.join(&name);
            if information.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(SecureFsError::ReparsePoint(path.display().to_string()));
            }
            let kind = if information.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
                SecureEntryKind::Directory
            } else {
                SecureEntryKind::File
            };
            entries.push(SecureDirEntry { name, kind });
        }

        if information.NextEntryOffset == 0 {
            break;
        }
        let next = information.NextEntryOffset as usize;
        if next < header_bytes || offset + next >= buffer_bytes {
            return Err(SecureFsError::InvalidPath(format!(
                "invalid directory enumeration offset for {}",
                directory.display()
            )));
        }
        offset += next;
    }
    Ok(())
}

fn validate_component(name: &OsStr, display_path: &Path) -> SecureFsResult<()> {
    let path = Path::new(name);
    let mut components = path.components();
    if name.is_empty()
        || !matches!(components.next(), Some(Component::Normal(_)))
        || components.next().is_some()
        || name.encode_wide().any(|unit| unit == b':' as u16)
    {
        return Err(SecureFsError::InvalidPath(
            display_path.display().to_string(),
        ));
    }
    Ok(())
}

fn child_display_path(parent: &Path, name: &OsStr) -> SecureFsResult<PathBuf> {
    let path = parent.join(name);
    validate_component(name, &path)?;
    Ok(path)
}

fn handle_into_file(handle: OwnedHandle) -> File {
    let raw = handle.into_raw();
    unsafe { File::from_raw_handle(raw) }
}

fn delete_open_handle(handle: &OwnedHandle, path: &Path) -> SecureFsResult<()> {
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: 1 };
    let removed = unsafe {
        SetFileInformationByHandle(
            handle.as_raw(),
            FileDispositionInfo,
            (&disposition as *const FILE_DISPOSITION_INFO).cast::<c_void>(),
            size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    };
    if removed == 0 {
        return Err(win32_error("delete by handle", path));
    }
    Ok(())
}

fn rollback_created(mut entries: Vec<SecureCreatedEntry>) -> Option<String> {
    let mut first_error = None;
    while let Some(entry) = entries.pop() {
        if let Err(error) = entry.remove() {
            if first_error.is_none() {
                first_error = Some(error.to_string());
            }
        }
    }
    first_error
}

fn wide_null(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

fn win32_error(operation: &'static str, path: &Path) -> SecureFsError {
    SecureFsError::Io {
        operation,
        path: path.display().to_string(),
        source: io::Error::last_os_error(),
    }
}

fn nt_error(operation: &'static str, path: &Path, status: i32) -> SecureFsError {
    if status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND {
        SecureFsError::NotFound(path.display().to_string())
    } else if status == STATUS_OBJECT_NAME_COLLISION {
        SecureFsError::AlreadyExists(path.display().to_string())
    } else if status == STATUS_NOT_A_DIRECTORY || status == STATUS_FILE_IS_A_DIRECTORY {
        SecureFsError::InvalidPath(path.display().to_string())
    } else {
        SecureFsError::Native {
            operation,
            path: path.display().to_string(),
            status,
        }
    }
}

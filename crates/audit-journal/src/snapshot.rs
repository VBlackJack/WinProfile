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

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::fs::File;
use std::io::Write;
use std::os::windows::fs::FileExt;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use thiserror::Error;
use windows_sys::Win32::Foundation::NTSTATUS;
use windows_sys::Win32::Security::Cryptography::{
    BCryptCloseAlgorithmProvider, BCryptCreateHash, BCryptDestroyHash, BCryptFinishHash,
    BCryptGetProperty, BCryptHashData, BCryptOpenAlgorithmProvider, BCRYPT_ALG_HANDLE,
    BCRYPT_HASH_HANDLE, BCRYPT_OBJECT_LENGTH, BCRYPT_SHA256_ALGORITHM,
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_GENERIC_READ, FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
};
use windows_sys::Win32::System::Registry::KEY_READ;

use platform_win32::{
    open_key, save_key, PrivilegeGuard, RegistryError, RegistryRoot, SE_BACKUP_NAME,
    SE_RESTORE_NAME,
};

use crate::storage::{
    delete_open_file, file_identity, CreatedStorageFile, FileIdentity, StorageDirectory,
    StorageError, StorageRoot,
};
use crate::ProductionStorage;

const SNAPSHOT_DIR: &str = "Snapshots";
const HASH_BUFFER_BYTES: usize = 64 * 1024;
static SNAPSHOT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Error, Debug)]
pub enum SnapshotError {
    #[error("Snapshot IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Registry error during snapshot: {0}")]
    RegistryError(#[from] RegistryError),
    #[error("Security privilege error: {0}")]
    SecurityError(#[from] platform_win32::SecurityError),
    #[error("Protected storage error: {0}")]
    StorageError(#[from] StorageError),
    #[error("snapshot file already exists: {0}")]
    Collision(String),
    #[error("snapshot save failed ({save_error}) and partial cleanup failed ({cleanup_error})")]
    SaveCleanupFailed {
        save_error: String,
        cleanup_error: String,
    },
    #[error(
        "Snapshot metadata failed ({metadata_error}) and hive cleanup failed ({cleanup_error})"
    )]
    CleanupFailed {
        metadata_error: String,
        cleanup_error: String,
    },
    #[error(
        "post-save validation failed ({operation_error}) and hive cleanup failed ({cleanup_error})"
    )]
    PostSaveCleanupFailed {
        operation_error: String,
        cleanup_error: String,
    },
    #[error(
        "privilege restoration failed ({restore_error}) and snapshot cleanup was incomplete: {cleanup_errors}"
    )]
    PrivilegeRestoreCleanupFailed {
        restore_error: String,
        cleanup_errors: String,
    },
    #[error(
        "snapshot operation failed ({operation_error}) and privilege restoration also failed ({restore_error})"
    )]
    OperationAndPrivilegeRestoreFailed {
        operation_error: String,
        restore_error: String,
    },
    #[error("snapshot inventory entry {metadata_file} is inconsistent: {reason}")]
    InvalidInventory {
        metadata_file: String,
        reason: String,
    },
    #[error("Windows CNG operation {operation} failed with NTSTATUS {status:#010x}")]
    HashError {
        operation: &'static str,
        status: NTSTATUS,
    },
}

pub type SnapshotResult<T> = Result<T, SnapshotError>;

/// Non-serializable proof binding a repair transaction to the exact open hive
/// file. Its share mode permits reads only and therefore blocks mutation and
/// deletion until the transaction ends.
#[derive(Debug)]
pub(crate) struct ProtectedSnapshotArtifact {
    pub(crate) file: Arc<File>,
    pub(crate) path: PathBuf,
    pub(crate) identity: FileIdentity,
}

impl ProtectedSnapshotArtifact {
    pub(crate) fn file(&self) -> &File {
        &self.file
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn identity(&self) -> FileIdentity {
        self.identity
    }
}

/// Metadata describing a pre-repair transactional snapshot. The serialized
/// form is inventory only: it deliberately omits the protected live handle and
/// contains no absolute path that rollback could trust.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotMetadata {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub sid: String,
    pub profile_path: String,
    pub registry_key_path: String,
    pub snapshot_file_name: String,
    pub sha256: String,
    pub file_volume_serial: u32,
    pub file_index: u64,
    pub reason: String,
    #[serde(skip, default)]
    pub(crate) protected_artifact: Option<Arc<ProtectedSnapshotArtifact>>,
}

impl SnapshotMetadata {
    pub(crate) fn artifact(&self) -> Option<&ProtectedSnapshotArtifact> {
        self.protected_artifact.as_deref()
    }
}

/// Snapshot engine responsible for capturing point-in-time system state.
pub struct SnapshotEngine {
    storage: Arc<StorageRoot>,
    directory: StorageDirectory,
}

impl SnapshotEngine {
    /// Builds the snapshot engine from the exact production storage token
    /// already approved by startup recovery.
    pub fn from_storage(storage: &ProductionStorage) -> SnapshotResult<Self> {
        let root = Arc::clone(&storage.root);
        let directory = root.open_or_create_directory(SNAPSHOT_DIR)?;
        Ok(Self {
            storage: root,
            directory,
        })
    }

    #[cfg(test)]
    pub(crate) fn storage_token(&self) -> *const StorageRoot {
        Arc::as_ptr(&self.storage)
    }

    /// Initializes production storage through FOLDERID_ProgramData, or a
    /// separately trusted test injection when an explicit directory is given.
    pub fn new(custom_dir: Option<PathBuf>) -> SnapshotResult<Self> {
        let (storage, directory) = match custom_dir {
            Some(path) => {
                let storage = StorageRoot::trusted(&path)?;
                let directory = storage.root_directory()?;
                (storage, directory)
            }
            None => {
                let storage = StorageRoot::production()?;
                let directory = storage.open_or_create_directory(SNAPSHOT_DIR)?;
                (storage, directory)
            }
        };
        Ok(Self { storage, directory })
    }

    /// Captures a binary export snapshot of a registry key under HKLM.
    pub fn create_registry_snapshot(
        &self,
        subkey: &str,
        sid: &str,
        profile_path: &str,
        reason: &str,
    ) -> SnapshotResult<SnapshotMetadata> {
        let _storage_lock = self.storage.acquire_lock()?;
        let privileges = PrivilegeGuard::new(&[SE_BACKUP_NAME, SE_RESTORE_NAME])?;
        let operation = (|| -> SnapshotResult<(SnapshotMetadata, CreatedStorageFile)> {
            let timestamp = Utc::now();
            let safe_sid = sid.replace(['\\', ':'], "_");
            let sequence = SNAPSHOT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let filename = format!(
                "snap_{}_{}_{}_{}.hiv",
                timestamp.format("%Y%m%dT%H%M%S%.6fZ"),
                std::process::id(),
                sequence,
                safe_sid
            );
            let snapshot_path = self.directory.child_path(&filename)?;

            match self.directory.open_file(
                OsStr::new(&filename),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ,
            ) {
                Ok(_) => return Err(SnapshotError::Collision(filename)),
                Err(error) if error.is_not_found() => {}
                Err(error) => return Err(error.into()),
            }

            let hkey = open_key(RegistryRoot::LocalMachine, subkey, KEY_READ)?;
            if let Err(save_error) = save_key(&hkey, &snapshot_path) {
                return Err(cleanup_after_failed_save(
                    &self.directory,
                    &filename,
                    save_error,
                ));
            }

            let artifact_result = (|| -> SnapshotResult<_> {
                let file = self.directory.open_file(
                    OsStr::new(&filename),
                    FILE_GENERIC_READ | FILE_READ_ATTRIBUTES | DELETE,
                    FILE_SHARE_READ,
                )?;
                let identity = file_identity(&file, &snapshot_path)?;
                let digest = sha256_file(&file)?;
                let artifact = Arc::new(ProtectedSnapshotArtifact {
                    file: Arc::new(file),
                    path: snapshot_path,
                    identity,
                });
                Ok((artifact, identity, digest))
            })();
            let (artifact, identity, digest) = match artifact_result {
                Ok(result) => result,
                Err(error) => {
                    return Err(cleanup_after_post_save_error(
                        &self.directory,
                        &filename,
                        error,
                    ));
                }
            };
            let metadata = SnapshotMetadata {
                id: format!(
                    "{}_{}_{}",
                    timestamp.timestamp_micros(),
                    std::process::id(),
                    sequence
                ),
                timestamp,
                sid: sid.to_string(),
                profile_path: profile_path.to_string(),
                registry_key_path: format!("HKLM\\{subkey}"),
                snapshot_file_name: filename.clone(),
                sha256: digest,
                file_volume_serial: identity.volume_serial,
                file_index: identity.file_index,
                reason: reason.to_string(),
                protected_artifact: Some(artifact),
            };

            let metadata_name = format!("{filename}.json");
            let mut created = match self
                .directory
                .create_file(OsStr::new(&metadata_name), FILE_SHARE_READ)
            {
                Ok(created) => created,
                Err(error) => {
                    return Err(cleanup_after_metadata_error(metadata, None, error.into()));
                }
            };
            let metadata_result = (|| -> SnapshotResult<()> {
                serde_json::to_writer_pretty(created.file_mut(), &metadata)
                    .map_err(|error| std::io::Error::other(error.to_string()))?;
                created.file_mut().flush()?;
                created.file_mut().sync_all()?;
                Ok(())
            })();
            if let Err(error) = metadata_result {
                return Err(cleanup_after_metadata_error(metadata, Some(created), error));
            }
            Ok((metadata, created))
        })();
        let restore_result = privileges.restore();
        finish_snapshot_operation(operation, restore_result)
    }

    /// Lists inventory metadata only. Deserialized entries intentionally have
    /// no transactional artifact handle and therefore cannot be restored.
    pub fn list_snapshots(&self) -> SnapshotResult<Vec<SnapshotMetadata>> {
        let _storage_lock = self.storage.acquire_lock()?;
        let mut results = Vec::new();
        for name in self.directory.entries()? {
            let Some(name) = name.to_str() else {
                continue;
            };
            if !name.ends_with(".json") {
                continue;
            }
            let file =
                self.directory
                    .open_file(OsStr::new(name), FILE_GENERIC_READ, FILE_SHARE_READ)?;
            let metadata = serde_json::from_reader::<_, SnapshotMetadata>(file)
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            validate_inventory_entry(&self.directory, name, &metadata)?;
            results.push(metadata);
        }
        results.sort_by_key(|metadata| std::cmp::Reverse(metadata.timestamp));
        Ok(results)
    }
}

fn validate_inventory_entry(
    directory: &StorageDirectory,
    metadata_file: &str,
    metadata: &SnapshotMetadata,
) -> SnapshotResult<()> {
    if !metadata.snapshot_file_name.ends_with(".hiv") {
        return Err(invalid_inventory(
            metadata_file,
            "snapshot file name must be a .hiv component",
        ));
    }
    let expected_metadata_file = format!("{}.json", metadata.snapshot_file_name);
    if metadata_file != expected_metadata_file {
        return Err(invalid_inventory(
            metadata_file,
            format!(
                "metadata name does not match associated hive {}",
                metadata.snapshot_file_name
            ),
        ));
    }
    let snapshot_path = directory
        .child_path(&metadata.snapshot_file_name)
        .map_err(|error| invalid_inventory(metadata_file, error.to_string()))?;
    let hive = directory
        .open_file(
            OsStr::new(&metadata.snapshot_file_name),
            FILE_GENERIC_READ | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ,
        )
        .map_err(|error| invalid_inventory(metadata_file, error.to_string()))?;
    let identity = file_identity(&hive, &snapshot_path)
        .map_err(|error| invalid_inventory(metadata_file, error.to_string()))?;
    let expected_identity = FileIdentity {
        volume_serial: metadata.file_volume_serial,
        file_index: metadata.file_index,
    };
    if identity != expected_identity {
        return Err(invalid_inventory(
            metadata_file,
            "associated hive identity does not match metadata",
        ));
    }
    let digest =
        sha256_file(&hive).map_err(|error| invalid_inventory(metadata_file, error.to_string()))?;
    if digest != metadata.sha256 {
        return Err(invalid_inventory(
            metadata_file,
            "associated hive SHA-256 does not match metadata",
        ));
    }
    Ok(())
}

fn invalid_inventory(metadata_file: impl Into<String>, reason: impl Into<String>) -> SnapshotError {
    SnapshotError::InvalidInventory {
        metadata_file: metadata_file.into(),
        reason: reason.into(),
    }
}

fn finish_snapshot_operation(
    operation: SnapshotResult<(SnapshotMetadata, CreatedStorageFile)>,
    restore_result: Result<(), platform_win32::SecurityError>,
) -> SnapshotResult<SnapshotMetadata> {
    match (operation, restore_result) {
        (Ok((metadata, metadata_file)), Ok(())) => {
            drop(metadata_file.commit());
            Ok(metadata)
        }
        (Err(operation_error), Ok(())) => Err(operation_error),
        (Err(operation_error), Err(restore_error)) => {
            Err(SnapshotError::OperationAndPrivilegeRestoreFailed {
                operation_error: operation_error.to_string(),
                restore_error: restore_error.to_string(),
            })
        }
        (Ok((metadata, metadata_file)), Err(restore_error)) => {
            let cleanup_errors = cleanup_transaction_artifacts(metadata, Some(metadata_file));
            if cleanup_errors.is_empty() {
                Err(restore_error.into())
            } else {
                Err(SnapshotError::PrivilegeRestoreCleanupFailed {
                    restore_error: restore_error.to_string(),
                    cleanup_errors: cleanup_errors.join("; "),
                })
            }
        }
    }
}

fn cleanup_after_metadata_error(
    metadata: SnapshotMetadata,
    metadata_file: Option<CreatedStorageFile>,
    operation_error: SnapshotError,
) -> SnapshotError {
    let cleanup_errors = cleanup_transaction_artifacts(metadata, metadata_file);
    if cleanup_errors.is_empty() {
        operation_error
    } else {
        SnapshotError::CleanupFailed {
            metadata_error: operation_error.to_string(),
            cleanup_error: cleanup_errors.join("; "),
        }
    }
}

fn cleanup_transaction_artifacts(
    metadata: SnapshotMetadata,
    metadata_file: Option<CreatedStorageFile>,
) -> Vec<String> {
    let mut cleanup_errors = Vec::new();
    if let Some(metadata_file) = metadata_file {
        if let Err(error) = metadata_file.rollback() {
            cleanup_errors.push(format!("metadata: {error}"));
        }
    }
    if let Some(artifact) = metadata.artifact() {
        if let Err(error) = delete_open_file(artifact.file(), artifact.path()) {
            cleanup_errors.push(format!("hive: {error}"));
        }
    } else {
        cleanup_errors.push("hive: protected artifact unavailable".to_string());
    }
    drop(metadata);
    cleanup_errors
}

fn cleanup_after_failed_save(
    directory: &StorageDirectory,
    filename: &str,
    save_error: RegistryError,
) -> SnapshotError {
    match directory.remove_file_if_exists(filename) {
        Ok(_) => save_error.into(),
        Err(cleanup_error) => SnapshotError::SaveCleanupFailed {
            save_error: save_error.to_string(),
            cleanup_error: cleanup_error.to_string(),
        },
    }
}

fn cleanup_after_post_save_error(
    directory: &StorageDirectory,
    filename: &str,
    operation_error: SnapshotError,
) -> SnapshotError {
    match directory.remove_file_if_exists(filename) {
        Ok(_) => operation_error,
        Err(cleanup_error) => SnapshotError::PostSaveCleanupFailed {
            operation_error: operation_error.to_string(),
            cleanup_error: cleanup_error.to_string(),
        },
    }
}

pub(crate) fn sha256_file(file: &File) -> SnapshotResult<String> {
    let algorithm = AlgorithmHandle::sha256()?;
    let object_length = algorithm.property_u32(BCRYPT_OBJECT_LENGTH)?;
    let mut object = vec![0u8; object_length as usize];
    let mut hash = null_mut();
    cng_ok("BCryptCreateHash", unsafe {
        BCryptCreateHash(
            algorithm.0,
            &mut hash,
            object.as_mut_ptr(),
            object_length,
            null(),
            0,
            0,
        )
    })?;
    let hash = HashHandle(hash);
    let mut offset = 0u64;
    let mut buffer = [0u8; HASH_BUFFER_BYTES];
    loop {
        let read = file.seek_read(&mut buffer, offset)?;
        if read == 0 {
            break;
        }
        cng_ok("BCryptHashData", unsafe {
            BCryptHashData(hash.0, buffer.as_ptr(), read as u32, 0)
        })?;
        offset += read as u64;
    }
    let mut output = [0u8; 32];
    cng_ok("BCryptFinishHash", unsafe {
        BCryptFinishHash(hash.0, output.as_mut_ptr(), output.len() as u32, 0)
    })?;
    Ok(output.iter().map(|byte| format!("{byte:02x}")).collect())
}

struct AlgorithmHandle(BCRYPT_ALG_HANDLE);

impl AlgorithmHandle {
    fn sha256() -> SnapshotResult<Self> {
        let mut handle = null_mut();
        cng_ok("BCryptOpenAlgorithmProvider", unsafe {
            BCryptOpenAlgorithmProvider(&mut handle, BCRYPT_SHA256_ALGORITHM, null(), 0)
        })?;
        Ok(Self(handle))
    }

    fn property_u32(&self, property: windows_sys::core::PCWSTR) -> SnapshotResult<u32> {
        let mut value = 0u32;
        let mut written = 0u32;
        cng_ok("BCryptGetProperty", unsafe {
            BCryptGetProperty(
                self.0,
                property,
                (&mut value as *mut u32).cast(),
                std::mem::size_of::<u32>() as u32,
                &mut written,
                0,
            )
        })?;
        if written != std::mem::size_of::<u32>() as u32 {
            return Err(SnapshotError::IoError(std::io::Error::other(
                "CNG returned an invalid property length",
            )));
        }
        Ok(value)
    }
}

impl Drop for AlgorithmHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                BCryptCloseAlgorithmProvider(self.0, 0);
            }
        }
    }
}

struct HashHandle(BCRYPT_HASH_HANDLE);

impl Drop for HashHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                BCryptDestroyHash(self.0);
            }
        }
    }
}

fn cng_ok(operation: &'static str, status: NTSTATUS) -> SnapshotResult<()> {
    if status < 0 {
        Err(SnapshotError::HashError { operation, status })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "winprofile-snapshot-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).expect("temporary directory");
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn create_inventory_metadata(
        directory: &StorageDirectory,
        hive_name: &str,
        bytes: &[u8],
    ) -> SnapshotMetadata {
        let mut created = directory
            .create_file(OsStr::new(hive_name), FILE_SHARE_READ)
            .expect("create inventory hive");
        created.file_mut().write_all(bytes).expect("hive bytes");
        created.file_mut().sync_all().expect("sync hive");
        let hive = created.commit();
        let path = directory.child_path(hive_name).expect("hive path");
        let identity = file_identity(&hive, &path).expect("hive identity");
        let sha256 = sha256_file(&hive).expect("hive digest");
        drop(hive);
        SnapshotMetadata {
            id: "inventory-test".to_string(),
            timestamp: Utc::now(),
            sid: "S-1-5-21-test".to_string(),
            profile_path: r"C:\Users\Test".to_string(),
            registry_key_path: r"HKLM\SOFTWARE\Test".to_string(),
            snapshot_file_name: hive_name.to_string(),
            sha256,
            file_volume_serial: identity.volume_serial,
            file_index: identity.file_index,
            reason: "inventory verification".to_string(),
            protected_artifact: None,
        }
    }

    fn write_inventory_metadata(
        directory: &StorageDirectory,
        metadata_name: &str,
        metadata: &SnapshotMetadata,
    ) {
        let mut created = directory
            .create_file(OsStr::new(metadata_name), FILE_SHARE_READ)
            .expect("create inventory metadata");
        serde_json::to_writer(created.file_mut(), metadata).expect("serialize metadata");
        created.file_mut().flush().expect("flush metadata");
        created.file_mut().sync_all().expect("sync metadata");
        created.commit();
    }

    #[test]
    fn failed_save_removes_partial_file_by_handle() {
        let temp = TestDirectory::new();
        let storage = StorageRoot::trusted(&temp.0).expect("storage");
        let directory = storage.root_directory().expect("directory");
        let partial = temp.0.join("partial.hiv");
        std::fs::write(&partial, b"partial").expect("partial save output");

        let error =
            cleanup_after_failed_save(&directory, "partial.hiv", RegistryError::Win32Error(5));

        assert!(matches!(error, SnapshotError::RegistryError(_)));
        assert!(!partial.exists(), "partial hive must be removed");
    }

    #[test]
    fn post_save_validation_error_cleans_hive_or_reports_double_error() {
        let temp = TestDirectory::new();
        let storage = StorageRoot::trusted(&temp.0).expect("storage");
        let directory = storage.root_directory().expect("directory");
        let clean_path = temp.0.join("clean.hiv");
        std::fs::write(&clean_path, b"invalid").expect("post-save hive");
        let original = cleanup_after_post_save_error(
            &directory,
            "clean.hiv",
            SnapshotError::HashError {
                operation: "test",
                status: -1,
            },
        );
        assert!(matches!(original, SnapshotError::HashError { .. }));
        assert!(!clean_path.exists());

        let held_path = temp.0.join("held.hiv");
        let mut created = directory
            .create_file(OsStr::new("held.hiv"), FILE_SHARE_READ)
            .expect("held hive");
        created
            .file_mut()
            .write_all(b"invalid")
            .expect("hive bytes");
        let held = created.commit();
        let double_error = cleanup_after_post_save_error(
            &directory,
            "held.hiv",
            SnapshotError::HashError {
                operation: "test",
                status: -1,
            },
        );
        assert!(matches!(
            double_error,
            SnapshotError::PostSaveCleanupFailed { .. }
        ));
        assert!(held_path.exists());
        drop(held);
        std::fs::remove_file(held_path).expect("cleanup held fixture");
    }

    #[test]
    fn protected_snapshot_handle_blocks_write_and_delete() {
        let temp = TestDirectory::new();
        let storage = StorageRoot::trusted(&temp.0).expect("storage");
        let directory = storage.root_directory().expect("directory");
        let mut created = directory
            .create_file(OsStr::new("snapshot.hiv"), FILE_SHARE_READ)
            .expect("create snapshot");
        created.file_mut().write_all(b"hive").expect("hive bytes");
        created.file_mut().sync_all().expect("sync hive");
        let held = created.commit();
        let path = temp.0.join("snapshot.hiv");

        assert!(OpenOptions::new().write(true).open(&path).is_err());
        assert!(std::fs::remove_file(&path).is_err());
        drop(held);
        std::fs::remove_file(&path).expect("delete after protected handle closes");
    }

    #[test]
    fn snapshot_inventory_revalidates_associated_hive_identity_and_digest() {
        let temp = TestDirectory::new();
        let engine = SnapshotEngine::new(Some(temp.0.clone())).expect("snapshot engine");
        let metadata = create_inventory_metadata(&engine.directory, "valid.hiv", b"hive");
        write_inventory_metadata(&engine.directory, "valid.hiv.json", &metadata);

        let listed = engine.list_snapshots().expect("verified inventory");

        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].snapshot_file_name, "valid.hiv");
    }

    #[test]
    fn snapshot_inventory_fails_closed_on_identity_mismatch() {
        let temp = TestDirectory::new();
        let engine = SnapshotEngine::new(Some(temp.0.clone())).expect("snapshot engine");
        let mut metadata = create_inventory_metadata(&engine.directory, "identity.hiv", b"hive");
        metadata.file_index ^= 1;
        write_inventory_metadata(&engine.directory, "identity.hiv.json", &metadata);

        assert!(matches!(
            engine.list_snapshots(),
            Err(SnapshotError::InvalidInventory { reason, .. })
                if reason.contains("identity")
        ));
    }

    #[test]
    fn snapshot_inventory_fails_closed_on_digest_mismatch() {
        let temp = TestDirectory::new();
        let engine = SnapshotEngine::new(Some(temp.0.clone())).expect("snapshot engine");
        let mut metadata = create_inventory_metadata(&engine.directory, "digest.hiv", b"hive");
        metadata.sha256 = "00".repeat(32);
        write_inventory_metadata(&engine.directory, "digest.hiv.json", &metadata);

        assert!(matches!(
            engine.list_snapshots(),
            Err(SnapshotError::InvalidInventory { reason, .. })
                if reason.contains("SHA-256")
        ));
    }

    #[test]
    fn snapshot_inventory_rejects_non_component_hive_name() {
        let temp = TestDirectory::new();
        let engine = SnapshotEngine::new(Some(temp.0.clone())).expect("snapshot engine");
        let mut metadata = create_inventory_metadata(&engine.directory, "safe.hiv", b"hive");
        metadata.snapshot_file_name = r"..\outside.hiv".to_string();
        write_inventory_metadata(&engine.directory, "safe.hiv.json", &metadata);

        assert!(matches!(
            engine.list_snapshots(),
            Err(SnapshotError::InvalidInventory { .. })
        ));
    }

    #[test]
    fn privilege_restore_failure_removes_persisted_metadata_and_hive() {
        let temp = TestDirectory::new();
        let storage = StorageRoot::trusted(&temp.0).expect("storage");
        let directory = storage.root_directory().expect("directory");
        let mut metadata = create_inventory_metadata(&directory, "restore.hiv", b"hive");
        let hive_path = directory.child_path("restore.hiv").expect("hive path");
        let hive = directory
            .open_file(
                OsStr::new("restore.hiv"),
                FILE_GENERIC_READ | FILE_READ_ATTRIBUTES | DELETE,
                FILE_SHARE_READ,
            )
            .expect("protected hive");
        metadata.protected_artifact = Some(Arc::new(ProtectedSnapshotArtifact {
            file: Arc::new(hive),
            path: hive_path,
            identity: FileIdentity {
                volume_serial: metadata.file_volume_serial,
                file_index: metadata.file_index,
            },
        }));
        let mut metadata_file = directory
            .create_file(OsStr::new("restore.hiv.json"), FILE_SHARE_READ)
            .expect("metadata file");
        serde_json::to_writer(metadata_file.file_mut(), &metadata).expect("metadata bytes");
        metadata_file.file_mut().flush().expect("metadata flush");
        metadata_file.file_mut().sync_all().expect("metadata sync");

        let result = finish_snapshot_operation(
            Ok((metadata, metadata_file)),
            Err(platform_win32::SecurityError::Win32Error(5)),
        );

        assert!(matches!(result, Err(SnapshotError::SecurityError(_))));
        assert!(!temp.0.join("restore.hiv.json").exists());
        assert!(!temp.0.join("restore.hiv").exists());
    }

    #[test]
    fn snapshot_operation_and_privilege_restore_errors_are_both_visible() {
        let operation: SnapshotResult<(SnapshotMetadata, CreatedStorageFile)> =
            Err(SnapshotError::HashError {
                operation: "simulated snapshot",
                status: -1,
            });

        let result =
            finish_snapshot_operation(operation, Err(platform_win32::SecurityError::Win32Error(5)));

        assert!(matches!(
            result,
            Err(SnapshotError::OperationAndPrivilegeRestoreFailed {
                operation_error,
                restore_error,
            }) if operation_error.contains("simulated snapshot")
                && restore_error.contains('5')
        ));
    }
}

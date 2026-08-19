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
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::Registry::{RegRestoreKeyW, KEY_ALL_ACCESS, REG_FORCE_RESTORE};

use platform_win32::{
    create_key, open_key, to_wide_null, PrivilegeGuard, RegistryError, RegistryRoot,
    SE_BACKUP_NAME, SE_RESTORE_NAME,
};

use crate::snapshot::{sha256_file, SnapshotError, SnapshotMetadata};
use crate::storage::file_identity;

#[derive(Error, Debug)]
pub enum RollbackError {
    #[error("snapshot has no protected transactional artifact; inventory JSON cannot be restored")]
    ArtifactUnavailable,
    #[error("snapshot target mismatch: transaction expected {expected}, metadata names {actual}")]
    TargetMismatch { expected: String, actual: String },
    #[error("snapshot handle identity no longer matches its captured identity")]
    IdentityMismatch,
    #[error("snapshot SHA-256 no longer matches its captured digest")]
    DigestMismatch,
    #[error("Registry restore failed with Win32 error code: {0}")]
    RegistryError(u32),
    #[error("Security privilege error: {0}")]
    SecurityError(#[from] platform_win32::SecurityError),
    #[error(
        "registry restore operation failed ({operation_error}) and privilege restoration also failed ({restore_error})"
    )]
    OperationAndPrivilegeRestoreFailed {
        operation_error: String,
        restore_error: String,
    },
    #[error("Base registry error: {0}")]
    BaseRegError(#[from] RegistryError),
    #[error("Snapshot validation error: {0}")]
    SnapshotError(#[from] SnapshotError),
    #[error("one or more rollback steps failed: {0}")]
    Aggregate(String),
}

pub type RollbackResult<T> = Result<T, RollbackError>;

/// Restores only the exact artifact captured by the current transaction. The
/// expected registry target comes from the live repair plan, never JSON.
pub fn restore_registry_snapshot(
    metadata: &SnapshotMetadata,
    expected_registry_key_path: &str,
) -> RollbackResult<()> {
    restore_registry_snapshot_with(metadata, expected_registry_key_path, restore_registry_file)
}

fn restore_registry_snapshot_with<F>(
    metadata: &SnapshotMetadata,
    expected_registry_key_path: &str,
    restore: F,
) -> RollbackResult<()>
where
    F: FnOnce(&Path, &str) -> RollbackResult<()>,
{
    if !metadata
        .registry_key_path
        .eq_ignore_ascii_case(expected_registry_key_path)
    {
        return Err(RollbackError::TargetMismatch {
            expected: expected_registry_key_path.to_string(),
            actual: metadata.registry_key_path.clone(),
        });
    }
    let artifact = metadata
        .artifact()
        .ok_or(RollbackError::ArtifactUnavailable)?;
    let current_identity = file_identity(artifact.file(), artifact.path())?;
    let captured_identity = artifact.identity();
    if current_identity != captured_identity
        || current_identity.volume_serial != metadata.file_volume_serial
        || current_identity.file_index != metadata.file_index
    {
        return Err(RollbackError::IdentityMismatch);
    }
    if sha256_file(artifact.file())? != metadata.sha256 {
        return Err(RollbackError::DigestMismatch);
    }
    restore(artifact.path(), expected_registry_key_path)
}

fn restore_registry_file(path: &Path, expected_registry_key_path: &str) -> RollbackResult<()> {
    let subkey_name = expected_registry_key_path
        .strip_prefix("HKLM\\")
        .ok_or(RollbackError::BaseRegError(RegistryError::InvalidPath))?;
    let (parent_path, leaf_name) = subkey_name
        .rsplit_once('\\')
        .ok_or(RollbackError::BaseRegError(RegistryError::InvalidPath))?;
    let privileges = PrivilegeGuard::new(&[SE_RESTORE_NAME, SE_BACKUP_NAME])?;
    let operation = (|| -> RollbackResult<()> {
        let parent = open_key(RegistryRoot::LocalMachine, parent_path, KEY_ALL_ACCESS)?;
        let hkey = create_key(&parent, leaf_name, KEY_ALL_ACCESS)?;
        let wide_file = to_wide_null(path.as_os_str());
        let status =
            unsafe { RegRestoreKeyW(hkey.as_raw(), wide_file.as_ptr(), REG_FORCE_RESTORE as u32) };
        if status != ERROR_SUCCESS {
            return Err(RollbackError::RegistryError(status));
        }
        Ok(())
    })();
    let restore_result = privileges.restore();
    finish_privileged_restore(operation, restore_result)
}

fn finish_privileged_restore(
    operation: RollbackResult<()>,
    restore_result: Result<(), platform_win32::SecurityError>,
) -> RollbackResult<()> {
    match (operation, restore_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(operation_error), Ok(())) => Err(operation_error),
        (Ok(()), Err(restore_error)) => Err(restore_error.into()),
        (Err(operation_error), Err(restore_error)) => {
            Err(RollbackError::OperationAndPrivilegeRestoreFailed {
                operation_error: operation_error.to_string(),
                restore_error: restore_error.to_string(),
            })
        }
    }
}

impl From<crate::storage::StorageError> for RollbackError {
    fn from(error: crate::storage::StorageError) -> Self {
        Self::SnapshotError(SnapshotError::StorageError(error))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::fs::OpenOptions;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use crate::snapshot::{sha256_file, ProtectedSnapshotArtifact};

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "winprofile-rollback-{}-{}",
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

    fn fixture() -> (TestDirectory, SnapshotMetadata) {
        let temp = TestDirectory::new();
        let path = temp.0.join("snapshot.hiv");
        std::fs::write(&path, b"protected hive bytes").expect("fixture bytes");
        let file = OpenOptions::new()
            .read(true)
            .open(&path)
            .expect("fixture handle");
        let identity = file_identity(&file, &path).expect("identity");
        let digest = sha256_file(&file).expect("digest");
        let metadata = SnapshotMetadata {
            id: "test".to_string(),
            timestamp: Utc::now(),
            sid: "S-1-5-21-1".to_string(),
            profile_path: r"C:\Users\Test".to_string(),
            registry_key_path: r"HKLM\SOFTWARE\WinProfile\Test".to_string(),
            snapshot_file_name: "snapshot.hiv".to_string(),
            sha256: digest,
            file_volume_serial: identity.volume_serial,
            file_index: identity.file_index,
            reason: "test".to_string(),
            protected_artifact: Some(Arc::new(ProtectedSnapshotArtifact {
                file: Arc::new(file),
                path,
                identity,
            })),
        };
        (temp, metadata)
    }

    #[test]
    fn digest_mismatch_refuses_before_restore_api() {
        let (_temp, mut metadata) = fixture();
        metadata.sha256 = "00".repeat(32);
        let called = AtomicUsize::new(0);
        let result =
            restore_registry_snapshot_with(&metadata, r"HKLM\SOFTWARE\WinProfile\Test", |_, _| {
                called.fetch_add(1, Ordering::Relaxed);
                Ok(())
            });
        assert!(matches!(result, Err(RollbackError::DigestMismatch)));
        assert_eq!(called.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn identity_mismatch_refuses_before_restore_api() {
        let (_temp, mut metadata) = fixture();
        metadata.file_index ^= 1;
        let called = AtomicUsize::new(0);
        let result =
            restore_registry_snapshot_with(&metadata, r"HKLM\SOFTWARE\WinProfile\Test", |_, _| {
                called.fetch_add(1, Ordering::Relaxed);
                Ok(())
            });
        assert!(matches!(result, Err(RollbackError::IdentityMismatch)));
        assert_eq!(called.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn restore_operation_and_privilege_restore_errors_are_both_visible() {
        let result = finish_privileged_restore(
            Err(RollbackError::RegistryError(5)),
            Err(platform_win32::SecurityError::Win32Error(1300)),
        );

        assert!(matches!(
            result,
            Err(RollbackError::OperationAndPrivilegeRestoreFailed {
                operation_error,
                restore_error,
            }) if operation_error.contains('5') && restore_error.contains("1300")
        ));
    }
}

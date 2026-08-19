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
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::Registry::{
    RegRestoreKeyW, HKEY_LOCAL_MACHINE, KEY_ALL_ACCESS, REG_FORCE_RESTORE,
};

use platform_win32::{
    create_key, to_wide_null, PrivilegeGuard, RegistryError,
    SE_BACKUP_NAME, SE_RESTORE_NAME,
};

use crate::journal::{AuditLogger, AuditStatus};
use crate::snapshot::SnapshotMetadata;

#[derive(Error, Debug)]
pub enum RollbackError {
    #[error("Snapshot file not found: {0}")]
    FileNotFound(String),
    #[error("Registry restore failed with Win32 error code: {0}")]
    RegistryError(u32),
    #[error("Security privilege error: {0}")]
    SecurityError(#[from] platform_win32::SecurityError),
    #[error("Base registry error: {0}")]
    BaseRegError(#[from] RegistryError),
}

pub type RollbackResult<T> = Result<T, RollbackError>;

/// Restores a captured registry snapshot back to the live Windows Registry.
pub fn restore_registry_snapshot(
    metadata: &SnapshotMetadata,
    logger: Option<&AuditLogger>,
) -> RollbackResult<()> {
    if !metadata.snapshot_file_path.exists() {
        return Err(RollbackError::FileNotFound(
            metadata.snapshot_file_path.to_string_lossy().to_string(),
        ));
    }

    let _privs = PrivilegeGuard::new(&[SE_RESTORE_NAME, SE_BACKUP_NAME])?;

    let subkey_name = metadata
        .registry_key_path
        .strip_prefix("HKLM\\")
        .unwrap_or(&metadata.registry_key_path);

    let hkey = create_key(HKEY_LOCAL_MACHINE, subkey_name, KEY_ALL_ACCESS)?;
    let wide_file = to_wide_null(metadata.snapshot_file_path.as_os_str());

    let status = unsafe {
        RegRestoreKeyW(
            hkey.as_raw(),
            wide_file.as_ptr(),
            REG_FORCE_RESTORE as u32,
        )
    };

    if status == ERROR_SUCCESS {
        if let Some(log) = logger {
            log.log(
                "RollbackSnapshot",
                "WinProfile",
                &metadata.sid,
                AuditStatus::RolledBack,
                format!("Restored snapshot from {}", metadata.snapshot_file_path.display()),
            );
        }
        Ok(())
    } else {
        if let Some(log) = logger {
            log.log(
                "RollbackSnapshot",
                "WinProfile",
                &metadata.sid,
                AuditStatus::Failed,
                format!("Rollback failed with error code: {status}"),
            );
        }
        Err(RollbackError::RegistryError(status))
    }
}

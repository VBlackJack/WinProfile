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

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use audit_journal::{AuditError, AuditLogger, AuditStatus};
use platform_win32::{
    SecureCreatedEntry, SecureDirectory, SecureEntryKind, SecureFsError, SecureFsResult,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::constants::*;
use crate::models::MigrationPlan;

const COPY_BUFFER_BYTES: usize = 1024 * 1024;
const PERSONAL_FOLDERS: [&str; 5] = ["Documents", "Desktop", "Downloads", "Favorites", "Pictures"];

#[derive(Error, Debug)]
pub enum MigrationError {
    #[error("Source profile directory does not exist: {0}")]
    SourceNotFound(String),
    #[error("Invalid migration plan: {0}")]
    InvalidPlan(String),
    #[error("Migration refuses to traverse a reparse point: {0}")]
    ReparsePoint(String),
    #[error("Destination file already exists and will not be overwritten: {0}")]
    DestinationExists(String),
    #[error("Migration was cancelled")]
    Cancelled,
    #[error("Migration internal state failure: {0}")]
    InternalState(String),
    #[error("Copied file verification failed: {0}")]
    VerificationFailed(String),
    #[error("Migration rollback failed after '{operation_error}': {rollback_error}")]
    RollbackFailed {
        operation_error: String,
        rollback_error: String,
    },
    #[error("IO error during migration copy: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Security validation failed: {0}")]
    Security(String),
    #[error("Audit journal error: {0}")]
    Audit(#[from] AuditError),
}

pub type MigrationResult<T> = Result<T, MigrationError>;

/// Durable summary of a verified migration operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationReceipt {
    pub copied_files: usize,
    pub copied_bytes: u64,
    pub manifest_sha256: String,
}

#[derive(Debug, Default)]
struct CopyTransaction {
    created_entries: Vec<SecureCreatedEntry>,
    manifest: Vec<(String, u64, String)>,
}

impl CopyTransaction {
    fn rollback(&mut self) -> SecureFsResult<()> {
        let mut first_error = None;
        while let Some(entry) = self.created_entries.pop() {
            if let Err(error) = entry.remove() {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn receipt(&self) -> MigrationReceipt {
        let mut manifest_hasher = Sha256::new();
        let mut copied_bytes = 0u64;
        for (relative_path, size, sha256) in &self.manifest {
            manifest_hasher.update(relative_path.as_bytes());
            manifest_hasher.update([0]);
            manifest_hasher.update(size.to_le_bytes());
            manifest_hasher.update(sha256.as_bytes());
            manifest_hasher.update(b"\n");
            copied_bytes = copied_bytes.saturating_add(*size);
        }
        MigrationReceipt {
            copied_files: self.manifest.len(),
            copied_bytes,
            manifest_sha256: format!("{:x}", manifest_hasher.finalize()),
        }
    }
}

/// Engine responsible for selective, verified profile data migration.
pub struct ProfileMigrationEngine<'a> {
    audit_logger: &'a AuditLogger,
}

impl<'a> ProfileMigrationEngine<'a> {
    pub fn new(audit_logger: &'a AuditLogger) -> Self {
        Self { audit_logger }
    }

    /// Performs a migration without cancellation support.
    pub fn execute_migration<F>(
        &self,
        plan: &MigrationPlan,
        on_progress: F,
    ) -> MigrationResult<MigrationReceipt>
    where
        F: FnMut(&str, f32),
    {
        self.execute_migration_with_cancel(plan, on_progress, || false)
    }

    /// Performs a transactional migration and rolls back every created item on failure.
    pub fn execute_migration_with_cancel<F, C>(
        &self,
        plan: &MigrationPlan,
        mut on_progress: F,
        mut is_cancelled: C,
    ) -> MigrationResult<MigrationReceipt>
    where
        F: FnMut(&str, f32),
        C: FnMut() -> bool,
    {
        let _operation_guard = self.audit_logger.acquire_operation_guard()?;
        let (source_root, target_root) = validate_plan(plan)?;
        self.audit_logger.log(
            "MigrationStarted",
            "WinProfile-Admin",
            &plan.source_sid,
            AuditStatus::Warning,
            format!(
                "Verified-copy migration started: {} -> {}",
                source_root.display(),
                target_root.display()
            ),
        )?;

        let mut transaction = CopyTransaction::default();
        let operation = (|| {
            let source_directory = SecureDirectory::open_absolute_existing(&source_root)
                .map_err(|error| map_source_root_error(error, &source_root))?;
            let (target_directory, created_target_entries) =
                SecureDirectory::open_or_create_absolute(&target_root).map_err(map_secure_error)?;
            transaction.created_entries.extend(created_target_entries);
            validate_opened_roots(&source_directory, &target_directory)?;

            if secure_directory_exists(
                &source_directory,
                Path::new(APPDATA_ROAMING_REL_PATH)
                    .join("Microsoft")
                    .join("Protect")
                    .as_path(),
            )? {
                self.audit_logger.log(
                    "MigrationWarning",
                    "WinProfile-Admin",
                    &plan.source_sid,
                    AuditStatus::Warning,
                    "DPAPI material detected; SID-bound secrets are copied but may not decrypt under the destination account.",
                )?;
            }

            let mut roots = Vec::new();
            if plan.include_roaming_appdata {
                roots.push(APPDATA_ROAMING_REL_PATH);
            }
            if plan.include_personal_folders {
                roots.extend(PERSONAL_FOLDERS);
            }
            if roots.is_empty() {
                return Err(MigrationError::InvalidPlan(
                    "at least one migration scope must be selected".to_string(),
                ));
            }

            let total_roots = roots.len() as f32;
            for (index, relative_root) in roots.iter().enumerate() {
                if is_cancelled() {
                    return Err(MigrationError::Cancelled);
                }
                let Some(source) = open_relative_directory_if_present(
                    &source_directory,
                    Path::new(relative_root),
                )?
                else {
                    continue;
                };
                let destination = ensure_relative_directory(
                    &target_directory,
                    Path::new(relative_root),
                    &mut transaction,
                )?;
                on_progress(relative_root, 0.1 + (index as f32 / total_roots) * 0.8);
                copy_tree_verified(
                    &source,
                    &destination,
                    Path::new(relative_root),
                    &mut transaction,
                    &mut is_cancelled,
                )?;
            }

            if is_cancelled() {
                return Err(MigrationError::Cancelled);
            }
            let receipt = transaction.receipt();
            on_progress("complete", 1.0);
            if is_cancelled() {
                return Err(MigrationError::Cancelled);
            }
            self.audit_logger.log(
                "MigrationSuccess",
                "WinProfile-Admin",
                &plan.source_sid,
                AuditStatus::Success,
                format!(
                    "Verified {} files ({} bytes); manifest SHA-256 {}",
                    receipt.copied_files, receipt.copied_bytes, receipt.manifest_sha256
                ),
            )?;
            Ok(receipt)
        })();

        match operation {
            Ok(receipt) => Ok(receipt),
            Err(error) => {
                if let Err(rollback_error) = transaction.rollback() {
                    let mut result = MigrationError::RollbackFailed {
                        operation_error: error.to_string(),
                        rollback_error: rollback_error.to_string(),
                    };
                    if let Err(audit_error) = self.audit_logger.log(
                        "MigrationRollbackFailed",
                        "WinProfile-Admin",
                        &plan.source_sid,
                        AuditStatus::Failed,
                        result.to_string(),
                    ) {
                        result = MigrationError::RollbackFailed {
                            operation_error: error.to_string(),
                            rollback_error: format!(
                                "{rollback_error}; audit logging also failed: {audit_error}"
                            ),
                        };
                    }
                    return Err(result);
                }
                self.audit_logger.log(
                    "MigrationRolledBack",
                    "WinProfile-Admin",
                    &plan.source_sid,
                    AuditStatus::RolledBack,
                    error.to_string(),
                )?;
                Err(error)
            }
        }
    }
}

fn validate_plan(plan: &MigrationPlan) -> MigrationResult<(PathBuf, PathBuf)> {
    if plan.source_sid.trim().is_empty() {
        return Err(MigrationError::InvalidPlan(
            "source SID is empty".to_string(),
        ));
    }
    let source = Path::new(&plan.source_path);
    if !source.is_dir() {
        return Err(MigrationError::SourceNotFound(plan.source_path.clone()));
    }
    let source = absolute_normalized(source)?;
    let target = absolute_normalized(Path::new(&plan.target_path))?;
    if paths_overlap(&source, &target) {
        return Err(MigrationError::InvalidPlan(
            "source and destination directories must not overlap".to_string(),
        ));
    }
    if target.exists() && !target.is_dir() {
        return Err(MigrationError::InvalidPlan(
            "destination exists but is not a directory".to_string(),
        ));
    }
    Ok((source, target))
}

fn absolute_normalized(path: &Path) -> std::io::Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    Ok(normalized)
}

fn copy_tree_verified<C>(
    source: &SecureDirectory,
    destination: &SecureDirectory,
    relative_directory: &Path,
    transaction: &mut CopyTransaction,
    is_cancelled: &mut C,
) -> MigrationResult<()>
where
    C: FnMut() -> bool,
{
    for entry in source.entries().map_err(map_secure_error)? {
        if is_cancelled() {
            return Err(MigrationError::Cancelled);
        }
        let relative_path = relative_directory.join(&entry.name);
        match entry.kind {
            SecureEntryKind::Directory => {
                let source_child = source
                    .open_directory(&entry.name)
                    .map_err(map_secure_error)?;
                let (destination_child, created) = destination
                    .open_or_create_directory(&entry.name)
                    .map_err(map_secure_error)?;
                if let Some(created) = created {
                    transaction.created_entries.push(created);
                }
                copy_tree_verified(
                    &source_child,
                    &destination_child,
                    &relative_path,
                    transaction,
                    is_cancelled,
                )?;
            }
            SecureEntryKind::File => copy_file_verified(
                source,
                destination,
                &entry.name,
                &relative_path,
                transaction,
                is_cancelled,
            )?,
        }
    }
    Ok(())
}

fn copy_file_verified<C>(
    source_directory: &SecureDirectory,
    destination_directory: &SecureDirectory,
    name: &std::ffi::OsStr,
    relative_path: &Path,
    transaction: &mut CopyTransaction,
    is_cancelled: &mut C,
) -> MigrationResult<()>
where
    C: FnMut() -> bool,
{
    let mut input = source_directory.open_file(name).map_err(map_secure_error)?;
    let (mut output, created) = destination_directory
        .create_file(name)
        .map_err(map_secure_error)?;
    transaction.created_entries.push(created);

    let mut source_hasher = Sha256::new();
    let mut buffer = vec![0u8; COPY_BUFFER_BYTES];
    let mut copied_bytes = 0u64;
    loop {
        if is_cancelled() {
            return Err(MigrationError::Cancelled);
        }
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        output.write_all(&buffer[..count])?;
        source_hasher.update(&buffer[..count]);
        copied_bytes = copied_bytes.saturating_add(count as u64);
    }
    if is_cancelled() {
        return Err(MigrationError::Cancelled);
    }
    output.flush()?;
    output.sync_all()?;

    let source_sha = format!("{:x}", source_hasher.finalize());
    output.seek(SeekFrom::Start(0))?;
    let destination_sha = sha256_file(&mut output, is_cancelled)?;
    if source_sha != destination_sha || copied_bytes != output.metadata()?.len() {
        return Err(MigrationError::VerificationFailed(
            relative_path.display().to_string(),
        ));
    }
    let relative = relative_path.to_string_lossy().replace('\\', "/");
    transaction
        .manifest
        .push((relative, copied_bytes, source_sha));
    Ok(())
}

fn sha256_file<C>(file: &mut File, is_cancelled: &mut C) -> MigrationResult<String>
where
    C: FnMut() -> bool,
{
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; COPY_BUFFER_BYTES];
    loop {
        if is_cancelled() {
            return Err(MigrationError::Cancelled);
        }
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn open_relative_directory_if_present(
    root: &SecureDirectory,
    relative: &Path,
) -> MigrationResult<Option<SecureDirectory>> {
    let mut current = None;
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(MigrationError::InvalidPlan(format!(
                "invalid relative migration root: {}",
                relative.display()
            )));
        };
        let parent = current.as_ref().unwrap_or(root);
        match parent.open_directory(name) {
            Ok(next) => current = Some(next),
            Err(SecureFsError::NotFound(_)) => return Ok(None),
            Err(error) => return Err(map_secure_error(error)),
        }
    }
    Ok(current)
}

fn ensure_relative_directory(
    root: &SecureDirectory,
    relative: &Path,
    transaction: &mut CopyTransaction,
) -> MigrationResult<SecureDirectory> {
    let mut current = None;
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(MigrationError::InvalidPlan(format!(
                "invalid relative migration destination: {}",
                relative.display()
            )));
        };
        let parent = current.as_ref().unwrap_or(root);
        let (next, created) = parent
            .open_or_create_directory(name)
            .map_err(map_secure_error)?;
        if let Some(created) = created {
            transaction.created_entries.push(created);
        }
        current = Some(next);
    }
    current.ok_or_else(|| {
        MigrationError::InvalidPlan("empty relative migration destination".to_string())
    })
}

fn secure_directory_exists(root: &SecureDirectory, relative: &Path) -> MigrationResult<bool> {
    Ok(open_relative_directory_if_present(root, relative)?.is_some())
}

fn validate_opened_roots(
    source: &SecureDirectory,
    target: &SecureDirectory,
) -> MigrationResult<()> {
    if source.overlaps(target) {
        return Err(MigrationError::InvalidPlan(
            "opened source and destination directory handles overlap".to_string(),
        ));
    }
    Ok(())
}

fn paths_overlap(first: &Path, second: &Path) -> bool {
    let first = normalized_path_key(first);
    let second = normalized_path_key(second);
    first == second
        || second
            .strip_prefix(&first)
            .is_some_and(|suffix| suffix.starts_with('\\'))
        || first
            .strip_prefix(&second)
            .is_some_and(|suffix| suffix.starts_with('\\'))
}

fn normalized_path_key(path: &Path) -> String {
    path.to_string_lossy()
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_lowercase()
}

fn map_source_root_error(error: SecureFsError, source: &Path) -> MigrationError {
    match error {
        SecureFsError::NotFound(_) => MigrationError::SourceNotFound(source.display().to_string()),
        other => map_secure_error(other),
    }
}

fn map_secure_error(error: SecureFsError) -> MigrationError {
    match error {
        SecureFsError::ReparsePoint(path) => MigrationError::ReparsePoint(path),
        SecureFsError::AlreadyExists(path) => MigrationError::DestinationExists(path),
        other => MigrationError::Security(other.to_string()),
    }
}

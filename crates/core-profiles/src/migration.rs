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

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use audit_journal::{AuditError, AuditLogger, AuditStatus};
use platform_win32::path_is_reparse_point;
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
    created_files: Vec<PathBuf>,
    created_directories: Vec<PathBuf>,
    manifest: Vec<(String, u64, String)>,
}

impl CopyTransaction {
    fn rollback(&mut self) -> std::io::Result<()> {
        let mut first_error = None;
        for path in self.created_files.iter().rev() {
            if let Err(error) = std::fs::remove_file(path) {
                if error.kind() != std::io::ErrorKind::NotFound && first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
        for path in self.created_directories.iter().rev() {
            if let Err(error) = std::fs::remove_dir(path) {
                if error.kind() != std::io::ErrorKind::NotFound && first_error.is_none() {
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
            ensure_directory(&target_root, &mut transaction)?;
            reject_reparse_point(&target_root)?;

            let dpapi_path = source_root
                .join(APPDATA_ROAMING_REL_PATH)
                .join("Microsoft")
                .join("Protect");
            if dpapi_path.exists() {
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
                let source = source_root.join(relative_root);
                if !source.exists() {
                    continue;
                }
                let destination = target_root.join(relative_root);
                on_progress(relative_root, 0.1 + (index as f32 / total_roots) * 0.8);
                copy_tree_verified(
                    &source,
                    &destination,
                    &source_root,
                    &mut transaction,
                    &mut is_cancelled,
                )?;
            }

            let receipt = transaction.receipt();
            on_progress("complete", 1.0);
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
    reject_reparse_point(source)?;
    let source = source.canonicalize()?;
    let target = canonicalize_allow_missing(Path::new(&plan.target_path))?;
    if source == target || target.starts_with(&source) || source.starts_with(&target) {
        return Err(MigrationError::InvalidPlan(
            "source and destination directories must not overlap".to_string(),
        ));
    }
    if target.exists() {
        if !target.is_dir() {
            return Err(MigrationError::InvalidPlan(
                "destination exists but is not a directory".to_string(),
            ));
        }
        reject_reparse_point(&target)?;
        let canonical_target = target.canonicalize()?;
        if canonical_target == source
            || canonical_target.starts_with(&source)
            || source.starts_with(&canonical_target)
        {
            return Err(MigrationError::InvalidPlan(
                "canonical source and destination directories overlap".to_string(),
            ));
        }
        return Ok((source, canonical_target));
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

fn canonicalize_allow_missing(path: &Path) -> std::io::Result<PathBuf> {
    let normalized = absolute_normalized(path)?;
    if normalized.exists() {
        return normalized.canonicalize();
    }
    let mut existing_ancestor = normalized.as_path();
    let mut missing_components = Vec::new();
    while !existing_ancestor.exists() {
        let name = existing_ancestor.file_name().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("no existing ancestor for {}", normalized.display()),
            )
        })?;
        missing_components.push(name.to_os_string());
        existing_ancestor = existing_ancestor.parent().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("no existing ancestor for {}", normalized.display()),
            )
        })?;
    }
    let mut canonical = existing_ancestor.canonicalize()?;
    for component in missing_components.iter().rev() {
        canonical.push(component);
    }
    Ok(canonical)
}

fn reject_reparse_point(path: &Path) -> MigrationResult<()> {
    match path_is_reparse_point(path) {
        Ok(false) => Ok(()),
        Ok(true) => Err(MigrationError::ReparsePoint(path.display().to_string())),
        Err(error) => Err(MigrationError::Security(format!(
            "{}: {error}",
            path.display()
        ))),
    }
}

fn ensure_directory(path: &Path, transaction: &mut CopyTransaction) -> MigrationResult<()> {
    if path.exists() {
        if !path.is_dir() {
            return Err(MigrationError::DestinationExists(
                path.display().to_string(),
            ));
        }
        reject_reparse_point(path)?;
        return Ok(());
    }
    let parent = path.parent().ok_or_else(|| {
        MigrationError::InvalidPlan(format!("directory has no parent: {}", path.display()))
    })?;
    ensure_directory(parent, transaction)?;
    std::fs::create_dir(path)?;
    transaction.created_directories.push(path.to_path_buf());
    Ok(())
}

fn copy_tree_verified<C>(
    source: &Path,
    destination: &Path,
    source_root: &Path,
    transaction: &mut CopyTransaction,
    is_cancelled: &mut C,
) -> MigrationResult<()>
where
    C: FnMut() -> bool,
{
    reject_reparse_point(source)?;
    ensure_directory(destination, transaction)?;
    let mut entries = std::fs::read_dir(source)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);

    for entry in entries {
        if is_cancelled() {
            return Err(MigrationError::Cancelled);
        }
        let source_path = entry.path();
        reject_reparse_point(&source_path)?;
        let destination_path = destination.join(entry.file_name());
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            copy_tree_verified(
                &source_path,
                &destination_path,
                source_root,
                transaction,
                is_cancelled,
            )?;
        } else if file_type.is_file() {
            copy_file_verified(&source_path, &destination_path, source_root, transaction)?;
        } else {
            return Err(MigrationError::InvalidPlan(format!(
                "unsupported filesystem entry: {}",
                source_path.display()
            )));
        }
    }
    Ok(())
}

fn copy_file_verified(
    source: &Path,
    destination: &Path,
    source_root: &Path,
    transaction: &mut CopyTransaction,
) -> MigrationResult<()> {
    let mut input = File::open(source)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                MigrationError::DestinationExists(destination.display().to_string())
            } else {
                error.into()
            }
        })?;
    transaction.created_files.push(destination.to_path_buf());

    let mut source_hasher = Sha256::new();
    let mut buffer = vec![0u8; COPY_BUFFER_BYTES];
    let mut copied_bytes = 0u64;
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        output.write_all(&buffer[..count])?;
        source_hasher.update(&buffer[..count]);
        copied_bytes = copied_bytes.saturating_add(count as u64);
    }
    output.flush()?;
    output.sync_all()?;
    drop(output);

    let source_sha = format!("{:x}", source_hasher.finalize());
    let destination_sha = sha256_file(destination)?;
    if source_sha != destination_sha || copied_bytes != std::fs::metadata(destination)?.len() {
        return Err(MigrationError::VerificationFailed(
            destination.display().to_string(),
        ));
    }
    let relative = source
        .strip_prefix(source_root)
        .map_err(|_| MigrationError::VerificationFailed(source.display().to_string()))?
        .to_string_lossy()
        .replace('\\', "/");
    transaction
        .manifest
        .push((relative, copied_bytes, source_sha));
    Ok(())
}

fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; COPY_BUFFER_BYTES];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

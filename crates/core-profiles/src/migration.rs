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

use std::ffi::OsString;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::windows::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf, Prefix};

use audit_journal::{AuditError, AuditLogger, AuditStatus};
use platform_win32::{
    open_key, RegistryError, RegistryRoot, SecureCreatedEntry, SecureDirectory, SecureEntryKind,
    SecureFsError, SecureFsResult,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND;
use windows_sys::Win32::System::Registry::KEY_READ;

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
    #[error("Source profile is currently loaded: {0}")]
    SourceLoaded(String),
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

/// Migration phases that can be measured without inventing a total.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MigrationPhase {
    Enumerating,
    Copying,
    Verifying,
    Finalizing,
    RollingBack,
}

/// Honest progress snapshot. No percentage is exposed because the total work
/// is unknown until traversal has completed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationProgress {
    pub phase: MigrationPhase,
    pub relative_path: Option<String>,
    pub completed_files: usize,
    pub copied_bytes: u64,
}

/// Result of a read-only validation performed before an operation is started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationPreflight {
    pub source_path: PathBuf,
    pub target_path: PathBuf,
}

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
    observed_copied_bytes: u64,
    last_relative_path: Option<String>,
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

    fn completed_files(&self) -> usize {
        self.manifest.len()
    }

    fn copied_bytes(&self) -> u64 {
        self.observed_copied_bytes.max(
            self.manifest
                .iter()
                .fold(0u64, |total, (_, size, _)| total.saturating_add(*size)),
        )
    }

    fn observe_copy(&mut self, relative_path: &Path, copied_bytes: u64) {
        self.observed_copied_bytes = copied_bytes;
        self.last_relative_path = Some(display_relative_path(relative_path));
    }
}

struct ValidatedMigration {
    source_path: PathBuf,
    target_path: PathBuf,
    source_directory: SecureDirectory,
    target_parent: SecureDirectory,
    target_leaf: OsString,
}

/// Performs the complete read-only validation used by the UI before it enables
/// a privileged migration.
pub fn prevalidate_migration_plan(plan: &MigrationPlan) -> MigrationResult<MigrationPreflight> {
    let validated = validate_for_execution(plan)?;
    Ok(MigrationPreflight {
        source_path: validated.source_path,
        target_path: validated.target_path,
    })
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
        F: FnMut(MigrationProgress),
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
        F: FnMut(MigrationProgress),
        C: FnMut() -> bool,
    {
        let _operation_guard = self.audit_logger.acquire_operation_guard()?;
        let validated = validate_for_execution(plan)?;
        self.audit_logger.log(
            "MigrationStarted",
            "WinProfile-Admin",
            &plan.source_sid,
            AuditStatus::Warning,
            format!(
                "Verified-copy migration started: {} -> {}",
                validated.source_path.display(),
                validated.target_path.display()
            ),
        )?;

        let mut transaction = CopyTransaction::default();
        let operation = (|| {
            let (target_directory, created_target) = validated
                .target_parent
                .create_directory(&validated.target_leaf)
                .map_err(map_secure_error)?;
            transaction.created_entries.push(created_target);
            validate_opened_roots(&validated.source_directory, &target_directory)?;

            if secure_directory_exists(
                &validated.source_directory,
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

            on_progress(MigrationProgress {
                phase: MigrationPhase::Enumerating,
                relative_path: None,
                completed_files: 0,
                copied_bytes: 0,
            });
            for relative_root in roots {
                if is_cancelled() {
                    return Err(MigrationError::Cancelled);
                }
                let Some(source) = open_relative_directory_if_present(
                    &validated.source_directory,
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
                copy_tree_verified(
                    &source,
                    &destination,
                    Path::new(relative_root),
                    &mut transaction,
                    &mut on_progress,
                    &mut is_cancelled,
                )?;
            }

            if is_cancelled() {
                return Err(MigrationError::Cancelled);
            }
            let receipt = transaction.receipt();
            if is_cancelled() {
                return Err(MigrationError::Cancelled);
            }
            on_progress(MigrationProgress {
                phase: MigrationPhase::Finalizing,
                relative_path: None,
                completed_files: receipt.copied_files,
                copied_bytes: receipt.copied_bytes,
            });
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
                on_progress(MigrationProgress {
                    phase: MigrationPhase::RollingBack,
                    relative_path: transaction.last_relative_path.clone(),
                    completed_files: transaction.completed_files(),
                    copied_bytes: transaction.copied_bytes(),
                });
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

fn validate_for_execution(plan: &MigrationPlan) -> MigrationResult<ValidatedMigration> {
    if plan.source_sid.trim().is_empty() {
        return Err(MigrationError::InvalidPlan(
            "source SID is empty".to_string(),
        ));
    }
    if !plan.include_roaming_appdata && !plan.include_personal_folders {
        return Err(MigrationError::InvalidPlan(
            "at least one migration scope must be selected".to_string(),
        ));
    }
    let source = release_absolute_path(Path::new(&plan.source_path), "source")?;
    let target = release_absolute_path(Path::new(&plan.target_path), "destination")?;
    if paths_overlap(&source, &target) {
        return Err(MigrationError::InvalidPlan(
            "source and destination directories must not overlap".to_string(),
        ));
    }
    ensure_source_offline(&plan.source_sid)?;

    let source_directory = SecureDirectory::open_absolute_existing(&source)
        .map_err(|error| map_source_root_error(error, &source))?;
    let target_parent_path = target.parent().ok_or_else(|| {
        MigrationError::InvalidPlan("destination must have an existing parent".to_string())
    })?;
    let target_leaf = target
        .file_name()
        .ok_or_else(|| {
            MigrationError::InvalidPlan("destination must include a final folder name".to_string())
        })?
        .to_os_string();
    validate_windows_component(&target_leaf, "destination folder name")?;
    let target_parent = SecureDirectory::open_absolute_existing(target_parent_path).map_err(
        |error| match error {
            SecureFsError::NotFound(_) => MigrationError::InvalidPlan(format!(
                "destination parent does not exist: {}",
                target_parent_path.display()
            )),
            other => map_secure_error(other),
        },
    )?;
    if target_parent.is_within(&source_directory) {
        return Err(MigrationError::InvalidPlan(
            "destination parent is inside the source directory".to_string(),
        ));
    }
    match target_parent
        .child_kind(&target_leaf)
        .map_err(map_secure_error)?
    {
        None => {}
        Some(_) => {
            return Err(MigrationError::DestinationExists(
                target.display().to_string(),
            ));
        }
    }

    Ok(ValidatedMigration {
        source_path: source,
        target_path: target,
        source_directory,
        target_parent,
        target_leaf,
    })
}

fn release_absolute_path(path: &Path, label: &str) -> MigrationResult<PathBuf> {
    if path.as_os_str().is_empty() {
        return Err(MigrationError::InvalidPlan(format!(
            "{label} path is empty"
        )));
    }
    validate_raw_release_path(path, label)?;
    let mut components = path.components();
    let prefix = match components.next() {
        Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::Disk(_)) => prefix,
        Some(Component::Prefix(_)) => {
            return Err(MigrationError::InvalidPlan(format!(
                "{label} path uses an unsupported UNC, device, or verbatim prefix"
            )));
        }
        _ => {
            return Err(MigrationError::InvalidPlan(format!(
                "{label} path must be an absolute drive path"
            )));
        }
    };
    if !matches!(components.next(), Some(Component::RootDir)) {
        return Err(MigrationError::InvalidPlan(format!(
            "{label} path must be rooted"
        )));
    }
    let mut normalized = PathBuf::new();
    normalized.push(prefix.as_os_str());
    normalized.push(Path::new(r"\"));
    for component in components {
        match component {
            Component::Normal(name) => {
                validate_windows_component(name, label)?;
                normalized.push(name);
            }
            Component::CurDir | Component::ParentDir => {
                return Err(MigrationError::InvalidPlan(format!(
                    "{label} path must not contain '.' or '..'"
                )));
            }
            _ => {
                return Err(MigrationError::InvalidPlan(format!(
                    "{label} path is not normalized"
                )));
            }
        }
    }
    if path != normalized {
        return Err(MigrationError::InvalidPlan(format!(
            "{label} path is not normalized"
        )));
    }
    Ok(normalized)
}

fn validate_raw_release_path(path: &Path, label: &str) -> MigrationResult<()> {
    const BACKSLASH: u16 = b'\\' as u16;
    const FORWARD_SLASH: u16 = b'/' as u16;
    const COLON: u16 = b':' as u16;
    const DOT: u16 = b'.' as u16;

    let encoded = path.as_os_str().encode_wide().collect::<Vec<_>>();
    let drive_is_ascii_letter = encoded
        .first()
        .is_some_and(|unit| (*unit as u8).is_ascii_alphabetic() && *unit <= u8::MAX as u16);
    if encoded.len() < 3
        || !drive_is_ascii_letter
        || encoded[1] != COLON
        || encoded[2] != BACKSLASH
        || encoded.contains(&FORWARD_SLASH)
    {
        return Err(MigrationError::InvalidPlan(format!(
            "{label} path must be a normalized absolute drive path"
        )));
    }

    let remainder = &encoded[3..];
    if remainder.is_empty() {
        return Ok(());
    }
    for component in remainder.split(|unit| *unit == BACKSLASH) {
        if component.is_empty() || component == [DOT] || component == [DOT, DOT] {
            return Err(MigrationError::InvalidPlan(format!(
                "{label} path must not contain empty, '.' or '..' components"
            )));
        }
    }
    Ok(())
}

fn validate_windows_component(component: &std::ffi::OsStr, label: &str) -> MigrationResult<()> {
    let value = component.to_string_lossy();
    if value.is_empty()
        || value.ends_with(['.', ' '])
        || value
            .chars()
            .any(|character| character <= '\u{1f}' || r#"<>:"/\|?*"#.contains(character))
    {
        return Err(MigrationError::InvalidPlan(format!(
            "{label} contains an invalid Windows path component: {value}"
        )));
    }

    let stem = value.split('.').next().unwrap_or_default();
    let upper = stem.to_ascii_uppercase();
    let reserved = matches!(
        upper.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || upper.strip_prefix("COM").is_some_and(|suffix| {
        matches!(
            suffix,
            "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
        )
    }) || upper.strip_prefix("LPT").is_some_and(|suffix| {
        matches!(
            suffix,
            "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
        )
    });
    if reserved {
        return Err(MigrationError::InvalidPlan(format!(
            "{label} contains a reserved Windows device name: {value}"
        )));
    }
    Ok(())
}

fn ensure_source_offline(source_sid: &str) -> MigrationResult<()> {
    let canonical_sid = source_sid
        .strip_suffix(BAK_EXTENSION)
        .unwrap_or(source_sid)
        .trim();
    if canonical_sid.is_empty() || canonical_sid.contains('\\') || canonical_sid.contains('/') {
        return Err(MigrationError::InvalidPlan(
            "source SID is invalid".to_string(),
        ));
    }
    match open_key(RegistryRoot::Users, canonical_sid, KEY_READ) {
        Ok(_) => Err(MigrationError::SourceLoaded(canonical_sid.to_string())),
        Err(RegistryError::Win32Error(ERROR_FILE_NOT_FOUND)) => Ok(()),
        Err(error) => Err(MigrationError::Security(format!(
            "failed to verify whether source profile is loaded: {error}"
        ))),
    }
}

fn copy_tree_verified<F, C>(
    source: &SecureDirectory,
    destination: &SecureDirectory,
    relative_directory: &Path,
    transaction: &mut CopyTransaction,
    on_progress: &mut F,
    is_cancelled: &mut C,
) -> MigrationResult<()>
where
    F: FnMut(MigrationProgress),
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
                    on_progress,
                    is_cancelled,
                )?;
            }
            SecureEntryKind::File => copy_file_verified(
                source,
                destination,
                &entry.name,
                &relative_path,
                transaction,
                on_progress,
                is_cancelled,
            )?,
        }
    }
    Ok(())
}

fn copy_file_verified<F, C>(
    source_directory: &SecureDirectory,
    destination_directory: &SecureDirectory,
    name: &std::ffi::OsStr,
    relative_path: &Path,
    transaction: &mut CopyTransaction,
    on_progress: &mut F,
    is_cancelled: &mut C,
) -> MigrationResult<()>
where
    F: FnMut(MigrationProgress),
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
    let completed_bytes = transaction.copied_bytes();
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
        let observed_bytes = completed_bytes.saturating_add(copied_bytes);
        transaction.observe_copy(relative_path, observed_bytes);
        on_progress(MigrationProgress {
            phase: MigrationPhase::Copying,
            relative_path: Some(display_relative_path(relative_path)),
            completed_files: transaction.completed_files(),
            copied_bytes: observed_bytes,
        });
    }
    if is_cancelled() {
        return Err(MigrationError::Cancelled);
    }
    output.flush()?;
    output.sync_all()?;

    let source_sha = format!("{:x}", source_hasher.finalize());
    output.seek(SeekFrom::Start(0))?;
    on_progress(MigrationProgress {
        phase: MigrationPhase::Verifying,
        relative_path: Some(display_relative_path(relative_path)),
        completed_files: transaction.completed_files(),
        copied_bytes: transaction.copied_bytes(),
    });
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

fn display_relative_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
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

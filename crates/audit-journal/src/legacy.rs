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

//! Fail-closed detachment of storage created by older WinProfile releases.
//!
//! Legacy contents are never enumerated, parsed, imported, restored, deleted,
//! or granted new permissions. Only the exact top-level object is renamed by
//! handle. A protected sibling journal makes the namespace transition
//! monotonic and recoverable after process termination.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use platform_win32::{PrivilegeGuard, SecurityError, SE_BACKUP_NAME, SE_RESTORE_NAME};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use windows_sys::Win32::Foundation::NTSTATUS;
use windows_sys::Win32::Security::Cryptography::{
    BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
};
use windows_sys::Win32::Storage::FileSystem::{FILE_GENERIC_READ, FILE_SHARE_READ};

use crate::storage::{
    production_program_data_directory, validate_production_root, StorageDirectory, StorageError,
    StorageLock, StorageObjectIdentity, StorageRoot, BOOTSTRAP_DIRECTORY, PRODUCT_DIRECTORY,
};

const BOOTSTRAP_LOCK: &str = ".bootstrap.lock";
const BOOTSTRAP_LOCK_TIMEOUT: Duration = Duration::from_secs(2);
const STATE_PREFIX: &str = "migration-";
const STATE_SUFFIX: &str = ".json";
const LEGACY_PREFIX: &str = "WinProfile.Legacy.Untrusted.";
const NEXT_PREFIX: &str = "WinProfile.Next.";
const AUDIT_OPERATION: &str = "LegacyStorageDetached";
const AUDIT_ACTOR: &str = "WinProfile-Admin";

#[derive(Error, Debug)]
pub enum LegacyStorageError {
    #[error("protected storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("legacy migration state serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("legacy migration state IO failed: {0}")]
    Io(#[from] std::io::Error),
    #[error(
        "legacy migration state {name} was published but final synchronization failed: {source}"
    )]
    PublishedStateSync {
        name: String,
        #[source]
        source: std::io::Error,
    },
    #[error("legacy migration state {name} publication failed with an ambiguous durable result: {source}")]
    StatePublication {
        name: String,
        #[source]
        source: StorageError,
    },
    #[error("privilege adjustment failed: {0}")]
    Privilege(#[from] SecurityError),
    #[error(
        "legacy namespace operation failed ({operation_error}) and privilege restoration failed ({restore_error})"
    )]
    OperationAndPrivilegeRestore {
        operation_error: String,
        restore_error: String,
    },
    #[error("privilege restoration failed after a recoverable namespace transition: {0}")]
    PrivilegeRestore(String),
    #[error("legacy source identity changed after consent; no object was moved")]
    IdentityChanged,
    #[error("legacy migration state is invalid: {0}")]
    InvalidState(String),
    #[error("multiple unfinished legacy migrations are present")]
    AmbiguousState,
    #[error("Windows secure random generation failed with NTSTATUS {0:#010x}")]
    Random(NTSTATUS),
}

pub type LegacyStorageResult<T> = Result<T, LegacyStorageError>;

/// Shared proof that production storage is canonical and ready for services.
#[derive(Clone, Debug)]
pub struct ProductionStorage {
    pub(crate) root: Arc<StorageRoot>,
}

impl ProductionStorage {
    pub fn root_path(&self) -> PathBuf {
        self.root.path().to_path_buf()
    }
}

#[derive(Debug)]
pub enum ProductionStorageState {
    Ready(ProductionStorage),
    NeedsConsent(LegacyStorageRecovery),
    NeedsResume(LegacyStorageRecovery),
}

#[derive(Debug)]
pub struct LegacyStorageRecovery {
    reason: String,
    detected_identity: StorageObjectIdentity,
    resume: bool,
}

impl LegacyStorageRecovery {
    pub fn reason(&self) -> &str {
        &self.reason
    }

    pub fn is_resume(&self) -> bool {
        self.resume
    }

    /// Performs only the consented namespace transition. The returned guard
    /// retains the bootstrap lock until the caller has durably audited success.
    pub fn execute(self) -> LegacyStorageResult<PendingProductionStorage> {
        let program_data = production_program_data_directory()?;
        execute_recovery(program_data, self.detected_identity)
    }
}

#[derive(Debug)]
pub struct PendingProductionStorage {
    storage: ProductionStorage,
    bootstrap: StorageDirectory,
    _bootstrap_lock: StorageLock,
    state: MigrationStateRecord,
}

impl PendingProductionStorage {
    pub fn storage(&self) -> &ProductionStorage {
        &self.storage
    }

    pub fn migration_id(&self) -> &str {
        &self.state.migration_id
    }

    pub fn legacy_name(&self) -> &str {
        &self.state.legacy_name
    }

    pub fn audit_operation(&self) -> &'static str {
        AUDIT_OPERATION
    }

    pub fn audit_actor(&self) -> &'static str {
        AUDIT_ACTOR
    }

    pub fn audit_details(&self) -> String {
        format!(
            "migration_id={}; legacy_object={}; contents are untrusted, opaque, not imported, and retain their previous permissions",
            self.state.migration_id, self.state.legacy_name
        )
    }

    /// Marks completion only after the new audit logger has synchronized the
    /// terminal event. Consuming self releases the external bootstrap lock.
    pub fn complete(mut self) -> LegacyStorageResult<ProductionStorage> {
        self.state.phase = MigrationPhase::Done;
        write_state(&self.bootstrap, &self.state)?;
        Ok(self.storage)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
enum MigrationPhase {
    Prepared = 0,
    Detached = 1,
    RootReady = 2,
    AuditPending = 3,
    Done = 4,
}

impl MigrationPhase {
    fn next(self) -> Option<Self> {
        match self {
            Self::Prepared => Some(Self::Detached),
            Self::Detached => Some(Self::RootReady),
            Self::RootReady => Some(Self::AuditPending),
            Self::AuditPending => Some(Self::Done),
            Self::Done => None,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Detached => "detached",
            Self::RootReady => "root-ready",
            Self::AuditPending => "audit-pending",
            Self::Done => "done",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecoveryPlan {
    DetachAndActivate,
    Activate,
    MarkAuditPending,
    RetryTerminalAudit,
    Complete,
}

fn recovery_plan(phase: MigrationPhase) -> RecoveryPlan {
    match phase {
        MigrationPhase::Prepared => RecoveryPlan::DetachAndActivate,
        MigrationPhase::Detached => RecoveryPlan::Activate,
        MigrationPhase::RootReady => RecoveryPlan::MarkAuditPending,
        MigrationPhase::AuditPending => RecoveryPlan::RetryTerminalAudit,
        MigrationPhase::Done => RecoveryPlan::Complete,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MigrationStateRecord {
    schema: u32,
    migration_id: String,
    phase: MigrationPhase,
    source_identity: StorageObjectIdentity,
    next_identity: StorageObjectIdentity,
    legacy_name: String,
    next_name: String,
}

pub fn inspect_production_storage() -> LegacyStorageResult<ProductionStorageState> {
    inspect_under(production_program_data_directory()?)
}

fn inspect_under(program_data: StorageDirectory) -> LegacyStorageResult<ProductionStorageState> {
    inspect_under_with_identity(program_data, |directory| {
        directory.open_object_identity(PRODUCT_DIRECTORY)
    })
}

fn inspect_under_with_identity(
    program_data: StorageDirectory,
    capture_identity: impl FnOnce(&StorageDirectory) -> Result<StorageObjectIdentity, StorageError>,
) -> LegacyStorageResult<ProductionStorageState> {
    if let Some(pending) = load_pending_state(&program_data)? {
        return Ok(ProductionStorageState::NeedsResume(LegacyStorageRecovery {
            reason: format!(
                "interrupted legacy storage migration {} at {}",
                pending.migration_id,
                pending.phase.label()
            ),
            detected_identity: pending.source_identity,
            resume: true,
        }));
    }

    match StorageRoot::open_existing_under(&program_data) {
        Ok(root) => Ok(ProductionStorageState::Ready(ProductionStorage { root })),
        Err(error) if error.is_not_found() => {
            let root = StorageRoot::open_or_create_under(&program_data)?;
            Ok(ProductionStorageState::Ready(ProductionStorage { root }))
        }
        Err(error) => {
            let identity = capture_identity(&program_data)?;
            Ok(ProductionStorageState::NeedsConsent(
                LegacyStorageRecovery {
                    reason: error.to_string(),
                    detected_identity: identity,
                    resume: false,
                },
            ))
        }
    }
}

fn execute_recovery(
    program_data: StorageDirectory,
    detected_identity: StorageObjectIdentity,
) -> LegacyStorageResult<PendingProductionStorage> {
    let bootstrap = open_or_create_bootstrap(&program_data)?;
    let bootstrap_lock =
        bootstrap.acquire_protected_named_lock(BOOTSTRAP_LOCK, BOOTSTRAP_LOCK_TIMEOUT)?;
    let existing = load_pending_from_bootstrap(&bootstrap)?;

    let state = if let Some(state) = existing {
        resume_namespace(&program_data, &bootstrap, state)?
    } else {
        start_namespace(&program_data, &bootstrap, detected_identity)?
    };
    let storage = StorageRoot::open_existing_under(&program_data)?;
    let mut state = state;
    match recovery_plan(state.phase) {
        RecoveryPlan::MarkAuditPending => {
            state.phase = MigrationPhase::AuditPending;
            write_state(&bootstrap, &state)?;
        }
        RecoveryPlan::RetryTerminalAudit => {}
        _ => {
            return Err(LegacyStorageError::InvalidState(format!(
                "expected root-ready or audit-pending, found {}",
                state.phase.label()
            )));
        }
    }
    Ok(PendingProductionStorage {
        storage: ProductionStorage { root: storage },
        bootstrap,
        _bootstrap_lock: bootstrap_lock,
        state,
    })
}

fn start_namespace(
    program_data: &StorageDirectory,
    bootstrap: &StorageDirectory,
    detected_identity: StorageObjectIdentity,
) -> LegacyStorageResult<MigrationStateRecord> {
    let privileges = PrivilegeGuard::new(&[SE_BACKUP_NAME, SE_RESTORE_NAME])?;
    let operation = (|| {
        let source = program_data.open_object_for_detach(PRODUCT_DIRECTORY)?;
        if detected_identity != source.identity() {
            return Err(LegacyStorageError::IdentityChanged);
        }
        let migration_id = random_id()?;
        let legacy_name = format!("{LEGACY_PREFIX}{migration_id}");
        let next_name = format!("{NEXT_PREFIX}{migration_id}");
        let next = program_data.create_protected_child(&next_name)?;
        let mut state = MigrationStateRecord {
            schema: 1,
            migration_id,
            phase: MigrationPhase::Prepared,
            source_identity: source.identity(),
            next_identity: next.identity()?,
            legacy_name,
            next_name,
        };
        let next = persist_prepared_state(next, || write_state(bootstrap, &state))?;
        source.rename_to(program_data, &state.legacy_name)?;
        state.phase = MigrationPhase::Detached;
        write_state(bootstrap, &state)?;
        let active = next.rename_to(program_data, PRODUCT_DIRECTORY)?;
        validate_production_root(&active.handle, active.path())?;
        if active.identity()? != state.next_identity {
            return Err(LegacyStorageError::IdentityChanged);
        }
        state.phase = MigrationPhase::RootReady;
        write_state(bootstrap, &state)?;
        Ok(state)
    })();
    finish_privileged_namespace(operation, privileges.restore())
}

fn resume_namespace(
    program_data: &StorageDirectory,
    bootstrap: &StorageDirectory,
    mut state: MigrationStateRecord,
) -> LegacyStorageResult<MigrationStateRecord> {
    let privileges = PrivilegeGuard::new(&[SE_BACKUP_NAME, SE_RESTORE_NAME])?;
    let operation = (|| {
        if matches!(
            recovery_plan(state.phase),
            RecoveryPlan::MarkAuditPending
                | RecoveryPlan::RetryTerminalAudit
                | RecoveryPlan::Complete
        ) {
            verify_ready_root(program_data, &state)?;
            return Ok(state);
        }

        if state.phase == MigrationPhase::Prepared {
            match program_data.open_object_for_detach(PRODUCT_DIRECTORY) {
                Ok(source) => {
                    if source.identity() != state.source_identity {
                        return Err(LegacyStorageError::IdentityChanged);
                    }
                    source.rename_to(program_data, &state.legacy_name)?;
                }
                Err(error) if error.is_not_found() => {
                    let identity = program_data.open_object_identity(&state.legacy_name)?;
                    if identity != state.source_identity {
                        return Err(LegacyStorageError::IdentityChanged);
                    }
                }
                Err(error) => return Err(error.into()),
            }
            state.phase = MigrationPhase::Detached;
            write_state(bootstrap, &state)?;
        }

        if state.phase == MigrationPhase::Detached {
            if program_data.open_object_identity(&state.legacy_name)? != state.source_identity {
                return Err(LegacyStorageError::IdentityChanged);
            }
            match program_data.open_existing_child_for_rename(&state.next_name) {
                Ok(next) => {
                    if next.identity()? != state.next_identity {
                        return Err(LegacyStorageError::IdentityChanged);
                    }
                    next.rename_to(program_data, PRODUCT_DIRECTORY)?;
                }
                Err(error) if error.is_not_found() => verify_ready_root(program_data, &state)?,
                Err(error) => return Err(error.into()),
            }
            state.phase = MigrationPhase::RootReady;
            write_state(bootstrap, &state)?;
        }
        Ok(state)
    })();
    finish_privileged_namespace(operation, privileges.restore())
}

fn finish_privileged_namespace(
    operation: LegacyStorageResult<MigrationStateRecord>,
    restore: Result<(), SecurityError>,
) -> LegacyStorageResult<MigrationStateRecord> {
    match (operation, restore) {
        (Ok(state), Ok(())) => Ok(state),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(LegacyStorageError::PrivilegeRestore(error.to_string())),
        (Err(operation_error), Err(restore_error)) => {
            Err(LegacyStorageError::OperationAndPrivilegeRestore {
                operation_error: operation_error.to_string(),
                restore_error: restore_error.to_string(),
            })
        }
    }
}

fn verify_ready_root(
    program_data: &StorageDirectory,
    state: &MigrationStateRecord,
) -> LegacyStorageResult<()> {
    let root = StorageRoot::open_existing_under(program_data)?;
    if root.root_directory()?.identity()? != state.next_identity {
        return Err(LegacyStorageError::IdentityChanged);
    }
    if program_data.open_object_identity(&state.legacy_name)? != state.source_identity {
        return Err(LegacyStorageError::IdentityChanged);
    }
    Ok(())
}

fn open_or_create_bootstrap(
    program_data: &StorageDirectory,
) -> LegacyStorageResult<StorageDirectory> {
    match program_data.open_existing_child(BOOTSTRAP_DIRECTORY) {
        Ok(directory) => {
            validate_production_root(&directory.handle, directory.path())?;
            Ok(directory)
        }
        Err(error) if error.is_not_found() => {
            match program_data.create_protected_child(BOOTSTRAP_DIRECTORY) {
                Ok(directory) => Ok(directory),
                Err(error) if error.is_collision() => {
                    let directory = program_data.open_existing_child(BOOTSTRAP_DIRECTORY)?;
                    validate_production_root(&directory.handle, directory.path())?;
                    Ok(directory)
                }
                Err(error) => Err(error.into()),
            }
        }
        Err(error) => Err(error.into()),
    }
}

fn load_pending_state(
    program_data: &StorageDirectory,
) -> LegacyStorageResult<Option<MigrationStateRecord>> {
    let bootstrap = match program_data.open_existing_child(BOOTSTRAP_DIRECTORY) {
        Ok(directory) => directory,
        Err(error) if error.is_not_found() => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    validate_production_root(&bootstrap.handle, bootstrap.path())?;
    load_pending_from_bootstrap(&bootstrap)
}

fn load_pending_from_bootstrap(
    bootstrap: &StorageDirectory,
) -> LegacyStorageResult<Option<MigrationStateRecord>> {
    let mut grouped: BTreeMap<String, Vec<MigrationStateRecord>> = BTreeMap::new();
    for name in bootstrap.entries()? {
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with(STATE_PREFIX) || !name.ends_with(STATE_SUFFIX) {
            continue;
        }
        let mut file = bootstrap.open_file(OsStr::new(name), FILE_GENERIC_READ, FILE_SHARE_READ)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let record: MigrationStateRecord = serde_json::from_slice(&bytes)
            .map_err(|error| LegacyStorageError::InvalidState(format!("{name}: {error}")))?;
        if record.schema != 1 || state_file_name(&record) != name {
            return Err(LegacyStorageError::InvalidState(format!(
                "state filename/content mismatch: {name}"
            )));
        }
        grouped
            .entry(record.migration_id.clone())
            .or_default()
            .push(record);
    }

    let mut pending = Vec::new();
    for records in grouped.values_mut() {
        records.sort_by_key(|record| record.phase);
        if records.first().map(|record| record.phase) != Some(MigrationPhase::Prepared) {
            return Err(LegacyStorageError::InvalidState(
                "migration does not start at prepared".to_string(),
            ));
        }
        for pair in records.windows(2) {
            if pair[0].phase.next() != Some(pair[1].phase)
                || pair[0].source_identity != pair[1].source_identity
                || pair[0].next_identity != pair[1].next_identity
                || pair[0].legacy_name != pair[1].legacy_name
                || pair[0].next_name != pair[1].next_name
            {
                return Err(LegacyStorageError::InvalidState(
                    "migration state sequence is inconsistent".to_string(),
                ));
            }
        }
        let latest = records
            .last()
            .expect("grouped migration has at least one record")
            .clone();
        if latest.phase != MigrationPhase::Done {
            pending.push(latest);
        }
    }
    match pending.len() {
        0 => Ok(None),
        1 => Ok(pending.pop()),
        _ => Err(LegacyStorageError::AmbiguousState),
    }
}

fn write_state(
    bootstrap: &StorageDirectory,
    state: &MigrationStateRecord,
) -> LegacyStorageResult<()> {
    write_state_with_final_sync(bootstrap, state, |file| file.sync_all())
}

fn write_state_with_final_sync(
    bootstrap: &StorageDirectory,
    state: &MigrationStateRecord,
    final_sync: impl FnOnce(&std::fs::File) -> std::io::Result<()>,
) -> LegacyStorageResult<()> {
    let final_name = state_file_name(state);
    match bootstrap.open_file(OsStr::new(&final_name), FILE_GENERIC_READ, FILE_SHARE_READ) {
        Ok(file) => {
            let existing: MigrationStateRecord = serde_json::from_reader(file)?;
            if existing == *state {
                return Ok(());
            }
            return Err(LegacyStorageError::InvalidState(format!(
                "state collision for {final_name}"
            )));
        }
        Err(error) if error.is_not_found() => {}
        Err(error) => return Err(error.into()),
    }

    let temp_name = format!(".{}-{}.tmp", state.migration_id, random_id()?);
    let mut created = bootstrap.create_state_file(&temp_name)?;
    let bytes = serde_json::to_vec(state)?;
    created.file_mut().write_all(&bytes)?;
    created.file_mut().flush()?;
    created.file_mut().sync_all()?;
    let published = created.publish(bootstrap, &final_name).map_err(|source| {
        LegacyStorageError::StatePublication {
            name: final_name.clone(),
            source,
        }
    })?;
    final_sync(&published).map_err(|source| LegacyStorageError::PublishedStateSync {
        name: final_name,
        source,
    })?;
    Ok(())
}

fn persist_prepared_state(
    next: StorageDirectory,
    persist: impl FnOnce() -> LegacyStorageResult<()>,
) -> LegacyStorageResult<StorageDirectory> {
    match persist() {
        Ok(()) => Ok(next),
        Err(
            error @ (LegacyStorageError::PublishedStateSync { .. }
            | LegacyStorageError::StatePublication { .. }),
        ) => Err(error),
        Err(operation_error) => match next.remove() {
            Ok(()) => Err(operation_error),
            Err(cleanup_error) => Err(StorageError::CleanupFailed {
                operation_error: operation_error.to_string(),
                cleanup_error: cleanup_error.to_string(),
            }
            .into()),
        },
    }
}

fn state_file_name(state: &MigrationStateRecord) -> String {
    format!(
        "{STATE_PREFIX}{}-{}-{}{}",
        state.migration_id,
        state.phase as u8,
        state.phase.label(),
        STATE_SUFFIX
    )
}

fn random_id() -> LegacyStorageResult<String> {
    let mut bytes = [0u8; 16];
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status < 0 {
        return Err(LegacyStorageError::Random(status));
    }
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "winprofile-legacy-{}-{}",
                std::process::id(),
                TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).expect("create test directory");
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn decline_path_inspection_does_not_mutate_legacy_storage() {
        let temp = TestDirectory::new();
        let legacy = temp.0.join(PRODUCT_DIRECTORY);
        std::fs::create_dir(&legacy).expect("legacy directory");
        let forged = legacy.join("audit_log.jsonl");
        std::fs::write(&forged, b"forged\n").expect("forged journal");
        let parent =
            super::super::storage::open_absolute_directory(&temp.0).expect("program data fixture");
        let state = inspect_under(parent).expect("inspect legacy");
        assert!(matches!(state, ProductionStorageState::NeedsConsent(_)));
        assert_eq!(std::fs::read(forged).expect("forged bytes"), b"forged\n");
        assert!(!temp.0.join(BOOTSTRAP_DIRECTORY).exists());
    }

    #[test]
    fn failed_identity_capture_never_offers_consent_or_mutates_storage() {
        let temp = TestDirectory::new();
        let legacy = temp.0.join(PRODUCT_DIRECTORY);
        std::fs::create_dir(&legacy).expect("legacy directory");
        let sentinel = legacy.join("sentinel.bin");
        std::fs::write(&sentinel, b"unchanged").expect("sentinel");
        let parent =
            super::super::storage::open_absolute_directory(&temp.0).expect("program data fixture");
        let result = inspect_under_with_identity(parent, |_| {
            Err(StorageError::LegacyStorageInsecure(
                "injected identity access denial".to_string(),
            ))
        });

        assert!(
            matches!(result, Err(LegacyStorageError::Storage(_))),
            "identity capture unexpectedly produced {result:?}"
        );
        assert_eq!(
            std::fs::read(sentinel).expect("sentinel bytes"),
            b"unchanged"
        );
        assert!(!temp.0.join(BOOTSTRAP_DIRECTORY).exists());
    }

    #[test]
    fn corrupt_bootstrap_marker_fails_closed() {
        let temp = TestDirectory::new();
        let storage = StorageRoot::trusted(&temp.0).expect("trusted test storage");
        let bootstrap = storage.root_directory().expect("bootstrap fixture");
        let mut marker = bootstrap
            .create_state_file("migration-corrupt.json")
            .expect("marker");
        marker
            .file_mut()
            .write_all(b"not json")
            .expect("marker bytes");
        marker.commit().sync_all().expect("sync marker");
        assert!(matches!(
            load_pending_from_bootstrap(&bootstrap),
            Err(LegacyStorageError::InvalidState(_))
        ));
    }

    #[test]
    fn exact_junction_object_is_renamed_without_touching_target() {
        let temp = TestDirectory::new();
        let target = temp.0.join("target");
        std::fs::create_dir(&target).expect("target");
        let sentinel = target.join("sentinel.bin");
        std::fs::write(&sentinel, b"untouched").expect("sentinel");
        let legacy = temp.0.join(PRODUCT_DIRECTORY);
        let status = std::process::Command::new("cmd.exe")
            .args([
                "/d",
                "/c",
                "mklink",
                "/J",
                &legacy.display().to_string(),
                &target.display().to_string(),
            ])
            .status()
            .expect("create junction");
        assert!(status.success());

        let parent =
            super::super::storage::open_absolute_directory(&temp.0).expect("program data fixture");
        let object = parent
            .open_object_for_detach(PRODUCT_DIRECTORY)
            .expect("open junction object");
        object
            .rename_to(&parent, "WinProfile.Legacy.Untrusted.test")
            .expect("rename exact junction");
        drop(object);

        assert!(!legacy.exists());
        assert_eq!(
            std::fs::read(&sentinel).expect("sentinel bytes"),
            b"untouched"
        );
        std::fs::remove_dir(temp.0.join("WinProfile.Legacy.Untrusted.test"))
            .expect("remove renamed junction");
    }

    #[test]
    fn identity_change_after_detection_is_observable_before_rename() {
        let temp = TestDirectory::new();
        let legacy = temp.0.join(PRODUCT_DIRECTORY);
        std::fs::create_dir(&legacy).expect("legacy");
        let parent =
            super::super::storage::open_absolute_directory(&temp.0).expect("program data fixture");
        let detected = parent
            .open_object_identity(PRODUCT_DIRECTORY)
            .expect("detected identity");
        std::fs::rename(&legacy, temp.0.join("swapped-out")).expect("swap original");
        std::fs::create_dir(&legacy).expect("replacement");
        let current = parent
            .open_object_for_detach(PRODUCT_DIRECTORY)
            .expect("replacement handle");
        assert_ne!(detected, current.identity());
        assert!(legacy.exists());
    }

    #[test]
    fn existing_root_holder_blocks_detach() {
        let temp = TestDirectory::new();
        std::fs::create_dir(temp.0.join(PRODUCT_DIRECTORY)).expect("legacy");
        let parent =
            super::super::storage::open_absolute_directory(&temp.0).expect("program data fixture");
        let holder = parent
            .open_existing_child(PRODUCT_DIRECTORY)
            .expect("held root");
        let result = parent.open_object_for_detach(PRODUCT_DIRECTORY);
        assert!(result.is_err());
        drop(holder);
        assert!(parent.open_object_for_detach(PRODUCT_DIRECTORY).is_ok());
    }

    #[test]
    fn rename_collision_never_replaces_target() {
        let temp = TestDirectory::new();
        std::fs::create_dir(temp.0.join(PRODUCT_DIRECTORY)).expect("legacy");
        let collision = temp.0.join("WinProfile.Legacy.Untrusted.collision");
        std::fs::create_dir(&collision).expect("collision");
        std::fs::write(collision.join("sentinel"), b"collision").expect("sentinel");
        let parent =
            super::super::storage::open_absolute_directory(&temp.0).expect("program data fixture");
        let source = parent
            .open_object_for_detach(PRODUCT_DIRECTORY)
            .expect("source");
        assert!(source
            .rename_to(&parent, "WinProfile.Legacy.Untrusted.collision")
            .is_err());
        assert!(temp.0.join(PRODUCT_DIRECTORY).exists());
        assert_eq!(
            std::fs::read(collision.join("sentinel")).expect("sentinel bytes"),
            b"collision"
        );
    }

    #[test]
    fn every_durable_phase_is_recoverable_and_audit_failure_stays_pending() {
        let temp = TestDirectory::new();
        let storage = StorageRoot::trusted(&temp.0).expect("trusted storage");
        let bootstrap = storage.root_directory().expect("bootstrap fixture");
        let identity = bootstrap.identity().expect("identity");
        let mut state = MigrationStateRecord {
            schema: 1,
            migration_id: "phase-test".to_string(),
            phase: MigrationPhase::Prepared,
            source_identity: identity,
            next_identity: identity,
            legacy_name: "WinProfile.Legacy.Untrusted.phase-test".to_string(),
            next_name: "WinProfile.Next.phase-test".to_string(),
        };

        for phase in [
            MigrationPhase::Prepared,
            MigrationPhase::Detached,
            MigrationPhase::RootReady,
            MigrationPhase::AuditPending,
        ] {
            state.phase = phase;
            write_state(&bootstrap, &state).expect("durable phase");
            let loaded = load_pending_from_bootstrap(&bootstrap)
                .expect("valid state")
                .expect("pending state");
            assert_eq!(loaded.phase, phase);
        }
        // Simulated terminal audit failure: Done is deliberately absent.
        assert_eq!(
            load_pending_from_bootstrap(&bootstrap)
                .expect("valid pending state")
                .expect("audit remains pending")
                .phase,
            MigrationPhase::AuditPending
        );
        state.phase = MigrationPhase::Done;
        write_state(&bootstrap, &state).expect("done state");
        assert!(load_pending_from_bootstrap(&bootstrap)
            .expect("complete state")
            .is_none());
    }

    #[test]
    fn post_publish_sync_failure_keeps_prepared_marker_and_replacement_root() {
        let temp = TestDirectory::new();
        let storage = StorageRoot::trusted(&temp.0).expect("trusted storage");
        let bootstrap = storage.root_directory().expect("bootstrap fixture");
        let identity = bootstrap.identity().expect("identity");
        let next_name = "WinProfile.Next.sync-failure";
        std::fs::create_dir(temp.0.join(next_name)).expect("replacement root fixture");
        let next = bootstrap
            .open_existing_child_for_rename(next_name)
            .expect("replacement root handle");
        let state = MigrationStateRecord {
            schema: 1,
            migration_id: "sync-failure".to_string(),
            phase: MigrationPhase::Prepared,
            source_identity: identity,
            next_identity: identity,
            legacy_name: "WinProfile.Legacy.Untrusted.sync-failure".to_string(),
            next_name: next_name.to_string(),
        };

        let result = persist_prepared_state(next, || {
            write_state_with_final_sync(&bootstrap, &state, |_| {
                Err(std::io::Error::other("injected final sync failure"))
            })
        });

        assert!(matches!(
            result,
            Err(LegacyStorageError::PublishedStateSync { name, .. })
                if name == state_file_name(&state)
        ));
        assert!(temp.0.join(next_name).is_dir());
        assert_eq!(
            load_pending_from_bootstrap(&bootstrap)
                .expect("published marker is valid")
                .expect("published marker stays pending"),
            state
        );
    }

    #[test]
    fn proven_prepublication_failure_removes_replacement_and_has_no_marker() {
        let temp = TestDirectory::new();
        let storage = StorageRoot::trusted(&temp.0).expect("trusted storage");
        let bootstrap = storage.root_directory().expect("bootstrap fixture");
        let next_name = "WinProfile.Next.prepublish-failure";
        std::fs::create_dir(temp.0.join(next_name)).expect("replacement root fixture");
        let next = bootstrap
            .open_existing_child_for_rename(next_name)
            .expect("replacement root handle");
        let result = persist_prepared_state(next, || {
            Err(LegacyStorageError::Io(std::io::Error::other(
                "injected temporary write failure",
            )))
        });

        assert!(matches!(result, Err(LegacyStorageError::Io(_))));
        assert!(!temp.0.join(next_name).exists());
        assert!(bootstrap
            .entries()
            .expect("bootstrap entries")
            .iter()
            .all(|name| !name.to_string_lossy().ends_with(STATE_SUFFIX)));
    }

    #[test]
    fn operation_and_privilege_restore_errors_remain_visible() {
        let operation = Err(LegacyStorageError::IdentityChanged);
        let result = finish_privileged_namespace(operation, Err(SecurityError::Win32Error(5)));
        assert!(matches!(
            result,
            Err(LegacyStorageError::OperationAndPrivilegeRestore {
                operation_error,
                restore_error,
            }) if operation_error.contains("identity changed") && restore_error.contains('5')
        ));
    }

    #[test]
    fn crash_recovery_plan_covers_every_durable_phase() {
        assert_eq!(
            recovery_plan(MigrationPhase::Prepared),
            RecoveryPlan::DetachAndActivate
        );
        assert_eq!(
            recovery_plan(MigrationPhase::Detached),
            RecoveryPlan::Activate
        );
        assert_eq!(
            recovery_plan(MigrationPhase::RootReady),
            RecoveryPlan::MarkAuditPending
        );
        assert_eq!(
            recovery_plan(MigrationPhase::AuditPending),
            RecoveryPlan::RetryTerminalAudit
        );
        assert_eq!(recovery_plan(MigrationPhase::Done), RecoveryPlan::Complete);
    }

    #[test]
    fn permissive_precreated_bootstrap_lock_is_refused_without_mutation() {
        let temp = TestDirectory::new();
        let storage = StorageRoot::trusted(&temp.0).expect("trusted storage");
        let bootstrap = storage.root_directory().expect("bootstrap fixture");
        let lock_path = temp.0.join(BOOTSTRAP_LOCK);
        std::fs::write(&lock_path, b"attacker bytes").expect("permissive lock fixture");

        assert!(matches!(
            bootstrap.acquire_protected_named_lock(BOOTSTRAP_LOCK, Duration::from_millis(20)),
            Err(StorageError::LegacyStorageInsecure(_))
        ));
        assert_eq!(
            std::fs::read(lock_path).expect("lock bytes"),
            b"attacker bytes"
        );
    }

    #[test]
    fn audit_and_snapshots_share_the_exact_production_storage_token() {
        let temp = TestDirectory::new();
        let root = StorageRoot::trusted(&temp.0).expect("trusted storage");
        let storage = ProductionStorage { root };
        let audit = crate::AuditLogger::from_storage(&storage, 10).expect("audit logger");
        let snapshots = crate::SnapshotEngine::from_storage(&storage).expect("snapshot engine");

        assert_eq!(audit.storage_token(), snapshots.storage_token());
    }
}

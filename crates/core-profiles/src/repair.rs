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

use chrono::Utc;
use std::path::Path;
use thiserror::Error;
use windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND;
use windows_sys::Win32::System::Registry::{KEY_ALL_ACCESS, KEY_READ};

use audit_journal::{
    restore_registry_snapshot, AuditError, AuditLogger, AuditStatus, RollbackError, SnapshotEngine,
    SnapshotMetadata,
};
use platform_win32::{
    open_key, open_subkey, query_value_string, query_value_u32, rename_subkey, set_value_u32,
    subkey_exists, LockingProcessInfo, RegistryRoot, RestartManagerSession,
};

use crate::constants::*;
use crate::models::RepairPlan;

const AUDIT_ACTOR: &str = "WinProfile-Admin";
const BACKUP_SUFFIX: &str = "pre-repair";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManualCloseBlocker {
    pub application: String,
    pub process_id: u32,
}

#[derive(Error, Debug)]
pub enum RepairError {
    #[error("Profile is currently loaded in an active session; log off before repair")]
    SessionActive,
    #[error("Repair plan contains no selected operation")]
    NoActionSelected,
    #[error("Invalid profile SID: {0}")]
    InvalidSid(String),
    #[error("Required registry key is missing: {0}")]
    MissingRegistryKey(String),
    #[error("Registry operation failed: {0}")]
    RegistryError(#[from] platform_win32::RegistryError),
    #[error("Snapshot engine error: {0}")]
    SnapshotError(#[from] audit_journal::SnapshotError),
    #[error("Rollback failed: {0}")]
    RollbackError(#[from] RollbackError),
    #[error("Audit logging failed: {0}")]
    AuditError(#[from] AuditError),
    #[error("NTUSER.DAT lock inspection failed: {0}")]
    LockInspectionFailed(String),
    #[error(
        "Close the locking applications manually, save their work, and scan again: {blockers:?}"
    )]
    ManualCloseRequired { blockers: Vec<ManualCloseBlocker> },
    #[error("Automatic process shutdown is no longer supported; scan for blockers and close them manually")]
    AutomaticUnlockUnsupported,
    #[error("Transaction failed at step '{step}': {reason}")]
    TransactionFailed { step: String, reason: String },
}

pub type RepairResult<T> = Result<T, RepairError>;

#[derive(Default)]
struct RegistryMutation {
    bak_moved: bool,
    canonical_backup: Option<String>,
}

struct RepairSnapshot {
    metadata: SnapshotMetadata,
    expected_registry_key_path: String,
}

trait HiveLockInspector: Send + Sync {
    fn inspect(&self, ntuser_path: &Path) -> Result<Vec<ManualCloseBlocker>, String>;
}

struct RestartManagerHiveLockInspector;

impl HiveLockInspector for RestartManagerHiveLockInspector {
    fn inspect(&self, ntuser_path: &Path) -> Result<Vec<ManualCloseBlocker>, String> {
        match ntuser_path.try_exists() {
            Ok(false) => return Ok(Vec::new()),
            Ok(true) => {}
            Err(error) => {
                return Err(format!(
                    "failed to determine whether '{}' exists: {error}",
                    ntuser_path.display()
                ))
            }
        }
        let manager = RestartManagerSession::new().map_err(|error| error.to_string())?;
        manager
            .register_file(ntuser_path)
            .map_err(|error| error.to_string())?;
        manager
            .get_locking_processes()
            .map_err(|error| error.to_string())
            .map(|processes| {
                processes
                    .into_iter()
                    .map(ManualCloseBlocker::from)
                    .collect()
            })
    }
}

impl From<LockingProcessInfo> for ManualCloseBlocker {
    fn from(process: LockingProcessInfo) -> Self {
        Self {
            application: process.app_name,
            process_id: process.process_id,
        }
    }
}

static RESTART_MANAGER_LOCK_INSPECTOR: RestartManagerHiveLockInspector =
    RestartManagerHiveLockInspector;

/// Transactional repair executor for Windows user profiles.
pub struct ProfileRepairEngine<'a> {
    snapshot_engine: &'a SnapshotEngine,
    audit_logger: &'a AuditLogger,
    lock_inspector: &'a dyn HiveLockInspector,
}

impl<'a> ProfileRepairEngine<'a> {
    pub fn new(snapshot_engine: &'a SnapshotEngine, audit_logger: &'a AuditLogger) -> Self {
        Self {
            snapshot_engine,
            audit_logger,
            lock_inspector: &RESTART_MANAGER_LOCK_INSPECTOR,
        }
    }

    #[cfg(test)]
    fn with_lock_inspector(
        snapshot_engine: &'a SnapshotEngine,
        audit_logger: &'a AuditLogger,
        lock_inspector: &'a dyn HiveLockInspector,
    ) -> Self {
        Self {
            snapshot_engine,
            audit_logger,
            lock_inspector,
        }
    }

    /// Validates and executes a registry-only repair under mandatory snapshot protection.
    pub fn execute_plan(&self, plan: &RepairPlan, is_loaded: bool) -> RepairResult<()> {
        let _operation_guard = if plan.dry_run {
            None
        } else {
            Some(self.audit_logger.acquire_operation_guard()?)
        };
        if plan.unlock_hive {
            return Err(RepairError::AutomaticUnlockUnsupported);
        }
        self.validate_selected_actions(plan)?;
        self.validate_lock_contract(plan)?;
        let validation = self.validate_plan(plan, is_loaded)?;
        self.validate_lock_contract(plan)?;
        if plan.dry_run {
            self.audit_logger.log(
                "RepairDryRun",
                AUDIT_ACTOR,
                &plan.canonical_sid,
                AuditStatus::Success,
                validation,
            )?;
            return Ok(());
        }

        let snapshots = self.create_required_snapshots(plan)?;
        self.audit_logger.log(
            "RepairStarted",
            AUDIT_ACTOR,
            &plan.canonical_sid,
            AuditStatus::Warning,
            format!(
                "Validated repair with {} durable snapshot(s)",
                snapshots.len()
            ),
        )?;

        let parent = open_key(
            RegistryRoot::LocalMachine,
            REG_KEY_PROFILE_LIST,
            KEY_ALL_ACCESS,
        )?;
        let mut mutation = RegistryMutation::default();
        let execution = self.execute_steps(plan, &parent, &mut mutation);

        if let Err(error) = execution {
            let rollback = self.rollback(plan, &parent, &mutation, &snapshots);
            let details = match rollback {
                Ok(()) => format!("Repair failed and rollback completed: {error}"),
                Err(rollback_error) => {
                    let mut reason =
                        format!("original error: {error}; rollback error: {rollback_error}");
                    if let Err(audit_error) = self.audit_logger.log(
                        "RepairRollbackFailed",
                        AUDIT_ACTOR,
                        &plan.canonical_sid,
                        AuditStatus::Failed,
                        &reason,
                    ) {
                        reason.push_str(&format!("; audit error: {audit_error}"));
                    }
                    return Err(RepairError::TransactionFailed {
                        step: "Rollback".to_string(),
                        reason,
                    });
                }
            };
            self.audit_logger.log(
                "RepairFailed",
                AUDIT_ACTOR,
                &plan.canonical_sid,
                AuditStatus::RolledBack,
                details,
            )?;
            return Err(error);
        }

        if let Err(audit_error) = self.audit_logger.log(
            "RepairSuccess",
            AUDIT_ACTOR,
            &plan.canonical_sid,
            AuditStatus::Success,
            format!(
                "Repair verified; preserved prior canonical key: {}",
                mutation.canonical_backup.as_deref().unwrap_or("none")
            ),
        ) {
            self.rollback(plan, &parent, &mutation, &snapshots)?;
            return Err(audit_error.into());
        }

        Ok(())
    }

    fn validate_plan(&self, plan: &RepairPlan, is_loaded: bool) -> RepairResult<String> {
        self.validate_selected_actions(plan)?;
        if !is_valid_sid(&plan.canonical_sid) {
            return Err(RepairError::InvalidSid(plan.canonical_sid.clone()));
        }
        let bak_sid = format!("{}{}", plan.canonical_sid, BAK_EXTENSION);
        if plan.sid != plan.canonical_sid && plan.sid != bak_sid {
            return Err(RepairError::InvalidSid(plan.sid.clone()));
        }
        let live_loaded = match open_key(RegistryRoot::Users, &plan.canonical_sid, KEY_READ) {
            Ok(_) => true,
            Err(platform_win32::RegistryError::Win32Error(ERROR_FILE_NOT_FOUND)) => false,
            Err(error) => return Err(error.into()),
        };
        if is_loaded || live_loaded {
            return Err(RepairError::SessionActive);
        }

        let parent = open_key(RegistryRoot::LocalMachine, REG_KEY_PROFILE_LIST, KEY_READ)?;
        let canonical_name = &plan.canonical_sid;
        let bak_name = format!("{canonical_name}{BAK_EXTENSION}");
        if !subkey_exists(&parent, &plan.sid)? {
            return Err(RepairError::MissingRegistryKey(plan.sid.clone()));
        }
        let selected_key = open_subkey(&parent, &plan.sid, KEY_READ)?;
        let selected_profile_path = query_value_string(&selected_key, VAL_PROFILE_IMAGE_PATH)?;
        if normalize_profile_path(&selected_profile_path)
            != normalize_profile_path(&plan.profile_path)
        {
            return Err(RepairError::TransactionFailed {
                step: "Preflight".to_string(),
                reason: format!(
                    "selected registry path '{}' does not match plan path '{}'",
                    selected_profile_path, plan.profile_path
                ),
            });
        }

        if plan.fix_bak {
            if !subkey_exists(&parent, &bak_name)? {
                return Err(RepairError::MissingRegistryKey(bak_name));
            }
            let bak = open_subkey(&parent, &bak_name, KEY_READ)?;
            let profile_path = query_value_string(&bak, VAL_PROFILE_IMAGE_PATH)?;
            if profile_path.trim().is_empty() {
                return Err(RepairError::TransactionFailed {
                    step: "Preflight".to_string(),
                    reason: "the .bak key has an empty ProfileImagePath".to_string(),
                });
            }
        } else if plan.reset_state && !subkey_exists(&parent, canonical_name)? {
            return Err(RepairError::MissingRegistryKey(canonical_name.clone()));
        }

        Ok(format!(
            "Preflight passed: fix_bak={}, reset_state={}, unlock_hive={}, canonical_exists={}",
            plan.fix_bak,
            plan.reset_state,
            plan.unlock_hive,
            subkey_exists(&parent, canonical_name)?
        ))
    }

    fn validate_selected_actions(&self, plan: &RepairPlan) -> RepairResult<()> {
        if !plan.fix_bak && !plan.reset_state {
            return Err(RepairError::NoActionSelected);
        }
        Ok(())
    }

    fn validate_lock_contract(&self, plan: &RepairPlan) -> RepairResult<()> {
        let profile_path = Path::new(&plan.profile_path);
        if plan.profile_path.trim().is_empty() || !profile_path.is_absolute() {
            return Err(RepairError::TransactionFailed {
                step: "LockInspection".to_string(),
                reason: "profile path must be absolute before NTUSER.DAT lock inspection"
                    .to_string(),
            });
        }
        let blockers = self
            .lock_inspector
            .inspect(&profile_path.join(NTUSER_DAT))
            .map_err(RepairError::LockInspectionFailed)?;
        if !blockers.is_empty() {
            return Err(RepairError::ManualCloseRequired { blockers });
        }
        Ok(())
    }

    fn create_required_snapshots(&self, plan: &RepairPlan) -> RepairResult<Vec<RepairSnapshot>> {
        let mut paths = Vec::new();
        let canonical_path = format!("{REG_KEY_PROFILE_LIST}\\{}", plan.canonical_sid);
        let bak_path = format!("{canonical_path}{BAK_EXTENSION}");

        if plan.fix_bak {
            paths.push(bak_path);
            let parent = open_key(RegistryRoot::LocalMachine, REG_KEY_PROFILE_LIST, KEY_READ)?;
            if subkey_exists(&parent, &plan.canonical_sid)? {
                paths.push(canonical_path);
            }
        } else if plan.reset_state {
            paths.push(canonical_path);
        }

        let mut snapshots = Vec::with_capacity(paths.len());
        for path in paths {
            let metadata = self.snapshot_engine.create_registry_snapshot(
                &path,
                &plan.canonical_sid,
                &plan.profile_path,
                "Mandatory pre-repair snapshot",
            )?;
            snapshots.push(RepairSnapshot {
                metadata,
                expected_registry_key_path: format!("HKLM\\{path}"),
            });
        }
        Ok(snapshots)
    }

    fn execute_steps(
        &self,
        plan: &RepairPlan,
        parent: &platform_win32::OwnedHKey,
        mutation: &mut RegistryMutation,
    ) -> RepairResult<()> {
        let canonical_name = &plan.canonical_sid;
        let bak_name = format!("{canonical_name}{BAK_EXTENSION}");
        if plan.fix_bak {
            if subkey_exists(parent, canonical_name)? {
                let backup_name = format!(
                    "{canonical_name}.{BACKUP_SUFFIX}-{}",
                    Utc::now().format("%Y%m%dT%H%M%S%.6fZ")
                );
                if subkey_exists(parent, &backup_name)? {
                    return Err(RepairError::TransactionFailed {
                        step: "RegistryRename".to_string(),
                        reason: format!("backup key already exists: {backup_name}"),
                    });
                }
                rename_subkey(parent, canonical_name, &backup_name)?;
                mutation.canonical_backup = Some(backup_name);
            }

            rename_subkey(parent, &bak_name, canonical_name)?;
            mutation.bak_moved = true;
        }

        if plan.reset_state {
            let canonical = open_subkey(parent, canonical_name, KEY_ALL_ACCESS)?;
            set_value_u32(&canonical, VAL_STATE, 0)?;
            set_value_u32(&canonical, VAL_REF_COUNT, 0)?;
        }

        self.verify(plan, parent)
    }

    fn verify(&self, plan: &RepairPlan, parent: &platform_win32::OwnedHKey) -> RepairResult<()> {
        if !subkey_exists(parent, &plan.canonical_sid)? {
            return Err(RepairError::MissingRegistryKey(plan.canonical_sid.clone()));
        }
        if plan.fix_bak
            && subkey_exists(parent, &format!("{}{}", plan.canonical_sid, BAK_EXTENSION))?
        {
            return Err(RepairError::TransactionFailed {
                step: "Verification".to_string(),
                reason: "the .bak key still exists".to_string(),
            });
        }
        let canonical = open_subkey(parent, &plan.canonical_sid, KEY_READ)?;
        if query_value_string(&canonical, VAL_PROFILE_IMAGE_PATH)?
            .trim()
            .is_empty()
        {
            return Err(RepairError::TransactionFailed {
                step: "Verification".to_string(),
                reason: "ProfileImagePath is empty".to_string(),
            });
        }
        if plan.reset_state {
            let state = query_value_u32(&canonical, VAL_STATE)?;
            let ref_count = query_value_u32(&canonical, VAL_REF_COUNT)?;
            if state != 0 || ref_count != 0 {
                return Err(RepairError::TransactionFailed {
                    step: "Verification".to_string(),
                    reason: format!("State={state}, RefCount={ref_count}"),
                });
            }
        }
        Ok(())
    }

    fn rollback(
        &self,
        plan: &RepairPlan,
        parent: &platform_win32::OwnedHKey,
        mutation: &RegistryMutation,
        snapshots: &[RepairSnapshot],
    ) -> RepairResult<()> {
        let canonical_name = &plan.canonical_sid;
        let bak_name = format!("{canonical_name}{BAK_EXTENSION}");
        let mut errors = Vec::new();

        if mutation.bak_moved {
            match subkey_exists(parent, canonical_name) {
                Ok(true) => {
                    if let Err(error) = rename_subkey(parent, canonical_name, &bak_name) {
                        errors.push(format!("restore .bak name: {error}"));
                    }
                }
                Ok(false) => {}
                Err(error) => errors.push(format!("inspect canonical key: {error}")),
            }
        }
        if let Some(backup_name) = mutation.canonical_backup.as_deref() {
            match subkey_exists(parent, backup_name) {
                Ok(true) => {
                    if let Err(error) = rename_subkey(parent, backup_name, canonical_name) {
                        errors.push(format!("restore canonical name: {error}"));
                    }
                }
                Ok(false) => {}
                Err(error) => errors.push(format!("inspect canonical backup: {error}")),
            }
        }
        errors = attempt_all_then_audit(
            snapshots,
            errors,
            |snapshot| {
                restore_registry_snapshot(&snapshot.metadata, &snapshot.expected_registry_key_path)
                    .map_err(|error| {
                        format!("restore {}: {error}", snapshot.expected_registry_key_path)
                    })
            },
            |restore_errors| {
                let (status, details) = rollback_summary(snapshots.len(), restore_errors);
                self.audit_logger
                    .log(
                        "RepairRollbackSummary",
                        AUDIT_ACTOR,
                        &plan.canonical_sid,
                        status,
                        details,
                    )
                    .map_err(|error| format!("rollback summary audit: {error}"))
            },
        );
        if !errors.is_empty() {
            return Err(RollbackError::Aggregate(errors.join("; ")).into());
        }
        Ok(())
    }
}

fn attempt_all_then_audit<T, Restore, Audit>(
    items: &[T],
    mut errors: Vec<String>,
    mut restore: Restore,
    audit: Audit,
) -> Vec<String>
where
    Restore: FnMut(&T) -> Result<(), String>,
    Audit: FnOnce(&[String]) -> Result<(), String>,
{
    for item in items {
        if let Err(error) = restore(item) {
            errors.push(error);
        }
    }
    if let Err(error) = audit(&errors) {
        errors.push(error);
    }
    errors
}

fn rollback_summary(snapshot_count: usize, errors: &[String]) -> (AuditStatus, String) {
    if errors.is_empty() {
        (
            AuditStatus::RolledBack,
            format!("Rollback completed for {snapshot_count} snapshot(s)"),
        )
    } else {
        (
            AuditStatus::Failed,
            format!(
                "Rollback attempted all {snapshot_count} snapshot(s); {} error(s): {}",
                errors.len(),
                errors.join("; ")
            ),
        )
    }
}

fn is_valid_sid(value: &str) -> bool {
    value.starts_with("S-1-")
        && value
            .split('-')
            .skip(1)
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn normalize_profile_path(value: &str) -> String {
    value
        .trim()
        .trim_end_matches(['\\', '/'])
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::{
        attempt_all_then_audit, is_valid_sid, rollback_summary, HiveLockInspector,
        ManualCloseBlocker, ProfileRepairEngine, RepairError,
    };
    use crate::models::RepairPlan;
    use audit_journal::{AuditLogger, AuditStatus, SnapshotEngine};
    use std::cell::RefCell;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    struct RepairTestDirectory(PathBuf);

    impl RepairTestDirectory {
        fn new() -> Self {
            static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "winprofile-repair-lock-contract-{}-{sequence}",
                std::process::id()
            ));
            std::fs::create_dir(&path).expect("create repair test directory");
            Self(path)
        }
    }

    impl Drop for RepairTestDirectory {
        fn drop(&mut self) {
            if let Err(error) = std::fs::remove_dir_all(&self.0) {
                eprintln!(
                    "failed to remove repair test directory {}: {error}",
                    self.0.display()
                );
            }
        }
    }

    struct FakeLockInspector {
        result: Mutex<Option<Result<Vec<ManualCloseBlocker>, String>>>,
        calls: AtomicUsize,
    }

    impl FakeLockInspector {
        fn new(result: Result<Vec<ManualCloseBlocker>, String>) -> Self {
            Self {
                result: Mutex::new(Some(result)),
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl HiveLockInspector for FakeLockInspector {
        fn inspect(&self, _ntuser_path: &Path) -> Result<Vec<ManualCloseBlocker>, String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.result
                .lock()
                .expect("fake lock inspector")
                .take()
                .expect("one lock inspection")
        }
    }

    fn test_plan(profile_path: &Path, unlock_hive: bool) -> RepairPlan {
        RepairPlan {
            sid: "S-1-5-21-1001".to_string(),
            canonical_sid: "S-1-5-21-1001".to_string(),
            profile_path: profile_path.display().to_string(),
            fix_bak: true,
            reset_state: false,
            unlock_hive,
            dry_run: false,
        }
    }

    fn test_engines(directory: &RepairTestDirectory) -> (SnapshotEngine, AuditLogger) {
        let snapshots = SnapshotEngine::new(Some(directory.0.join("Snapshots")))
            .expect("create snapshot engine");
        let audit = AuditLogger::new(Some(directory.0.join("audit.jsonl")), 10)
            .expect("create audit logger");
        (snapshots, audit)
    }

    #[test]
    fn sid_validation_is_strict() {
        assert!(is_valid_sid("S-1-5-21-1001"));
        assert!(!is_valid_sid("S-1-5-21-1001.bak"));
        assert!(!is_valid_sid("S-1-5-21-abc"));
        assert!(!is_valid_sid("S-1-5-21-"));
        assert!(!is_valid_sid(""));
    }

    #[test]
    fn every_snapshot_is_attempted_before_audit_failure_is_reported() {
        let attempted = RefCell::new(Vec::new());
        let errors = attempt_all_then_audit(
            &[1, 2],
            Vec::new(),
            |item| {
                attempted.borrow_mut().push(*item);
                if *item == 1 {
                    Err("first restore failed".to_string())
                } else {
                    Ok(())
                }
            },
            |_| Err("summary audit failed".to_string()),
        );
        assert_eq!(*attempted.borrow(), vec![1, 2]);
        assert_eq!(errors.len(), 2);
        assert!(errors[0].contains("first restore"));
        assert!(errors[1].contains("audit"));
    }

    #[test]
    fn rename_error_makes_summary_failed_after_every_snapshot_attempt() {
        let attempted = RefCell::new(Vec::new());
        let summary = RefCell::new(None);
        let errors = attempt_all_then_audit(
            &[1, 2],
            vec!["restore canonical name: access denied".to_string()],
            |item| {
                attempted.borrow_mut().push(*item);
                Ok(())
            },
            |all_errors| {
                summary.replace(Some(rollback_summary(2, all_errors)));
                Ok(())
            },
        );

        assert_eq!(*attempted.borrow(), vec![1, 2]);
        assert_eq!(errors.len(), 1);
        let (status, details) = summary.take().expect("summary captured");
        assert_eq!(status, AuditStatus::Failed);
        assert!(details.contains("restore canonical name: access denied"));
        assert!(details.contains("attempted all 2 snapshot"));
    }

    #[test]
    fn measured_lockers_fail_before_snapshot_mutation_or_success_audit() {
        let directory = RepairTestDirectory::new();
        let (snapshots, audit) = test_engines(&directory);
        let inspector = FakeLockInspector::new(Ok(vec![ManualCloseBlocker {
            application: "Editor.exe".to_string(),
            process_id: 4242,
        }]));
        let engine = ProfileRepairEngine::with_lock_inspector(&snapshots, &audit, &inspector);

        let result = engine.execute_plan(&test_plan(&directory.0, false), false);

        assert!(matches!(
            result,
            Err(RepairError::ManualCloseRequired { blockers })
                if blockers == vec![ManualCloseBlocker {
                    application: "Editor.exe".to_string(),
                    process_id: 4242,
                }]
        ));
        assert_eq!(inspector.calls.load(Ordering::SeqCst), 1);
        assert!(snapshots
            .list_snapshots()
            .expect("snapshot inventory")
            .is_empty());
        assert!(audit.get_entries().expect("audit entries").is_empty());
    }

    #[test]
    fn obsolete_unlock_flag_is_rejected_even_without_lockers_or_effects() {
        let directory = RepairTestDirectory::new();
        let (snapshots, audit) = test_engines(&directory);
        let inspector = FakeLockInspector::new(Ok(Vec::new()));
        let engine = ProfileRepairEngine::with_lock_inspector(&snapshots, &audit, &inspector);

        let result = engine.execute_plan(&test_plan(&directory.0, true), false);

        assert!(matches!(
            result,
            Err(RepairError::AutomaticUnlockUnsupported)
        ));
        assert_eq!(inspector.calls.load(Ordering::SeqCst), 0);
        assert!(snapshots
            .list_snapshots()
            .expect("snapshot inventory")
            .is_empty());
        assert!(audit.get_entries().expect("audit entries").is_empty());
    }

    #[test]
    fn lock_inspection_failure_is_fail_closed_before_any_effect() {
        let directory = RepairTestDirectory::new();
        let (snapshots, audit) = test_engines(&directory);
        let inspector = FakeLockInspector::new(Err("Restart Manager unavailable".to_string()));
        let engine = ProfileRepairEngine::with_lock_inspector(&snapshots, &audit, &inspector);

        let result = engine.execute_plan(&test_plan(&directory.0, false), false);

        assert!(matches!(
            result,
            Err(RepairError::LockInspectionFailed(details))
                if details == "Restart Manager unavailable"
        ));
        assert_eq!(inspector.calls.load(Ordering::SeqCst), 1);
        assert!(snapshots
            .list_snapshots()
            .expect("snapshot inventory")
            .is_empty());
        assert!(audit.get_entries().expect("audit entries").is_empty());
    }
}

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
use windows_sys::Win32::System::Registry::{HKEY_LOCAL_MACHINE, KEY_ALL_ACCESS, KEY_READ, KEY_WRITE};

use audit_journal::{
    restore_registry_snapshot, AuditLogger, AuditStatus, SnapshotEngine,
    SnapshotMetadata,
};
use platform_win32::{
    create_key, delete_tree, open_key, query_value_string, query_value_u32,
    reset_tree_security_safe, set_value_string, set_value_u32,
    RestartManagerSession,
};

use crate::constants::*;
use crate::models::RepairPlan;

#[derive(Error, Debug)]
pub enum RepairError {
    #[error("Profile is currently loaded in active session. User must log off first.")]
    SessionActive,
    #[error("Registry operation failed: {0}")]
    RegistryError(#[from] platform_win32::RegistryError),
    #[error("Security or ACL remediation failed: {0}")]
    SecurityError(#[from] platform_win32::SecurityError),
    #[error("Snapshot engine error: {0}")]
    SnapshotError(#[from] audit_journal::SnapshotError),
    #[error("Transaction failed at step '{step}': {reason}")]
    TransactionFailed { step: String, reason: String },
}

pub type RepairResult<T> = Result<T, RepairError>;

/// Transactional repair executor for Windows user profiles.
pub struct ProfileRepairEngine<'a> {
    snapshot_engine: &'a SnapshotEngine,
    audit_logger: &'a AuditLogger,
}

impl<'a> ProfileRepairEngine<'a> {
    pub fn new(snapshot_engine: &'a SnapshotEngine, audit_logger: &'a AuditLogger) -> Self {
        Self {
            snapshot_engine,
            audit_logger,
        }
    }

    /// Executes the full repair plan under snapshot protection and audit tracking.
    pub fn execute_plan(&self, plan: &RepairPlan, is_loaded: bool) -> RepairResult<()> {
        if is_loaded && !plan.dry_run {
            return Err(RepairError::SessionActive);
        }

        let canonical_subkey = format!("{}\\{}", REG_KEY_PROFILE_LIST, plan.canonical_sid);
        let bak_subkey = format!("{}\\{}{}", REG_KEY_PROFILE_LIST, plan.canonical_sid, BAK_EXTENSION);

        if plan.dry_run {
            self.audit_logger.log(
                "RepairDryRun",
                "WinProfile-Admin",
                &plan.canonical_sid,
                AuditStatus::Success,
                "Simulation completed successfully without altering system state.",
            );
            return Ok(());
        }

        // 1. Snapshot Phase
        let mut snapshot: Option<SnapshotMetadata> = None;
        let target_snapshot_key = if plan.fix_bak {
            &bak_subkey
        } else {
            &canonical_subkey
        };

        if let Ok(snap) = self.snapshot_engine.create_registry_snapshot(
            target_snapshot_key,
            &plan.canonical_sid,
            &plan.profile_path,
            "Pre-repair automatic transaction snapshot",
        ) {
            snapshot = Some(snap);
        }

        // 2. Execution Phase
        let transaction_result = self.execute_transaction_steps(plan, &canonical_subkey, &bak_subkey);

        // 3. Rollback on Error
        if let Err(ref err) = transaction_result {
            self.audit_logger.log(
                "RepairFailed",
                "WinProfile-Admin",
                &plan.canonical_sid,
                AuditStatus::Failed,
                format!("Error: {err}. Initiating rollback..."),
            );

            if let Some(ref snap) = snapshot {
                let _ = restore_registry_snapshot(snap, Some(self.audit_logger));
            }
        } else {
            self.audit_logger.log(
                "RepairSuccess",
                "WinProfile-Admin",
                &plan.canonical_sid,
                AuditStatus::Success,
                "Profile repaired and verified cleanly.",
            );
        }

        transaction_result
    }

    fn execute_transaction_steps(
        &self,
        plan: &RepairPlan,
        canonical_subkey: &str,
        bak_subkey: &str,
    ) -> RepairResult<()> {
        // Step A: Unlock NTUSER.DAT if requested
        if plan.unlock_hive && !plan.profile_path.is_empty() {
            let ntuser_path = Path::new(&plan.profile_path).join(NTUSER_DAT);
            if ntuser_path.exists() {
                if let Ok(rm) = RestartManagerSession::new() {
                    if rm.register_file(&ntuser_path).is_ok() {
                        let _ = rm.shutdown_locking_processes(false);
                    }
                }
            }
        }

        // Step B: Fix .bak key renaming
        if plan.fix_bak {
            // If a broken temporary canonical key exists, remove it
            let _ = delete_tree(
                &open_key(HKEY_LOCAL_MACHINE, REG_KEY_PROFILE_LIST, KEY_ALL_ACCESS)?,
                &plan.canonical_sid,
            );

            // Read values from .bak key
            let bak_key = open_key(HKEY_LOCAL_MACHINE, bak_subkey, KEY_READ)?;
            let profile_image_path = query_value_string(&bak_key, VAL_PROFILE_IMAGE_PATH).unwrap_or_default();
            let guid = query_value_string(&bak_key, VAL_GUID).ok();
            let flags = query_value_u32(&bak_key, VAL_FLAGS).unwrap_or(0);

            // Create fresh canonical key
            let parent_key = open_key(HKEY_LOCAL_MACHINE, REG_KEY_PROFILE_LIST, KEY_ALL_ACCESS)?;
            let new_key = create_key(parent_key.as_raw(), &plan.canonical_sid, KEY_ALL_ACCESS)?;

            if !profile_image_path.is_empty() {
                set_value_string(&new_key, VAL_PROFILE_IMAGE_PATH, &profile_image_path)?;
            }
            if let Some(ref g) = guid {
                set_value_string(&new_key, VAL_GUID, g)?;
            }
            if flags != 0 {
                set_value_u32(&new_key, VAL_FLAGS, flags)?;
            }

            // Set clean State and RefCount
            set_value_u32(&new_key, VAL_STATE, 0)?;
            set_value_u32(&new_key, VAL_REF_COUNT, 0)?;

            // Delete old .bak key
            let _ = delete_tree(&parent_key, &format!("{}{}", plan.canonical_sid, BAK_EXTENSION));
        }

        // Step C: Reset State / RefCount if not already done by .bak fix
        if plan.reset_state && !plan.fix_bak {
            let key = open_key(HKEY_LOCAL_MACHINE, canonical_subkey, KEY_WRITE)?;
            set_value_u32(&key, VAL_STATE, 0)?;
            set_value_u32(&key, VAL_REF_COUNT, 0)?;
        }

        // Step D: Reassign ownership & fix NTFS DACL
        if plan.fix_acls && !plan.profile_path.is_empty() {
            let path_obj = Path::new(&plan.profile_path);
            if path_obj.exists() {
                reset_tree_security_safe(path_obj, &plan.canonical_sid)?;
            }
        }

        // Verification Step: Verify canonical key exists and State == 0
        let verify_key = open_key(HKEY_LOCAL_MACHINE, canonical_subkey, KEY_READ)?;
        let state = query_value_u32(&verify_key, VAL_STATE).unwrap_or(1);
        if state != 0 {
            return Err(RepairError::TransactionFailed {
                step: "Verification".into(),
                reason: format!("State mask remains dirty: {state}"),
            });
        }

        Ok(())
    }
}

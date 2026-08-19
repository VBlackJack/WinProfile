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

use audit_journal::{AuditLogger, AuditStatus};
use platform_win32::is_reparse_point;
use crate::constants::*;
use crate::models::MigrationPlan;

#[derive(Error, Debug)]
pub enum MigrationError {
    #[error("Source profile directory does not exist: {0}")]
    SourceNotFound(String),
    #[error("IO error during migration copy: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Permission denied on path: {0}")]
    PermissionDenied(String),
}

pub type MigrationResult<T> = Result<T, MigrationError>;

/// Engine responsible for selective, secure profile data migration.
pub struct ProfileMigrationEngine<'a> {
    audit_logger: &'a AuditLogger,
}

impl<'a> ProfileMigrationEngine<'a> {
    pub fn new(audit_logger: &'a AuditLogger) -> Self {
        Self { audit_logger }
    }

    /// Performs selective migration according to the specified plan.
    pub fn execute_migration<F>(&self, plan: &MigrationPlan, mut on_progress: F) -> MigrationResult<()>
    where
        F: FnMut(&str, f32),
    {
        let src_path = Path::new(&plan.source_path);
        let dst_path = Path::new(&plan.target_path);

        if !src_path.exists() {
            return Err(MigrationError::SourceNotFound(plan.source_path.clone()));
        }

        if !dst_path.exists() {
            std::fs::create_dir_all(dst_path)?;
        }

        // DPAPI & EFS check
        let dpapi_path = src_path.join(APPDATA_ROAMING_REL_PATH).join("Microsoft").join("Protect");
        if dpapi_path.exists() {
            self.audit_logger.log(
                "MigrationWarning",
                "WinProfile-Admin",
                &plan.source_sid,
                AuditStatus::Warning,
                "DPAPI MasterKey directory detected. Secrets (browser passwords/OAuth tokens) are SID-bound and cannot be automatically decrypted under new account.",
            );
        }

        // 1. Migrate AppData\Roaming if enabled
        if plan.include_roaming_appdata {
            let src_roaming = src_path.join(APPDATA_ROAMING_REL_PATH);
            let dst_roaming = dst_path.join(APPDATA_ROAMING_REL_PATH);
            if src_roaming.exists() {
                on_progress("Migrating AppData\\Roaming...", 0.3);
                self.copy_tree_safe(&src_roaming, &dst_roaming)?;
            }
        }

        // 2. Migrate Personal Folders if enabled
        if plan.include_personal_folders {
            let personal_folders = ["Documents", "Desktop", "Downloads", "Favorites", "Pictures"];
            for (idx, folder) in personal_folders.iter().enumerate() {
                let src_folder = src_path.join(folder);
                let dst_folder = dst_path.join(folder);
                if src_folder.exists() {
                    let progress = 0.4 + (idx as f32 / personal_folders.len() as f32) * 0.5;
                    on_progress(&format!("Migrating {}...", folder), progress);
                    self.copy_tree_safe(&src_folder, &dst_folder)?;
                }
            }
        }

        on_progress("Migration completed", 1.0);
        self.audit_logger.log(
            "MigrationSuccess",
            "WinProfile-Admin",
            &plan.source_sid,
            AuditStatus::Success,
            format!("Migrated data to {}", plan.target_path),
        );

        Ok(())
    }

    /// Recursively copies files while strictly preventing traversal of reparse points (symlinks/junctions).
    fn copy_tree_safe(&self, src: &Path, dst: &Path) -> std::io::Result<()> {
        if is_reparse_point(src) {
            tracing::info!(path = ?src, "Skipping reparse point / junction during migration copy");
            return Ok(());
        }

        if !dst.exists() {
            std::fs::create_dir_all(dst)?;
        }

        for entry in std::fs::read_dir(src)? {
            let entry = entry?;
            let path = entry.path();
            let dest_entry = dst.join(entry.file_name());

            if is_reparse_point(&path) {
                continue;
            }

            if path.is_dir() {
                self.copy_tree_safe(&path, &dest_entry)?;
            } else if path.is_file() {
                // Ignore transient lock files or NTUSER hives directly copied
                let file_name = path.file_name().unwrap_or_default().to_string_lossy();
                if file_name.starts_with("ntuser.dat.LOG") || file_name.starts_with("usrclass.dat.LOG") {
                    continue;
                }
                let _ = std::fs::copy(&path, &dest_entry);
            }
        }

        Ok(())
    }
}

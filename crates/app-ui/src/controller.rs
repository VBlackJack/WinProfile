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

use slint::{ComponentHandle, Model, ModelRc, VecModel};
use std::rc::Rc;
use std::sync::Arc;

use audit_journal::{AuditLogger, AuditStatus, SnapshotEngine};
use broker_protocol::{send_broker_request, BrokerRequest, BrokerResponse};
use core_profiles::{
    t, MigrationPlan, ProfileMigrationEngine, ProfileRepairEngine,
    ProfileScanner, RepairPlan,
};
use platform_win32::{
    duplicate_trustedinstaller_token, get_active_console_session,
    launch_process_with_token,
};

use crate::state::{audit_entry_to_slint, user_profile_to_slint};
use crate::{AuditLogEntry, MainWindow, ProfileEntry};

pub struct AppController {
    snapshot_engine: Arc<SnapshotEngine>,
    audit_logger: Arc<AuditLogger>,
}

impl AppController {
    pub fn new(snapshot_engine: Arc<SnapshotEngine>, audit_logger: Arc<AuditLogger>) -> Self {
        Self {
            snapshot_engine,
            audit_logger,
        }
    }

    /// Scans all user profiles and populates the Slint view model.
    pub fn scan_profiles(&self, ui: &MainWindow) {
        ui.set_status_message(t("status.scanning").into());

        match ProfileScanner::scan_all() {
            Ok(report) => {
                let slint_profiles: Vec<ProfileEntry> = report
                    .profiles
                    .iter()
                    .map(user_profile_to_slint)
                    .collect();

                let model = Rc::new(VecModel::from(slint_profiles));
                ui.set_profiles(ModelRc::from(model));

                ui.set_total_profiles_count(report.total_count as i32);
                ui.set_healthy_count(report.healthy_count as i32);
                ui.set_corrupted_count(report.corrupted_count as i32);
                ui.set_temp_count(report.temporary_count as i32);

                ui.set_status_message(t("status.completed").into());

                self.audit_logger.log(
                    "ProfileScan",
                    "WinProfile-Admin",
                    "System",
                    AuditStatus::Success,
                    format!("Discovered {} profiles ({} healthy, {} anomalies)", report.total_count, report.healthy_count, report.corrupted_count),
                );
            }
            Err(e) => {
                ui.set_status_message(format!("Error: {e}").into());
                self.audit_logger.log(
                    "ProfileScan",
                    "WinProfile-Admin",
                    "System",
                    AuditStatus::Failed,
                    format!("Scan failed: {e}"),
                );
            }
        }

        self.refresh_audit_logs(ui);
    }

    /// Selects a profile from the table and loads details into the repair/migration tabs.
    pub fn select_profile(&self, ui: &MainWindow, index: usize) {
        let profiles = ui.get_profiles();
        if let Some(profile) = profiles.row_data(index) {
            ui.set_selected_idx(index as i32);
            ui.set_selected_sid(profile.sid.clone());
            ui.set_selected_path(profile.profile_path.clone());
            ui.set_selected_username(profile.username.clone());
            ui.set_selected_anomalies(profile.anomalies.clone());
            ui.set_selected_loaded(profile.loaded);
        }
    }

    /// Executes the repair transaction for the selected profile.
    pub fn execute_repair(&self, ui: &MainWindow, dry_run: bool) {
        let sid = ui.get_selected_sid().to_string();
        let path = ui.get_selected_path().to_string();
        let is_loaded = ui.get_selected_loaded();

        if sid.is_empty() {
            return;
        }

        let canonical_sid = sid.trim_end_matches(".bak").to_string();

        let plan = RepairPlan {
            sid: sid.clone(),
            canonical_sid,
            profile_path: path,
            fix_bak: ui.get_repair_fix_bak(),
            reset_state: ui.get_repair_reset_state(),
            fix_acls: ui.get_repair_fix_acls(),
            unlock_hive: ui.get_repair_unlock_hive(),
            dry_run,
        };

        ui.set_status_message(t("status.repairing").into());

        let repair_engine = ProfileRepairEngine::new(&self.snapshot_engine, &self.audit_logger);
        match repair_engine.execute_plan(&plan, is_loaded) {
            Ok(()) => {
                ui.set_status_message(t("repair.success.message").into());
                self.scan_profiles(ui);
            }
            Err(e) => {
                ui.set_status_message(format!("Repair error: {e}").into());
            }
        }

        self.refresh_audit_logs(ui);
    }

    /// Starts selective profile data migration.
    pub fn start_migration(&self, ui: &MainWindow) {
        let src_path = ui.get_selected_path().to_string();
        let src_sid = ui.get_selected_sid().to_string();
        let target_path = ui.get_migration_target_account().to_string();

        if src_path.is_empty() || target_path.is_empty() {
            return;
        }

        let plan = MigrationPlan {
            source_sid: src_sid,
            source_path: src_path,
            target_account: target_path.clone(),
            target_path,
            include_roaming_appdata: ui.get_migration_include_roaming(),
            include_personal_folders: ui.get_migration_include_docs(),
            include_registry_software: false,
        };

        ui.set_status_message(t("status.migrating").into());
        ui.set_migration_progress(0.1);
        ui.set_migration_status("Starting migration...".into());

        let migration_engine = ProfileMigrationEngine::new(&self.audit_logger);
        let ui_weak = ui.as_weak();

        match migration_engine.execute_migration(&plan, move |status, progress| {
            if let Some(ui_instance) = ui_weak.upgrade() {
                ui_instance.set_migration_status(status.into());
                ui_instance.set_migration_progress(progress);
            }
        }) {
            Ok(()) => {
                ui.set_status_message("Migration completed successfully.".into());
                ui.set_migration_progress(1.0);
            }
            Err(e) => {
                ui.set_status_message(format!("Migration failed: {e}").into());
                ui.set_migration_status(format!("Failed: {e}").into());
            }
        }

        self.refresh_audit_logs(ui);
    }

    /// Launches an interactive command console running under TrustedInstaller elevation.
    pub fn launch_ti_console(&self, ui: &MainWindow) {
        let session_id = get_active_console_session();
        ui.set_status_message("Elevating TrustedInstaller token...".into());

        match duplicate_trustedinstaller_token(session_id) {
            Ok(token) => {
                match launch_process_with_token(&token, "cmd.exe /k title TrustedInstaller Elevated Console", None) {
                    Ok(pid) => {
                        ui.set_status_message(format!("TrustedInstaller console spawned (PID: {pid})").into());
                        self.audit_logger.log(
                            "LaunchTrustedInstallerConsole",
                            "WinProfile-Admin",
                            "cmd.exe",
                            AuditStatus::Success,
                            format!("Spawned PID {pid} in interactive session {session_id}"),
                        );
                    }
                    Err(e) => {
                        ui.set_status_message(format!("Failed to launch process: {e}").into());
                    }
                }
            }
            Err(e) => {
                ui.set_status_message(format!("Token duplication failed: {e}").into());
                self.audit_logger.log(
                    "LaunchTrustedInstallerConsole",
                    "WinProfile-Admin",
                    "cmd.exe",
                    AuditStatus::Failed,
                    format!("Error: {e}"),
                );
            }
        }

        self.refresh_audit_logs(ui);
    }

    /// Tests the secure Named Pipe communication and identity validation against the Broker Service.
    pub fn test_broker_pipe(&self, ui: &MainWindow) {
        ui.set_status_message("Testing Broker Named Pipe connection...".into());

        match send_broker_request(&BrokerRequest::Ping) {
            Ok(BrokerResponse::Pong) => {
                ui.set_is_broker_connected(true);
                ui.set_status_message("Broker Service Connected & Verified via Impersonation.".into());
                self.audit_logger.log(
                    "TestBrokerPipe",
                    "WinProfile-Admin",
                    "\\\\.\\pipe\\WinProfileBrokerSecure",
                    AuditStatus::Success,
                    "Named Pipe Ping/Pong and Impersonation validated.",
                );
            }
            Ok(resp) => {
                ui.set_status_message(format!("Broker response: {:?}", resp).into());
            }
            Err(e) => {
                ui.set_is_broker_connected(false);
                ui.set_status_message(format!("Broker offline or inaccessible: {e}").into());
                self.audit_logger.log(
                    "TestBrokerPipe",
                    "WinProfile-Admin",
                    "\\\\.\\pipe\\WinProfileBrokerSecure",
                    AuditStatus::Warning,
                    format!("Broker connection check: {e}"),
                );
            }
        }

        self.refresh_audit_logs(ui);
    }

    /// Refreshes the audit log entries displayed in Slint.
    pub fn refresh_audit_logs(&self, ui: &MainWindow) {
        let entries = self.audit_logger.get_entries();
        let slint_entries: Vec<AuditLogEntry> = entries.iter().map(audit_entry_to_slint).collect();
        ui.set_audit_entries(ModelRc::from(Rc::new(VecModel::from(slint_entries))));
    }

    /// Clears the in-memory audit logs.
    pub fn clear_audit_logs(&self, ui: &MainWindow) {
        self.audit_logger.clear_memory();
        self.refresh_audit_logs(ui);
    }
}

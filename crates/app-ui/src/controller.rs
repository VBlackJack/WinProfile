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

use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

use audit_journal::{AuditEntry, AuditLogger, AuditStatus, SnapshotEngine};
use core_profiles::{
    t, t_args, DiagnosticReport, MigrationError, MigrationPlan, ProfileMigrationEngine,
    ProfileRepairEngine, ProfileScanner, RepairPlan,
};
use platform_win32::{
    duplicate_trustedinstaller_token, get_active_console_session, is_process_elevated,
    launch_process_with_token,
};
use slint::{CloseRequestResponse, ComponentHandle, Model, ModelRc, VecModel, Weak};

use crate::state::{audit_entry_to_slint, user_profile_to_slint};
use crate::{AuditLogEntry, MainWindow, ProfileEntry};

const CONFIRM_REPAIR: i32 = 0;
const CONFIRM_TRUSTED_INSTALLER: i32 = 1;
const MIGRATION_SOURCE_LOADED_ERROR: &str = "error.migration_source_loaded";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum OperationKind {
    Idle = 0,
    Scan = 1,
    Repair = 2,
    Migration = 3,
    TrustedInstaller = 4,
    Export = 5,
    Unknown = u8::MAX,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClosePolicy {
    Allow,
    Block,
    CancelMigration,
}

impl OperationKind {
    fn from_raw(value: u8) -> Self {
        match value {
            value if value == Self::Idle as u8 => Self::Idle,
            value if value == Self::Scan as u8 => Self::Scan,
            value if value == Self::Repair as u8 => Self::Repair,
            value if value == Self::Migration as u8 => Self::Migration,
            value if value == Self::TrustedInstaller as u8 => Self::TrustedInstaller,
            value if value == Self::Export as u8 => Self::Export,
            _ => Self::Unknown,
        }
    }

    fn close_policy(self) -> ClosePolicy {
        match self {
            Self::Repair | Self::Unknown => ClosePolicy::Block,
            Self::Migration => ClosePolicy::CancelMigration,
            Self::Idle | Self::Scan | Self::TrustedInstaller | Self::Export => ClosePolicy::Allow,
        }
    }
}

struct OperationState {
    active: AtomicU8,
    close_after_finish: AtomicBool,
}

impl OperationState {
    fn new() -> Self {
        Self {
            active: AtomicU8::new(OperationKind::Idle as u8),
            close_after_finish: AtomicBool::new(false),
        }
    }

    fn try_begin(&self, operation: OperationKind) -> bool {
        self.active
            .compare_exchange(
                OperationKind::Idle as u8,
                operation as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    fn active_operation(&self) -> OperationKind {
        OperationKind::from_raw(self.active.load(Ordering::Acquire))
    }

    fn request_close_after_finish(&self) {
        self.close_after_finish.store(true, Ordering::Release);
    }

    fn cancel_if_close_deferred(&self, cancellation: &AtomicBool) {
        if self.close_after_finish.load(Ordering::Acquire) {
            cancellation.store(true, Ordering::Release);
        }
    }

    fn finish(&self) -> bool {
        self.active
            .store(OperationKind::Idle as u8, Ordering::Release);
        self.close_after_finish.swap(false, Ordering::AcqRel)
    }
}

fn validate_migration_source(loaded: bool) -> Result<(), &'static str> {
    if loaded {
        Err(MIGRATION_SOURCE_LOADED_ERROR)
    } else {
        Ok(())
    }
}

pub struct AppController {
    snapshot_engine: Arc<SnapshotEngine>,
    audit_logger: Arc<AuditLogger>,
    operation_state: OperationState,
    migration_cancellation: Mutex<Option<Arc<AtomicBool>>>,
}

impl AppController {
    pub fn new(snapshot_engine: Arc<SnapshotEngine>, audit_logger: Arc<AuditLogger>) -> Self {
        Self {
            snapshot_engine,
            audit_logger,
            operation_state: OperationState::new(),
            migration_cancellation: Mutex::new(None),
        }
    }

    /// Starts a complete profile scan on a worker thread.
    pub fn scan_profiles(self: &Arc<Self>, ui: &MainWindow) {
        if !self.begin_operation(ui, OperationKind::Scan) {
            return;
        }
        ui.set_status_message(t("status.scanning").into());
        let controller = Arc::clone(self);
        let weak = ui.as_weak();
        std::thread::spawn(move || {
            let result = match ProfileScanner::scan_all() {
                Ok(report) => match controller.audit_logger.log(
                    "ProfileScan",
                    "WinProfile-Admin",
                    "System",
                    AuditStatus::Success,
                    format!(
                        "Discovered {} profiles ({} healthy, {} corrupted)",
                        report.total_count, report.healthy_count, report.corrupted_count
                    ),
                ) {
                    Ok(()) => Ok(report),
                    Err(error) => Err(format!("scan completed but audit logging failed: {error}")),
                },
                Err(error) => Err(error.to_string()),
            };
            let result = match result {
                Ok(report) => Ok(report),
                Err(error) => match controller.audit_logger.log(
                    "ProfileScan",
                    "WinProfile-Admin",
                    "System",
                    AuditStatus::Failed,
                    &error,
                ) {
                    Ok(()) => Err(error),
                    Err(audit_error) => {
                        Err(format!("{error}; audit logging also failed: {audit_error}"))
                    }
                },
            };
            let audit_entries = controller.audit_logger.get_entries();
            controller.finish_operation();
            queue_scan_result(weak, result, audit_entries);
        });
    }

    /// Loads the selected row into repair and migration state.
    pub fn select_profile(&self, ui: &MainWindow, index: usize) {
        if let Some(profile) = ui.get_profiles().row_data(index) {
            ui.set_selected_idx(index as i32);
            ui.set_selected_sid(profile.sid.clone());
            ui.set_selected_path(profile.profile_path.clone());
            ui.set_selected_username(profile.username.clone());
            ui.set_selected_anomalies(profile.anomalies.clone());
            ui.set_selected_loaded(profile.loaded);
            ui.set_repair_fix_bak(profile.suggest_fix_bak);
            ui.set_repair_reset_state(profile.suggest_reset_state);
            ui.set_repair_unlock_hive(profile.suggest_unlock_hive);
        }
    }

    /// Builds a localized, explicit confirmation for the selected repair actions.
    pub fn request_repair_confirmation(&self, ui: &MainWindow) {
        if ui.get_selected_sid().is_empty() {
            ui.set_status_message(t("error.profile_not_selected").into());
            return;
        }
        let actions = selected_repair_actions(ui);
        if actions.is_empty() {
            ui.set_status_message(t("error.no_repair_action").into());
            return;
        }
        let actions_text = actions.join(", ");
        let sid = ui.get_selected_sid().to_string();
        ui.set_confirmation_kind(CONFIRM_REPAIR);
        ui.set_confirmation_title(t("repair.confirm.title").into());
        ui.set_confirmation_message(
            t_args(
                "repair.confirm.summary",
                &[("sid", sid.as_str()), ("actions", actions_text.as_str())],
            )
            .into(),
        );
        ui.set_confirmation_visible(true);
    }

    /// Builds a confirmation for a TrustedInstaller console launch.
    pub fn request_ti_confirmation(&self, ui: &MainWindow) {
        ui.set_confirmation_kind(CONFIRM_TRUSTED_INSTALLER);
        ui.set_confirmation_title(t("maintenance.confirm.title").into());
        ui.set_confirmation_message(t("maintenance.confirm.message").into());
        ui.set_confirmation_visible(true);
    }

    /// Executes the selected repair plan on a worker thread.
    pub fn execute_repair(self: &Arc<Self>, ui: &MainWindow, dry_run: bool) {
        if !require_elevation(ui) || !self.begin_operation(ui, OperationKind::Repair) {
            return;
        }
        let plan = RepairPlan {
            sid: ui.get_selected_sid().to_string(),
            canonical_sid: ui.get_selected_sid().trim_end_matches(".bak").to_string(),
            profile_path: ui.get_selected_path().to_string(),
            fix_bak: ui.get_repair_fix_bak(),
            reset_state: ui.get_repair_reset_state(),
            unlock_hive: ui.get_repair_unlock_hive(),
            dry_run,
        };
        let is_loaded = ui.get_selected_loaded();
        ui.set_status_message(t("status.repairing").into());
        let controller = Arc::clone(self);
        let weak = ui.as_weak();
        std::thread::spawn(move || {
            let engine = ProfileRepairEngine::new(
                controller.snapshot_engine.as_ref(),
                controller.audit_logger.as_ref(),
            );
            let repair_result = engine.execute_plan(&plan, is_loaded);
            let report = if repair_result.is_ok() && !dry_run {
                Some(ProfileScanner::scan_all().map_err(|error| error.to_string()))
            } else {
                None
            };
            let audit_entries = controller.audit_logger.get_entries();
            controller.finish_operation();
            let result = repair_result.map_err(|error| error.to_string());
            if let Err(error) = weak.upgrade_in_event_loop(move |ui| {
                ui.set_operation_busy(false);
                match result {
                    Ok(()) => match report {
                        Some(Ok(report)) => {
                            apply_report(&ui, report);
                            ui.set_status_message(t("repair.success.message").into());
                        }
                        Some(Err(error)) => {
                            let success = t("repair.success.message");
                            ui.set_status_message(
                                t_args(
                                    "status.refresh_failed",
                                    &[("success", success.as_str()), ("error", error.as_str())],
                                )
                                .into(),
                            );
                        }
                        None => ui.set_status_message(t("status.completed").into()),
                    },
                    Err(error) => set_error(&ui, &error),
                }
                apply_audit_result(&ui, audit_entries);
            }) {
                eprintln!("failed to queue repair result: {error}");
            }
        });
    }

    /// Starts a verified, cancellable migration on a worker thread.
    pub fn start_migration(self: &Arc<Self>, ui: &MainWindow) {
        if let Err(message_key) = validate_migration_source(ui.get_selected_loaded()) {
            ui.set_status_message(t(message_key).into());
            return;
        }
        if !require_elevation(ui) || !self.begin_operation(ui, OperationKind::Migration) {
            return;
        }
        let plan = MigrationPlan {
            source_sid: ui.get_selected_sid().to_string(),
            source_path: ui.get_selected_path().to_string(),
            target_path: ui.get_migration_target_path().to_string(),
            include_roaming_appdata: ui.get_migration_include_roaming(),
            include_personal_folders: ui.get_migration_include_docs(),
        };
        if plan.source_path.is_empty()
            || plan.target_path.is_empty()
            || (!plan.include_roaming_appdata && !plan.include_personal_folders)
        {
            self.finish_operation();
            ui.set_operation_busy(false);
            ui.set_status_message(t("error.migration_scope").into());
            return;
        }

        let cancellation = Arc::new(AtomicBool::new(false));
        match self.migration_cancellation.lock() {
            Ok(mut slot) => {
                // The close handler takes the same mutex before recording a deferred close.
                // Checking the flag before publishing the token therefore closes both race orders.
                self.operation_state.cancel_if_close_deferred(&cancellation);
                *slot = Some(Arc::clone(&cancellation));
            }
            Err(_) => {
                self.finish_operation();
                ui.set_operation_busy(false);
                set_error(ui, "migration cancellation state is unavailable");
                return;
            }
        }
        ui.set_migration_running(true);
        ui.set_migration_progress(0.0);
        ui.set_status_message(t("status.migrating").into());

        let controller = Arc::clone(self);
        let weak = ui.as_weak();
        std::thread::spawn(move || {
            let engine = ProfileMigrationEngine::new(controller.audit_logger.as_ref());
            let progress_weak = weak.clone();
            let progress = move |item: &str, value: f32| {
                let message = t_args("migration.progress.copying", &[("file", item)]);
                let update_weak = progress_weak.clone();
                if let Err(error) = update_weak.upgrade_in_event_loop(move |ui| {
                    ui.set_migration_status(message.into());
                    ui.set_migration_progress(value);
                }) {
                    eprintln!("failed to queue migration progress: {error}");
                }
            };
            let mut result = engine.execute_migration_with_cancel(&plan, progress, || {
                cancellation.load(Ordering::Acquire)
            });
            match controller.migration_cancellation.lock() {
                Ok(mut slot) => *slot = None,
                Err(_) => {
                    let operation = result
                        .as_ref()
                        .err()
                        .map(ToString::to_string)
                        .unwrap_or_else(|| "copy completed".to_string());
                    result = Err(MigrationError::InternalState(format!(
                        "{operation}; cancellation state is poisoned"
                    )));
                }
            }
            let audit_entries = controller.audit_logger.get_entries();
            let close_after_operation = controller.finish_operation();
            if let Err(error) = weak.upgrade_in_event_loop(move |ui| {
                ui.set_operation_busy(false);
                ui.set_migration_running(false);
                match result {
                    Ok(receipt) => {
                        let file_count = receipt.copied_files.to_string();
                        let short_hash =
                            receipt.manifest_sha256.chars().take(16).collect::<String>();
                        let message = t_args(
                            "migration.success",
                            &[
                                ("files", file_count.as_str()),
                                ("hash", short_hash.as_str()),
                            ],
                        );
                        ui.set_migration_progress(1.0);
                        ui.set_migration_status(message.clone().into());
                        ui.set_status_message(message.into());
                    }
                    Err(MigrationError::Cancelled) => {
                        ui.set_migration_status(t("status.cancelled").into());
                        ui.set_status_message(t("status.cancelled").into());
                    }
                    Err(error) => {
                        ui.set_migration_status(error.to_string().into());
                        set_error(&ui, &error.to_string());
                    }
                }
                apply_audit_result(&ui, audit_entries);
                if close_after_operation {
                    if let Err(error) = ui.hide() {
                        eprintln!("failed to close the window after migration rollback: {error}");
                    }
                }
            }) {
                eprintln!("failed to queue migration result: {error}");
            }
        });
    }

    /// Signals the active migration to stop at the next safe copy boundary.
    pub fn cancel_migration(&self, ui: &MainWindow) {
        match self.migration_cancellation.lock() {
            Ok(slot) => {
                if let Some(cancellation) = slot.as_ref() {
                    cancellation.store(true, Ordering::Release);
                    ui.set_status_message(t("status.cancelling").into());
                }
            }
            Err(_) => set_error(ui, "migration cancellation state is unavailable"),
        }
    }

    /// Coordinates a window close request with any active destructive transaction.
    pub fn handle_close_requested(&self, ui: &MainWindow) -> CloseRequestResponse {
        let operation = self.operation_state.active_operation();
        match operation.close_policy() {
            ClosePolicy::Allow => CloseRequestResponse::HideWindow,
            ClosePolicy::Block => {
                ui.set_status_message(t("status.close_blocked_repair").into());
                CloseRequestResponse::KeepWindowShown
            }
            ClosePolicy::CancelMigration => {
                match self.migration_cancellation.lock() {
                    Ok(slot) => {
                        self.operation_state.request_close_after_finish();
                        if let Some(cancellation) = slot.as_ref() {
                            cancellation.store(true, Ordering::Release);
                        }
                        ui.set_status_message(t("status.cancelling").into());
                    }
                    Err(_) => set_error(ui, "migration cancellation state is unavailable"),
                }
                CloseRequestResponse::KeepWindowShown
            }
        }
    }

    /// Launches an audited TrustedInstaller console on a worker thread.
    pub fn launch_ti_console(self: &Arc<Self>, ui: &MainWindow) {
        if !require_elevation(ui) || !self.begin_operation(ui, OperationKind::TrustedInstaller) {
            return;
        }
        ui.set_status_message(t("status.launching_ti").into());
        let controller = Arc::clone(self);
        let weak = ui.as_weak();
        std::thread::spawn(move || {
            let result = get_active_console_session().and_then(|session_id| {
                duplicate_trustedinstaller_token(session_id).and_then(|token| {
                    launch_process_with_token(
                        &token,
                        "cmd.exe /k title TrustedInstaller Elevated Console",
                        None,
                    )
                    .map(|pid| (pid, session_id))
                })
            });
            let audited_result = match result {
                Ok((pid, session_id)) => controller
                    .audit_logger
                    .log(
                        "LaunchTrustedInstallerConsole",
                        "WinProfile-Admin",
                        "cmd.exe",
                        AuditStatus::Success,
                        format!("Spawned PID {pid} in session {session_id}"),
                    )
                    .map(|_| pid)
                    .map_err(|error| error.to_string()),
                Err(error) => {
                    let detail = error.to_string();
                    match controller.audit_logger.log(
                        "LaunchTrustedInstallerConsole",
                        "WinProfile-Admin",
                        "cmd.exe",
                        AuditStatus::Failed,
                        &detail,
                    ) {
                        Ok(()) => Err(detail),
                        Err(audit_error) => Err(format!("{detail}; audit error: {audit_error}")),
                    }
                }
            };
            let audit_entries = controller.audit_logger.get_entries();
            controller.finish_operation();
            if let Err(error) = weak.upgrade_in_event_loop(move |ui| {
                ui.set_operation_busy(false);
                match audited_result {
                    Ok(pid) => {
                        let pid_text = pid.to_string();
                        ui.set_status_message(
                            t_args("status.ti_success", &[("pid", pid_text.as_str())]).into(),
                        );
                    }
                    Err(error) => set_error(&ui, &error),
                }
                apply_audit_result(&ui, audit_entries);
            }) {
                eprintln!("failed to queue TrustedInstaller result: {error}");
            }
        });
    }

    /// Exports the durable audit file without blocking the UI thread.
    pub fn export_audit(self: &Arc<Self>, ui: &MainWindow) {
        if !self.begin_operation(ui, OperationKind::Export) {
            return;
        }
        let controller = Arc::clone(self);
        let weak = ui.as_weak();
        std::thread::spawn(move || {
            let result = controller.audit_logger.export_copy();
            controller.finish_operation();
            if let Err(error) = weak.upgrade_in_event_loop(move |ui| {
                ui.set_operation_busy(false);
                match result {
                    Ok(path) => {
                        let path_text = path.display().to_string();
                        ui.set_status_message(
                            t_args("status.export_success", &[("path", path_text.as_str())]).into(),
                        );
                    }
                    Err(error) => set_error(&ui, &error.to_string()),
                }
            }) {
                eprintln!("failed to queue audit export result: {error}");
            }
        });
    }

    /// Clears only the display buffer and preserves the durable journal.
    pub fn clear_audit_logs(&self, ui: &MainWindow) {
        match self.audit_logger.clear_memory() {
            Ok(()) => {
                ui.set_audit_entries(ModelRc::from(Rc::new(VecModel::from(
                    Vec::<AuditLogEntry>::new(),
                ))));
                ui.set_status_message(t("status.audit_cleared").into());
            }
            Err(error) => set_error(ui, &error.to_string()),
        }
    }

    /// Loads the initial audit display and reports read errors visibly.
    pub fn refresh_audit_logs(&self, ui: &MainWindow) {
        apply_audit_result(ui, self.audit_logger.get_entries());
    }

    fn begin_operation(&self, ui: &MainWindow, operation: OperationKind) -> bool {
        if !self.operation_state.try_begin(operation) {
            ui.set_status_message(t("error.operation_busy").into());
            return false;
        }
        ui.set_operation_busy(true);
        true
    }

    fn finish_operation(&self) -> bool {
        self.operation_state.finish()
    }
}

fn require_elevation(ui: &MainWindow) -> bool {
    match is_process_elevated() {
        Ok(true) => true,
        Ok(false) => {
            ui.set_status_message(t("error.elevation_required").into());
            false
        }
        Err(error) => {
            set_error(ui, &error.to_string());
            false
        }
    }
}

fn selected_repair_actions(ui: &MainWindow) -> Vec<String> {
    let mut actions = Vec::new();
    if ui.get_repair_fix_bak() {
        actions.push(t("repair.confirm.fix_bak"));
    }
    if ui.get_repair_reset_state() {
        actions.push(t("repair.confirm.reset_state"));
    }
    if ui.get_repair_unlock_hive() {
        actions.push(t("repair.confirm.unlock_hive"));
    }
    actions
}

fn queue_scan_result(
    weak: Weak<MainWindow>,
    result: Result<DiagnosticReport, String>,
    audit_entries: Result<Vec<AuditEntry>, audit_journal::AuditError>,
) {
    if let Err(error) = weak.upgrade_in_event_loop(move |ui| {
        ui.set_operation_busy(false);
        match result {
            Ok(report) => {
                apply_report(&ui, report);
                ui.set_status_message(t("status.completed").into());
            }
            Err(error) => set_error(&ui, &error),
        }
        apply_audit_result(&ui, audit_entries);
    }) {
        eprintln!("failed to queue profile scan result: {error}");
    }
}

fn apply_report(ui: &MainWindow, report: DiagnosticReport) {
    let profiles = report
        .profiles
        .iter()
        .map(user_profile_to_slint)
        .collect::<Vec<ProfileEntry>>();
    ui.set_profiles(ModelRc::from(Rc::new(VecModel::from(profiles))));
    ui.set_total_profiles_count(report.total_count as i32);
    ui.set_healthy_count(report.healthy_count as i32);
    ui.set_corrupted_count(report.corrupted_count as i32);
    ui.set_temp_count(report.temporary_count as i32);
    ui.set_selected_idx(-1);
    ui.set_selected_sid("".into());
    ui.set_selected_path("".into());
    ui.set_selected_username("".into());
    ui.set_selected_anomalies("".into());
    ui.set_selected_loaded(false);
}

fn apply_audit_result(ui: &MainWindow, result: Result<Vec<AuditEntry>, audit_journal::AuditError>) {
    match result {
        Ok(entries) => {
            let model = entries
                .iter()
                .map(audit_entry_to_slint)
                .collect::<Vec<AuditLogEntry>>();
            ui.set_audit_entries(ModelRc::from(Rc::new(VecModel::from(model))));
        }
        Err(error) => set_error(ui, &error.to_string()),
    }
}

fn set_error(ui: &MainWindow, error: &str) {
    ui.set_status_message(format!("{} {error}", t("common.error_prefix")).into());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn close_policy_blocks_repair_and_unknown_state() {
        assert_eq!(OperationKind::Repair.close_policy(), ClosePolicy::Block);
        assert_eq!(OperationKind::Unknown.close_policy(), ClosePolicy::Block);
    }

    #[test]
    fn close_policy_cancels_migration_before_closing() {
        assert_eq!(
            OperationKind::Migration.close_policy(),
            ClosePolicy::CancelMigration
        );
    }

    #[test]
    fn close_policy_allows_non_transactional_operations() {
        for operation in [
            OperationKind::Idle,
            OperationKind::Scan,
            OperationKind::TrustedInstaller,
            OperationKind::Export,
        ] {
            assert_eq!(operation.close_policy(), ClosePolicy::Allow);
        }
    }

    #[test]
    fn operation_state_blocks_repair_until_finish() {
        let state = OperationState::new();

        assert!(state.try_begin(OperationKind::Repair));
        assert!(!state.try_begin(OperationKind::Scan));
        assert_eq!(state.active_operation().close_policy(), ClosePolicy::Block);
        assert!(!state.finish());
        assert_eq!(state.active_operation().close_policy(), ClosePolicy::Allow);
        assert!(state.try_begin(OperationKind::Scan));
    }

    #[test]
    fn operation_state_defers_migration_close_until_finish() {
        let state = OperationState::new();

        assert!(state.try_begin(OperationKind::Migration));
        assert_eq!(
            state.active_operation().close_policy(),
            ClosePolicy::CancelMigration
        );
        state.request_close_after_finish();
        assert!(state.finish());
        assert_eq!(state.active_operation().close_policy(), ClosePolicy::Allow);
        assert!(
            !state.finish(),
            "the deferred close request must be consumed"
        );
    }

    #[test]
    fn deferred_close_cancels_a_migration_token_installed_after_the_request() {
        let state = OperationState::new();
        let cancellation = AtomicBool::new(false);

        assert!(state.try_begin(OperationKind::Migration));
        state.request_close_after_finish();
        state.cancel_if_close_deferred(&cancellation);

        assert!(cancellation.load(Ordering::Acquire));
        assert!(state.finish());
    }

    #[test]
    fn migration_source_must_be_offline() {
        assert_eq!(validate_migration_source(false), Ok(()));
        assert_eq!(
            validate_migration_source(true),
            Err(MIGRATION_SOURCE_LOADED_ERROR)
        );
    }
}

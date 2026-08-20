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
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use audit_journal::{AuditEntry, AuditLogger, AuditStatus, SnapshotEngine};
use core_profiles::{
    t, t_args, DiagnosticReport, MigrationError, MigrationPlan, ProfileMigrationEngine,
    ProfileRepairEngine, ProfileScanner, RepairPlan,
};
use platform_win32::{
    duplicate_trustedinstaller_token, get_requesting_process_session, is_process_elevated,
    launch_process_with_token, trustedinstaller_console_launch_spec, LaunchedProcess,
};
use slint::{CloseRequestResponse, ComponentHandle, Model, ModelRc, VecModel, Weak};
use thiserror::Error;

use crate::state::{audit_entry_to_slint, user_profile_to_slint};
use crate::{AuditLogEntry, MainWindow, ProfileEntry};

const CONFIRM_REPAIR: i32 = 0;
const CONFIRM_TRUSTED_INSTALLER: i32 = 1;
const MIGRATION_SOURCE_LOADED_ERROR: &str = "error.migration_source_loaded";
const TI_REQUEST_OPERATION: &str = "LaunchTrustedInstallerConsoleRequested";
const TI_TERMINAL_OPERATION: &str = "LaunchTrustedInstallerConsole";
const TI_AUDIT_ACTOR: &str = "WinProfile-Admin";
const TI_AUDIT_TARGET: &str = "Windows system command interpreter";
const TI_REQUEST_DETAIL: &str = "TrustedInstaller console launch request accepted";
const TI_TERMINATION_EXIT_CODE: u32 = 1;
const TI_TERMINATION_TIMEOUT: Duration = Duration::from_secs(5);

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

#[derive(Debug, Clone, PartialEq, Eq)]
enum MigrationTerminalPresentation {
    Success {
        files: usize,
        bytes: u64,
        manifest_hash: String,
    },
    Cancelled,
    Error {
        details: String,
    },
}

impl MigrationTerminalPresentation {
    fn render(&self) -> String {
        match self {
            Self::Success {
                files,
                bytes,
                manifest_hash,
            } => {
                let files = files.to_string();
                let bytes = bytes.to_string();
                t_args(
                    "migration.success",
                    &[
                        ("files", files.as_str()),
                        ("bytes", bytes.as_str()),
                        ("hash", manifest_hash.as_str()),
                    ],
                )
            }
            Self::Cancelled => t("status.cancelled"),
            Self::Error { details } => details.clone(),
        }
    }
}

#[derive(Error, Debug)]
enum TrustedInstallerLaunchError {
    #[error(
        "TrustedInstaller operation lock acquisition failed before audit or process effects: {0}"
    )]
    OperationLock(String),
    #[error("TrustedInstaller launch request audit failed before process acquisition: {0}")]
    RequestAudit(String),
    #[error("TrustedInstaller process launch failed: {0}")]
    Launch(String),
    #[error(
        "TrustedInstaller process launch failed: {launch_error}; FAILED audit also failed: {audit_error}"
    )]
    LaunchAndFailureAudit {
        launch_error: String,
        audit_error: String,
    },
    #[error(
        "TrustedInstaller SUCCESS audit failed for PID {pid}: {audit_error}; process was terminated and reaped"
    )]
    TerminalAuditCompensated { pid: u32, audit_error: String },
    #[error(
        "TrustedInstaller SUCCESS audit failed for PID {pid}: {audit_error}; compensation failed: {compensation_error}"
    )]
    TerminalAuditCompensationFailed {
        pid: u32,
        audit_error: String,
        compensation_error: String,
    },
}

trait TrustedInstallerAudit {
    fn record(&self, operation: &str, status: AuditStatus, details: String) -> Result<(), String>;
}

trait TrustedInstallerOperationLock {
    type Guard;

    fn acquire_trustedinstaller_operation_guard(&self) -> Result<Self::Guard, String>;
}

impl TrustedInstallerAudit for AuditLogger {
    fn record(&self, operation: &str, status: AuditStatus, details: String) -> Result<(), String> {
        self.log(operation, TI_AUDIT_ACTOR, TI_AUDIT_TARGET, status, details)
            .map_err(|error| error.to_string())
    }
}

impl TrustedInstallerOperationLock for AuditLogger {
    type Guard = audit_journal::OperationGuard;

    fn acquire_trustedinstaller_operation_guard(&self) -> Result<Self::Guard, String> {
        AuditLogger::acquire_operation_guard(self).map_err(|error| error.to_string())
    }
}

trait ManagedTrustedInstallerProcess {
    fn pid(&self) -> u32;
    fn terminate(&self) -> Result<(), String>;
    fn wait_for_exit(&self) -> Result<(), String>;
}

impl ManagedTrustedInstallerProcess for LaunchedProcess {
    fn pid(&self) -> u32 {
        LaunchedProcess::pid(self)
    }

    fn terminate(&self) -> Result<(), String> {
        LaunchedProcess::terminate(self, TI_TERMINATION_EXIT_CODE)
            .map_err(|error| error.to_string())
    }

    fn wait_for_exit(&self) -> Result<(), String> {
        LaunchedProcess::wait_for_exit(self, TI_TERMINATION_TIMEOUT)
            .map_err(|error| error.to_string())
    }
}

fn execute_trustedinstaller_launch<A, L, P>(
    audit: &A,
    launcher: L,
) -> Result<u32, TrustedInstallerLaunchError>
where
    A: TrustedInstallerAudit + TrustedInstallerOperationLock,
    L: FnOnce() -> Result<(P, u32), String>,
    P: ManagedTrustedInstallerProcess,
{
    let _operation_guard = audit
        .acquire_trustedinstaller_operation_guard()
        .map_err(TrustedInstallerLaunchError::OperationLock)?;
    audit
        .record(
            TI_REQUEST_OPERATION,
            AuditStatus::Success,
            TI_REQUEST_DETAIL.to_string(),
        )
        .map_err(TrustedInstallerLaunchError::RequestAudit)?;

    let (process, session_id) = match launcher() {
        Ok(launched) => launched,
        Err(launch_error) => {
            let audit_result = audit.record(
                TI_TERMINAL_OPERATION,
                AuditStatus::Failed,
                launch_error.clone(),
            );
            return match audit_result {
                Ok(()) => Err(TrustedInstallerLaunchError::Launch(launch_error)),
                Err(audit_error) => Err(TrustedInstallerLaunchError::LaunchAndFailureAudit {
                    launch_error,
                    audit_error,
                }),
            };
        }
    };

    let pid = process.pid();
    let terminal_audit = audit.record(
        TI_TERMINAL_OPERATION,
        AuditStatus::Success,
        format!("Spawned PID {pid} in session {session_id}"),
    );
    let audit_error = match terminal_audit {
        Ok(()) => return Ok(pid),
        Err(error) => error,
    };

    let terminate_error = process.terminate().err();
    let wait_error = process.wait_for_exit().err();
    drop(process);

    match (terminate_error, wait_error) {
        (None, None) => {
            Err(TrustedInstallerLaunchError::TerminalAuditCompensated { pid, audit_error })
        }
        (terminate_error, wait_error) => {
            let mut failures = Vec::new();
            if let Some(error) = terminate_error {
                failures.push(format!("terminate: {error}"));
            }
            if let Some(error) = wait_error {
                failures.push(format!("wait: {error}"));
            }
            Err(
                TrustedInstallerLaunchError::TerminalAuditCompensationFailed {
                    pid,
                    audit_error,
                    compensation_error: failures.join("; "),
                },
            )
        }
    }
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
            Self::Scan | Self::Repair | Self::TrustedInstaller | Self::Export | Self::Unknown => {
                ClosePolicy::Block
            }
            Self::Migration => ClosePolicy::CancelMigration,
            Self::Idle => ClosePolicy::Allow,
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
    last_report: Mutex<Option<DiagnosticReport>>,
    last_audit_entries: Mutex<Option<Vec<AuditEntry>>>,
    last_migration_terminal: Mutex<Option<MigrationTerminalPresentation>>,
    #[cfg(test)]
    scanner_calls: AtomicUsize,
    #[cfg(test)]
    journal_read_calls: AtomicUsize,
}

impl AppController {
    pub fn new(snapshot_engine: Arc<SnapshotEngine>, audit_logger: Arc<AuditLogger>) -> Self {
        Self {
            snapshot_engine,
            audit_logger,
            operation_state: OperationState::new(),
            migration_cancellation: Mutex::new(None),
            last_report: Mutex::new(None),
            last_audit_entries: Mutex::new(None),
            last_migration_terminal: Mutex::new(None),
            #[cfg(test)]
            scanner_calls: AtomicUsize::new(0),
            #[cfg(test)]
            journal_read_calls: AtomicUsize::new(0),
        }
    }

    /// Re-renders cached UI models in a new session locale without touching services.
    pub fn change_locale(&self, ui: &MainWindow, locale: &str) -> Result<bool, String> {
        if self.operation_state.active_operation() != OperationKind::Idle
            || ui.get_operation_busy()
            || !ui.get_language_switch_enabled()
        {
            return Ok(false);
        }
        let report = self
            .last_report
            .lock()
            .map_err(|_| "profile report cache is unavailable".to_string())?
            .clone();
        let audit_entries = self
            .last_audit_entries
            .lock()
            .map_err(|_| "audit entry cache is unavailable".to_string())?
            .clone();
        let migration_terminal = self
            .last_migration_terminal
            .lock()
            .map_err(|_| "migration status cache is unavailable".to_string())?
            .clone();

        crate::locale::set_locale_and_app_strings(ui, locale).map_err(|error| error.to_string())?;
        if let Some(report) = report.as_ref() {
            render_report(ui, report, false);
        }
        if let Some(entries) = audit_entries.as_ref() {
            render_audit_entries(ui, entries);
        }
        if let Some(presentation) = migration_terminal.as_ref() {
            ui.set_migration_status(presentation.render().into());
        }
        ui.set_status_message(t("status.ready").into());
        Ok(true)
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
            let result = match controller.scan_all_profiles() {
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
            let audit_entries = controller.read_audit_entries();
            controller.finish_operation();
            queue_scan_result(controller, weak, result, audit_entries);
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
            ui.set_selected_locking_processes(profile.locking_processes.clone());
            ui.set_selected_has_locking_processes(profile.has_locking_processes);
            ui.set_selected_lock_inspection_failure(profile.lock_inspection_failure.clone());
            ui.set_selected_repair_blocked_by_lock_inspection(
                profile.repair_blocked_by_lock_inspection,
            );
            ui.set_selected_loaded(profile.loaded);
            ui.set_repair_fix_bak(profile.suggest_fix_bak);
            ui.set_repair_reset_state(profile.suggest_reset_state);
        }
    }

    /// Builds a localized, explicit confirmation for the selected repair actions.
    pub fn request_repair_confirmation(&self, ui: &MainWindow) {
        if ui.get_selected_repair_blocked_by_lock_inspection() {
            ui.set_status_message(t("repair.locked.status").into());
            return;
        }
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
        if ui.get_selected_repair_blocked_by_lock_inspection() {
            ui.set_status_message(t("repair.locked.status").into());
            return;
        }
        if !require_elevation(ui) || !self.begin_operation(ui, OperationKind::Repair) {
            return;
        }
        let plan = RepairPlan {
            sid: ui.get_selected_sid().to_string(),
            canonical_sid: ui.get_selected_sid().trim_end_matches(".bak").to_string(),
            profile_path: ui.get_selected_path().to_string(),
            fix_bak: ui.get_repair_fix_bak(),
            reset_state: ui.get_repair_reset_state(),
            unlock_hive: false,
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
                Some(
                    controller
                        .scan_all_profiles()
                        .map_err(|error| error.to_string()),
                )
            } else {
                None
            };
            let audit_entries = controller.read_audit_entries();
            controller.finish_operation();
            let result = repair_result.map_err(|error| error.to_string());
            if let Err(error) = weak.upgrade_in_event_loop(move |ui| {
                ui.set_operation_busy(false);
                match result {
                    Ok(()) => match report {
                        Some(Ok(report)) => {
                            match controller.cache_and_apply_report(&ui, report, true) {
                                Ok(()) => ui.set_status_message(t("repair.success.message").into()),
                                Err(error) => set_error(&ui, &error),
                            }
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
                controller.apply_audit_result(&ui, audit_entries);
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
            let audit_entries = controller.read_audit_entries();
            let close_after_operation = controller.finish_operation();
            if let Err(error) = weak.upgrade_in_event_loop(move |ui| {
                ui.set_operation_busy(false);
                ui.set_migration_running(false);
                match result {
                    Ok(receipt) => {
                        let presentation = MigrationTerminalPresentation::Success {
                            files: receipt.copied_files,
                            bytes: receipt.copied_bytes,
                            manifest_hash: receipt
                                .manifest_sha256
                                .chars()
                                .take(16)
                                .collect::<String>(),
                        };
                        ui.set_migration_progress(1.0);
                        match controller.cache_and_apply_migration_terminal(&ui, presentation) {
                            Ok(message) => ui.set_status_message(message.into()),
                            Err(error) => set_error(&ui, &error),
                        }
                    }
                    Err(MigrationError::Cancelled) => {
                        match controller.cache_and_apply_migration_terminal(
                            &ui,
                            MigrationTerminalPresentation::Cancelled,
                        ) {
                            Ok(message) => ui.set_status_message(message.into()),
                            Err(error) => set_error(&ui, &error),
                        }
                    }
                    Err(error) => {
                        let details = error.to_string();
                        if let Err(cache_error) = controller.cache_and_apply_migration_terminal(
                            &ui,
                            MigrationTerminalPresentation::Error {
                                details: details.clone(),
                            },
                        ) {
                            set_error(&ui, &cache_error);
                        } else {
                            set_error(&ui, &details);
                        }
                    }
                }
                controller.apply_audit_result(&ui, audit_entries);
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
            let audited_result =
                execute_trustedinstaller_launch(controller.audit_logger.as_ref(), || {
                    let launch_spec = trustedinstaller_console_launch_spec()
                        .map_err(|error| error.to_string())?;
                    let session_id =
                        get_requesting_process_session().map_err(|error| error.to_string())?;
                    let token =
                        duplicate_trustedinstaller_token().map_err(|error| error.to_string())?;
                    let process = launch_process_with_token(token, &launch_spec)
                        .map_err(|error| error.to_string())?;
                    Ok((process, session_id))
                })
                .map_err(|error| error.to_string());
            let audit_entries = controller.read_audit_entries();
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
                controller.apply_audit_result(&ui, audit_entries);
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
            Ok(()) => match self.cache_and_apply_audit_entries(ui, Vec::new()) {
                Ok(()) => ui.set_status_message(t("status.audit_cleared").into()),
                Err(error) => set_error(ui, &error),
            },
            Err(error) => set_error(ui, &error.to_string()),
        }
    }

    /// Loads the initial audit display and reports read errors visibly.
    pub fn refresh_audit_logs(&self, ui: &MainWindow) {
        self.apply_audit_result(ui, self.read_audit_entries());
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

    fn scan_all_profiles(&self) -> core_profiles::ScannerResult<DiagnosticReport> {
        #[cfg(test)]
        self.scanner_calls.fetch_add(1, Ordering::SeqCst);
        ProfileScanner::scan_all()
    }

    fn read_audit_entries(&self) -> audit_journal::AuditResult<Vec<AuditEntry>> {
        #[cfg(test)]
        self.journal_read_calls.fetch_add(1, Ordering::SeqCst);
        self.audit_logger.get_entries()
    }

    fn cache_and_apply_report(
        &self,
        ui: &MainWindow,
        report: DiagnosticReport,
        reset_selection: bool,
    ) -> Result<(), String> {
        let rendered_report = report.clone();
        *self
            .last_report
            .lock()
            .map_err(|_| "profile report cache is unavailable".to_string())? = Some(report);
        render_report(ui, &rendered_report, reset_selection);
        Ok(())
    }

    fn cache_and_apply_audit_entries(
        &self,
        ui: &MainWindow,
        entries: Vec<AuditEntry>,
    ) -> Result<(), String> {
        let rendered_entries = entries.clone();
        *self
            .last_audit_entries
            .lock()
            .map_err(|_| "audit entry cache is unavailable".to_string())? = Some(entries);
        render_audit_entries(ui, &rendered_entries);
        Ok(())
    }

    fn cache_and_apply_migration_terminal(
        &self,
        ui: &MainWindow,
        presentation: MigrationTerminalPresentation,
    ) -> Result<String, String> {
        let message = presentation.render();
        *self
            .last_migration_terminal
            .lock()
            .map_err(|_| "migration status cache is unavailable".to_string())? = Some(presentation);
        ui.set_migration_status(message.clone().into());
        Ok(message)
    }

    fn apply_audit_result(
        &self,
        ui: &MainWindow,
        result: Result<Vec<AuditEntry>, audit_journal::AuditError>,
    ) {
        match result {
            Ok(entries) => {
                if let Err(error) = self.cache_and_apply_audit_entries(ui, entries) {
                    set_error(ui, &error);
                }
            }
            Err(error) => set_error(ui, &error.to_string()),
        }
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
    actions
}

fn queue_scan_result(
    controller: Arc<AppController>,
    weak: Weak<MainWindow>,
    result: Result<DiagnosticReport, String>,
    audit_entries: Result<Vec<AuditEntry>, audit_journal::AuditError>,
) {
    if let Err(error) = weak.upgrade_in_event_loop(move |ui| {
        ui.set_operation_busy(false);
        match result {
            Ok(report) => match controller.cache_and_apply_report(&ui, report, true) {
                Ok(()) => ui.set_status_message(t("status.completed").into()),
                Err(error) => set_error(&ui, &error),
            },
            Err(error) => set_error(&ui, &error),
        }
        controller.apply_audit_result(&ui, audit_entries);
    }) {
        eprintln!("failed to queue profile scan result: {error}");
    }
}

fn render_report(ui: &MainWindow, report: &DiagnosticReport, reset_selection: bool) {
    let profiles = report
        .profiles
        .iter()
        .map(user_profile_to_slint)
        .collect::<Vec<ProfileEntry>>();
    let selected_details = if reset_selection {
        None
    } else {
        usize::try_from(ui.get_selected_idx())
            .ok()
            .and_then(|index| profiles.get(index))
            .filter(|profile| {
                profile.sid.as_str() == ui.get_selected_sid().as_str()
                    && profile.profile_path.as_str() == ui.get_selected_path().as_str()
            })
            .map(|profile| {
                (
                    profile.anomalies.clone(),
                    profile.locking_processes.clone(),
                    profile.has_locking_processes,
                    profile.lock_inspection_failure.clone(),
                    profile.repair_blocked_by_lock_inspection,
                )
            })
    };
    ui.set_profiles(ModelRc::from(Rc::new(VecModel::from(profiles))));
    ui.set_total_profiles_count(report.total_count as i32);
    ui.set_healthy_count(report.healthy_count as i32);
    ui.set_corrupted_count(report.corrupted_count as i32);
    ui.set_temp_count(report.temporary_count as i32);
    if reset_selection {
        ui.set_selected_idx(-1);
        ui.set_selected_sid("".into());
        ui.set_selected_path("".into());
        ui.set_selected_username("".into());
        ui.set_selected_anomalies("".into());
        ui.set_selected_locking_processes(ModelRc::default());
        ui.set_selected_has_locking_processes(false);
        ui.set_selected_lock_inspection_failure("".into());
        ui.set_selected_repair_blocked_by_lock_inspection(false);
        ui.set_selected_loaded(false);
    } else if let Some((
        anomalies,
        locking_processes,
        has_locking_processes,
        lock_inspection_failure,
        repair_blocked_by_lock_inspection,
    )) = selected_details
    {
        ui.set_selected_anomalies(anomalies);
        ui.set_selected_locking_processes(locking_processes);
        ui.set_selected_has_locking_processes(has_locking_processes);
        ui.set_selected_lock_inspection_failure(lock_inspection_failure);
        ui.set_selected_repair_blocked_by_lock_inspection(repair_blocked_by_lock_inspection);
    }
}

fn render_audit_entries(ui: &MainWindow, entries: &[AuditEntry]) {
    let model = entries
        .iter()
        .map(audit_entry_to_slint)
        .collect::<Vec<AuditLogEntry>>();
    ui.set_audit_entries(ModelRc::from(Rc::new(VecModel::from(model))));
}

fn set_error(ui: &MainWindow, error: &str) {
    ui.set_status_message(error.into());
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use core_profiles::{I18nManager, ProfileAnomaly, ProfileHealth, UserProfile};
    use std::collections::VecDeque;
    use std::path::PathBuf;
    use std::sync::atomic::AtomicUsize;

    struct FakeAudit {
        outcomes: Mutex<VecDeque<Result<(), String>>>,
        events: Mutex<Vec<(String, AuditStatus)>>,
        operation_lock_error: Option<String>,
        operation_lock_alive: Arc<AtomicBool>,
        observed_lock_states: Mutex<Vec<bool>>,
    }

    struct FakeOperationGuard(Arc<AtomicBool>);

    impl Drop for FakeOperationGuard {
        fn drop(&mut self) {
            self.0.store(false, Ordering::SeqCst);
        }
    }

    impl FakeAudit {
        fn new(outcomes: impl IntoIterator<Item = Result<(), &'static str>>) -> Self {
            Self {
                outcomes: Mutex::new(
                    outcomes
                        .into_iter()
                        .map(|result| result.map_err(str::to_string))
                        .collect(),
                ),
                events: Mutex::new(Vec::new()),
                operation_lock_error: None,
                operation_lock_alive: Arc::new(AtomicBool::new(false)),
                observed_lock_states: Mutex::new(Vec::new()),
            }
        }

        fn with_operation_lock_error(error: &'static str) -> Self {
            let mut audit = Self::new([]);
            audit.operation_lock_error = Some(error.to_string());
            audit
        }

        fn events(&self) -> Vec<(String, AuditStatus)> {
            self.events.lock().expect("events lock").clone()
        }

        fn observed_lock_states(&self) -> Vec<bool> {
            self.observed_lock_states
                .lock()
                .expect("lock observations")
                .clone()
        }
    }

    impl TrustedInstallerOperationLock for FakeAudit {
        type Guard = FakeOperationGuard;

        fn acquire_trustedinstaller_operation_guard(&self) -> Result<Self::Guard, String> {
            if let Some(error) = self.operation_lock_error.as_ref() {
                return Err(error.clone());
            }
            self.operation_lock_alive.store(true, Ordering::SeqCst);
            Ok(FakeOperationGuard(Arc::clone(&self.operation_lock_alive)))
        }
    }

    impl TrustedInstallerAudit for FakeAudit {
        fn record(
            &self,
            operation: &str,
            status: AuditStatus,
            _details: String,
        ) -> Result<(), String> {
            self.observed_lock_states
                .lock()
                .expect("lock observations")
                .push(self.operation_lock_alive.load(Ordering::SeqCst));
            self.events
                .lock()
                .expect("events lock")
                .push((operation.to_string(), status));
            self.outcomes
                .lock()
                .expect("outcomes lock")
                .pop_front()
                .unwrap_or(Ok(()))
        }
    }

    struct FakeProcess {
        pid: u32,
        terminate_calls: Arc<AtomicUsize>,
        wait_calls: Arc<AtomicUsize>,
        terminate_result: Result<(), String>,
        wait_result: Result<(), String>,
    }

    struct LocaleTestDirectory(PathBuf);

    impl LocaleTestDirectory {
        fn new() -> Self {
            static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "winprofile-controller-locale-{}-{sequence}",
                std::process::id()
            ));
            std::fs::create_dir(&path).expect("create locale test directory");
            Self(path)
        }
    }

    impl Drop for LocaleTestDirectory {
        fn drop(&mut self) {
            if let Err(error) = std::fs::remove_dir_all(&self.0) {
                eprintln!(
                    "failed to remove locale test directory {}: {error}",
                    self.0.display()
                );
            }
        }
    }

    fn locale_test_controller(directory: &LocaleTestDirectory) -> AppController {
        let snapshots = Arc::new(
            SnapshotEngine::new(Some(directory.0.join("Snapshots")))
                .expect("create snapshot engine"),
        );
        let audit = Arc::new(
            AuditLogger::new(Some(directory.0.join("audit.jsonl")), 10)
                .expect("create audit logger"),
        );
        AppController::new(snapshots, audit)
    }

    fn locale_report() -> DiagnosticReport {
        DiagnosticReport {
            timestamp: Utc::now(),
            total_count: 1,
            healthy_count: 0,
            corrupted_count: 1,
            temporary_count: 0,
            profiles: vec![UserProfile {
                sid: "S-1-5-21-1000.bak".to_string(),
                canonical_sid: "S-1-5-21-1000".to_string(),
                username: "LocaleUser".to_string(),
                domain: "TEST".to_string(),
                profile_path: "C:\\Users\\LocaleUser".to_string(),
                loaded: false,
                is_bak: true,
                state_mask: 0,
                ref_count: 0,
                guid: None,
                ntuser_exists: true,
                usrclass_exists: true,
                disk_size_bytes: 0,
                anomalies: vec![ProfileAnomaly::BakSuffix],
                health: ProfileHealth::Corrupted,
            }],
        }
    }

    fn repair_report(anomalies: Vec<ProfileAnomaly>) -> DiagnosticReport {
        DiagnosticReport {
            timestamp: Utc::now(),
            total_count: 1,
            healthy_count: 0,
            corrupted_count: 1,
            temporary_count: 0,
            profiles: vec![UserProfile {
                sid: "S-1-5-21-4242.bak".to_string(),
                canonical_sid: "S-1-5-21-4242".to_string(),
                username: "LockedUser".to_string(),
                domain: "TEST".to_string(),
                profile_path: "C:\\Users\\LockedUser".to_string(),
                loaded: false,
                is_bak: true,
                state_mask: 0,
                ref_count: 0,
                guid: None,
                ntuser_exists: true,
                usrclass_exists: true,
                disk_size_bytes: 0,
                anomalies,
                health: ProfileHealth::Corrupted,
            }],
        }
    }

    fn locale_audit_entries() -> Vec<AuditEntry> {
        vec![AuditEntry {
            timestamp: Utc::now(),
            operation: "LocaleFixture".to_string(),
            actor: "test".to_string(),
            target: "profile".to_string(),
            status: AuditStatus::RolledBack,
            details: "raw audit details".to_string(),
        }]
    }

    fn displayed_models(ui: &MainWindow) -> String {
        let profile = ui.get_profiles().row_data(0).expect("displayed profile");
        let audit = ui
            .get_audit_entries()
            .row_data(0)
            .expect("displayed audit entry");
        format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            profile.sid,
            profile.canonical_sid,
            profile.username,
            profile.domain,
            profile.profile_path,
            profile.status_text,
            profile.health_type,
            profile.loaded,
            profile.is_bak,
            profile.suggest_fix_bak,
            profile.suggest_reset_state,
            profile.repair_blocked_by_lock_inspection,
            profile.state_raw,
            profile.anomalies,
            audit.timestamp,
            audit.operation,
            audit.target,
            audit.status,
            audit.status_type,
            audit.details,
            ui.get_total_profiles_count()
        )
    }

    impl FakeProcess {
        fn successful(pid: u32) -> (Self, Arc<AtomicUsize>, Arc<AtomicUsize>) {
            let terminate_calls = Arc::new(AtomicUsize::new(0));
            let wait_calls = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    pid,
                    terminate_calls: Arc::clone(&terminate_calls),
                    wait_calls: Arc::clone(&wait_calls),
                    terminate_result: Ok(()),
                    wait_result: Ok(()),
                },
                terminate_calls,
                wait_calls,
            )
        }
    }

    impl ManagedTrustedInstallerProcess for FakeProcess {
        fn pid(&self) -> u32 {
            self.pid
        }

        fn terminate(&self) -> Result<(), String> {
            self.terminate_calls.fetch_add(1, Ordering::SeqCst);
            self.terminate_result.clone()
        }

        fn wait_for_exit(&self) -> Result<(), String> {
            self.wait_calls.fetch_add(1, Ordering::SeqCst);
            self.wait_result.clone()
        }
    }

    #[test]
    fn close_policy_blocks_every_active_non_migration_operation() {
        for operation in [
            OperationKind::Scan,
            OperationKind::Repair,
            OperationKind::TrustedInstaller,
            OperationKind::Export,
            OperationKind::Unknown,
        ] {
            assert_eq!(operation.close_policy(), ClosePolicy::Block);
        }
    }

    #[test]
    fn technical_error_status_is_preserved_byte_for_byte() {
        crate::locale::with_test_window(|ui| {
            let raw = "RAW-WIN32-ERROR-0xC0000022: chemin C:\\Users\\Test";
            set_error(ui, raw);
            assert_eq!(ui.get_status_message().as_str(), raw);
        });
    }

    #[test]
    fn measured_lockers_and_inspection_failures_block_repair_until_rescan_clears_them() {
        crate::locale::with_test_window(|ui| {
            let directory = LocaleTestDirectory::new();
            let controller = Arc::new(locale_test_controller(&directory));
            ui.set_startup_visible(false);
            ui.set_is_elevated(true);
            crate::locale::set_locale_and_app_strings(ui, "en").expect("English locale");

            controller
                .cache_and_apply_report(
                    ui,
                    repair_report(vec![
                        ProfileAnomaly::BakSuffix,
                        ProfileAnomaly::LockedNtUserDat(vec![
                            "Editor.exe (PID: 4242)".to_string(),
                            "Sync.exe (PID: 4343)".to_string(),
                        ]),
                    ]),
                    true,
                )
                .expect("render locked report");
            controller.select_profile(ui, 0);

            assert!(ui.get_selected_repair_blocked_by_lock_inspection());
            assert_eq!(ui.get_selected_locking_processes().row_count(), 2);
            assert_eq!(
                ui.get_selected_locking_processes()
                    .row_data(0)
                    .expect("first blocker")
                    .as_str(),
                "Editor.exe (PID: 4242)"
            );
            assert!(!ui.get_repair_execution_enabled());
            controller.request_repair_confirmation(ui);
            assert!(!ui.get_confirmation_visible());
            assert!(ui
                .get_status_message()
                .as_str()
                .contains("close the listed"));
            controller.execute_repair(ui, false);
            assert_eq!(
                controller.operation_state.active_operation(),
                OperationKind::Idle
            );

            controller
                .cache_and_apply_report(ui, repair_report(vec![ProfileAnomaly::BakSuffix]), true)
                .expect("render rescanned unlocked report");
            controller.select_profile(ui, 0);
            assert!(!ui.get_selected_repair_blocked_by_lock_inspection());
            assert!(ui.get_repair_execution_enabled());

            controller
                .cache_and_apply_report(
                    ui,
                    repair_report(vec![
                        ProfileAnomaly::BakSuffix,
                        ProfileAnomaly::LockInspectionFailure(
                            "RAW-RM-INSPECTION-ERROR-5".to_string(),
                        ),
                    ]),
                    true,
                )
                .expect("render failed inspection report");
            controller.select_profile(ui, 0);
            assert!(ui.get_selected_repair_blocked_by_lock_inspection());
            assert_eq!(
                ui.get_selected_lock_inspection_failure().as_str(),
                "RAW-RM-INSPECTION-ERROR-5"
            );
            assert!(!ui.get_repair_execution_enabled());
            controller.request_repair_confirmation(ui);
            assert!(!ui.get_confirmation_visible());
        });
    }

    #[test]
    fn close_policy_cancels_migration_before_closing() {
        assert_eq!(
            OperationKind::Migration.close_policy(),
            ClosePolicy::CancelMigration
        );
    }

    #[test]
    fn close_policy_allows_only_idle() {
        assert_eq!(OperationKind::Idle.close_policy(), ClosePolicy::Allow);
    }

    #[test]
    fn operation_state_blocks_scan_and_export_until_each_finishes() {
        let state = OperationState::new();

        for operation in [OperationKind::Scan, OperationKind::Export] {
            assert!(state.try_begin(operation));
            assert_eq!(state.active_operation().close_policy(), ClosePolicy::Block);
            assert!(!state.finish());
            assert_eq!(state.active_operation().close_policy(), ClosePolicy::Allow);
        }
    }

    #[test]
    fn operation_state_blocks_close_until_trustedinstaller_terminal_handling_finishes() {
        let state = OperationState::new();

        assert!(state.try_begin(OperationKind::TrustedInstaller));
        assert_eq!(state.active_operation().close_policy(), ClosePolicy::Block);
        assert!(!state.finish());
        assert_eq!(state.active_operation().close_policy(), ClosePolicy::Allow);
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

    #[test]
    fn locale_change_remaps_cached_models_without_scanner_or_journal_reads() {
        crate::locale::with_test_window(|ui| {
            let directory = LocaleTestDirectory::new();
            let controller = locale_test_controller(&directory);
            ui.set_startup_visible(false);
            crate::locale::set_locale_and_app_strings(ui, "en").expect("English locale");
            controller
                .cache_and_apply_report(ui, locale_report(), true)
                .expect("cache report");
            controller
                .cache_and_apply_audit_entries(ui, locale_audit_entries())
                .expect("cache audit entries");
            controller
                .cache_and_apply_migration_terminal(
                    ui,
                    MigrationTerminalPresentation::Success {
                        files: 7,
                        bytes: 4_096,
                        manifest_hash: "0123456789abcdef".to_string(),
                    },
                )
                .expect("cache migration success");
            controller.select_profile(ui, 0);
            ui.set_repair_reset_state(true);
            ui.set_migration_include_roaming(true);
            ui.set_migration_progress(0.42);
            ui.set_startup_consent_granted(true);

            let english_profile = ui.get_profiles().row_data(0).expect("English profile");
            let english_audit = ui
                .get_audit_entries()
                .row_data(0)
                .expect("English audit entry");
            assert!(english_profile.status_text.as_str().contains(".bak suffix"));
            assert_eq!(english_audit.status.as_str(), "Rolled back");
            assert_eq!(
                ui.get_migration_status().as_str(),
                "Migration verified: 7 files, manifest 0123456789abcdef"
            );
            let preserved_identity = (
                ui.get_selected_idx(),
                ui.get_selected_sid(),
                ui.get_selected_path(),
                ui.get_selected_username(),
                ui.get_total_profiles_count(),
                ui.get_healthy_count(),
                ui.get_corrupted_count(),
                ui.get_temp_count(),
            );
            let preserved_state = (
                english_profile.health_type,
                english_audit.status_type,
                ui.get_repair_fix_bak(),
                ui.get_repair_reset_state(),
                ui.get_selected_repair_blocked_by_lock_inspection(),
                ui.get_migration_include_roaming(),
                ui.get_migration_progress(),
                ui.get_startup_consent_granted(),
            );

            assert!(controller.change_locale(ui, "fr").expect("French rerender"));

            let french_profile = ui.get_profiles().row_data(0).expect("French profile");
            let french_audit = ui
                .get_audit_entries()
                .row_data(0)
                .expect("French audit entry");
            assert!(french_profile.status_text.as_str().contains("suffixe .bak"));
            assert_eq!(french_audit.status.as_str(), "Rollback effectué");
            assert!(ui
                .get_selected_anomalies()
                .as_str()
                .contains("suffixe .bak"));
            assert_eq!(
                ui.get_migration_status().as_str(),
                "Migration vérifiée : 7 fichiers, manifeste 0123456789abcdef"
            );
            assert_eq!(
                preserved_identity,
                (
                    ui.get_selected_idx(),
                    ui.get_selected_sid(),
                    ui.get_selected_path(),
                    ui.get_selected_username(),
                    ui.get_total_profiles_count(),
                    ui.get_healthy_count(),
                    ui.get_corrupted_count(),
                    ui.get_temp_count(),
                )
            );
            assert_eq!(
                preserved_state,
                (
                    french_profile.health_type,
                    french_audit.status_type,
                    ui.get_repair_fix_bak(),
                    ui.get_repair_reset_state(),
                    ui.get_selected_repair_blocked_by_lock_inspection(),
                    ui.get_migration_include_roaming(),
                    ui.get_migration_progress(),
                    ui.get_startup_consent_granted(),
                )
            );
            assert_eq!(ui.get_status_message().as_str(), "Prêt");
            assert_eq!(controller.scanner_calls.load(Ordering::SeqCst), 0);
            assert_eq!(controller.journal_read_calls.load(Ordering::SeqCst), 0);
        });
    }

    #[test]
    fn locale_change_rerenders_cancelled_but_preserves_raw_migration_error() {
        crate::locale::with_test_window(|ui| {
            let directory = LocaleTestDirectory::new();
            let controller = locale_test_controller(&directory);
            ui.set_startup_visible(false);
            ui.set_migration_progress(0.73);
            crate::locale::set_locale_and_app_strings(ui, "en").expect("English locale");
            controller
                .cache_and_apply_migration_terminal(ui, MigrationTerminalPresentation::Cancelled)
                .expect("cache cancelled status");
            assert_eq!(
                ui.get_migration_status().as_str(),
                "Operation cancelled and rolled back"
            );

            assert!(controller.change_locale(ui, "fr").expect("French rerender"));
            assert_eq!(
                ui.get_migration_status().as_str(),
                "Opération annulée et changements annulés"
            );
            assert_eq!(ui.get_migration_progress(), 0.73);

            let raw_error = "RAW-MIGRATION-ERROR-0x1234";
            controller
                .cache_and_apply_migration_terminal(
                    ui,
                    MigrationTerminalPresentation::Error {
                        details: raw_error.to_string(),
                    },
                )
                .expect("cache raw migration error");
            assert!(controller
                .change_locale(ui, "en")
                .expect("English rerender"));
            assert_eq!(ui.get_migration_status().as_str(), raw_error);
            assert_eq!(ui.get_migration_progress(), 0.73);
            assert_eq!(controller.scanner_calls.load(Ordering::SeqCst), 0);
            assert_eq!(controller.journal_read_calls.load(Ordering::SeqCst), 0);
        });
    }

    #[test]
    fn busy_or_modal_locale_change_preserves_locale_and_models() {
        crate::locale::with_test_window(|ui| {
            let directory = LocaleTestDirectory::new();
            let controller = locale_test_controller(&directory);
            ui.set_startup_visible(false);
            crate::locale::set_locale_and_app_strings(ui, "en").expect("English locale");
            controller
                .cache_and_apply_report(ui, locale_report(), true)
                .expect("cache report");
            controller
                .cache_and_apply_audit_entries(ui, locale_audit_entries())
                .expect("cache audit entries");
            let original_models = displayed_models(ui);

            assert!(controller.operation_state.try_begin(OperationKind::Scan));
            ui.set_operation_busy(true);
            assert!(!controller
                .change_locale(ui, "fr")
                .expect("busy change refusal"));
            assert_eq!(I18nManager::get_locale(), "en");
            assert_eq!(ui.get_current_locale().as_str(), "en");
            assert_eq!(displayed_models(ui), original_models);
            controller.finish_operation();
            ui.set_operation_busy(false);

            ui.set_confirmation_visible(true);
            assert!(!ui.get_language_switch_enabled());
            assert!(!controller
                .change_locale(ui, "fr")
                .expect("modal change refusal"));
            assert_eq!(I18nManager::get_locale(), "en");
            assert_eq!(displayed_models(ui), original_models);
            assert_eq!(controller.scanner_calls.load(Ordering::SeqCst), 0);
            assert_eq!(controller.journal_read_calls.load(Ordering::SeqCst), 0);
        });
    }

    #[test]
    fn trustedinstaller_request_audit_failure_prevents_launcher_call() {
        let audit = FakeAudit::new([Err("request journal unavailable")]);
        let launcher_called = AtomicBool::new(false);

        let result = execute_trustedinstaller_launch(&audit, || {
            launcher_called.store(true, Ordering::SeqCst);
            let (process, _, _) = FakeProcess::successful(41);
            Ok((process, 1))
        });

        assert!(matches!(
            result,
            Err(TrustedInstallerLaunchError::RequestAudit(error))
                if error == "request journal unavailable"
        ));
        assert!(!launcher_called.load(Ordering::SeqCst));
        assert_eq!(
            audit.events(),
            vec![(TI_REQUEST_OPERATION.to_string(), AuditStatus::Success)]
        );
    }

    #[test]
    fn trustedinstaller_operation_lock_failure_prevents_request_and_launcher() {
        let audit = FakeAudit::with_operation_lock_error("another operation is active");
        let launcher_called = AtomicBool::new(false);

        let result = execute_trustedinstaller_launch(&audit, || {
            launcher_called.store(true, Ordering::SeqCst);
            let (process, _, _) = FakeProcess::successful(41);
            Ok((process, 1))
        });

        assert!(matches!(
            result,
            Err(TrustedInstallerLaunchError::OperationLock(error))
                if error == "another operation is active"
        ));
        assert!(!launcher_called.load(Ordering::SeqCst));
        assert!(audit.events().is_empty(), "REQUEST must not be journaled");
    }

    #[test]
    fn trustedinstaller_operation_guard_covers_request_and_terminal_audit() {
        let audit = FakeAudit::new([Ok(()), Ok(())]);
        let (process, _, _) = FakeProcess::successful(4242);

        assert_eq!(
            execute_trustedinstaller_launch(&audit, || Ok((process, 7)))
                .expect("trustedinstaller launch"),
            4242
        );
        assert_eq!(audit.observed_lock_states(), vec![true, true]);
        assert!(!audit.operation_lock_alive.load(Ordering::SeqCst));
    }

    #[test]
    fn trustedinstaller_terminal_audit_failure_terminates_and_waits() {
        let audit = FakeAudit::new([Ok(()), Err("terminal journal unavailable")]);
        let (process, terminate_calls, wait_calls) = FakeProcess::successful(4242);

        let result = execute_trustedinstaller_launch(&audit, || Ok((process, 7)));

        assert!(matches!(
            result,
            Err(TrustedInstallerLaunchError::TerminalAuditCompensated {
                pid: 4242,
                audit_error,
            }) if audit_error == "terminal journal unavailable"
        ));
        assert_eq!(terminate_calls.load(Ordering::SeqCst), 1);
        assert_eq!(wait_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            audit.events(),
            vec![
                (TI_REQUEST_OPERATION.to_string(), AuditStatus::Success),
                (TI_TERMINAL_OPERATION.to_string(), AuditStatus::Success),
            ]
        );
    }

    #[test]
    fn trustedinstaller_launch_failure_is_durably_audited() {
        let audit = FakeAudit::new([Ok(()), Ok(())]);

        let result =
            execute_trustedinstaller_launch(&audit, || -> Result<(FakeProcess, u32), String> {
                Err("CreateProcess denied".to_string())
            });

        assert!(matches!(
            result,
            Err(TrustedInstallerLaunchError::Launch(error))
                if error == "CreateProcess denied"
        ));
        assert_eq!(
            audit.events(),
            vec![
                (TI_REQUEST_OPERATION.to_string(), AuditStatus::Success),
                (TI_TERMINAL_OPERATION.to_string(), AuditStatus::Failed),
            ]
        );
    }

    #[test]
    fn trustedinstaller_launch_and_failure_audit_errors_are_both_visible() {
        let audit = FakeAudit::new([Ok(()), Err("failed journal unavailable")]);

        let result =
            execute_trustedinstaller_launch(&audit, || -> Result<(FakeProcess, u32), String> {
                Err("CreateProcess denied".to_string())
            });

        assert!(matches!(
            result,
            Err(TrustedInstallerLaunchError::LaunchAndFailureAudit {
                launch_error,
                audit_error,
            }) if launch_error == "CreateProcess denied"
                && audit_error == "failed journal unavailable"
        ));
    }
}

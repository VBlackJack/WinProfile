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

#![windows_subsystem = "windows"]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use app_ui::startup::{self, StartupDecision};
use app_ui::{AppController, AppStrings, MainWindow};
use audit_journal::LegacyStorageRecovery;
use core_profiles::{t, t_args, I18nManager};
use platform_win32::is_process_elevated;
use slint::{CloseRequestResponse, ComponentHandle};

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    I18nManager::validate()?;
    I18nManager::set_locale("fr")?;

    let main_window = MainWindow::new()?;
    load_translations(&main_window);
    main_window.set_is_elevated(is_process_elevated()?);
    main_window.set_startup_title(t("startup.checking.title").into());
    main_window.set_startup_message(t("startup.checking.message").into());
    main_window.set_startup_details("".into());
    main_window.set_startup_action_text(t("startup.retry").into());
    main_window.set_startup_quit_text(t("startup.quit").into());
    main_window.set_startup_consent_text(t("startup.legacy.consent").into());

    let runtime = Arc::new(StartupRuntime::new());

    {
        let runtime = Arc::clone(&runtime);
        let weak = main_window.as_weak();
        main_window.window().on_close_requested(move || {
            let Some(ui) = weak.upgrade() else {
                return CloseRequestResponse::HideWindow;
            };
            if runtime.startup_busy.load(Ordering::Acquire) {
                ui.set_status_message(t("startup.close_blocked").into());
                return CloseRequestResponse::KeepWindowShown;
            }
            match runtime.controller.lock() {
                Ok(controller) => controller
                    .as_ref()
                    .map_or(CloseRequestResponse::HideWindow, |controller| {
                        controller.handle_close_requested(&ui)
                    }),
                Err(_) => CloseRequestResponse::KeepWindowShown,
            }
        });
    }

    {
        let runtime = Arc::clone(&runtime);
        let weak = main_window.as_weak();
        main_window.on_startup_quit(move || {
            if !runtime.startup_busy.load(Ordering::Acquire) {
                if let Some(ui) = weak.upgrade() {
                    let _ = ui.hide();
                }
            }
        });
    }

    {
        let runtime = Arc::clone(&runtime);
        let weak = main_window.as_weak();
        main_window.on_startup_proceed(move || {
            start_or_retry(Arc::clone(&runtime), weak.clone());
        });
    }

    {
        let runtime = Arc::clone(&runtime);
        let weak = main_window.as_weak();
        slint::Timer::single_shot(Duration::ZERO, move || {
            spawn_startup_work(runtime, weak, None);
        });
    }

    main_window.run()?;
    Ok(())
}

struct StartupRuntime {
    controller: Mutex<Option<Arc<AppController>>>,
    recovery: Mutex<Option<LegacyStorageRecovery>>,
    startup_busy: AtomicBool,
}

impl StartupRuntime {
    fn new() -> Self {
        Self {
            controller: Mutex::new(None),
            recovery: Mutex::new(None),
            startup_busy: AtomicBool::new(true),
        }
    }
}

fn start_or_retry(runtime: Arc<StartupRuntime>, weak: slint::Weak<MainWindow>) {
    let Some(ui) = weak.upgrade() else {
        return;
    };
    if ui.get_startup_consent_required() && !ui.get_startup_consent_granted() {
        return;
    }
    drop(ui);
    if runtime.startup_busy.swap(true, Ordering::AcqRel) {
        return;
    }
    if let Some(ui) = weak.upgrade() {
        ui.set_startup_busy(true);
        ui.set_startup_title(t("startup.working.title").into());
        ui.set_startup_message(t("startup.working.message").into());
        ui.set_startup_details(t("startup.working.details").into());
    }
    let recovery = runtime
        .recovery
        .lock()
        .ok()
        .and_then(|mut recovery| recovery.take());
    spawn_startup_work(runtime, weak, recovery);
}

fn spawn_startup_work(
    runtime: Arc<StartupRuntime>,
    weak: slint::Weak<MainWindow>,
    recovery: Option<LegacyStorageRecovery>,
) {
    std::thread::spawn(move || {
        let result = match recovery {
            Some(recovery) => startup::complete_recovery(recovery).map(StartupDecision::Ready),
            None => startup::inspect(),
        };
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(ui) = weak.upgrade() {
                match result {
                    Ok(decision) => present_startup_decision(&ui, &runtime, decision),
                    Err(error) => present_startup_error(&ui, &runtime, error.to_string()),
                }
            }
        });
    });
}

fn present_startup_decision(
    ui: &MainWindow,
    runtime: &Arc<StartupRuntime>,
    decision: StartupDecision,
) {
    match decision {
        StartupDecision::Ready(controller) => {
            if let Ok(mut slot) = runtime.controller.lock() {
                *slot = Some(Arc::clone(&controller));
            } else {
                present_startup_error(
                    ui,
                    runtime,
                    "startup controller state is unavailable".into(),
                );
                return;
            }
            bind_controller(ui, Arc::clone(&controller));
            runtime.startup_busy.store(false, Ordering::Release);
            ui.set_startup_busy(false);
            ui.set_startup_consent_required(false);
            ui.set_startup_consent_granted(true);
            ui.set_startup_visible(false);
            ui.set_status_message(t("status.ready").into());
            controller.refresh_audit_logs(ui);
            controller.scan_profiles(ui);
        }
        StartupDecision::Recovery(recovery) => {
            let resume = recovery.is_resume();
            let reason = recovery.reason().to_string();
            if let Ok(mut slot) = runtime.recovery.lock() {
                *slot = Some(recovery);
            } else {
                present_startup_error(ui, runtime, "startup recovery state is unavailable".into());
                return;
            }
            runtime.startup_busy.store(false, Ordering::Release);
            ui.set_startup_visible(true);
            ui.set_startup_busy(false);
            let consent_required = startup::requires_fresh_consent(resume);
            ui.set_startup_consent_required(consent_required);
            ui.set_startup_consent_granted(!consent_required);
            ui.set_startup_title(
                t(if resume {
                    "startup.resume.title"
                } else {
                    "startup.legacy.title"
                })
                .into(),
            );
            ui.set_startup_message(t("startup.legacy.message").into());
            ui.set_startup_details(t_args("startup.legacy.details", &[("reason", &reason)]).into());
            ui.set_startup_action_text(
                t(if resume {
                    "startup.resume.action"
                } else {
                    "startup.legacy.action"
                })
                .into(),
            );
            ui.set_startup_quit_text(t("startup.quit").into());
        }
    }
}

fn present_startup_error(ui: &MainWindow, runtime: &Arc<StartupRuntime>, error: String) {
    if let Ok(mut recovery) = runtime.recovery.lock() {
        recovery.take();
    }
    runtime.startup_busy.store(false, Ordering::Release);
    ui.set_startup_visible(true);
    ui.set_startup_busy(false);
    ui.set_startup_consent_required(false);
    ui.set_startup_consent_granted(true);
    ui.set_startup_title(t("startup.error.title").into());
    ui.set_startup_message(t("startup.error.message").into());
    ui.set_startup_details(error.into());
    ui.set_startup_action_text(t("startup.retry").into());
    ui.set_startup_quit_text(t("startup.quit").into());
}

fn bind_controller(main_window: &MainWindow, controller: Arc<AppController>) {
    {
        let controller = Arc::clone(&controller);
        let weak = main_window.as_weak();
        main_window.on_scan_profiles(move || {
            if let Some(ui) = weak.upgrade() {
                controller.scan_profiles(&ui);
            }
        });
    }
    {
        let controller = Arc::clone(&controller);
        let weak = main_window.as_weak();
        main_window.on_select_profile(move |index| {
            if let Some(ui) = weak.upgrade() {
                controller.select_profile(&ui, index as usize);
            }
        });
    }
    {
        let controller = Arc::clone(&controller);
        let weak = main_window.as_weak();
        main_window.on_execute_dry_run(move || {
            if let Some(ui) = weak.upgrade() {
                controller.execute_repair(&ui, true);
            }
        });
    }
    {
        let controller = Arc::clone(&controller);
        let weak = main_window.as_weak();
        main_window.on_request_repair(move || {
            if let Some(ui) = weak.upgrade() {
                controller.request_repair_confirmation(&ui);
            }
        });
    }
    {
        let controller = Arc::clone(&controller);
        let weak = main_window.as_weak();
        main_window.on_start_migration(move || {
            if let Some(ui) = weak.upgrade() {
                controller.start_migration(&ui);
            }
        });
    }
    {
        let controller = Arc::clone(&controller);
        let weak = main_window.as_weak();
        main_window.on_cancel_migration(move || {
            if let Some(ui) = weak.upgrade() {
                controller.cancel_migration(&ui);
            }
        });
    }
    {
        let controller = Arc::clone(&controller);
        let weak = main_window.as_weak();
        main_window.on_request_ti_console(move || {
            if let Some(ui) = weak.upgrade() {
                controller.request_ti_confirmation(&ui);
            }
        });
    }
    {
        let controller = Arc::clone(&controller);
        let weak = main_window.as_weak();
        main_window.on_confirm_action(move |kind| {
            if let Some(ui) = weak.upgrade() {
                match kind {
                    0 => controller.execute_repair(&ui, false),
                    1 => controller.launch_ti_console(&ui),
                    _ => tracing::warn!(kind, "Unknown confirmation action"),
                }
            }
        });
    }
    {
        let controller = Arc::clone(&controller);
        let weak = main_window.as_weak();
        main_window.on_export_audit_json(move || {
            if let Some(ui) = weak.upgrade() {
                controller.export_audit(&ui);
            }
        });
    }
    {
        let controller = Arc::clone(&controller);
        let weak = main_window.as_weak();
        main_window.on_clear_audit_logs(move || {
            if let Some(ui) = weak.upgrade() {
                controller.clear_audit_logs(&ui);
            }
        });
    }
}

fn load_translations(ui: &MainWindow) {
    let strings = ui.global::<AppStrings>();
    strings.set_window_title(t("app.window_title").into());
    strings.set_app_title(t("app.title").into());
    strings.set_app_subtitle(t("app.subtitle").into());
    strings.set_app_version(t("app.version").into());
    strings.set_app_license(t("app.license").into());
    strings.set_nav_dashboard(t("nav.dashboard").into());
    strings.set_nav_repair(t("nav.repair").into());
    strings.set_nav_migration(t("nav.migration").into());
    strings.set_nav_maintenance(t("nav.maintenance").into());
    strings.set_nav_logs(t("nav.logs").into());
    strings.set_elevated(t("status.elevated").into());
    strings.set_unelevated(t("status.unelevated").into());
    strings.set_scan(t("dashboard.scan_btn").into());
    strings.set_total(t("dashboard.total_profiles").into());
    strings.set_healthy(t("dashboard.healthy_profiles").into());
    strings.set_corrupted(t("dashboard.corrupted_profiles").into());
    strings.set_temporary(t("dashboard.temporary_profiles").into());
    strings.set_column_account(t("dashboard.column.username").into());
    strings.set_column_sid(t("dashboard.column.sid").into());
    strings.set_column_path(t("dashboard.column.path").into());
    strings.set_column_status(t("dashboard.column.status").into());
    strings.set_column_loaded(t("dashboard.column.loaded").into());
    strings.set_column_action(t("dashboard.column.actions").into());
    strings.set_select(t("common.select").into());
    strings.set_yes(t("common.yes").into());
    strings.set_no(t("common.no").into());
    strings.set_no_profiles(t("dashboard.no_profiles").into());
    strings.set_repair_title(t("repair.title").into());
    strings.set_target_account(t("repair.target_account").into());
    strings.set_target_sid(t("repair.target_sid").into());
    strings.set_profile_path(t("repair.profile_path").into());
    strings.set_anomalies(t("repair.anomalies").into());
    strings.set_none_selected(t("common.none").into());
    strings.set_loaded_warning(t("repair.warning.loaded_session").into());
    strings.set_repair_pipeline(t("repair.pipeline").into());
    strings.set_fix_bak(t("repair.action.fix_bak").into());
    strings.set_reset_state(t("repair.action.reset_state").into());
    strings.set_unlock_hive(t("repair.action.unlock_hive").into());
    strings.set_dry_run(t("repair.btn.dry_run").into());
    strings.set_execute_repair(t("repair.btn.execute").into());
    strings.set_migration_title(t("migration.title").into());
    strings.set_migration_warning(t("migration.warning_dpapi").into());
    strings.set_migration_source(t("migration.source").into());
    strings.set_migration_target(t("migration.target").into());
    strings.set_migration_placeholder(t("migration.target_placeholder").into());
    strings.set_include_roaming(t("migration.include_roaming").into());
    strings.set_include_docs(t("migration.include_docs").into());
    strings.set_start_migration(t("migration.btn.start").into());
    strings.set_cancel_migration(t("migration.btn.cancel").into());
    strings.set_maintenance_title(t("maintenance.title").into());
    strings.set_maintenance_description(t("maintenance.description").into());
    strings.set_launch_ti(t("maintenance.btn.launch_ti").into());
    strings.set_audit_title(t("audit.title").into());
    strings.set_clear_audit(t("audit.btn.clear").into());
    strings.set_export_audit(t("audit.btn.export").into());
    strings.set_audit_timestamp(t("audit.column.timestamp").into());
    strings.set_audit_operation(t("audit.column.operation").into());
    strings.set_audit_target(t("audit.column.target").into());
    strings.set_audit_result(t("audit.column.result").into());
    strings.set_audit_details(t("audit.column.details").into());
    strings.set_about(t("about.title").into());
    strings.set_close(t("common.close").into());
    strings.set_confirm(t("common.confirm").into());
    strings.set_cancel(t("common.cancel").into());
}

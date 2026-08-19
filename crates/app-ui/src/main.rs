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

mod controller;
mod state;

use std::sync::Arc;

use audit_journal::{AuditLogger, SnapshotEngine};
use controller::AppController;
use core_profiles::{t, I18nManager};
use platform_win32::is_process_elevated;
use slint::ComponentHandle;

slint::include_modules!();

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    I18nManager::validate()?;
    I18nManager::set_locale("fr")?;

    let snapshot_engine = Arc::new(SnapshotEngine::new(None)?);
    let audit_logger = Arc::new(AuditLogger::new(None, 500)?);
    let controller = Arc::new(AppController::new(snapshot_engine, audit_logger));
    let main_window = MainWindow::new()?;

    load_translations(&main_window);
    main_window.set_status_message(t("status.ready").into());
    main_window.set_is_elevated(is_process_elevated()?);
    controller.refresh_audit_logs(&main_window);

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

    controller.scan_profiles(&main_window);
    main_window.run()?;
    Ok(())
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
    strings.set_confirm(t("common.confirm").into());
    strings.set_cancel(t("common.cancel").into());
}

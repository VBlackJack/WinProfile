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
use slint::ComponentHandle;

use audit_journal::{AuditLogger, SnapshotEngine};
use controller::AppController;

slint::include_modules!();

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    tracing::info!("Starting WinProfile Suite (winprofile-admin.exe)...");

    let snapshot_engine = Arc::new(SnapshotEngine::new(None)?);
    let audit_logger = Arc::new(AuditLogger::new(None, 500)?);

    let controller = Arc::new(AppController::new(
        snapshot_engine.clone(),
        audit_logger.clone(),
    ));

    let main_window = MainWindow::new()?;

    // Check if running as administrator
    let is_admin = unsafe {
        let mut handle = std::ptr::null_mut();
        windows_sys::Win32::System::Threading::OpenProcessToken(
            windows_sys::Win32::System::Threading::GetCurrentProcess(),
            windows_sys::Win32::Security::TOKEN_QUERY,
            &mut handle,
        ) != 0
    };
    main_window.set_is_elevated(is_admin);

    // Wire callbacks
    {
        let ctrl = controller.clone();
        let ui_weak = main_window.as_weak();
        main_window.on_scan_profiles(move || {
            if let Some(ui) = ui_weak.upgrade() {
                ctrl.scan_profiles(&ui);
            }
        });
    }

    {
        let ctrl = controller.clone();
        let ui_weak = main_window.as_weak();
        main_window.on_select_profile(move |idx| {
            if let Some(ui) = ui_weak.upgrade() {
                ctrl.select_profile(&ui, idx as usize);
            }
        });
    }

    {
        let ctrl = controller.clone();
        let ui_weak = main_window.as_weak();
        main_window.on_execute_repair(move |dry_run| {
            if let Some(ui) = ui_weak.upgrade() {
                ctrl.execute_repair(&ui, dry_run);
            }
        });
    }

    {
        let ctrl = controller.clone();
        let ui_weak = main_window.as_weak();
        main_window.on_start_migration(move || {
            if let Some(ui) = ui_weak.upgrade() {
                ctrl.start_migration(&ui);
            }
        });
    }

    {
        let ctrl = controller.clone();
        let ui_weak = main_window.as_weak();
        main_window.on_launch_ti_console(move || {
            if let Some(ui) = ui_weak.upgrade() {
                ctrl.launch_ti_console(&ui);
            }
        });
    }

    {
        let ctrl = controller.clone();
        let ui_weak = main_window.as_weak();
        main_window.on_test_broker_pipe(move || {
            if let Some(ui) = ui_weak.upgrade() {
                ctrl.test_broker_pipe(&ui);
            }
        });
    }

    {
        let ctrl = controller.clone();
        let ui_weak = main_window.as_weak();
        main_window.on_clear_audit_logs(move || {
            if let Some(ui) = ui_weak.upgrade() {
                ctrl.clear_audit_logs(&ui);
            }
        });
    }

    {
        let ui_weak = main_window.as_weak();
        main_window.on_export_audit_json(move || {
            if let Some(ui) = ui_weak.upgrade() {
                ui.set_status_message("Exported audit log to %ProgramData%\\WinProfile\\audit_log.jsonl".into());
            }
        });
    }

    // Initial scan
    controller.scan_profiles(&main_window);

    main_window.run()?;
    Ok(())
}

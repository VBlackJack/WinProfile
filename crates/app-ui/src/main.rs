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

use app_ui::locale::{self, StartupPresentation};
use app_ui::startup::{self, StartupDecision};
use app_ui::{AppController, MainWindow};
use audit_journal::LegacyStorageRecovery;
use core_profiles::{t, I18nManager};
use platform_win32::{folder_dialog_owner, is_process_elevated, pick_existing_folder};
use slint::{CloseRequestResponse, ComponentHandle};

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    I18nManager::validate()?;

    let main_window = MainWindow::new()?;
    locale::set_locale_and_app_strings(&main_window, locale::detect_initial_locale())?;
    main_window.set_is_elevated(is_process_elevated()?);

    let runtime = Arc::new(StartupRuntime::new());
    present_startup(&main_window, &runtime, StartupPresentation::Checking);

    {
        let runtime = Arc::clone(&runtime);
        let weak = main_window.as_weak();
        main_window.on_change_locale(move |requested_locale| {
            let Some(ui) = weak.upgrade() else {
                return;
            };
            let requested_locale = requested_locale.to_string();
            if ui.get_startup_visible() {
                let presentation = match runtime.presentation.lock() {
                    Ok(presentation) => presentation.clone(),
                    Err(_) => {
                        tracing::error!("Startup presentation state is unavailable");
                        return;
                    }
                };
                if let Err(error) =
                    locale::set_locale_and_app_strings(&ui, requested_locale.as_str())
                {
                    tracing::error!(%error, "Startup locale change was rejected");
                    return;
                }
                presentation.apply(&ui);
                return;
            }
            if !ui.get_language_switch_enabled() {
                return;
            }
            match runtime.controller.lock() {
                Ok(controller) => {
                    if let Some(controller) = controller.as_ref() {
                        if let Err(error) = controller.change_locale(&ui, requested_locale.as_str())
                        {
                            tracing::error!(%error, "Application locale change failed");
                        }
                    }
                }
                Err(_) => tracing::error!("Startup controller state is unavailable"),
            }
        });
    }

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
    presentation: Mutex<StartupPresentation>,
    startup_busy: AtomicBool,
}

impl StartupRuntime {
    fn new() -> Self {
        Self {
            controller: Mutex::new(None),
            recovery: Mutex::new(None),
            presentation: Mutex::new(StartupPresentation::Checking),
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
        present_startup(&ui, &runtime, StartupPresentation::Working);
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
            let presentation = if resume {
                StartupPresentation::ResumeRecovery { reason }
            } else {
                StartupPresentation::FreshRecovery { reason }
            };
            present_startup(ui, runtime, presentation);
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
    present_startup(ui, runtime, StartupPresentation::Error { details: error });
}

fn present_startup(ui: &MainWindow, runtime: &StartupRuntime, presentation: StartupPresentation) {
    match runtime.presentation.lock() {
        Ok(mut current) => *current = presentation.clone(),
        Err(_) => tracing::error!("Startup presentation state is unavailable"),
    }
    presentation.apply(ui);
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
        main_window.on_pick_migration_parent(move || {
            let Some(ui) = weak.upgrade() else {
                return;
            };
            let owner = match folder_dialog_owner(&ui.window().window_handle()) {
                Ok(owner) => owner,
                Err(error) => {
                    controller.report_migration_picker_failure(&ui, error.to_string());
                    return;
                }
            };
            let title = t("migration.picker.title");
            let accept = t("migration.picker.accept");
            match pick_existing_folder(owner, title.as_str(), accept.as_str()) {
                Ok(Some(parent)) => controller.apply_migration_parent(&ui, &parent),
                Ok(None) => {}
                Err(error) => {
                    controller.report_migration_picker_failure(&ui, error.to_string());
                }
            }
        });
    }
    {
        let controller = Arc::clone(&controller);
        let weak = main_window.as_weak();
        main_window.on_validate_migration(move || {
            if let Some(ui) = weak.upgrade() {
                controller.prevalidate_migration(&ui);
            }
        });
    }
    {
        let controller = Arc::clone(&controller);
        let weak = main_window.as_weak();
        main_window.on_invalidate_migration_preflight(move || {
            if let Some(ui) = weak.upgrade() {
                controller.invalidate_migration_preflight(&ui);
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

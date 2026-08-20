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

use core_profiles::i18n::{resolve_supported_locale, ENGLISH_LOCALE};
use core_profiles::{t, t_args, I18nError, I18nManager};
use platform_win32::{user_preferred_ui_languages, LocaleError};
use slint::ComponentHandle;

use crate::{AppStrings, MainWindow};

const ENGLISH_AUTONYM: &str = "English";
const FRENCH_AUTONYM: &str = "Français";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartupPresentation {
    Checking,
    FreshRecovery { reason: String },
    ResumeRecovery { reason: String },
    Working,
    Error { details: String },
}

impl StartupPresentation {
    /// Re-renders startup text without changing recovery state or invoking services.
    pub fn apply(&self, ui: &MainWindow) {
        let (title_key, message_key, details, action_key) = match self {
            Self::Checking => (
                "startup.checking.title",
                "startup.checking.message",
                String::new(),
                "startup.retry",
            ),
            Self::FreshRecovery { reason } => (
                "startup.legacy.title",
                "startup.legacy.message",
                t_args("startup.legacy.details", &[("reason", reason)]),
                "startup.legacy.action",
            ),
            Self::ResumeRecovery { reason } => (
                "startup.resume.title",
                "startup.legacy.message",
                t_args("startup.legacy.details", &[("reason", reason)]),
                "startup.resume.action",
            ),
            Self::Working => (
                "startup.working.title",
                "startup.working.message",
                t("startup.working.details"),
                "startup.retry",
            ),
            Self::Error { details } => (
                "startup.error.title",
                "startup.error.message",
                details.clone(),
                "startup.retry",
            ),
        };
        ui.set_startup_title(t(title_key).into());
        ui.set_startup_message(t(message_key).into());
        ui.set_startup_details(details.into());
        ui.set_startup_action_text(t(action_key).into());
        ui.set_startup_quit_text(t("startup.quit").into());
        ui.set_startup_consent_text(t("startup.legacy.consent").into());
    }
}

/// Resolves the initial session locale from Windows and fails closed to English.
pub fn detect_initial_locale() -> &'static str {
    detect_initial_locale_with(user_preferred_ui_languages)
}

fn detect_initial_locale_with(
    query: impl FnOnce() -> Result<Vec<String>, LocaleError>,
) -> &'static str {
    match query() {
        Ok(tags) => resolve_supported_locale(tags.iter().map(String::as_str)),
        Err(_) => ENGLISH_LOCALE,
    }
}

/// Changes the process-local locale and refreshes every global application string.
pub fn set_locale_and_app_strings(ui: &MainWindow, locale: &str) -> Result<(), I18nError> {
    I18nManager::set_locale(locale)?;
    apply_app_strings(ui);
    ui.set_current_locale(locale.into());
    Ok(())
}

/// Loads every generated AppStrings property from the validated translation bundles.
pub fn apply_app_strings(ui: &MainWindow) {
    let strings = ui.global::<AppStrings>();
    strings.set_window_title(t("app.window_title").into());
    strings.set_app_title(t("app.title").into());
    strings.set_app_subtitle(t("app.subtitle").into());
    strings.set_app_version(t("app.version").into());
    strings.set_app_license(t("app.license").into());
    strings.set_language_english(ENGLISH_AUTONYM.into());
    strings.set_language_french(FRENCH_AUTONYM.into());
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

#[cfg(test)]
type UiTestJob = Box<dyn FnOnce() + Send + 'static>;

#[cfg(test)]
std::thread_local! {
    static UI_TEST_WINDOW: std::rc::Rc<slint::platform::software_renderer::MinimalSoftwareWindow> =
        slint::platform::software_renderer::MinimalSoftwareWindow::new(
            slint::platform::software_renderer::RepaintBufferType::ReusedBuffer,
        );
}

#[cfg(test)]
struct UiTestPlatform;

#[cfg(test)]
impl slint::platform::Platform for UiTestPlatform {
    fn create_window_adapter(
        &self,
    ) -> Result<std::rc::Rc<dyn slint::platform::WindowAdapter>, slint::PlatformError> {
        Ok(UI_TEST_WINDOW.with(Clone::clone))
    }
}

#[cfg(test)]
fn ui_test_sender() -> &'static std::sync::mpsc::Sender<UiTestJob> {
    static SENDER: std::sync::OnceLock<std::sync::mpsc::Sender<UiTestJob>> =
        std::sync::OnceLock::new();
    SENDER.get_or_init(|| {
        let (sender, receiver) = std::sync::mpsc::channel::<UiTestJob>();
        std::thread::Builder::new()
            .name("slint-testing".to_string())
            .spawn(move || {
                slint::platform::set_platform(Box::new(UiTestPlatform))
                    .expect("install the headless Slint test platform");
                UI_TEST_WINDOW.with(|window| {
                    window.set_size(slint::PhysicalSize::new(1100, 760));
                });
                for job in receiver {
                    job();
                }
            })
            .expect("start the Slint testing thread");
        sender
    })
}

#[cfg(test)]
pub(crate) fn with_test_window<T, F>(test: F) -> T
where
    T: Send + 'static,
    F: FnOnce(&MainWindow) -> T + Send + 'static,
{
    let (result_sender, result_receiver) = std::sync::mpsc::sync_channel(0);
    ui_test_sender()
        .send(Box::new(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let ui =
                    MainWindow::new().expect("create MainWindow with the Slint testing backend");
                test(&ui)
            }));
            let _ = result_sender.send(result);
        }))
        .expect("dispatch the Slint UI test");

    match result_receiver
        .recv()
        .expect("receive the Slint UI test result")
    {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_profiles::i18n::FRENCH_LOCALE;
    use slint::platform::{Key, WindowEvent};
    use std::cell::Cell;
    use std::rc::Rc;

    #[test]
    fn windows_failure_empty_and_malformed_preferences_resolve_to_english() {
        assert_eq!(
            detect_initial_locale_with(|| Err(LocaleError::Windows(5))),
            ENGLISH_LOCALE
        );
        assert_eq!(
            detect_initial_locale_with(|| Ok(Vec::new())),
            ENGLISH_LOCALE
        );
        assert_eq!(
            detect_initial_locale_with(|| Ok(vec!["fr_CA".to_string()])),
            ENGLISH_LOCALE
        );
    }

    #[test]
    fn generated_slint_properties_change_between_english_and_french() {
        with_test_window(|ui| {
            set_locale_and_app_strings(ui, ENGLISH_LOCALE).expect("apply English strings");
            let strings = ui.global::<AppStrings>();
            assert_eq!(strings.get_nav_dashboard().as_str(), "Inventory & Health");
            assert_eq!(strings.get_scan().as_str(), "Scan Profiles");
            assert_eq!(strings.get_language_english().as_str(), ENGLISH_AUTONYM);
            assert_eq!(strings.get_language_french().as_str(), FRENCH_AUTONYM);

            set_locale_and_app_strings(ui, FRENCH_LOCALE).expect("apply French strings");
            assert_eq!(strings.get_nav_dashboard().as_str(), "Inventaire & Santé");
            assert_eq!(strings.get_scan().as_str(), "Analyser les profils");
            assert_eq!(ui.get_current_locale().as_str(), FRENCH_LOCALE);
        });
    }

    #[test]
    fn every_startup_state_rerenders_without_changing_raw_state_or_invoking_actions() {
        with_test_window(|ui| {
            ui.set_startup_visible(true);
            ui.set_startup_consent_granted(true);
            let proceed_calls = Rc::new(Cell::new(0));
            let quit_calls = Rc::new(Cell::new(0));
            {
                let proceed_calls = Rc::clone(&proceed_calls);
                ui.on_startup_proceed(move || proceed_calls.set(proceed_calls.get() + 1));
            }
            {
                let quit_calls = Rc::clone(&quit_calls);
                ui.on_startup_quit(move || quit_calls.set(quit_calls.get() + 1));
            }

            let states = [
                StartupPresentation::Checking,
                StartupPresentation::FreshRecovery {
                    reason: "RAW-FRESH-REASON".to_string(),
                },
                StartupPresentation::ResumeRecovery {
                    reason: "RAW-RESUME-REASON".to_string(),
                },
                StartupPresentation::Working,
                StartupPresentation::Error {
                    details: "RAW-ERROR-DETAILS".to_string(),
                },
            ];
            for state in states {
                set_locale_and_app_strings(ui, ENGLISH_LOCALE).expect("English startup state");
                state.apply(ui);
                let english_title = ui.get_startup_title().to_string();
                let english_action = ui.get_startup_action_text().to_string();
                let english_details = ui.get_startup_details().to_string();

                set_locale_and_app_strings(ui, FRENCH_LOCALE).expect("French startup state");
                state.apply(ui);
                assert_ne!(ui.get_startup_title().as_str(), english_title);
                assert_ne!(ui.get_startup_action_text().as_str(), english_action);
                match &state {
                    StartupPresentation::FreshRecovery { reason }
                    | StartupPresentation::ResumeRecovery { reason } => {
                        assert!(english_details.contains(reason));
                        assert!(ui.get_startup_details().as_str().contains(reason));
                    }
                    StartupPresentation::Error { details } => {
                        assert_eq!(english_details, *details);
                        assert_eq!(ui.get_startup_details().as_str(), details);
                    }
                    StartupPresentation::Checking | StartupPresentation::Working => {}
                }
                assert!(ui.get_startup_consent_granted());
            }
            assert_eq!(proceed_calls.get(), 0);
            assert_eq!(quit_calls.get(), 0);
        });
    }

    #[test]
    fn recovery_quit_keeps_initial_focus_and_activates_from_keyboard() {
        with_test_window(|ui| {
            set_locale_and_app_strings(ui, ENGLISH_LOCALE).expect("apply English strings");
            StartupPresentation::FreshRecovery {
                reason: "focus fixture".to_string(),
            }
            .apply(ui);
            ui.set_startup_visible(true);
            ui.set_startup_busy(false);
            let quit_calls = Rc::new(Cell::new(0));
            {
                let quit_calls = Rc::clone(&quit_calls);
                ui.on_startup_quit(move || quit_calls.set(quit_calls.get() + 1));
            }

            ui.show().expect("show testing window");
            ui.window()
                .dispatch_event(WindowEvent::WindowActiveChanged(true));
            slint::platform::update_timers_and_animations();
            assert!(ui.get_startup_quit_focused());
            ui.window().dispatch_event(WindowEvent::KeyPressed {
                text: Key::Return.into(),
            });
            ui.window().dispatch_event(WindowEvent::KeyReleased {
                text: Key::Return.into(),
            });
            assert_eq!(quit_calls.get(), 1);
            ui.hide().expect("hide testing window");
        });
    }
}

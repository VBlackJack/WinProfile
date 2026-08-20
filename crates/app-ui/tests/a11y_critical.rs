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

use app_ui::{AppStrings, AuditLogEntry, MainWindow, ProfileEntry, ProfileIssueEntry};
use i_slint_backend_testing::{AccessibleLiveness, AccessibleRole, ElementHandle, ElementQuery};
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};
use std::collections::BTreeSet;
use std::rc::Rc;

fn labeled_element(ui: &MainWindow, role: AccessibleRole, label: &str) -> ElementHandle {
    ElementQuery::from_root(ui)
        .match_accessible_role(role)
        .match_predicate({
            let label = label.to_string();
            move |element| {
                element
                    .accessible_label()
                    .is_some_and(|value| value == label)
            }
        })
        .find_first()
        .unwrap_or_else(|| panic!("missing {role:?} element labeled '{label}'"))
}

fn relative_luminance(color: slint::Color) -> f64 {
    let rgba = color.to_argb_u8();
    let channel = |value: u8| {
        let value = f64::from(value) / 255.0;
        if value <= 0.04045 {
            value / 12.92
        } else {
            ((value + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * channel(rgba.red) + 0.7152 * channel(rgba.green) + 0.0722 * channel(rgba.blue)
}

fn contrast_ratio(foreground: slint::Color, background: slint::Color) -> f64 {
    let foreground = relative_luminance(foreground);
    let background = relative_luminance(background);
    let (lighter, darker) = if foreground >= background {
        (foreground, background)
    } else {
        (background, foreground)
    };
    (lighter + 0.05) / (darker + 0.05)
}

fn json_keys(source: &str) -> BTreeSet<String> {
    serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(source)
        .expect("valid translation object")
        .into_iter()
        .map(|(key, _)| key)
        .collect()
}

fn verify_static_and_runtime_contract(ui: &MainWindow) {
    assert_eq!(ui.get_a11y_text_secondary().to_argb_u8().red, 0xae);
    assert_eq!(ui.get_a11y_text_secondary().to_argb_u8().green, 0xb9);
    assert_eq!(ui.get_a11y_text_secondary().to_argb_u8().blue, 0xdf);
    assert_eq!(ui.get_a11y_purple().to_argb_u8().red, 0xca);
    assert_eq!(ui.get_a11y_pink().to_argb_u8().green, 0x95);
    assert_eq!(ui.get_a11y_red().to_argb_u8().green, 0x9a);
    for (name, foreground, background) in [
        (
            "secondary/background",
            ui.get_a11y_text_secondary(),
            ui.get_a11y_background(),
        ),
        (
            "secondary/current-line",
            ui.get_a11y_text_secondary(),
            ui.get_a11y_current_line(),
        ),
        (
            "purple/current-line",
            ui.get_a11y_purple(),
            ui.get_a11y_current_line(),
        ),
        ("pink/card", ui.get_a11y_pink(), ui.get_a11y_card_bg()),
        (
            "red/lock-warning",
            ui.get_a11y_red(),
            slint::Color::from_rgb_u8(0x51, 0x2c, 0x35),
        ),
    ] {
        let ratio = contrast_ratio(foreground, background);
        assert!(ratio >= 4.5, "{name} contrast {ratio:.2}:1 is below 4.5:1");
    }

    let en = include_str!("../../../locales/en.json");
    let fr = include_str!("../../../locales/fr.json");
    assert_eq!(json_keys(en), json_keys(fr));
    let ui_source = include_str!("../ui/main-window.slint");
    for line in ui_source.lines().filter(|line| line.contains("font-size:")) {
        let size = line
            .split("font-size:")
            .nth(1)
            .and_then(|value| value.split("px").next())
            .and_then(|value| value.trim().parse::<u32>().ok())
            .unwrap_or_else(|| panic!("unparseable font size in '{line}'"));
        assert!(size >= 12, "body text below 12px in '{line}'");
    }
    assert!(ui_source.contains("min-width: 900px;"));
    assert!(ui_source.contains("min-height: 480px;"));
    assert!(ui_source.contains("preferred-width: 1040px;"));
    assert!(ui_source.contains("preferred-height: 680px;"));
    assert!(ui_source.contains("x: (parent.width - self.width) / 2;"));
    assert!(ui_source.contains("width: 680px;"));
    assert!(ui_source.contains("height: 390px;"));
    assert!(ui_source.contains("startup-quit-focus-pending"));
    assert!(ui_source.contains("interval: 0ms;"));
    assert!(ui_source.contains("indeterminate: root.migration-running;"));
    assert!(!ui_source.contains("accessible-live:"));

    let repair_source = include_str!("../../core-profiles/src/repair.rs");
    let controller_source = include_str!("../src/controller.rs");
    for forbidden in [
        concat!("shutdown_", "locking_processes"),
        concat!("Rm", "Shutdown"),
        concat!("Terminate", "Process"),
        concat!("task", "kill"),
    ] {
        assert!(
            !repair_source.contains(forbidden),
            "core contains {forbidden}"
        );
        assert!(
            !controller_source.contains(forbidden),
            "UI contains {forbidden}"
        );
    }
}

#[test]
fn critical_accessibility_contract_is_present_in_the_runtime_tree() {
    i_slint_backend_testing::init_no_event_loop();
    let ui = MainWindow::new().expect("create MainWindow with explicit headless testing backend");
    app_ui::locale::set_locale_and_app_strings(&ui, "en").expect("English locale");
    ui.set_startup_visible(false);
    ui.set_is_elevated(true);
    ui.window().set_size(slint::PhysicalSize::new(1040, 680));
    ui.show().expect("show headless MainWindow");

    if option_env!("SLINT_EMIT_DEBUG_INFO") != Some("1") {
        verify_static_and_runtime_contract(&ui);
        ui.hide().expect("hide headless MainWindow");
        return;
    }

    let strings = ui.global::<AppStrings>();
    let navigation = labeled_element(
        &ui,
        AccessibleRole::Navigation,
        strings.get_navigation_label().as_str(),
    );
    assert!(navigation.size().width > 0.0);
    let main = labeled_element(
        &ui,
        AccessibleRole::Main,
        strings.get_main_content_label().as_str(),
    );
    assert!(main.size().height > 0.0);

    let profile_accessible_label =
        "LockedUser, S-1-5-21-4242.bak, C:\\Users\\LockedUser, NTUSER.DAT locked, No";
    let raw_issue_details = "RAW-RM-CAUSE-0xC0000022\nEditor.exe (PID: 4242)";
    let issues = ModelRc::from(Rc::new(VecModel::from(vec![ProfileIssueEntry {
        code: "LOCK_INSPECTION_FAILURE".into(),
        summary: "Lock inspection failed".into(),
        technical_details: raw_issue_details.into(),
    }])));
    ui.set_profiles(ModelRc::from(Rc::new(VecModel::from(vec![ProfileEntry {
        sid: "S-1-5-21-4242.bak".into(),
        canonical_sid: "S-1-5-21-4242".into(),
        username: "LockedUser".into(),
        domain: "TEST".into(),
        profile_path: "C:\\Users\\LockedUser".into(),
        status_text: "NTUSER.DAT locked".into(),
        health_type: 1,
        loaded: false,
        is_bak: true,
        suggest_fix_bak: true,
        suggest_reset_state: false,
        locking_processes: ModelRc::from(Rc::new(VecModel::from(vec![
            SharedString::from("Editor.exe (PID: 4242)"),
            SharedString::from("Sync.exe (PID: 4343)"),
        ]))),
        has_locking_processes: true,
        lock_inspection_failure: "".into(),
        repair_blocked_by_lock_inspection: true,
        state_raw: "0x0000".into(),
        anomalies: "NTUSER.DAT locked".into(),
        issues: issues.clone(),
    }]))));
    assert!(
        ElementHandle::find_by_accessible_label(&ui, profile_accessible_label)
            .any(|element| element.accessible_role() == Some(AccessibleRole::ListItem))
    );

    ui.set_selected_idx(0);
    ui.set_selected_sid("S-1-5-21-4242.bak".into());
    ui.set_selected_path("C:\\Users\\LockedUser".into());
    ui.set_selected_username("LockedUser".into());
    ui.set_selected_account("TEST\\LockedUser".into());
    ui.set_selected_health_type(1);
    ui.set_selected_anomalies("NTUSER.DAT locked".into());
    ui.set_selected_issues(issues);
    let profile_details = labeled_element(
        &ui,
        AccessibleRole::Groupbox,
        strings.get_profile_details_label().as_str(),
    );
    assert!(profile_details.size().height > 0.0);
    let warning_card = labeled_element(
        &ui,
        AccessibleRole::Groupbox,
        &format!("{}: NTUSER.DAT locked", strings.get_warning()),
    );
    assert!(warning_card.size().height > 0.0);
    let issue_list = labeled_element(
        &ui,
        AccessibleRole::List,
        strings.get_profile_issues_list_label().as_str(),
    );
    assert_eq!(
        issue_list
            .query_descendants()
            .match_accessible_role(AccessibleRole::ListItem)
            .find_all()
            .len(),
        1
    );
    let technical_details = labeled_element(
        &ui,
        AccessibleRole::TextInput,
        &format!(
            "{} LOCK_INSPECTION_FAILURE",
            strings.get_technical_details()
        ),
    );
    assert_eq!(
        technical_details.accessible_value().as_deref(),
        Some(raw_issue_details)
    );
    assert_eq!(technical_details.accessible_read_only(), Some(true));
    assert!(
        ElementHandle::find_by_accessible_label(&ui, strings.get_examine_repair().as_str())
            .any(|element| element.accessible_role() == Some(AccessibleRole::Button))
    );
    assert!(
        ElementHandle::find_by_accessible_label(&ui, strings.get_prepare_migration().as_str())
            .any(|element| element.accessible_role() == Some(AccessibleRole::Button))
    );

    ui.set_selected_idx(-1);
    ui.set_active_tab(1);
    assert!(ElementHandle::find_by_accessible_label(
        &ui,
        strings.get_choose_profile_instruction().as_str()
    )
    .any(|element| element.accessible_role() == Some(AccessibleRole::Groupbox)));
    assert!(
        ElementHandle::find_by_accessible_label(&ui, strings.get_choose_profile().as_str())
            .any(|element| element.accessible_role() == Some(AccessibleRole::Button))
    );
    ui.set_active_tab(2);
    assert!(ElementHandle::find_by_accessible_label(
        &ui,
        strings.get_choose_profile_instruction().as_str()
    )
    .any(|element| element.accessible_role() == Some(AccessibleRole::Groupbox)));
    ui.set_selected_idx(0);
    ui.set_active_tab(1);
    ui.set_selected_locking_processes(ModelRc::from(Rc::new(VecModel::from(vec![
        SharedString::from("Editor.exe (PID: 4242)"),
        SharedString::from("Sync.exe (PID: 4343)"),
    ]))));
    ui.set_selected_has_locking_processes(true);
    ui.set_selected_repair_blocked_by_lock_inspection(true);
    ui.set_repair_fix_bak(true);
    assert!(!ui.get_repair_execution_enabled());
    let blocker_list = labeled_element(
        &ui,
        AccessibleRole::List,
        strings.get_blockers_list_label().as_str(),
    );
    let blocker_labels = blocker_list
        .query_descendants()
        .match_accessible_role(AccessibleRole::ListItem)
        .find_all()
        .into_iter()
        .filter_map(|element| element.accessible_label())
        .collect::<Vec<_>>();
    assert_eq!(
        blocker_labels,
        vec![
            SharedString::from("Editor.exe (PID: 4242)"),
            SharedString::from("Sync.exe (PID: 4343)"),
        ]
    );

    ui.set_active_tab(2);
    ui.set_migration_progress(0.42);
    let progress = labeled_element(
        &ui,
        AccessibleRole::ProgressIndicator,
        strings.get_migration_progress_label().as_str(),
    );
    assert_eq!(progress.accessible_value().as_deref(), Some("0.42"));
    assert_eq!(progress.accessible_value_minimum(), Some(0.0));
    assert_eq!(progress.accessible_value_maximum(), Some(1.0));
    assert!(ElementHandle::find_by_accessible_label(
        &ui,
        strings.get_migration_browse_parent().as_str()
    )
    .any(|element| element.accessible_role() == Some(AccessibleRole::Button)));
    assert!(ElementHandle::find_by_accessible_label(
        &ui,
        strings.get_migration_validate().as_str()
    )
    .any(|element| element.accessible_role() == Some(AccessibleRole::Button)));
    ui.set_migration_running(true);
    let indeterminate_progress = labeled_element(
        &ui,
        AccessibleRole::ProgressIndicator,
        strings.get_migration_progress_label().as_str(),
    );
    assert_eq!(
        indeterminate_progress.accessible_value().as_deref(),
        Some("")
    );
    ui.set_migration_running(false);

    let raw_audit_details = "RAW-AUDIT-DETAILS-0xC0000022-UNABRIDGED";
    ui.set_audit_entries(ModelRc::from(Rc::new(VecModel::from(vec![
        AuditLogEntry {
            timestamp: "2026-08-20 17:18:19Z".into(),
            operation: "Repair".into(),
            target: "S-1-5-21-4242".into(),
            status: "Failed".into(),
            status_type: 2,
            details: raw_audit_details.into(),
        },
    ]))));
    ui.set_active_tab(4);
    let audit_label =
        format!("2026-08-20 17:18:19Z, Repair, S-1-5-21-4242, Failed, {raw_audit_details}");
    assert!(ElementHandle::find_by_accessible_label(&ui, &audit_label)
        .any(|element| element.accessible_role() == Some(AccessibleRole::ListItem)));

    let raw_details = "RAW-LONG-TECHNICAL-DETAIL-0xC0000022\nsecond line remains intact";
    ui.invoke_show_details("Status details".into(), raw_details.into());
    let details = labeled_element(&ui, AccessibleRole::TextInput, "Status details");
    assert_eq!(details.accessible_value().as_deref(), Some(raw_details));
    assert_eq!(details.accessible_read_only(), Some(true));
    assert_eq!(
        details.accessible_description().as_deref(),
        Some(strings.get_details_copy_hint().as_str())
    );
    ui.invoke_close_details();

    let status_region = labeled_element(
        &ui,
        AccessibleRole::ContentInfo,
        &format!(
            "{}: {}",
            strings.get_status_region_label(),
            ui.get_status_message()
        ),
    );
    assert_eq!(
        status_region.accessible_live_region(),
        Some(AccessibleLiveness::Polite)
    );
    assert!(ElementQuery::from_root(&ui)
        .match_accessible_role(AccessibleRole::Table)
        .find_all()
        .is_empty());

    verify_static_and_runtime_contract(&ui);
    ui.hide().expect("hide headless MainWindow");
}

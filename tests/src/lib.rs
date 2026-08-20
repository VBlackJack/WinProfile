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

#[cfg(test)]
mod tests {
    use audit_journal::{AuditLogger, AuditStatus, SnapshotEngine, SnapshotMetadata};
    use chrono::Utc;
    use core_profiles::constants::*;
    use core_profiles::i18n::{t, t_args, I18nManager};
    use core_profiles::models::{ProfileAnomaly, ProfileHealth, UserProfile};
    use core_profiles::{
        MigrationError, MigrationPlan, ProfileMigrationEngine, ProfileRepairEngine, RepairError,
        RepairPlan,
    };
    use platform_win32::SecureDirectory;
    use std::cell::Cell;
    use std::ffi::OsStr;
    use std::fs::OpenOptions;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "winprofile-tests-{}-{sequence}",
                std::process::id()
            ));
            std::fs::create_dir(&path).expect("create isolated test directory");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            if let Err(error) = std::fs::remove_dir_all(&self.0) {
                eprintln!(
                    "failed to remove test directory {}: {error}",
                    self.0.display()
                );
            }
        }
    }

    struct SubstDrive(String);

    impl SubstDrive {
        fn new(target: &Path) -> Self {
            for letter in ('T'..='Z').rev() {
                let drive = format!("{letter}:");
                if Path::new(&format!(r"{drive}\")).exists() {
                    continue;
                }
                let status = Command::new("subst.exe")
                    .arg(&drive)
                    .arg(target)
                    .status()
                    .expect("run subst fixture");
                if status.success() {
                    return Self(drive);
                }
            }
            panic!("no free drive letter for SUBST overlap fixture");
        }

        fn root(&self) -> PathBuf {
            PathBuf::from(format!(r"{}\", self.0))
        }
    }

    impl Drop for SubstDrive {
        fn drop(&mut self) {
            let _ = Command::new("subst.exe").arg(&self.0).arg("/D").status();
        }
    }

    fn create_junction(link: &Path, target: &Path) {
        let result = Command::new("cmd.exe")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .output()
            .expect("run mklink junction fixture");
        assert!(
            result.status.success(),
            "mklink failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
    }

    #[test]
    fn test_state_bitmask_constants() {
        assert_eq!(STATE_TEMP_PROFILE, 0x0080);
        assert_eq!(STATE_MANDATORY, 0x0001);
        assert_eq!(STATE_READONLY, 0x0002);
        assert_eq!(STATE_LOCAL_ONLY, 0x0004);
        assert_eq!(STATE_DELETE_ROAMING, 0x0008);
    }

    #[test]
    fn test_profile_health_computation() {
        let mut profile = UserProfile {
            sid: "S-1-5-21-12345-500".into(),
            canonical_sid: "S-1-5-21-12345-500".into(),
            username: "TestAdmin".into(),
            domain: "CONTOSO".into(),
            profile_path: "C:\\Users\\TestAdmin".into(),
            loaded: false,
            is_bak: false,
            state_mask: 0,
            ref_count: 0,
            guid: None,
            ntuser_exists: true,
            usrclass_exists: true,
            disk_size_bytes: 1024,
            anomalies: vec![],
            health: ProfileHealth::Healthy,
        };

        profile.compute_health();
        assert_eq!(profile.health, ProfileHealth::Healthy);

        // Add temporary anomaly
        profile.anomalies.push(ProfileAnomaly::BakSuffix);
        profile.is_bak = true;
        profile.compute_health();
        assert_eq!(profile.health, ProfileHealth::Corrupted);
    }

    #[test]
    fn test_i18n_translation_and_interpolation() {
        I18nManager::validate().expect("translation bundles must be valid");
        I18nManager::set_locale("en").expect("English locale must exist");
        assert_eq!(t("app.title"), "WinProfile Suite");
        assert_eq!(t("nav.dashboard"), "Inventory & Health");

        let msg = t_args(
            "migration.progress.copying",
            &[("file", "AppData\\Roaming\\settings.dat")],
        );
        assert_eq!(msg, "Copying: AppData\\Roaming\\settings.dat");

        I18nManager::set_locale("fr").expect("French locale must exist");
        assert_eq!(t("app.title"), "WinProfile Suite");
        assert_eq!(t("nav.dashboard"), "Inventaire & Santé");
        assert!(I18nManager::global().expect("valid i18n").keys().len() > 80);
    }

    #[test]
    fn startup_recovery_catalog_is_complete_in_english_and_french() {
        let required = [
            "startup.checking.title",
            "startup.checking.message",
            "startup.legacy.title",
            "startup.legacy.message",
            "startup.legacy.details",
            "startup.legacy.consent",
            "startup.legacy.action",
            "startup.resume.title",
            "startup.resume.action",
            "startup.working.title",
            "startup.working.message",
            "startup.working.details",
            "startup.error.title",
            "startup.error.message",
            "startup.retry",
            "startup.quit",
            "startup.close_blocked",
        ];

        for locale in ["en", "fr"] {
            I18nManager::set_locale(locale).expect("recovery locale must exist");
            for key in required {
                let value = t(key);
                assert!(!value.trim().is_empty(), "{locale}:{key} is empty");
                assert_ne!(value, key, "{locale}:{key} is missing");
            }
        }
    }

    #[test]
    fn legacy_storage_documentation_states_the_non_forensic_boundary() {
        let readme = include_str!("../../README.md");
        let architecture = include_str!("../../docs/architecture.md");
        let runbook = include_str!("../../docs/storage-recovery.md");
        for document in [readme, architecture, runbook] {
            assert!(document.contains("permissions"));
            assert!(document.contains("forensic"));
            assert!(document.contains("never automatically"));
        }
    }

    #[test]
    fn recovery_ui_requires_fresh_consent_and_keeps_about_accessible() {
        let ui = include_str!("../../crates/app-ui/ui/main-window.slint");
        let main = include_str!("../../crates/app-ui/src/main.rs");
        assert!(ui.contains("if root.startup-visible && !root.about-visible"));
        assert!(ui.contains("checked <=> root.startup-consent-granted"));
        assert!(ui.contains(
            "enabled: !root.startup-busy && (!root.startup-consent-required || root.startup-consent-granted)"
        ));
        assert!(ui.contains("clicked => { root.about-visible = true; }"));
        assert!(ui.contains("AboutSlint"));
        assert!(main.contains("slint::Timer::single_shot(Duration::ZERO"));
        assert!(!main.contains("match startup::inspect()"));
    }

    #[test]
    fn test_packaging_version_and_elevation_contract() {
        let workspace_manifest = include_str!("../../Cargo.toml");
        let windows_manifest = include_str!("../../resources/app.manifest");
        let version_resource = include_str!("../../resources/version.rc");
        assert!(workspace_manifest.contains("version = \"2026.819.0\""));
        assert!(windows_manifest.contains("version=\"2026.819.0.0\""));
        assert!(windows_manifest.contains("level=\"requireAdministrator\""));
        assert!(version_resource.contains("FILEVERSION 2026,819,0,0"));
        assert!(version_resource.contains("\"FileVersion\", \"2026.819.0\\0\""));
    }

    #[test]
    fn test_removed_privileged_surfaces_do_not_return() {
        let ui = include_str!("../../crates/app-ui/ui/main-window.slint");
        let workspace_manifest = include_str!("../../Cargo.toml");
        assert!(!ui.contains("fix-acls"));
        assert!(!ui.contains("broker"));
        assert!(!workspace_manifest.contains("broker-service"));
        assert!(!workspace_manifest.contains("broker-protocol"));
    }

    #[test]
    fn test_audit_log_rotation_export_and_bounded_memory() {
        let temp = TestDirectory::new();
        let log_path = temp.path().join("audit.jsonl");
        let logger =
            AuditLogger::with_limits(Some(log_path.clone()), 3, 320, 2).expect("audit logger");

        for index in 0..10 {
            logger
                .log(
                    "TestOperation",
                    "test",
                    format!("target-{index}"),
                    AuditStatus::Success,
                    "bounded durable test entry",
                )
                .expect("audit write");
        }

        assert!(logger.get_entries().expect("entries").len() <= 3);
        assert!(temp.path().join("audit.jsonl.1").is_file());
        let export = logger.export_copy().expect("verified audit export");
        assert_eq!(
            std::fs::metadata(&log_path).expect("source metadata").len(),
            std::fs::metadata(export).expect("export metadata").len()
        );
        logger.clear_memory().expect("clear display buffer");
        assert!(logger.get_entries().expect("empty display").is_empty());
        assert!(log_path.is_file());
    }

    #[test]
    fn test_invalid_audit_history_is_rejected() {
        let temp = TestDirectory::new();
        let log_path = temp.path().join("audit.jsonl");
        std::fs::write(&log_path, "not-json\n").expect("write malformed fixture");
        assert!(AuditLogger::new(Some(log_path), 10).is_err());
    }

    #[test]
    fn test_invalid_audit_limits_are_rejected() {
        let temp = TestDirectory::new();
        let path = temp.path().join("audit.jsonl");
        assert!(AuditLogger::with_limits(Some(path.clone()), 10, 0, 1).is_err());
        assert!(AuditLogger::with_limits(Some(path), 10, 1024, 0).is_err());
    }

    #[test]
    fn destructive_engines_fail_closed_on_operation_lock_while_dry_run_remains_available() {
        let temp = TestDirectory::new();
        let log_path = temp.path().join("audit.jsonl");
        let holder = AuditLogger::new(Some(log_path.clone()), 10).expect("lock holder");
        let worker = AuditLogger::new(Some(log_path), 10).expect("worker logger");
        let held = holder
            .acquire_operation_guard()
            .expect("destructive operation guard");

        let source = temp.path().join("source");
        let target = temp.path().join("target");
        std::fs::create_dir(&source).expect("migration source");
        let migration = ProfileMigrationEngine::new(&worker);
        let migration_plan = MigrationPlan {
            source_sid: "S-1-5-21-1001".to_string(),
            source_path: source.display().to_string(),
            target_path: target.display().to_string(),
            include_roaming_appdata: false,
            include_personal_folders: true,
        };
        assert!(matches!(
            migration.execute_migration(&migration_plan, |_, _| {}),
            Err(MigrationError::Audit(_))
        ));
        assert!(
            !target.exists(),
            "migration must not create its target before locking"
        );

        let snapshots =
            SnapshotEngine::new(Some(temp.path().join("snapshots"))).expect("snapshot engine");
        let repair = ProfileRepairEngine::new(&snapshots, &worker);
        let mut repair_plan = RepairPlan {
            sid: "invalid".to_string(),
            canonical_sid: "invalid".to_string(),
            profile_path: String::new(),
            fix_bak: false,
            reset_state: false,
            unlock_hive: false,
            dry_run: false,
        };
        assert!(matches!(
            repair.execute_plan(&repair_plan, false),
            Err(RepairError::AuditError(_))
        ));

        repair_plan.dry_run = true;
        assert!(matches!(
            repair.execute_plan(&repair_plan, false),
            Err(RepairError::NoActionSelected)
        ));
        drop(held);
    }

    #[test]
    fn test_migration_copies_and_verifies_without_overwrite() {
        let temp = TestDirectory::new();
        let source = temp.path().join("source");
        let target = temp.path().join("target");
        std::fs::create_dir_all(source.join("Documents")).expect("source directory");
        std::fs::write(
            source.join("Documents").join("report.txt"),
            b"verified data",
        )
        .expect("source file");
        let logger =
            AuditLogger::new(Some(temp.path().join("audit.jsonl")), 20).expect("audit logger");
        let engine = ProfileMigrationEngine::new(&logger);
        let plan = MigrationPlan {
            source_sid: "S-1-5-21-1001".to_string(),
            source_path: source.display().to_string(),
            target_path: target.display().to_string(),
            include_roaming_appdata: false,
            include_personal_folders: true,
        };

        let receipt = engine
            .execute_migration(&plan, |_, _| {})
            .expect("verified migration");
        assert_eq!(receipt.copied_files, 1);
        assert_eq!(receipt.copied_bytes, 13);
        assert_eq!(receipt.manifest_sha256.len(), 64);
        assert_eq!(
            std::fs::read(target.join("Documents").join("report.txt")).expect("copied file"),
            b"verified data"
        );
    }

    #[test]
    fn test_migration_refuses_overwrite_and_preserves_existing_file() {
        let temp = TestDirectory::new();
        let source = temp.path().join("source");
        let target = temp.path().join("target");
        std::fs::create_dir_all(source.join("Documents")).expect("source directory");
        std::fs::create_dir_all(target.join("Documents")).expect("target directory");
        std::fs::write(source.join("Documents").join("same.txt"), b"new").expect("source file");
        std::fs::write(target.join("Documents").join("same.txt"), b"keep").expect("target file");
        let logger =
            AuditLogger::new(Some(temp.path().join("audit.jsonl")), 20).expect("audit logger");
        let engine = ProfileMigrationEngine::new(&logger);
        let plan = MigrationPlan {
            source_sid: "S-1-5-21-1001".to_string(),
            source_path: source.display().to_string(),
            target_path: target.display().to_string(),
            include_roaming_appdata: false,
            include_personal_folders: true,
        };

        assert!(matches!(
            engine.execute_migration(&plan, |_, _| {}),
            Err(MigrationError::DestinationExists(_))
        ));
        assert_eq!(
            std::fs::read(target.join("Documents").join("same.txt")).expect("preserved target"),
            b"keep"
        );
    }

    #[test]
    fn test_cancelled_migration_rolls_back_created_target() {
        let temp = TestDirectory::new();
        let source = temp.path().join("source");
        let target = temp.path().join("target");
        std::fs::create_dir_all(source.join("Documents")).expect("source directory");
        std::fs::write(source.join("Documents").join("data.txt"), b"data").expect("source file");
        let logger =
            AuditLogger::new(Some(temp.path().join("audit.jsonl")), 20).expect("audit logger");
        let engine = ProfileMigrationEngine::new(&logger);
        let plan = MigrationPlan {
            source_sid: "S-1-5-21-1001".to_string(),
            source_path: source.display().to_string(),
            target_path: target.display().to_string(),
            include_roaming_appdata: false,
            include_personal_folders: true,
        };

        assert!(matches!(
            engine.execute_migration_with_cancel(&plan, |_, _| {}, || true),
            Err(MigrationError::Cancelled)
        ));
        assert!(!target.exists());
    }

    #[test]
    fn test_migration_rejects_intermediate_junction_component() {
        let temp = TestDirectory::new();
        let real_source = temp.path().join("real-source");
        let junction = temp.path().join("source-junction");
        let source = junction.join("profile");
        let target = temp.path().join("target");
        std::fs::create_dir_all(real_source.join("profile").join("Documents"))
            .expect("real source directory");
        std::fs::write(
            real_source
                .join("profile")
                .join("Documents")
                .join("data.txt"),
            b"must not be reached through a junction",
        )
        .expect("source file");
        create_junction(&junction, &real_source);

        let logger =
            AuditLogger::new(Some(temp.path().join("audit.jsonl")), 20).expect("audit logger");
        let engine = ProfileMigrationEngine::new(&logger);
        let plan = MigrationPlan {
            source_sid: "S-1-5-21-1001".to_string(),
            source_path: source.display().to_string(),
            target_path: target.display().to_string(),
            include_roaming_appdata: false,
            include_personal_folders: true,
        };

        let result = engine.execute_migration(&plan, |_, _| {});
        std::fs::remove_dir(&junction).expect("remove junction fixture");
        assert!(matches!(result, Err(MigrationError::ReparsePoint(_))));
        assert!(!target.exists());
    }

    #[test]
    fn test_migration_never_writes_through_intermediate_target_junction() {
        let temp = TestDirectory::new();
        let source = temp.path().join("source");
        let real_target = temp.path().join("real-target");
        let junction = temp.path().join("target-junction");
        let target = junction.join("profile");
        std::fs::create_dir_all(source.join("Documents")).expect("source directory");
        std::fs::create_dir(&real_target).expect("real target directory");
        std::fs::write(source.join("Documents").join("data.txt"), b"data").expect("source file");
        create_junction(&junction, &real_target);

        let logger =
            AuditLogger::new(Some(temp.path().join("audit.jsonl")), 20).expect("audit logger");
        let engine = ProfileMigrationEngine::new(&logger);
        let plan = MigrationPlan {
            source_sid: "S-1-5-21-1001".to_string(),
            source_path: source.display().to_string(),
            target_path: target.display().to_string(),
            include_roaming_appdata: false,
            include_personal_folders: true,
        };

        let result = engine.execute_migration(&plan, |_, _| {});
        std::fs::remove_dir(&junction).expect("remove junction fixture");
        assert!(matches!(result, Err(MigrationError::ReparsePoint(_))));
        assert!(
            !real_target.join("profile").exists(),
            "migration must not create through a destination junction"
        );
    }

    #[test]
    fn test_migration_rejects_subst_alias_overlap_by_handle_identity() {
        let temp = TestDirectory::new();
        let source = temp.path().join("source");
        std::fs::create_dir_all(source.join("Documents")).expect("source directory");
        std::fs::write(source.join("Documents").join("data.txt"), b"data").expect("source file");
        let alias = SubstDrive::new(&source);
        let target = alias.root().join("nested-target");
        let logger =
            AuditLogger::new(Some(temp.path().join("audit.jsonl")), 20).expect("audit logger");
        let engine = ProfileMigrationEngine::new(&logger);
        let plan = MigrationPlan {
            source_sid: "S-1-5-21-1001".to_string(),
            source_path: source.display().to_string(),
            target_path: target.display().to_string(),
            include_roaming_appdata: false,
            include_personal_folders: true,
        };

        assert!(matches!(
            engine.execute_migration(&plan, |_, _| {}),
            Err(MigrationError::InvalidPlan(_))
        ));
        assert!(
            !source.join("nested-target").exists(),
            "alias target created during validation must be rolled back"
        );
    }

    #[test]
    fn test_secure_file_handles_block_concurrent_write_and_delete() {
        let temp = TestDirectory::new();
        let source_path = temp.path().join("source.bin");
        let destination_path = temp.path().join("destination.bin");
        std::fs::write(&source_path, b"stable source").expect("source fixture");
        let directory =
            SecureDirectory::open_absolute_existing(temp.path()).expect("secure directory");

        let source = directory
            .open_file(OsStr::new("source.bin"))
            .expect("secure source handle");
        let source_write_error = OpenOptions::new()
            .write(true)
            .open(&source_path)
            .expect_err("concurrent source write must be denied");
        assert_eq!(source_write_error.raw_os_error(), Some(32));
        let source_delete_error = std::fs::remove_file(&source_path)
            .expect_err("concurrent source delete must be denied");
        assert_eq!(source_delete_error.raw_os_error(), Some(32));
        drop(source);

        let (destination, created) = directory
            .create_file(OsStr::new("destination.bin"))
            .expect("secure destination handle");
        drop(destination);
        let destination_write_error = OpenOptions::new()
            .write(true)
            .open(&destination_path)
            .expect_err("transaction handle must retain the destination write lock");
        assert_eq!(destination_write_error.raw_os_error(), Some(32));
        let destination_delete_error = std::fs::remove_file(&destination_path)
            .expect_err("transaction handle must retain the destination delete lock");
        assert_eq!(destination_delete_error.raw_os_error(), Some(32));

        created.remove().expect("remove exact created handle");
        assert!(!destination_path.exists());
    }

    #[test]
    fn test_cancellation_during_large_file_rolls_back_exact_created_handles() {
        let temp = TestDirectory::new();
        let source = temp.path().join("source");
        let target = temp.path().join("target");
        std::fs::create_dir_all(source.join("Documents")).expect("source directory");
        std::fs::write(
            source.join("Documents").join("large.bin"),
            vec![0x5a; 8 * 1024 * 1024],
        )
        .expect("large source file");
        let logger =
            AuditLogger::new(Some(temp.path().join("audit.jsonl")), 20).expect("audit logger");
        let engine = ProfileMigrationEngine::new(&logger);
        let plan = MigrationPlan {
            source_sid: "S-1-5-21-1001".to_string(),
            source_path: source.display().to_string(),
            target_path: target.display().to_string(),
            include_roaming_appdata: false,
            include_personal_folders: true,
        };
        let checks = Cell::new(0usize);

        let result = engine.execute_migration_with_cancel(
            &plan,
            |_, _| {},
            || {
                let next = checks.get() + 1;
                checks.set(next);
                next >= 5
            },
        );

        assert!(matches!(result, Err(MigrationError::Cancelled)));
        assert!(checks.get() >= 5, "cancellation was not polled per chunk");
        assert!(!target.exists(), "cancelled target must be rolled back");
    }

    #[test]
    fn test_migration_rejects_overlapping_roots() {
        let temp = TestDirectory::new();
        let source = temp.path().join("source");
        std::fs::create_dir_all(&source).expect("source directory");
        let logger =
            AuditLogger::new(Some(temp.path().join("audit.jsonl")), 20).expect("audit logger");
        let engine = ProfileMigrationEngine::new(&logger);
        let plan = MigrationPlan {
            source_sid: "S-1-5-21-1001".to_string(),
            source_path: source.display().to_string(),
            target_path: source.join("nested").display().to_string(),
            include_roaming_appdata: false,
            include_personal_folders: true,
        };

        assert!(matches!(
            engine.execute_migration(&plan, |_, _| {}),
            Err(MigrationError::InvalidPlan(_))
        ));
    }

    #[test]
    fn test_snapshot_metadata_serialization() {
        let json = serde_json::json!({
            "id": "snap_12345",
            "timestamp": Utc::now(),
            "sid": "S-1-5-21-1001",
            "profile_path": "C:\\Users\\TestUser",
            "registry_key_path": "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\S-1-5-21-1001",
            "snapshot_file_name": "snap_1.hiv",
            "sha256": "00".repeat(32),
            "file_volume_serial": 1,
            "file_index": 2,
            "reason": "Pre-test snapshot"
        })
        .to_string();
        let deserialized: SnapshotMetadata =
            serde_json::from_str(&json).expect("Deserialization failed");
        let serialized = serde_json::to_string_pretty(&deserialized).expect("Serialization failed");
        assert_eq!(deserialized.id, "snap_12345");
        assert_eq!(deserialized.sid, "S-1-5-21-1001");
        assert!(!serialized.contains("C:\\\\ProgramData"));
        assert!(!serialized.contains("protected_artifact"));
        assert!(!serialized.contains("snapshot_file_path"));
    }
}

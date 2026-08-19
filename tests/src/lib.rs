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
    use audit_journal::{AuditLogger, AuditStatus, SnapshotMetadata};
    use chrono::Utc;
    use core_profiles::constants::*;
    use core_profiles::i18n::{t, t_args, I18nManager};
    use core_profiles::models::{ProfileAnomaly, ProfileHealth, UserProfile};
    use core_profiles::{MigrationError, MigrationPlan, ProfileMigrationEngine};
    use std::path::{Path, PathBuf};
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
        let meta = SnapshotMetadata {
            id: "snap_12345".into(),
            timestamp: Utc::now(),
            sid: "S-1-5-21-1001".into(),
            profile_path: "C:\\Users\\TestUser".into(),
            registry_key_path:
                "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\S-1-5-21-1001"
                    .into(),
            snapshot_file_path: PathBuf::from("C:\\ProgramData\\WinProfile\\Snapshots\\snap_1.hiv"),
            reason: "Pre-test snapshot".into(),
        };

        let json = serde_json::to_string_pretty(&meta).expect("Serialization failed");
        let deserialized: SnapshotMetadata =
            serde_json::from_str(&json).expect("Deserialization failed");
        assert_eq!(deserialized.id, "snap_12345");
        assert_eq!(deserialized.sid, "S-1-5-21-1001");
    }
}

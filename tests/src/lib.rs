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
    use audit_journal::SnapshotMetadata;
    use broker_protocol::{BrokerRequest, BrokerResponse};
    use chrono::Utc;
    use core_profiles::constants::*;
    use core_profiles::i18n::{t, t_args, I18nManager};
    use core_profiles::models::{ProfileAnomaly, ProfileHealth, UserProfile};
    use std::path::PathBuf;

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
        I18nManager::set_locale("en");
        assert_eq!(t("app.title"), "WinProfile Suite");
        assert_eq!(t("nav.dashboard"), "Inventory & Health");

        let msg = t_args("migration.progress.copying", &[("file", "AppData\\Roaming\\settings.dat")]);
        assert_eq!(msg, "Copying files: AppData\\Roaming\\settings.dat");

        I18nManager::set_locale("fr");
        assert_eq!(t("app.title"), "WinProfile Suite");
        assert_eq!(t("nav.dashboard"), "Inventaire & Santé");
    }

    #[test]
    fn test_broker_protocol_serialization() {
        let req = BrokerRequest::RepairBakProfile {
            sid: "S-1-5-21-123456789-1001.bak".into(),
        };
        let json = serde_json::to_string(&req).expect("Serialization failed");
        let parsed: BrokerRequest = serde_json::from_str(&json).expect("Deserialization failed");

        match parsed {
            BrokerRequest::RepairBakProfile { sid } => {
                assert_eq!(sid, "S-1-5-21-123456789-1001.bak");
            }
            _ => panic!("Unexpected request variant"),
        }

        let resp = BrokerResponse::ProcessLaunched { pid: 1234 };
        let resp_json = serde_json::to_string(&resp).expect("Serialization failed");
        let parsed_resp: BrokerResponse = serde_json::from_str(&resp_json).expect("Deserialization failed");

        match parsed_resp {
            BrokerResponse::ProcessLaunched { pid } => assert_eq!(pid, 1234),
            _ => panic!("Unexpected response variant"),
        }
    }

    #[test]
    fn test_snapshot_metadata_serialization() {
        let meta = SnapshotMetadata {
            id: "snap_12345".into(),
            timestamp: Utc::now(),
            sid: "S-1-5-21-1001".into(),
            profile_path: "C:\\Users\\TestUser".into(),
            registry_key_path: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\S-1-5-21-1001".into(),
            snapshot_file_path: PathBuf::from("C:\\ProgramData\\WinProfile\\Snapshots\\snap_1.hiv"),
            reason: "Pre-test snapshot".into(),
        };

        let json = serde_json::to_string_pretty(&meta).expect("Serialization failed");
        let deserialized: SnapshotMetadata = serde_json::from_str(&json).expect("Deserialization failed");
        assert_eq!(deserialized.id, "snap_12345");
        assert_eq!(deserialized.sid, "S-1-5-21-1001");
    }
}

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

use audit_journal::{AuditEntry, AuditStatus};
use core_profiles::models::{ProfileAnomaly, ProfileHealth, UserProfile};
use slint::{ModelRc, SharedString, VecModel};
use std::rc::Rc;

// Slint generated types
use crate::{AuditLogEntry, ProfileEntry};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RepairSuggestions {
    fix_bak: bool,
    reset_state: bool,
}

fn repair_suggestions(profile: &UserProfile) -> RepairSuggestions {
    RepairSuggestions {
        fix_bak: profile
            .anomalies
            .iter()
            .any(|anomaly| matches!(anomaly, ProfileAnomaly::BakSuffix)),
        reset_state: profile
            .anomalies
            .iter()
            .any(|anomaly| matches!(anomaly, ProfileAnomaly::DirtyStateMask(_))),
    }
}

fn locking_processes(profile: &UserProfile) -> Vec<SharedString> {
    profile
        .anomalies
        .iter()
        .filter_map(|anomaly| match anomaly {
            ProfileAnomaly::LockedNtUserDat(processes) => Some(processes.as_slice()),
            _ => None,
        })
        .flatten()
        .map(|process| process.as_str().into())
        .collect()
}

fn lock_inspection_failure(profile: &UserProfile) -> Option<&str> {
    profile.anomalies.iter().find_map(|anomaly| match anomaly {
        ProfileAnomaly::LockInspectionFailure(details) => Some(details.as_str()),
        _ => None,
    })
}

pub fn user_profile_to_slint(profile: &UserProfile) -> ProfileEntry {
    let health_type = match profile.health {
        ProfileHealth::Healthy => 0,
        ProfileHealth::Warning => 1,
        ProfileHealth::Corrupted => 2,
    };

    let status_text = if profile.anomalies.is_empty() {
        core_profiles::t("profile.status.healthy")
    } else {
        profile
            .anomalies
            .iter()
            .map(|a| a.localized_description())
            .collect::<Vec<_>>()
            .join("; ")
    };

    let anomalies = profile
        .anomalies
        .iter()
        .map(|a| a.localized_description())
        .collect::<Vec<_>>()
        .join("; ");
    let suggestions = repair_suggestions(profile);
    let locking_processes = locking_processes(profile);
    let has_locking_processes = !locking_processes.is_empty();
    let lock_inspection_failure = lock_inspection_failure(profile).unwrap_or_default();

    ProfileEntry {
        sid: profile.sid.clone().into(),
        canonical_sid: profile.canonical_sid.clone().into(),
        username: profile.username.clone().into(),
        domain: profile.domain.clone().into(),
        profile_path: profile.profile_path.clone().into(),
        status_text: status_text.into(),
        health_type,
        loaded: profile.loaded,
        is_bak: profile.is_bak,
        suggest_fix_bak: suggestions.fix_bak,
        suggest_reset_state: suggestions.reset_state,
        locking_processes: ModelRc::from(Rc::new(VecModel::from(locking_processes))),
        has_locking_processes,
        lock_inspection_failure: lock_inspection_failure.into(),
        repair_blocked_by_lock_inspection: has_locking_processes
            || !lock_inspection_failure.is_empty(),
        state_raw: format!("0x{:04X}", profile.state_mask).into(),
        anomalies: anomalies.into(),
    }
}

pub fn audit_entry_to_slint(entry: &AuditEntry) -> AuditLogEntry {
    let (status_str, status_type) = match entry.status {
        AuditStatus::Success => (core_profiles::t("audit.status.success"), 0),
        AuditStatus::Warning => (core_profiles::t("audit.status.warning"), 1),
        AuditStatus::Failed => (core_profiles::t("audit.status.failed"), 2),
        AuditStatus::RolledBack => (core_profiles::t("audit.status.rolled_back"), 3),
    };

    AuditLogEntry {
        timestamp: entry
            .timestamp
            .format("%Y-%m-%d %H:%M:%SZ")
            .to_string()
            .into(),
        operation: entry.operation.clone().into(),
        target: entry.target.clone().into(),
        status: status_str.into(),
        status_type,
        details: entry.details.clone().into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use slint::Model;

    fn profile_with_anomalies(anomalies: Vec<ProfileAnomaly>) -> UserProfile {
        UserProfile {
            sid: "S-1-5-21-1000".to_string(),
            canonical_sid: "S-1-5-21-1000".to_string(),
            username: "TestUser".to_string(),
            domain: "TEST".to_string(),
            profile_path: "C:\\Users\\TestUser".to_string(),
            loaded: false,
            is_bak: false,
            state_mask: 0,
            ref_count: 0,
            guid: None,
            ntuser_exists: true,
            usrclass_exists: true,
            disk_size_bytes: 0,
            anomalies,
            health: ProfileHealth::Healthy,
        }
    }

    #[test]
    fn exact_anomalies_enable_only_matching_repair_suggestions() {
        let profile = profile_with_anomalies(vec![
            ProfileAnomaly::BakSuffix,
            ProfileAnomaly::DirtyStateMask(0x100),
            ProfileAnomaly::LockedNtUserDat(vec!["process.exe".to_string()]),
        ]);

        assert_eq!(
            repair_suggestions(&profile),
            RepairSuggestions {
                fix_bak: true,
                reset_state: true,
            }
        );
        assert_eq!(
            locking_processes(&profile),
            vec![SharedString::from("process.exe")]
        );
    }

    #[test]
    fn lock_inspection_failure_is_preserved_raw_and_blocks_repair() {
        let profile = profile_with_anomalies(vec![ProfileAnomaly::LockInspectionFailure(
            "raw Restart Manager failure 123".to_string(),
        )]);

        let entry = user_profile_to_slint(&profile);
        assert_eq!(
            entry.lock_inspection_failure.as_str(),
            "raw Restart Manager failure 123"
        );
        assert!(entry.repair_blocked_by_lock_inspection);
        assert_eq!(entry.locking_processes.row_count(), 0);
    }

    #[test]
    fn unrelated_warnings_do_not_enable_destructive_repair_suggestions() {
        let mut profile = profile_with_anomalies(vec![
            ProfileAnomaly::MissingDirectory("C:\\Users\\Missing".to_string()),
            ProfileAnomaly::SidResolutionFailure("lookup failed".to_string()),
            ProfileAnomaly::FilesystemScanFailure("access denied".to_string()),
        ]);
        profile.health = ProfileHealth::Warning;

        assert_eq!(
            repair_suggestions(&profile),
            RepairSuggestions {
                fix_bak: false,
                reset_state: false,
            }
        );
    }

    #[test]
    fn audit_timestamp_is_explicit_utc() {
        let entry = AuditEntry {
            timestamp: chrono::DateTime::parse_from_rfc3339("2026-08-20T17:18:19Z")
                .expect("valid timestamp")
                .with_timezone(&chrono::Utc),
            operation: "Test".to_string(),
            actor: "test".to_string(),
            target: "profile".to_string(),
            status: AuditStatus::Success,
            details: "raw details".to_string(),
        };

        assert_eq!(
            audit_entry_to_slint(&entry).timestamp.as_str(),
            "2026-08-20 17:18:19Z"
        );
    }
}

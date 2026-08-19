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
use core_profiles::models::{ProfileHealth, UserProfile};

// Slint generated types
use crate::{AuditLogEntry, ProfileEntry};

pub fn user_profile_to_slint(profile: &UserProfile) -> ProfileEntry {
    let health_type = match profile.health {
        ProfileHealth::Healthy => 0,
        ProfileHealth::Warning => 1,
        ProfileHealth::Corrupted => 2,
    };

    let status_text = if profile.anomalies.is_empty() {
        "Healthy".to_string()
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
        state_raw: format!("0x{:04X}", profile.state_mask).into(),
        anomalies: anomalies.into(),
    }
}

pub fn audit_entry_to_slint(entry: &AuditEntry) -> AuditLogEntry {
    let status_str = match entry.status {
        AuditStatus::Success => "Success",
        AuditStatus::Warning => "Warning",
        AuditStatus::Failed => "Failed",
        AuditStatus::RolledBack => "RolledBack",
    };

    AuditLogEntry {
        timestamp: entry.timestamp.format("%Y-%m-%d %H:%M:%S").to_string().into(),
        operation: entry.operation.clone().into(),
        target: entry.target.clone().into(),
        status: status_str.into(),
        details: entry.details.clone().into(),
    }
}

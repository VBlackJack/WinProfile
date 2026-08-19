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

use crate::i18n::t;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Specific anomaly detected during profile scanning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProfileAnomaly {
    BakSuffix,
    TempSession,
    OrphanSid,
    PathCollision(String),
    DirtyStateMask(u32),
    LockedNtUserDat(Vec<String>),
    MissingDirectory(String),
    RegistryReadFailure(String),
    SidResolutionFailure(String),
    FilesystemScanFailure(String),
    LockInspectionFailure(String),
}

impl ProfileAnomaly {
    /// Returns the localized description of the anomaly.
    pub fn localized_description(&self) -> String {
        match self {
            ProfileAnomaly::BakSuffix => t("profile.status.bak_suffix"),
            ProfileAnomaly::TempSession => t("profile.status.temp_session"),
            ProfileAnomaly::OrphanSid => t("profile.status.orphan_sid"),
            ProfileAnomaly::PathCollision(_) => t("profile.status.path_collision"),
            ProfileAnomaly::DirtyStateMask(_) => t("profile.status.dirty_state"),
            ProfileAnomaly::LockedNtUserDat(_) => t("profile.status.hive_locked"),
            ProfileAnomaly::MissingDirectory(_) => t("profile.status.missing_directory"),
            ProfileAnomaly::RegistryReadFailure(_) => t("profile.status.registry_read_failure"),
            ProfileAnomaly::SidResolutionFailure(_) => t("profile.status.sid_resolution_failure"),
            ProfileAnomaly::FilesystemScanFailure(_) => t("profile.status.filesystem_scan_failure"),
            ProfileAnomaly::LockInspectionFailure(_) => t("profile.status.lock_inspection_failure"),
        }
    }
}

/// Overall health categorization of a profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProfileHealth {
    Healthy,
    Warning,
    Corrupted,
}

/// Detailed in-memory model of a Windows user profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    pub sid: String,
    pub canonical_sid: String,
    pub username: String,
    pub domain: String,
    pub profile_path: String,
    pub loaded: bool,
    pub is_bak: bool,
    pub state_mask: u32,
    pub ref_count: u32,
    pub guid: Option<String>,
    pub ntuser_exists: bool,
    pub usrclass_exists: bool,
    pub disk_size_bytes: u64,
    pub anomalies: Vec<ProfileAnomaly>,
    pub health: ProfileHealth,
}

impl UserProfile {
    /// Computes overall health based on detected anomalies.
    pub fn compute_health(&mut self) {
        if self.is_bak
            || self.anomalies.iter().any(|a| {
                matches!(
                    a,
                    ProfileAnomaly::BakSuffix
                        | ProfileAnomaly::TempSession
                        | ProfileAnomaly::PathCollision(_)
                )
            })
        {
            self.health = ProfileHealth::Corrupted;
        } else if !self.anomalies.is_empty() {
            self.health = ProfileHealth::Warning;
        } else {
            self.health = ProfileHealth::Healthy;
        }
    }
}

/// Full system diagnostic summary report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticReport {
    pub timestamp: DateTime<Utc>,
    pub total_count: usize,
    pub healthy_count: usize,
    pub corrupted_count: usize,
    pub temporary_count: usize,
    pub profiles: Vec<UserProfile>,
}

/// Execution plan for repairing a profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairPlan {
    pub sid: String,
    pub canonical_sid: String,
    pub profile_path: String,
    pub fix_bak: bool,
    pub reset_state: bool,
    pub unlock_hive: bool,
    pub dry_run: bool,
}

/// Options for migrating a user profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationPlan {
    pub source_sid: String,
    pub source_path: String,
    pub target_path: String,
    pub include_roaming_appdata: bool,
    pub include_personal_folders: bool,
}

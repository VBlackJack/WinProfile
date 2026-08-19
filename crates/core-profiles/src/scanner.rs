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

use std::path::Path;
use thiserror::Error;
use windows_sys::Win32::System::Registry::{HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_READ};

use platform_win32::{
    enum_subkeys, lookup_account_by_sid_string, open_key, query_value_string,
    query_value_u32, RestartManagerSession,
};

use crate::constants::*;
use crate::models::{ProfileAnomaly, ProfileHealth, UserProfile};

#[derive(Error, Debug)]
pub enum ScannerError {
    #[error("Failed to access Windows Registry: {0}")]
    RegistryError(#[from] platform_win32::RegistryError),
    #[error("Failed to query Restart Manager: {0}")]
    RestartManagerError(#[from] platform_win32::RestartManagerError),
}

pub type ScannerResult<T> = Result<T, ScannerError>;

/// Engine responsible for scanning, detecting anomalies, and calculating health scores
/// across all Windows user profiles on the host machine.
pub struct ProfileScanner;

impl ProfileScanner {
    /// Performs a full scan and returns a complete diagnostic summary report.
    pub fn scan_all() -> ScannerResult<crate::models::DiagnosticReport> {
        let profiles = Self::scan_all_profiles()?;
        let total_count = profiles.len();
        let healthy_count = profiles.iter().filter(|p| p.health == ProfileHealth::Healthy).count();
        let corrupted_count = profiles.iter().filter(|p| p.health == ProfileHealth::Corrupted).count();
        let temporary_count = profiles.iter().filter(|p| p.anomalies.contains(&ProfileAnomaly::TempSession)).count();

        Ok(crate::models::DiagnosticReport {
            timestamp: chrono::Utc::now(),
            total_count,
            healthy_count,
            corrupted_count,
            temporary_count,
            profiles,
        })
    }

    /// Discovers and evaluates all user profiles listed in HKLM\...\ProfileList.
    pub fn scan_all_profiles() -> ScannerResult<Vec<UserProfile>> {
        let mut profiles = Vec::new();

        let profile_list_key = open_key(HKEY_LOCAL_MACHINE, REG_KEY_PROFILE_LIST, KEY_READ)?;
        let subkeys = enum_subkeys(&profile_list_key)?;

        for sid_key_name in subkeys {
            // Ignore standard non-user well-known SIDs
            if SYSTEM_SID_PREFIXES.iter().any(|prefix| sid_key_name.starts_with(prefix)) {
                continue;
            }

            let is_bak = sid_key_name.ends_with(BAK_EXTENSION);
            let canonical_sid = if is_bak {
                sid_key_name.trim_end_matches(BAK_EXTENSION).to_string()
            } else {
                sid_key_name.clone()
            };

            let subkey_rel_path = format!("{}\\{}", REG_KEY_PROFILE_LIST, sid_key_name);
            let current_key = match open_key(HKEY_LOCAL_MACHINE, &subkey_rel_path, KEY_READ) {
                Ok(k) => k,
                Err(_) => continue,
            };

            let profile_image_path = query_value_string(&current_key, VAL_PROFILE_IMAGE_PATH)
                .unwrap_or_default();
            let state_mask = query_value_u32(&current_key, VAL_STATE).unwrap_or(0);
            let ref_count = query_value_u32(&current_key, VAL_REF_COUNT).unwrap_or(0);
            let guid = query_value_string(&current_key, VAL_GUID).ok();

            // Lookup username and domain from SID
            let (domain, username) = lookup_account_by_sid_string(&canonical_sid)
                .unwrap_or_else(|_| ("Unknown".to_string(), canonical_sid.clone()));

            // Check if hive is currently loaded under HKEY_USERS
            let loaded = open_key(HKEY_USERS, &canonical_sid, KEY_READ).is_ok();

            // Detect anomalies
            let mut anomalies = Vec::new();

            if is_bak {
                anomalies.push(ProfileAnomaly::BakSuffix);
            }

            if (state_mask & STATE_TEMP_PROFILE) != 0 {
                anomalies.push(ProfileAnomaly::TempSession);
            }

            if state_mask != 0 && (state_mask & STATE_TEMP_PROFILE) == 0 {
                anomalies.push(ProfileAnomaly::DirtyStateMask(state_mask));
            }

            let profile_dir = Path::new(&profile_image_path);
            let dir_exists = profile_dir.exists();
            if !dir_exists {
                anomalies.push(ProfileAnomaly::MissingDirectory(profile_image_path.clone()));
            }

            let ntuser_dat_path = profile_dir.join(NTUSER_DAT);
            let ntuser_exists = ntuser_dat_path.exists();
            let usrclass_exists = profile_dir.join(USRCLASS_DAT_REL_PATH).exists();

            if profile_image_path.to_ascii_lowercase().contains("temp") {
                anomalies.push(ProfileAnomaly::PathCollision(profile_image_path.clone()));
            }

            // Check for locks on NTUSER.DAT if hive exists and not currently loaded in HKU
            if dir_exists && ntuser_exists && !loaded {
                if let Ok(rm_session) = RestartManagerSession::new() {
                    if rm_session.register_file(&ntuser_dat_path).is_ok() {
                        if let Ok(processes) = rm_session.get_locking_processes() {
                            if !processes.is_empty() {
                                let lock_names: Vec<String> = processes
                                    .iter()
                                    .map(|p| format!("{} (PID: {})", p.app_name, p.process_id))
                                    .collect();
                                anomalies.push(ProfileAnomaly::LockedNtUserDat(lock_names));
                            }
                        }
                    }
                }
            }

            let mut profile = UserProfile {
                sid: sid_key_name,
                canonical_sid,
                username,
                domain,
                profile_path: profile_image_path,
                loaded,
                is_bak,
                state_mask,
                ref_count,
                guid,
                ntuser_exists,
                usrclass_exists,
                disk_size_bytes: 0,
                anomalies,
                health: ProfileHealth::Healthy,
            };

            profile.compute_health();
            profiles.push(profile);
        }

        Ok(profiles)
    }
}

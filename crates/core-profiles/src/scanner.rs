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

use std::collections::HashMap;
use std::path::Path;

use thiserror::Error;
use windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND;
use windows_sys::Win32::System::Registry::KEY_READ;

use platform_win32::{
    enum_subkeys, lookup_account_by_sid_string, open_key, path_is_reparse_point,
    query_value_string, query_value_u32, RegistryError, RegistryRoot, RestartManagerSession,
};

use crate::constants::*;
use crate::models::{ProfileAnomaly, ProfileHealth, UserProfile};

#[derive(Error, Debug)]
pub enum ScannerError {
    #[error("Failed to access Windows Registry: {0}")]
    RegistryError(#[from] RegistryError),
    #[error("Profile key '{key}' cannot be read: {source}")]
    ProfileKeyUnreadable { key: String, source: RegistryError },
}

pub type ScannerResult<T> = Result<T, ScannerError>;

/// Engine responsible for scanning and detecting Windows profile anomalies.
pub struct ProfileScanner;

impl ProfileScanner {
    /// Performs a full scan and returns a complete diagnostic summary report.
    pub fn scan_all() -> ScannerResult<crate::models::DiagnosticReport> {
        let profiles = Self::scan_all_profiles()?;
        let total_count = profiles.len();
        let healthy_count = profiles
            .iter()
            .filter(|profile| profile.health == ProfileHealth::Healthy)
            .count();
        let corrupted_count = profiles
            .iter()
            .filter(|profile| profile.health == ProfileHealth::Corrupted)
            .count();
        let temporary_count = profiles
            .iter()
            .filter(|profile| profile.anomalies.contains(&ProfileAnomaly::TempSession))
            .count();

        Ok(crate::models::DiagnosticReport {
            timestamp: chrono::Utc::now(),
            total_count,
            healthy_count,
            corrupted_count,
            temporary_count,
            profiles,
        })
    }

    /// Discovers and evaluates all user profiles listed in HKLM ProfileList.
    pub fn scan_all_profiles() -> ScannerResult<Vec<UserProfile>> {
        let profile_list_key =
            open_key(RegistryRoot::LocalMachine, REG_KEY_PROFILE_LIST, KEY_READ)?;
        let subkeys = enum_subkeys(&profile_list_key)?;
        let mut profiles = Vec::new();

        for sid_key_name in subkeys {
            let is_bak = sid_key_name.ends_with(BAK_EXTENSION);
            let canonical_sid = sid_key_name
                .strip_suffix(BAK_EXTENSION)
                .unwrap_or(&sid_key_name)
                .to_string();
            if SYSTEM_SID_PREFIXES.contains(&canonical_sid.as_str()) {
                continue;
            }

            let subkey_rel_path = format!("{REG_KEY_PROFILE_LIST}\\{sid_key_name}");
            let current_key = open_key(RegistryRoot::LocalMachine, &subkey_rel_path, KEY_READ)
                .map_err(|source| ScannerError::ProfileKeyUnreadable {
                    key: sid_key_name.clone(),
                    source,
                })?;
            let mut anomalies = Vec::new();

            let profile_image_path =
                required_string(&current_key, VAL_PROFILE_IMAGE_PATH, &mut anomalies);
            let state_mask = optional_u32(&current_key, VAL_STATE, &mut anomalies);
            let ref_count = optional_u32(&current_key, VAL_REF_COUNT, &mut anomalies);
            let guid = optional_string(&current_key, VAL_GUID, &mut anomalies);

            let (domain, username) = match lookup_account_by_sid_string(&canonical_sid) {
                Ok(account) => account,
                Err(error) => {
                    anomalies.push(ProfileAnomaly::SidResolutionFailure(error.to_string()));
                    (String::new(), canonical_sid.clone())
                }
            };
            let loaded = match open_key(RegistryRoot::Users, &canonical_sid, KEY_READ) {
                Ok(_) => true,
                Err(RegistryError::Win32Error(ERROR_FILE_NOT_FOUND)) => false,
                Err(error) => {
                    anomalies.push(ProfileAnomaly::RegistryReadFailure(format!(
                        "HKEY_USERS\\{canonical_sid}: {error}"
                    )));
                    false
                }
            };

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
            let dir_exists = profile_dir.is_dir();
            if !dir_exists {
                anomalies.push(ProfileAnomaly::MissingDirectory(profile_image_path.clone()));
            }
            let ntuser_dat_path = profile_dir.join(NTUSER_DAT);
            let ntuser_exists = ntuser_dat_path.is_file();
            let usrclass_exists = profile_dir.join(USRCLASS_DAT_REL_PATH).is_file();

            if dir_exists && ntuser_exists && !loaded {
                inspect_locks(&ntuser_dat_path, &mut anomalies);
            }
            let disk_size_bytes = if dir_exists {
                match directory_size(profile_dir) {
                    Ok(size) => size,
                    Err(error) => {
                        anomalies.push(ProfileAnomaly::FilesystemScanFailure(error));
                        0
                    }
                }
            } else {
                0
            };

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
                disk_size_bytes,
                anomalies,
                health: ProfileHealth::Healthy,
            };
            profile.compute_health();
            profiles.push(profile);
        }

        mark_path_collisions(&mut profiles);
        Ok(profiles)
    }
}

fn required_string(
    key: &platform_win32::OwnedHKey,
    value_name: &str,
    anomalies: &mut Vec<ProfileAnomaly>,
) -> String {
    match query_value_string(key, value_name) {
        Ok(value) if !value.trim().is_empty() => value,
        Ok(_) => {
            anomalies.push(ProfileAnomaly::RegistryReadFailure(format!(
                "{value_name}: empty value"
            )));
            String::new()
        }
        Err(error) => {
            anomalies.push(ProfileAnomaly::RegistryReadFailure(format!(
                "{value_name}: {error}"
            )));
            String::new()
        }
    }
}

fn optional_string(
    key: &platform_win32::OwnedHKey,
    value_name: &str,
    anomalies: &mut Vec<ProfileAnomaly>,
) -> Option<String> {
    match query_value_string(key, value_name) {
        Ok(value) => Some(value),
        Err(RegistryError::ValueNotFound(_)) => None,
        Err(error) => {
            anomalies.push(ProfileAnomaly::RegistryReadFailure(format!(
                "{value_name}: {error}"
            )));
            None
        }
    }
}

fn optional_u32(
    key: &platform_win32::OwnedHKey,
    value_name: &str,
    anomalies: &mut Vec<ProfileAnomaly>,
) -> u32 {
    match query_value_u32(key, value_name) {
        Ok(value) => value,
        Err(RegistryError::ValueNotFound(_)) => 0,
        Err(error) => {
            anomalies.push(ProfileAnomaly::RegistryReadFailure(format!(
                "{value_name}: {error}"
            )));
            0
        }
    }
}

fn inspect_locks(path: &Path, anomalies: &mut Vec<ProfileAnomaly>) {
    let result = (|| {
        let session = RestartManagerSession::new()?;
        session.register_file(path)?;
        session.get_locking_processes()
    })();
    match result {
        Ok(processes) if !processes.is_empty() => {
            let names = processes
                .iter()
                .map(|process| format!("{} (PID: {})", process.app_name, process.process_id))
                .collect();
            anomalies.push(ProfileAnomaly::LockedNtUserDat(names));
        }
        Ok(_) => {}
        Err(error) => anomalies.push(ProfileAnomaly::LockInspectionFailure(error.to_string())),
    }
}

fn directory_size(root: &Path) -> Result<u64, String> {
    match path_is_reparse_point(root) {
        Ok(false) => {}
        Ok(true) => return Err(format!("reparse point refused: {}", root.display())),
        Err(error) => return Err(format!("{}: {error}", root.display())),
    }
    let mut total = 0u64;
    let entries =
        std::fs::read_dir(root).map_err(|error| format!("{}: {error}", root.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("{}: {error}", root.display()))?;
        let path = entry.path();
        match path_is_reparse_point(&path) {
            Ok(false) => {}
            Ok(true) => return Err(format!("reparse point refused: {}", path.display())),
            Err(error) => return Err(format!("{}: {error}", path.display())),
        }
        let file_type = entry
            .file_type()
            .map_err(|error| format!("{}: {error}", path.display()))?;
        if file_type.is_dir() {
            total = total.saturating_add(directory_size(&path)?);
        } else if file_type.is_file() {
            total = total.saturating_add(
                entry
                    .metadata()
                    .map_err(|error| format!("{}: {error}", path.display()))?
                    .len(),
            );
        } else {
            return Err(format!("unsupported filesystem entry: {}", path.display()));
        }
    }
    Ok(total)
}

fn mark_path_collisions(profiles: &mut [UserProfile]) {
    let mut indexes_by_path: HashMap<String, Vec<usize>> = HashMap::new();
    for (index, profile) in profiles.iter().enumerate() {
        if profile.profile_path.trim().is_empty() {
            continue;
        }
        let normalized = profile
            .profile_path
            .trim_end_matches(['\\', '/'])
            .to_ascii_lowercase();
        indexes_by_path.entry(normalized).or_default().push(index);
    }
    for indexes in indexes_by_path.values().filter(|indexes| indexes.len() > 1) {
        for index in indexes {
            let path = profiles[*index].profile_path.clone();
            profiles[*index]
                .anomalies
                .push(ProfileAnomaly::PathCollision(path));
            profiles[*index].compute_health();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mark_path_collisions;
    use crate::models::{ProfileAnomaly, ProfileHealth, UserProfile};

    fn profile(sid: &str, path: &str) -> UserProfile {
        UserProfile {
            sid: sid.to_string(),
            canonical_sid: sid.to_string(),
            username: sid.to_string(),
            domain: String::new(),
            profile_path: path.to_string(),
            loaded: false,
            is_bak: false,
            state_mask: 0,
            ref_count: 0,
            guid: None,
            ntuser_exists: true,
            usrclass_exists: true,
            disk_size_bytes: 0,
            anomalies: Vec::new(),
            health: ProfileHealth::Healthy,
        }
    }

    #[test]
    fn collision_detection_uses_duplicate_paths_not_temp_substrings() {
        let mut profiles = vec![
            profile("S-1-5-21-1", r"C:\Users\Template"),
            profile("S-1-5-21-2", r"c:\users\duplicate"),
            profile("S-1-5-21-3", r"C:\Users\Duplicate\"),
        ];
        mark_path_collisions(&mut profiles);

        assert!(profiles[0].anomalies.is_empty());
        assert!(profiles[1]
            .anomalies
            .iter()
            .any(|anomaly| matches!(anomaly, ProfileAnomaly::PathCollision(_))));
        assert!(profiles[2]
            .anomalies
            .iter()
            .any(|anomaly| matches!(anomaly, ProfileAnomaly::PathCollision(_))));
    }
}

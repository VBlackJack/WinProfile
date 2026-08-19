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

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use thiserror::Error;
use windows_sys::Win32::System::Registry::{HKEY_LOCAL_MACHINE, KEY_READ};

use platform_win32::{
    open_key, save_key, PrivilegeGuard, RegistryError, SE_BACKUP_NAME,
    SE_RESTORE_NAME,
};

#[derive(Error, Debug)]
pub enum SnapshotError {
    #[error("Snapshot IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Registry error during snapshot: {0}")]
    RegistryError(#[from] RegistryError),
    #[error("Security privilege error: {0}")]
    SecurityError(#[from] platform_win32::SecurityError),
}

pub type SnapshotResult<T> = Result<T, SnapshotError>;

/// Metadata describing a pre-repair transactional snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotMetadata {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub sid: String,
    pub profile_path: String,
    pub registry_key_path: String,
    pub snapshot_file_path: PathBuf,
    pub reason: String,
}

/// Snapshot engine responsible for capturing point-in-time system state.
pub struct SnapshotEngine {
    storage_dir: PathBuf,
}

impl SnapshotEngine {
    /// Initializes snapshot storage in the specified directory or standard %ProgramData%/WinProfile/Snapshots.
    pub fn new(custom_dir: Option<PathBuf>) -> SnapshotResult<Self> {
        let storage_dir = match custom_dir {
            Some(d) => d,
            None => {
                let program_data = std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string());
                PathBuf::from(program_data).join("WinProfile").join("Snapshots")
            }
        };

        if !storage_dir.exists() {
            std::fs::create_dir_all(&storage_dir)?;
        }

        Ok(Self { storage_dir })
    }

    /// Captures a binary export snapshot of a registry key under HKLM.
    pub fn create_registry_snapshot(
        &self,
        subkey: &str,
        sid: &str,
        profile_path: &str,
        reason: &str,
    ) -> SnapshotResult<SnapshotMetadata> {
        let _privs = PrivilegeGuard::new(&[SE_BACKUP_NAME, SE_RESTORE_NAME])?;

        let timestamp = Utc::now();
        let safe_sid = sid.replace('\\', "_").replace(':', "_");
        let filename = format!("snap_{}_{}.hiv", timestamp.format("%Y%m%d_%H%M%S"), safe_sid);
        let snapshot_file_path = self.storage_dir.join(&filename);

        let hkey = open_key(HKEY_LOCAL_MACHINE, subkey, KEY_READ)?;
        save_key(&hkey, &snapshot_file_path)?;

        let meta = SnapshotMetadata {
            id: format!("{}_{}", timestamp.timestamp(), safe_sid),
            timestamp,
            sid: sid.to_string(),
            profile_path: profile_path.to_string(),
            registry_key_path: format!("HKLM\\{}", subkey),
            snapshot_file_path,
            reason: reason.to_string(),
        };

        // Save metadata alongside binary hive
        let meta_file = self.storage_dir.join(format!("{}.json", filename));
        let json = serde_json::to_string_pretty(&meta).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        std::fs::write(meta_file, json)?;

        Ok(meta)
    }

    /// Lists all existing snapshot metadata stored on the system.
    pub fn list_snapshots(&self) -> SnapshotResult<Vec<SnapshotMetadata>> {
        let mut results = Vec::new();
        if !self.storage_dir.exists() {
            return Ok(results);
        }

        for entry in std::fs::read_dir(&self.storage_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if let Ok(meta) = serde_json::from_str::<SnapshotMetadata>(&content) {
                        results.push(meta);
                    }
                }
            }
        }

        results.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        Ok(results)
    }
}

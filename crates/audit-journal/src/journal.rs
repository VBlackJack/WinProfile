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
use std::collections::VecDeque;
use std::ffi::OsStr;
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use thiserror::Error;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
};

use crate::storage::{StorageError, StorageLock, StorageRoot};

const DEFAULT_MAX_LOG_BYTES: u64 = 10 * 1024 * 1024;
const DEFAULT_MAX_ARCHIVES: usize = 5;
const AUDIT_FILE: &str = "audit_log.jsonl";
const EXPORT_DIR: &str = "Exports";

#[derive(Error, Debug)]
pub enum AuditError {
    #[error("Audit IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Audit serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Audit memory buffer is poisoned")]
    BufferPoisoned,
    #[error("Audit log contains an invalid entry at line {line}: {reason}")]
    InvalidEntry { line: usize, reason: String },
    #[error("Invalid audit configuration: {0}")]
    InvalidConfiguration(String),
    #[error("Audit entry is {actual} bytes, exceeding the {maximum}-byte file limit")]
    EntryTooLarge { actual: u64, maximum: u64 },
    #[error("Protected storage error: {0}")]
    Storage(#[from] StorageError),
}

pub type AuditResult<T> = Result<T, AuditError>;

/// Exclusive kernel-backed guard for one destructive WinProfile transaction.
///
/// It is deliberately independent from the journal's internal storage lock,
/// so terminal audit writes remain possible while this guard is held.
#[derive(Debug)]
pub struct OperationGuard {
    _lock: StorageLock,
}

/// Status of an audited administrative operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditStatus {
    Success,
    Warning,
    Failed,
    RolledBack,
}

/// A structured immutable audit event entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: DateTime<Utc>,
    pub operation: String,
    pub actor: String,
    pub target: String,
    pub status: AuditStatus,
    pub details: String,
}

/// Thread-safe, bounded JSON-lines audit logger.
#[derive(Clone)]
pub struct AuditLogger {
    storage: Arc<StorageRoot>,
    log_file_name: String,
    log_file_path: PathBuf,
    memory_buffer: Arc<Mutex<VecDeque<AuditEntry>>>,
    max_memory_entries: usize,
    max_log_bytes: u64,
    max_archives: usize,
}

impl AuditLogger {
    /// Initializes the logger with bounded production defaults.
    pub fn new(custom_path: Option<PathBuf>, max_memory: usize) -> AuditResult<Self> {
        Self::with_limits(
            custom_path,
            max_memory,
            DEFAULT_MAX_LOG_BYTES,
            DEFAULT_MAX_ARCHIVES,
        )
    }

    /// Initializes the logger with explicit limits for tests and controlled deployments.
    pub fn with_limits(
        custom_path: Option<PathBuf>,
        max_memory: usize,
        max_log_bytes: u64,
        max_archives: usize,
    ) -> AuditResult<Self> {
        if max_log_bytes == 0 {
            return Err(AuditError::InvalidConfiguration(
                "maximum log size must be greater than zero".to_string(),
            ));
        }
        if max_archives == 0 {
            return Err(AuditError::InvalidConfiguration(
                "at least one archive must be retained".to_string(),
            ));
        }
        let (storage, log_file_name) = match custom_path {
            Some(path) => {
                let parent = path.parent().ok_or_else(|| {
                    AuditError::InvalidConfiguration(
                        "custom audit path must have an absolute parent".to_string(),
                    )
                })?;
                let file_name = path.file_name().and_then(OsStr::to_str).ok_or_else(|| {
                    AuditError::InvalidConfiguration(
                        "custom audit path must have a Unicode file name".to_string(),
                    )
                })?;
                (StorageRoot::trusted(parent)?, file_name.to_string())
            }
            None => (StorageRoot::production()?, AUDIT_FILE.to_string()),
        };
        let log_file_path = storage.child_path(&log_file_name)?;
        let _storage_lock = storage.acquire_lock()?;
        let entries = load_recent_entries(&storage, &log_file_name, max_memory)?;
        Ok(Self {
            storage,
            log_file_name,
            log_file_path,
            memory_buffer: Arc::new(Mutex::new(entries)),
            max_memory_entries: max_memory,
            max_log_bytes,
            max_archives,
        })
    }

    /// Writes a durable event before adding it to the bounded display buffer.
    pub fn log(
        &self,
        operation: impl Into<String>,
        actor: impl Into<String>,
        target: impl Into<String>,
        status: AuditStatus,
        details: impl Into<String>,
    ) -> AuditResult<()> {
        let entry = AuditEntry {
            timestamp: Utc::now(),
            operation: operation.into(),
            actor: actor.into(),
            target: target.into(),
            status,
            details: details.into(),
        };
        let json_line = serde_json::to_string(&entry)?;
        let entry_bytes = json_line.len() as u64 + 1;
        if entry_bytes > self.max_log_bytes {
            return Err(AuditError::EntryTooLarge {
                actual: entry_bytes,
                maximum: self.max_log_bytes,
            });
        }
        let _storage_lock = self.storage.acquire_lock()?;
        // Acquire every fallible in-process guard before the durable append. Once
        // sync_data succeeds, only infallible buffer updates remain and Ok is guaranteed.
        let mut buffer = self
            .memory_buffer
            .lock()
            .map_err(|_| AuditError::BufferPoisoned)?;
        self.rotate_if_needed(entry_bytes)?;

        let mut file = self.open_log_for_append()?;
        file.seek(SeekFrom::End(0))?;
        writeln!(file, "{json_line}")?;
        file.flush()?;
        file.sync_data()?;

        if self.max_memory_entries > 0 && buffer.len() >= self.max_memory_entries {
            buffer.pop_front();
        }
        if self.max_memory_entries > 0 {
            buffer.push_back(entry);
        }
        Ok(())
    }

    /// Acquires the cross-process lock for one destructive operation.
    pub fn acquire_operation_guard(&self) -> AuditResult<OperationGuard> {
        Ok(OperationGuard {
            _lock: self.storage.acquire_operation_lock()?,
        })
    }

    #[cfg(test)]
    fn acquire_operation_guard_with_timeout(
        &self,
        timeout: std::time::Duration,
    ) -> AuditResult<OperationGuard> {
        Ok(OperationGuard {
            _lock: self.storage.acquire_operation_lock_with_timeout(timeout)?,
        })
    }

    /// Returns recent entries ordered newest first.
    pub fn get_entries(&self) -> AuditResult<Vec<AuditEntry>> {
        let buffer = self
            .memory_buffer
            .lock()
            .map_err(|_| AuditError::BufferPoisoned)?;
        Ok(buffer.iter().cloned().rev().collect())
    }

    /// Clears only the in-memory display buffer; durable history remains intact.
    pub fn clear_memory(&self) -> AuditResult<()> {
        self.memory_buffer
            .lock()
            .map_err(|_| AuditError::BufferPoisoned)?
            .clear();
        Ok(())
    }

    /// Creates a verified, non-overwriting export beside the protected audit directory.
    pub fn export_copy(&self) -> AuditResult<PathBuf> {
        let _storage_lock = self.storage.acquire_lock()?;
        let export_dir = self.storage.open_or_create_directory(EXPORT_DIR)?;
        let timestamp = Utc::now().format("%Y%m%dT%H%M%S%.6fZ");
        let export_name = format!("audit-{timestamp}.jsonl");
        let export_path = export_dir.path().join(&export_name);

        let mut source =
            self.storage
                .open_file(&self.log_file_name, FILE_GENERIC_READ, FILE_SHARE_READ)?;
        let mut target = export_dir.create_file(OsStr::new(&export_name), FILE_SHARE_READ)?;
        std::io::copy(&mut source, target.file_mut())?;
        target.file_mut().flush()?;
        target.file_mut().sync_all()?;

        if source.metadata()?.len() != target.file_mut().metadata()?.len() {
            return Err(AuditError::Io(std::io::Error::other(
                "audit export size verification failed",
            )));
        }
        target.commit();
        Ok(export_path)
    }

    /// Returns the durable audit path for diagnostics and documentation.
    pub fn log_file_path(&self) -> &Path {
        &self.log_file_path
    }

    fn rotate_if_needed(&self, additional_bytes: u64) -> AuditResult<()> {
        let current_bytes = match self.storage.open_file(
            &self.log_file_name,
            FILE_GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        ) {
            Ok(file) => file.metadata()?.len(),
            Err(error) if error.is_not_found() => 0,
            Err(error) => return Err(error.into()),
        };
        if current_bytes.saturating_add(additional_bytes) <= self.max_log_bytes {
            return Ok(());
        }

        for index in (1..=self.max_archives).rev() {
            let current_name = archive_name(&self.log_file_name, index);
            if index == self.max_archives {
                if self.validate_optional_file(&current_name)? {
                    self.storage.remove_file_if_exists(&current_name)?;
                }
            } else if self.validate_optional_file(&current_name)? {
                self.storage
                    .durable_rename(&current_name, &archive_name(&self.log_file_name, index + 1))?;
            }
        }
        if self.validate_optional_file(&self.log_file_name)? {
            self.storage
                .durable_rename(&self.log_file_name, &archive_name(&self.log_file_name, 1))?;
        }
        Ok(())
    }

    fn validate_optional_file(&self, name: &str) -> AuditResult<bool> {
        match self.storage.open_file(
            name,
            FILE_GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        ) {
            Ok(_) => Ok(true),
            Err(error) if error.is_not_found() => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    fn open_log_for_append(&self) -> AuditResult<File> {
        match self
            .storage
            .create_file(&self.log_file_name, FILE_SHARE_READ)
        {
            Ok(created) => Ok(created.commit()),
            Err(error) if error.is_collision() => Ok(self.storage.open_file(
                &self.log_file_name,
                FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                FILE_SHARE_READ,
            )?),
            Err(error) => Err(error.into()),
        }
    }
}

fn archive_name(file_name: &str, index: usize) -> String {
    format!("{file_name}.{index}")
}

fn load_recent_entries(
    storage: &StorageRoot,
    file_name: &str,
    max_memory: usize,
) -> AuditResult<VecDeque<AuditEntry>> {
    let file = match storage.open_file(
        file_name,
        FILE_GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    ) {
        Ok(file) => file,
        Err(error) if error.is_not_found() => return Ok(VecDeque::new()),
        Err(error) => return Err(error.into()),
    };
    let mut entries = VecDeque::with_capacity(max_memory);
    for (line_index, line_result) in BufReader::new(file).lines().enumerate() {
        let line = line_result?;
        if line.trim().is_empty() {
            continue;
        }
        let entry = serde_json::from_str::<AuditEntry>(&line).map_err(|error| {
            AuditError::InvalidEntry {
                line: line_index + 1,
                reason: error.to_string(),
            }
        })?;
        if max_memory > 0 && entries.len() >= max_memory {
            entries.pop_front();
        }
        if max_memory > 0 {
            entries.push_back(entry);
        }
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let suffix = NEXT_TEMP_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "winprofile-audit-poison-{}-{suffix}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).expect("create test directory");
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn poisoned_display_buffer_prevents_durable_append() {
        let test_directory = TestDirectory::new();
        let log_path = test_directory.0.join("audit.jsonl");
        let logger =
            AuditLogger::with_limits(Some(log_path.clone()), 10, 4096, 1).expect("create logger");
        let buffer = Arc::clone(&logger.memory_buffer);
        let poison_result = std::panic::catch_unwind(move || {
            let _guard = buffer.lock().expect("acquire buffer lock");
            panic!("poison buffer for test");
        });
        assert!(poison_result.is_err());

        let result = logger.log(
            "test",
            "tester",
            "audit",
            AuditStatus::Success,
            "must not be appended",
        );

        assert!(matches!(result, Err(AuditError::BufferPoisoned)));
        assert!(
            !log_path.exists(),
            "an error result must not conceal a durable append"
        );
    }

    #[test]
    fn separate_logger_instances_never_interleave_json_lines() {
        let test_directory = TestDirectory::new();
        let log_path = test_directory.0.join("audit.jsonl");
        let first =
            AuditLogger::with_limits(Some(log_path.clone()), 0, 4096, 16).expect("first logger");
        let second =
            AuditLogger::with_limits(Some(log_path.clone()), 0, 4096, 16).expect("second logger");
        let first_thread = std::thread::spawn(move || {
            for index in 0..100 {
                first
                    .log(
                        "concurrent",
                        "first",
                        index.to_string(),
                        AuditStatus::Success,
                        "durable line",
                    )
                    .expect("first append");
            }
        });
        let second_thread = std::thread::spawn(move || {
            for index in 0..100 {
                second
                    .log(
                        "concurrent",
                        "second",
                        index.to_string(),
                        AuditStatus::Success,
                        "durable line",
                    )
                    .expect("second append");
            }
        });
        first_thread.join().expect("first thread");
        second_thread.join().expect("second thread");

        let mut parsed = Vec::new();
        for path in std::iter::once(log_path.clone()).chain(
            (1..=16).map(|index| log_path.with_file_name(archive_name("audit.jsonl", index))),
        ) {
            let Ok(lines) = std::fs::read_to_string(path) else {
                continue;
            };
            parsed.extend(
                lines.lines().map(|line| {
                    serde_json::from_str::<AuditEntry>(line).expect("complete JSON line")
                }),
            );
        }
        assert_eq!(parsed.len(), 200);
    }

    #[test]
    fn operation_lock_is_exclusive_released_on_drop_and_does_not_deadlock_audit() {
        let test_directory = TestDirectory::new();
        let log_path = test_directory.0.join("audit.jsonl");
        let first = AuditLogger::new(Some(log_path.clone()), 10).expect("first logger");
        let second = AuditLogger::new(Some(log_path), 10).expect("second logger");

        let held = first
            .acquire_operation_guard()
            .expect("first operation guard");
        assert!(matches!(
            second.acquire_operation_guard_with_timeout(std::time::Duration::from_millis(30)),
            Err(AuditError::Storage(StorageError::LockTimeout(_)))
        ));

        first
            .log(
                "OperationTerminal",
                "test",
                "guard",
                AuditStatus::Success,
                "journal storage lock remains independent",
            )
            .expect("terminal audit while operation guard is held");
        first
            .export_copy()
            .expect("export must not take the destructive operation lock");

        drop(held);
        second
            .acquire_operation_guard_with_timeout(std::time::Duration::from_millis(30))
            .expect("operation guard after release");
    }
}

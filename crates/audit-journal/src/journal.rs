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
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use thiserror::Error;

const DEFAULT_MAX_LOG_BYTES: u64 = 10 * 1024 * 1024;
const DEFAULT_MAX_ARCHIVES: usize = 5;
const PROGRAM_DATA_ENV: &str = "ProgramData";
const PROGRAM_DATA_FALLBACK: &str = r"C:\ProgramData";
const PRODUCT_DIR: &str = "WinProfile";
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
    #[error("Audit file lock is poisoned")]
    FileLockPoisoned,
    #[error("Audit log contains an invalid entry at line {line}: {reason}")]
    InvalidEntry { line: usize, reason: String },
    #[error("Invalid audit configuration: {0}")]
    InvalidConfiguration(String),
    #[error("Audit entry is {actual} bytes, exceeding the {maximum}-byte file limit")]
    EntryTooLarge { actual: u64, maximum: u64 },
}

pub type AuditResult<T> = Result<T, AuditError>;

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
    log_file_path: PathBuf,
    memory_buffer: Arc<Mutex<VecDeque<AuditEntry>>>,
    file_lock: Arc<Mutex<()>>,
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
        let log_file_path = custom_path.unwrap_or_else(default_log_path);
        if let Some(parent) = log_file_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let entries = load_recent_entries(&log_file_path, max_memory)?;
        Ok(Self {
            log_file_path,
            memory_buffer: Arc::new(Mutex::new(entries)),
            file_lock: Arc::new(Mutex::new(())),
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
        let _file_guard = self
            .file_lock
            .lock()
            .map_err(|_| AuditError::FileLockPoisoned)?;
        // Acquire every fallible in-process guard before the durable append. Once
        // sync_data succeeds, only infallible buffer updates remain and Ok is guaranteed.
        let mut buffer = self
            .memory_buffer
            .lock()
            .map_err(|_| AuditError::BufferPoisoned)?;
        self.rotate_if_needed(entry_bytes)?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_file_path)?;
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
        let _file_guard = self
            .file_lock
            .lock()
            .map_err(|_| AuditError::FileLockPoisoned)?;
        let parent = self
            .log_file_path
            .parent()
            .unwrap_or_else(|| Path::new("."));
        let export_dir = parent.join(EXPORT_DIR);
        std::fs::create_dir_all(&export_dir)?;
        let timestamp = Utc::now().format("%Y%m%dT%H%M%S%.6fZ");
        let export_path = export_dir.join(format!("audit-{timestamp}.jsonl"));

        let mut source = File::open(&self.log_file_path)?;
        let mut target = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&export_path)?;
        std::io::copy(&mut source, &mut target)?;
        target.flush()?;
        target.sync_all()?;

        if std::fs::metadata(&self.log_file_path)?.len() != std::fs::metadata(&export_path)?.len() {
            return Err(AuditError::Io(std::io::Error::other(
                "audit export size verification failed",
            )));
        }
        Ok(export_path)
    }

    /// Returns the durable audit path for diagnostics and documentation.
    pub fn log_file_path(&self) -> &Path {
        &self.log_file_path
    }

    fn rotate_if_needed(&self, additional_bytes: u64) -> AuditResult<()> {
        let current_bytes = match std::fs::metadata(&self.log_file_path) {
            Ok(metadata) => metadata.len(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
            Err(error) => return Err(error.into()),
        };
        if current_bytes.saturating_add(additional_bytes) <= self.max_log_bytes {
            return Ok(());
        }

        for index in (1..=self.max_archives).rev() {
            let current = archive_path(&self.log_file_path, index);
            if index == self.max_archives {
                if current.exists() {
                    std::fs::remove_file(&current)?;
                }
            } else if current.exists() {
                std::fs::rename(&current, archive_path(&self.log_file_path, index + 1))?;
            }
        }
        if self.log_file_path.exists() {
            std::fs::rename(&self.log_file_path, archive_path(&self.log_file_path, 1))?;
        }
        Ok(())
    }
}

fn default_log_path() -> PathBuf {
    let program_data =
        std::env::var(PROGRAM_DATA_ENV).unwrap_or_else(|_| PROGRAM_DATA_FALLBACK.to_string());
    PathBuf::from(program_data)
        .join(PRODUCT_DIR)
        .join(AUDIT_FILE)
}

fn archive_path(log_path: &Path, index: usize) -> PathBuf {
    let file_name = log_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(AUDIT_FILE);
    log_path.with_file_name(format!("{file_name}.{index}"))
}

fn load_recent_entries(path: &Path, max_memory: usize) -> AuditResult<VecDeque<AuditEntry>> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(VecDeque::new()),
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
}

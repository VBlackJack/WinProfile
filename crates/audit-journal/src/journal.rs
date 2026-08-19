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
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

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

/// Thread-safe audit logger writing JSON lines to disk while holding recent entries in RAM.
#[derive(Clone)]
pub struct AuditLogger {
    log_file_path: PathBuf,
    memory_buffer: Arc<Mutex<VecDeque<AuditEntry>>>,
    max_memory_entries: usize,
}

impl AuditLogger {
    /// Initializes the audit logger.
    pub fn new(custom_path: Option<PathBuf>, max_memory: usize) -> std::io::Result<Self> {
        let log_file_path = match custom_path {
            Some(p) => p,
            None => {
                let program_data = std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string());
                let dir = PathBuf::from(program_data).join("WinProfile");
                if !dir.exists() {
                    std::fs::create_dir_all(&dir)?;
                }
                dir.join("audit_log.jsonl")
            }
        };

        let mut entries = VecDeque::new();
        // Load recent entries if log file exists
        if log_file_path.exists() {
            if let Ok(content) = std::fs::read_to_string(&log_file_path) {
                for line in content.lines().rev().take(max_memory) {
                    if let Ok(entry) = serde_json::from_str::<AuditEntry>(line) {
                        entries.push_front(entry);
                    }
                }
            }
        }

        Ok(Self {
            log_file_path,
            memory_buffer: Arc::new(Mutex::new(entries)),
            max_memory_entries: max_memory,
        })
    }

    /// Logs an event to disk and appends to in-memory history.
    pub fn log(
        &self,
        operation: impl Into<String>,
        actor: impl Into<String>,
        target: impl Into<String>,
        status: AuditStatus,
        details: impl Into<String>,
    ) {
        let entry = AuditEntry {
            timestamp: Utc::now(),
            operation: operation.into(),
            actor: actor.into(),
            target: target.into(),
            status,
            details: details.into(),
        };

        // Write to file (append)
        if let Ok(json_line) = serde_json::to_string(&entry) {
            if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&self.log_file_path) {
                let _ = writeln!(file, "{}", json_line);
            }
        }

        // Add to in-memory buffer
        if let Ok(mut buf) = self.memory_buffer.lock() {
            if buf.len() >= self.max_memory_entries {
                buf.pop_front();
            }
            buf.push_back(entry);
        }
    }

    /// Returns a copy of current in-memory audit entries (ordered latest first).
    pub fn get_entries(&self) -> Vec<AuditEntry> {
        if let Ok(buf) = self.memory_buffer.lock() {
            buf.iter().cloned().rev().collect()
        } else {
            Vec::new()
        }
    }

    /// Clears the in-memory display buffer.
    pub fn clear_memory(&self) {
        if let Ok(mut buf) = self.memory_buffer.lock() {
            buf.clear();
        }
    }
}

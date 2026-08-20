/*
 * Copyright 2026 Julien Bombled
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

//! Startup boundary between untrusted legacy storage and product services.

use std::sync::Arc;

use audit_journal::{
    inspect_production_storage, AuditLogger, AuditStatus, LegacyStorageError,
    LegacyStorageRecovery, ProductionStorage, ProductionStorageState, SnapshotEngine,
};
use thiserror::Error;

use crate::AppController;

#[derive(Error, Debug)]
pub enum StartupError {
    #[error("legacy storage recovery failed: {0}")]
    Legacy(#[from] LegacyStorageError),
    #[error("audit service initialization failed: {0}")]
    Audit(#[from] audit_journal::AuditError),
    #[error("snapshot service initialization failed: {0}")]
    Snapshot(#[from] audit_journal::SnapshotError),
}

pub enum StartupDecision {
    Ready(Arc<AppController>),
    Recovery(LegacyStorageRecovery),
}

/// A resumed, already durable migration must not ask the operator to consent
/// again. A newly detected legacy root always requires a fresh affirmative
/// control before any namespace mutation.
pub fn requires_fresh_consent(is_resume: bool) -> bool {
    !is_resume
}

pub fn inspect() -> Result<StartupDecision, StartupError> {
    match inspect_production_storage()? {
        ProductionStorageState::Ready(storage) => {
            Ok(StartupDecision::Ready(build_controller(&storage)?))
        }
        ProductionStorageState::NeedsConsent(recovery)
        | ProductionStorageState::NeedsResume(recovery) => Ok(StartupDecision::Recovery(recovery)),
    }
}

pub fn complete_recovery(
    recovery: LegacyStorageRecovery,
) -> Result<Arc<AppController>, StartupError> {
    let pending = recovery.execute()?;
    let logger = Arc::new(AuditLogger::from_storage(pending.storage(), 500)?);
    let snapshots = Arc::new(SnapshotEngine::from_storage(pending.storage())?);
    logger.log(
        pending.audit_operation(),
        pending.audit_actor(),
        pending.legacy_name(),
        AuditStatus::Warning,
        pending.audit_details(),
    )?;
    let storage = pending.complete()?;
    debug_assert!(logger
        .log_file_path()
        .parent()
        .is_some_and(|parent| parent == storage.root_path()));
    Ok(Arc::new(AppController::new(snapshots, logger)))
}

fn build_controller(storage: &ProductionStorage) -> Result<Arc<AppController>, StartupError> {
    let logger = Arc::new(AuditLogger::from_storage(storage, 500)?);
    let snapshots = Arc::new(SnapshotEngine::from_storage(storage)?);
    Ok(Arc::new(AppController::new(snapshots, logger)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_error_text_keeps_storage_context() {
        let error = StartupError::Legacy(LegacyStorageError::IdentityChanged);
        assert!(error.to_string().contains("identity changed"));
    }

    #[test]
    fn only_a_fresh_legacy_transition_requires_consent() {
        assert!(requires_fresh_consent(false));
        assert!(!requires_fresh_consent(true));
    }
}

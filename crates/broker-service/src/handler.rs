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
use audit_journal::{AuditLogger, AuditStatus, SnapshotEngine};
use broker_protocol::{
    BrokerRequest, BrokerResponse, LockingProcessDto, UserProfileDto,
};
use core_profiles::{
    ProfileRepairEngine, ProfileScanner, RepairPlan,
};
use platform_win32::{
    duplicate_trustedinstaller_token, launch_process_with_token,
    reset_tree_security_safe, RestartManagerSession,
};

/// Dispatches a typed broker request and returns a typed response.
pub fn handle_broker_request(
    request: BrokerRequest,
    snapshot_engine: &SnapshotEngine,
    audit_logger: &AuditLogger,
) -> BrokerResponse {
    match request {
        BrokerRequest::Ping => BrokerResponse::Pong,

        BrokerRequest::InspectProfiles => match ProfileScanner::scan_all() {
            Ok(report) => {
                let dtos = report
                    .profiles
                    .into_iter()
                    .map(|p| UserProfileDto {
                        sid: p.sid,
                        username: p.username,
                        domain: p.domain,
                        profile_path: p.profile_path,
                        loaded: p.loaded,
                        is_bak: p.is_bak,
                        state_mask: p.state_mask,
                        ref_count: p.ref_count,
                        ntuser_exists: p.ntuser_exists,
                        usrclass_exists: p.usrclass_exists,
                        anomalies: p
                            .anomalies
                            .into_iter()
                            .map(|a| a.localized_description())
                            .collect(),
                    })
                    .collect();
                BrokerResponse::Profiles(dtos)
            }
            Err(e) => BrokerResponse::Error {
                code: 1,
                message: e.to_string(),
            },
        },

        BrokerRequest::RepairBakProfile { sid } => {
            let repair_engine = ProfileRepairEngine::new(snapshot_engine, audit_logger);
            let canonical_sid = sid.trim_end_matches(".bak").to_string();

            let plan = RepairPlan {
                sid: sid.clone(),
                canonical_sid,
                profile_path: String::new(),
                fix_bak: true,
                reset_state: true,
                fix_acls: true,
                unlock_hive: true,
                dry_run: false,
            };

            match repair_engine.execute_plan(&plan, false) {
                Ok(()) => BrokerResponse::Success {
                    message: format!("Profile {sid} successfully repaired."),
                },
                Err(e) => BrokerResponse::Error {
                    code: 2,
                    message: e.to_string(),
                },
            }
        }

        BrokerRequest::ResetProfileState { sid } => {
            let repair_engine = ProfileRepairEngine::new(snapshot_engine, audit_logger);
            let plan = RepairPlan {
                sid: sid.clone(),
                canonical_sid: sid.clone(),
                profile_path: String::new(),
                fix_bak: false,
                reset_state: true,
                fix_acls: false,
                unlock_hive: false,
                dry_run: false,
            };

            match repair_engine.execute_plan(&plan, false) {
                Ok(()) => BrokerResponse::Success {
                    message: format!("State and RefCount reset for {sid}."),
                },
                Err(e) => BrokerResponse::Error {
                    code: 3,
                    message: e.to_string(),
                },
            }
        }

        BrokerRequest::ResetAclTree { path, owner_sid } => {
            match reset_tree_security_safe(Path::new(&path), &owner_sid) {
                Ok(()) => {
                    audit_logger.log(
                        "ResetAclTree",
                        "WinProfile-Broker",
                        &path,
                        AuditStatus::Success,
                        format!("NTFS Ownership & DACL restored for {owner_sid}"),
                    );
                    BrokerResponse::Success {
                        message: format!("ACL tree successfully reset for {path}"),
                    }
                }
                Err(e) => BrokerResponse::Error {
                    code: 4,
                    message: e.to_string(),
                },
            }
        }

        BrokerRequest::UnlockHiveProcesses { hive_path, force } => {
            let path_obj = Path::new(&hive_path);
            match RestartManagerSession::new() {
                Ok(rm) => {
                    let _ = rm.register_file(path_obj);
                    let procs = rm.get_locking_processes().unwrap_or_default();
                    let dtos = procs
                        .iter()
                        .map(|p| LockingProcessDto {
                            pid: p.process_id,
                            app_name: p.app_name.clone(),
                            service_name: p.service_short_name.clone(),
                        })
                        .collect();

                    if force {
                        let _ = rm.shutdown_locking_processes(true);
                    }

                    BrokerResponse::LockingProcesses(dtos)
                }
                Err(e) => BrokerResponse::Error {
                    code: 5,
                    message: e.to_string(),
                },
            }
        }

        BrokerRequest::LaunchTrustedInstallerProcess {
            command_line,
            target_session_id,
        } => {
            match duplicate_trustedinstaller_token(target_session_id) {
                Ok(token) => {
                    match launch_process_with_token(&token, &command_line, None) {
                        Ok(pid) => {
                            audit_logger.log(
                                "LaunchTrustedInstallerProcess",
                                "WinProfile-Broker",
                                &command_line,
                                AuditStatus::Success,
                                format!("Spawned PID {pid} in interactive session {target_session_id}"),
                            );
                            BrokerResponse::ProcessLaunched { pid }
                        }
                        Err(e) => BrokerResponse::Error {
                            code: 6,
                            message: format!("Failed to spawn process: {e}"),
                        },
                    }
                }
                Err(e) => BrokerResponse::Error {
                    code: 7,
                    message: format!("Token duplication failed: {e}"),
                },
            }
        }
    }
}

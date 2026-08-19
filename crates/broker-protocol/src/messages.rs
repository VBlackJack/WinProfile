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

use serde::{Deserialize, Serialize};

/// Lightweight DTO representing a discovered Windows user profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfileDto {
    pub sid: String,
    pub username: String,
    pub domain: String,
    pub profile_path: String,
    pub loaded: bool,
    pub is_bak: bool,
    pub state_mask: u32,
    pub ref_count: u32,
    pub ntuser_exists: bool,
    pub usrclass_exists: bool,
    pub anomalies: Vec<String>,
}

/// DTO for a process holding a file lock.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockingProcessDto {
    pub pid: u32,
    pub app_name: String,
    pub service_name: String,
}

/// Typed requests supported by the privileged Broker Service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BrokerRequest {
    Ping,
    InspectProfiles,
    RepairBakProfile {
        sid: String,
    },
    ResetProfileState {
        sid: String,
    },
    ResetAclTree {
        path: String,
        owner_sid: String,
    },
    UnlockHiveProcesses {
        hive_path: String,
        force: bool,
    },
    LaunchTrustedInstallerProcess {
        command_line: String,
        target_session_id: u32,
    },
}

/// Typed responses sent back by the Broker Service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BrokerResponse {
    Pong,
    Success { message: String },
    Error { code: u32, message: String },
    Profiles(Vec<UserProfileDto>),
    LockingProcesses(Vec<LockingProcessDto>),
    ProcessLaunched { pid: u32 },
}

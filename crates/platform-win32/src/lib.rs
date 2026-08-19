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

pub mod handles;
pub mod registry;
pub mod restart_manager;
pub mod secure_fs;
pub mod security;
pub mod tokens;

pub use handles::{OwnedEnvironmentBlock, OwnedHandle, OwnedScHandle};
pub use registry::{
    create_key, delete_tree, delete_value, enum_subkeys, from_wide_null, load_hive, open_key,
    open_subkey, query_value_string, query_value_u32, rename_subkey, save_key, set_value_string,
    set_value_u32, subkey_exists, to_wide_null, unload_hive, OwnedHKey, RegResult, RegistryError,
    RegistryRoot,
};
pub use restart_manager::{
    LockingProcessInfo, RestartManagerError, RestartManagerSession, RmResult, RM_FORCE_SHUTDOWN,
    RM_NORMAL_SHUTDOWN,
};
pub use secure_fs::{
    SecureCreatedEntry, SecureDirEntry, SecureDirectory, SecureEntryKind, SecureFsError,
    SecureFsResult,
};
pub use security::{
    is_process_elevated, lookup_account_by_sid_string, path_is_reparse_point, PrivilegeGuard,
    SecResult, SecurityError, SE_BACKUP_NAME, SE_DEBUG_NAME, SE_IMPERSONATE_NAME, SE_RESTORE_NAME,
    SE_TAKE_OWNERSHIP_NAME, SE_TCB_NAME,
};
pub use tokens::{
    duplicate_trustedinstaller_token, ensure_trustedinstaller_service_running,
    find_process_id_by_name, get_active_console_session, launch_process_with_token, TokenError,
    TokenResult, MAXIMUM_ALLOWED,
};

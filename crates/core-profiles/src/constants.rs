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

/// Registry key containing all user profile configurations.
pub const REG_KEY_PROFILE_LIST: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";

/// Profile registry value names.
pub const VAL_PROFILE_IMAGE_PATH: &str = "ProfileImagePath";
pub const VAL_STATE: &str = "State";
pub const VAL_REF_COUNT: &str = "RefCount";
pub const VAL_GUID: &str = "Guid";
pub const VAL_FLAGS: &str = "Flags";

/// State bitmask constants defined by Windows User Profile Service.
pub const STATE_MANDATORY: u32 = 0x0001;
pub const STATE_READONLY: u32 = 0x0002;
pub const STATE_LOCAL_ONLY: u32 = 0x0004;
pub const STATE_DELETE_ROAMING: u32 = 0x0008;
pub const STATE_TEMP_PROFILE: u32 = 0x0080;
pub const STATE_GUEST_USER: u32 = 0x0800;

/// Standard file names and extensions.
pub const BAK_EXTENSION: &str = ".bak";
pub const NTUSER_DAT: &str = "NTUSER.DAT";
pub const USRCLASS_DAT_REL_PATH: &str = r"AppData\Local\Microsoft\Windows\UsrClass.dat";
pub const APPDATA_ROAMING_REL_PATH: &str = r"AppData\Roaming";
pub const APPDATA_LOCAL_REL_PATH: &str = r"AppData\Local";

/// Well-known system SIDs to ignore or categorize.
pub const SYSTEM_SID_PREFIXES: &[&str] = &[
    "S-1-5-18", // LocalSystem
    "S-1-5-19", // LocalService
    "S-1-5-20", // NetworkService
];

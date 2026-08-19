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

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use thiserror::Error;
use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegDeleteValueW, RegEnumKeyExW, RegLoadKeyW,
    RegOpenKeyExW, RegQueryValueExW, RegRenameKey, RegSaveKeyExW, RegSetValueExW, RegUnLoadKeyW,
    HKEY, HKEY_CLASSES_ROOT, HKEY_CURRENT_CONFIG, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE,
    HKEY_USERS, REG_DWORD, REG_EXPAND_SZ, REG_NO_COMPRESSION, REG_OPTION_NON_VOLATILE, REG_SZ,
    REG_VALUE_TYPE,
};

#[derive(Error, Debug)]
pub enum RegistryError {
    #[error("Registry operation failed with Win32 error code: {0}")]
    Win32Error(u32),
    #[error("Registry value '{0}' not found")]
    ValueNotFound(String),
    #[error("Registry value '{value}' has type {actual}, expected {expected}")]
    UnexpectedValueType {
        value: String,
        expected: u32,
        actual: u32,
    },
    #[error("Invalid UTF-16 registry data")]
    InvalidUtf16,
    #[error("Registry key path cannot be converted to wide string")]
    InvalidPath,
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

pub type RegResult<T> = Result<T, RegistryError>;

/// Safe selector for the predefined Windows Registry roots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryRoot {
    LocalMachine,
    CurrentUser,
    Users,
    ClassesRoot,
    CurrentConfig,
}

impl RegistryRoot {
    fn as_raw(self) -> HKEY {
        match self {
            Self::LocalMachine => HKEY_LOCAL_MACHINE,
            Self::CurrentUser => HKEY_CURRENT_USER,
            Self::Users => HKEY_USERS,
            Self::ClassesRoot => HKEY_CLASSES_ROOT,
            Self::CurrentConfig => HKEY_CURRENT_CONFIG,
        }
    }
}

/// RAII wrapper around a Windows Registry HKEY handle.
#[derive(Debug)]
pub struct OwnedHKey {
    hkey: HKEY,
}

impl OwnedHKey {
    /// Creates an `OwnedHKey` from a raw HKEY.
    pub fn from_raw(raw: HKEY) -> Option<Self> {
        if raw.is_null() {
            None
        } else {
            Some(Self { hkey: raw })
        }
    }

    /// Returns the underlying raw HKEY.
    pub fn as_raw(&self) -> HKEY {
        self.hkey
    }
}

impl Drop for OwnedHKey {
    fn drop(&mut self) {
        if !self.hkey.is_null()
            && self.hkey != HKEY_LOCAL_MACHINE
            && self.hkey != HKEY_CURRENT_USER
            && self.hkey != HKEY_USERS
            && self.hkey != HKEY_CLASSES_ROOT
            && self.hkey != HKEY_CURRENT_CONFIG
        {
            unsafe {
                RegCloseKey(self.hkey);
            }
        }
    }
}

/// Encodes a string into a null-terminated UTF-16 wide vector.
pub fn to_wide_null(s: impl AsRef<OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(std::iter::once(0)).collect()
}

/// Decodes a null-terminated UTF-16 slice into a standard Rust String.
pub fn from_wide_null(slice: &[u16]) -> Result<String, RegistryError> {
    let len = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
    String::from_utf16(&slice[..len]).map_err(|_| RegistryError::InvalidUtf16)
}

/// Opens an existing registry key with the requested SAM access mask.
pub fn open_key(root: RegistryRoot, subkey: &str, sam_desired: u32) -> RegResult<OwnedHKey> {
    open_key_raw(root.as_raw(), subkey, sam_desired)
}

/// Opens a subkey relative to an already-owned registry handle.
pub fn open_subkey(parent: &OwnedHKey, subkey: &str, sam_desired: u32) -> RegResult<OwnedHKey> {
    open_key_raw(parent.as_raw(), subkey, sam_desired)
}

fn open_key_raw(root: HKEY, subkey: &str, sam_desired: u32) -> RegResult<OwnedHKey> {
    let wide_subkey = to_wide_null(subkey);
    let mut hkey_out: HKEY = std::ptr::null_mut();

    let status =
        unsafe { RegOpenKeyExW(root, wide_subkey.as_ptr(), 0, sam_desired, &mut hkey_out) };

    if status == ERROR_SUCCESS {
        OwnedHKey::from_raw(hkey_out).ok_or(RegistryError::Win32Error(status))
    } else {
        Err(RegistryError::Win32Error(status))
    }
}

/// Creates or opens a registry key with the specified access mask.
pub fn create_key(parent: &OwnedHKey, subkey: &str, sam_desired: u32) -> RegResult<OwnedHKey> {
    let wide_subkey = to_wide_null(subkey);
    let mut hkey_out: HKEY = std::ptr::null_mut();
    let mut disposition: u32 = 0;

    let status = unsafe {
        RegCreateKeyExW(
            parent.as_raw(),
            wide_subkey.as_ptr(),
            0,
            std::ptr::null_mut(),
            REG_OPTION_NON_VOLATILE,
            sam_desired,
            std::ptr::null(),
            &mut hkey_out,
            &mut disposition,
        )
    };

    if status == ERROR_SUCCESS {
        OwnedHKey::from_raw(hkey_out).ok_or(RegistryError::Win32Error(status))
    } else {
        Err(RegistryError::Win32Error(status))
    }
}

/// Reads a 32-bit integer (REG_DWORD) from a registry key.
pub fn query_value_u32(hkey: &OwnedHKey, value_name: &str) -> RegResult<u32> {
    let wide_name = to_wide_null(value_name);
    let mut val_type: REG_VALUE_TYPE = 0;
    let mut data: u32 = 0;
    let mut data_size = std::mem::size_of::<u32>() as u32;

    let status = unsafe {
        RegQueryValueExW(
            hkey.as_raw(),
            wide_name.as_ptr(),
            std::ptr::null_mut(),
            &mut val_type,
            &mut data as *mut u32 as *mut u8,
            &mut data_size,
        )
    };

    if status == ERROR_SUCCESS {
        if val_type == REG_DWORD {
            Ok(data)
        } else {
            Err(RegistryError::UnexpectedValueType {
                value: value_name.to_string(),
                expected: REG_DWORD,
                actual: val_type,
            })
        }
    } else if status == ERROR_FILE_NOT_FOUND {
        Err(RegistryError::ValueNotFound(value_name.to_string()))
    } else {
        Err(RegistryError::Win32Error(status))
    }
}

/// Reads a UTF-16 string (REG_SZ or REG_EXPAND_SZ) from a registry key.
pub fn query_value_string(hkey: &OwnedHKey, value_name: &str) -> RegResult<String> {
    let wide_name = to_wide_null(value_name);
    let mut val_type: REG_VALUE_TYPE = 0;
    let mut data_size: u32 = 0;

    // First query buffer size
    let status = unsafe {
        RegQueryValueExW(
            hkey.as_raw(),
            wide_name.as_ptr(),
            std::ptr::null_mut(),
            &mut val_type,
            std::ptr::null_mut(),
            &mut data_size,
        )
    };

    if status != ERROR_SUCCESS {
        if status == ERROR_FILE_NOT_FOUND {
            return Err(RegistryError::ValueNotFound(value_name.to_string()));
        }
        return Err(RegistryError::Win32Error(status));
    }

    if val_type != REG_SZ && val_type != REG_EXPAND_SZ {
        return Err(RegistryError::UnexpectedValueType {
            value: value_name.to_string(),
            expected: REG_SZ,
            actual: val_type,
        });
    }

    let u16_len = (data_size as usize).div_ceil(2);
    let mut buffer: Vec<u16> = vec![0; u16_len];

    let status = unsafe {
        RegQueryValueExW(
            hkey.as_raw(),
            wide_name.as_ptr(),
            std::ptr::null_mut(),
            &mut val_type,
            buffer.as_mut_ptr() as *mut u8,
            &mut data_size,
        )
    };

    if status == ERROR_SUCCESS {
        from_wide_null(&buffer)
    } else {
        Err(RegistryError::Win32Error(status))
    }
}

/// Sets a 32-bit integer (REG_DWORD) in a registry key.
pub fn set_value_u32(hkey: &OwnedHKey, value_name: &str, val: u32) -> RegResult<()> {
    let wide_name = to_wide_null(value_name);
    let status = unsafe {
        RegSetValueExW(
            hkey.as_raw(),
            wide_name.as_ptr(),
            0,
            REG_DWORD,
            &val as *const u32 as *const u8,
            std::mem::size_of::<u32>() as u32,
        )
    };

    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(RegistryError::Win32Error(status))
    }
}

/// Sets a string (REG_SZ) in a registry key.
pub fn set_value_string(hkey: &OwnedHKey, value_name: &str, val: &str) -> RegResult<()> {
    let wide_name = to_wide_null(value_name);
    let wide_val = to_wide_null(val);
    let bytes_size = (wide_val.len() * std::mem::size_of::<u16>()) as u32;

    let status = unsafe {
        RegSetValueExW(
            hkey.as_raw(),
            wide_name.as_ptr(),
            0,
            REG_SZ,
            wide_val.as_ptr() as *const u8,
            bytes_size,
        )
    };

    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(RegistryError::Win32Error(status))
    }
}

/// Deletes a value from a registry key.
pub fn delete_value(hkey: &OwnedHKey, value_name: &str) -> RegResult<()> {
    let wide_name = to_wide_null(value_name);
    let status = unsafe { RegDeleteValueW(hkey.as_raw(), wide_name.as_ptr()) };
    if status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND {
        Ok(())
    } else {
        Err(RegistryError::Win32Error(status))
    }
}

/// Deletes a subkey and all its subkeys and values recursively.
pub fn delete_tree(hkey: &OwnedHKey, subkey: &str) -> RegResult<()> {
    let wide_subkey = to_wide_null(subkey);
    let status = unsafe { RegDeleteTreeW(hkey.as_raw(), wide_subkey.as_ptr()) };
    if status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND {
        Ok(())
    } else {
        Err(RegistryError::Win32Error(status))
    }
}

/// Renames a direct child key while preserving all values and subkeys.
pub fn rename_subkey(hkey: &OwnedHKey, old_name: &str, new_name: &str) -> RegResult<()> {
    let wide_old = to_wide_null(old_name);
    let wide_new = to_wide_null(new_name);
    let status = unsafe { RegRenameKey(hkey.as_raw(), wide_old.as_ptr(), wide_new.as_ptr()) };
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(RegistryError::Win32Error(status))
    }
}

/// Returns whether a direct child key exists, propagating all errors except not-found.
pub fn subkey_exists(hkey: &OwnedHKey, subkey: &str) -> RegResult<bool> {
    match open_subkey(hkey, subkey, windows_sys::Win32::System::Registry::KEY_READ) {
        Ok(_) => Ok(true),
        Err(RegistryError::Win32Error(ERROR_FILE_NOT_FOUND)) => Ok(false),
        Err(error) => Err(error),
    }
}

/// Enumerates all subkeys under an open registry key.
pub fn enum_subkeys(hkey: &OwnedHKey) -> RegResult<Vec<String>> {
    let mut results = Vec::new();
    let mut index = 0;
    let mut name_buffer = vec![0u16; 256];

    loop {
        let mut name_len = name_buffer.len() as u32;
        let status = unsafe {
            RegEnumKeyExW(
                hkey.as_raw(),
                index,
                name_buffer.as_mut_ptr(),
                &mut name_len,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };

        if status == ERROR_SUCCESS {
            let key_name = from_wide_null(&name_buffer[..name_len as usize + 1])?;
            results.push(key_name);
            index += 1;
        } else if status == ERROR_NO_MORE_ITEMS {
            break;
        } else {
            return Err(RegistryError::Win32Error(status));
        }
    }

    Ok(results)
}

/// Saves the specified registry key and all of its subkeys and values to a new binary hive file.
pub fn save_key(hkey: &OwnedHKey, target_file: &Path) -> RegResult<()> {
    let wide_path = to_wide_null(target_file.as_os_str());
    let status = unsafe {
        RegSaveKeyExW(
            hkey.as_raw(),
            wide_path.as_ptr(),
            std::ptr::null(),
            REG_NO_COMPRESSION,
        )
    };

    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(RegistryError::Win32Error(status))
    }
}

/// Mounts an off-line registry hive file into the registry under HKEY_USERS or HKEY_LOCAL_MACHINE.
pub fn load_hive(root: RegistryRoot, subkey: &str, hive_path: &Path) -> RegResult<()> {
    let wide_subkey = to_wide_null(subkey);
    let wide_path = to_wide_null(hive_path.as_os_str());

    let status = unsafe { RegLoadKeyW(root.as_raw(), wide_subkey.as_ptr(), wide_path.as_ptr()) };
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(RegistryError::Win32Error(status))
    }
}

/// Unloads the specified off-line registry hive.
pub fn unload_hive(root: RegistryRoot, subkey: &str) -> RegResult<()> {
    let wide_subkey = to_wide_null(subkey);
    let status = unsafe { RegUnLoadKeyW(root.as_raw(), wide_subkey.as_ptr()) };
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(RegistryError::Win32Error(status))
    }
}

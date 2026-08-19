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

use std::ffi::c_void;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Environment::DestroyEnvironmentBlock;
use windows_sys::Win32::System::Services::{CloseServiceHandle, SC_HANDLE};

/// RAII wrapper around a Win32 generic HANDLE.
/// Automatically invokes `CloseHandle` on drop if valid.
#[derive(Debug)]
pub struct OwnedHandle {
    handle: HANDLE,
}

impl OwnedHandle {
    /// Creates a new `OwnedHandle` from a raw Win32 HANDLE.
    /// Returns `None` if the handle is `NULL` or `INVALID_HANDLE_VALUE`.
    pub fn from_raw(raw: HANDLE) -> Option<Self> {
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            None
        } else {
            Some(Self { handle: raw })
        }
    }

    /// Creates an `OwnedHandle` assuming validity or returns an error.
    pub fn from_raw_checked(raw: HANDLE) -> Result<Self, std::io::Error> {
        Self::from_raw(raw).ok_or_else(std::io::Error::last_os_error)
    }

    /// Returns the underlying raw Win32 HANDLE.
    pub fn as_raw(&self) -> HANDLE {
        self.handle
    }

    /// Consumes the wrapper and releases ownership without closing the handle.
    pub fn into_raw(self) -> HANDLE {
        let h = self.handle;
        std::mem::forget(self);
        h
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.handle.is_null() && self.handle != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.handle);
            }
        }
    }
}

/// RAII wrapper around a Service Control Manager SC_HANDLE.
/// Automatically invokes `CloseServiceHandle` on drop if valid.
#[derive(Debug)]
pub struct OwnedScHandle {
    handle: SC_HANDLE,
}

impl OwnedScHandle {
    /// Creates a new `OwnedScHandle` from a raw SC_HANDLE.
    pub fn from_raw(raw: SC_HANDLE) -> Option<Self> {
        if raw.is_null() {
            None
        } else {
            Some(Self { handle: raw })
        }
    }

    /// Creates an `OwnedScHandle` assuming validity or returns an error.
    pub fn from_raw_checked(raw: SC_HANDLE) -> Result<Self, std::io::Error> {
        Self::from_raw(raw).ok_or_else(std::io::Error::last_os_error)
    }

    /// Returns the underlying raw SC_HANDLE.
    pub fn as_raw(&self) -> SC_HANDLE {
        self.handle
    }
}

impl Drop for OwnedScHandle {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                CloseServiceHandle(self.handle);
            }
        }
    }
}

/// RAII wrapper for a user environment block allocated via `CreateEnvironmentBlock`.
#[derive(Debug)]
pub struct OwnedEnvironmentBlock {
    block: *mut c_void,
}

impl OwnedEnvironmentBlock {
    /// Creates a wrapper for an environment block pointer.
    pub fn from_raw(ptr: *mut c_void) -> Option<Self> {
        if ptr.is_null() {
            None
        } else {
            Some(Self { block: ptr })
        }
    }

    /// Returns the raw pointer to the environment block.
    pub fn as_ptr(&self) -> *mut c_void {
        self.block
    }
}

impl Drop for OwnedEnvironmentBlock {
    fn drop(&mut self) {
        if !self.block.is_null() {
            unsafe {
                DestroyEnvironmentBlock(self.block);
            }
        }
    }
}

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
use std::path::PathBuf;

use raw_window_handle::{HasWindowHandle, RawWindowHandle};
use thiserror::Error;
use windows::core::{Error as WindowsError, HRESULT, HSTRING};
use windows::Win32::Foundation::{HWND, RPC_E_CHANGED_MODE};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoTaskMemFree, CoUninitialize, CLSCTX_INPROC_SERVER,
    COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE,
};
use windows::Win32::UI::Shell::{
    FileOpenDialog, IFileOpenDialog, FOS_DONTADDTORECENT, FOS_FORCEFILESYSTEM, FOS_NOCHANGEDIR,
    FOS_PATHMUSTEXIST, FOS_PICKFOLDERS, SIGDN_FILESYSPATH,
};

const CANCELLED_HRESULT: HRESULT = HRESULT(0x8007_04c7u32 as i32);

#[derive(Debug, Error)]
pub enum FolderDialogError {
    #[error("The application window handle is unavailable")]
    OwnerUnavailable,
    #[error("The application window did not expose a Win32 window handle")]
    UnsupportedOwner,
    #[error("Folder picker COM initialization failed: {0}")]
    ComInitialization(WindowsError),
    #[error("Folder picker requires an STA UI thread, but this thread uses another COM apartment")]
    ApartmentMismatch,
    #[error("Folder picker failed: {0}")]
    Native(WindowsError),
    #[error("Folder picker returned an invalid filesystem path: {0}")]
    InvalidPath(String),
}

pub type FolderDialogResult<T> = Result<T, FolderDialogError>;

/// Exact Win32 owner token captured from the Slint window on the UI thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FolderDialogOwner(isize);

impl FolderDialogOwner {
    fn hwnd(self) -> HWND {
        HWND(self.0 as *mut c_void)
    }
}

/// Extracts the exact Win32 owner from the application's window handle.
pub fn folder_dialog_owner<T: HasWindowHandle>(
    window: &T,
) -> FolderDialogResult<FolderDialogOwner> {
    let handle = window
        .window_handle()
        .map_err(|_| FolderDialogError::OwnerUnavailable)?;
    owner_from_raw_handle(handle.as_raw())
}

/// Shows the native folder picker on the current thread in an STA apartment.
///
/// This must run synchronously on the UI thread. `IFileOpenDialog::Show` owns
/// the native modal loop. User cancellation is returned as `Ok(None)`.
pub fn pick_existing_folder(
    owner: FolderDialogOwner,
    title: &str,
    accept_label: &str,
) -> FolderDialogResult<Option<PathBuf>> {
    let _apartment = ComApartment::initialize_sta()?;
    let dialog: IFileOpenDialog = unsafe {
        CoCreateInstance(&FileOpenDialog, None, CLSCTX_INPROC_SERVER)
            .map_err(FolderDialogError::Native)?
    };
    let options = unsafe { dialog.GetOptions().map_err(FolderDialogError::Native)? };
    unsafe {
        dialog
            .SetOptions(
                options
                    | FOS_PICKFOLDERS
                    | FOS_FORCEFILESYSTEM
                    | FOS_PATHMUSTEXIST
                    | FOS_NOCHANGEDIR
                    | FOS_DONTADDTORECENT,
            )
            .map_err(FolderDialogError::Native)?;
        dialog
            .SetTitle(&HSTRING::from(title))
            .map_err(FolderDialogError::Native)?;
        dialog
            .SetOkButtonLabel(&HSTRING::from(accept_label))
            .map_err(FolderDialogError::Native)?;
    }
    match unsafe { dialog.Show(owner.hwnd()) } {
        Ok(()) => {}
        Err(error) if error.code() == CANCELLED_HRESULT => return Ok(None),
        Err(error) => return Err(FolderDialogError::Native(error)),
    }
    let item = unsafe { dialog.GetResult().map_err(FolderDialogError::Native)? };
    let display_name = unsafe {
        item.GetDisplayName(SIGDN_FILESYSPATH)
            .map_err(FolderDialogError::Native)?
    };
    let path = unsafe { display_name.to_string() }
        .map_err(|error| FolderDialogError::InvalidPath(error.to_string()));
    unsafe { CoTaskMemFree(Some(display_name.0.cast_const().cast::<c_void>())) };
    path.map(|path| Some(PathBuf::from(path)))
}

fn owner_from_raw_handle(handle: RawWindowHandle) -> FolderDialogResult<FolderDialogOwner> {
    match handle {
        RawWindowHandle::Win32(handle) => Ok(FolderDialogOwner(handle.hwnd.get())),
        _ => Err(FolderDialogError::UnsupportedOwner),
    }
}

struct ComApartment;

impl ComApartment {
    fn initialize_sta() -> FolderDialogResult<Self> {
        let result =
            unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) };
        if result == RPC_E_CHANGED_MODE {
            return Err(FolderDialogError::ApartmentMismatch);
        }
        result.ok().map_err(FolderDialogError::ComInitialization)?;
        Ok(Self)
    }
}

impl Drop for ComApartment {
    fn drop(&mut self) {
        unsafe { CoUninitialize() };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroIsize;
    use windows::Win32::System::Com::COINIT_MULTITHREADED;

    #[test]
    fn owner_requires_an_exact_win32_handle() {
        let hwnd = raw_window_handle::Win32WindowHandle::new(
            NonZeroIsize::new(1).expect("non-zero test HWND"),
        );
        assert_eq!(
            owner_from_raw_handle(RawWindowHandle::Win32(hwnd)).expect("Win32 owner"),
            FolderDialogOwner(1)
        );
        assert!(matches!(
            owner_from_raw_handle(RawWindowHandle::Web(
                raw_window_handle::WebWindowHandle::new(1)
            )),
            Err(FolderDialogError::UnsupportedOwner)
        ));
    }

    #[test]
    fn fresh_ui_thread_accepts_sta_initialization() {
        std::thread::spawn(|| ComApartment::initialize_sta().map(drop))
            .join()
            .expect("STA UI thread")
            .expect("STA initialization");
    }

    #[test]
    fn incompatible_com_apartment_is_refused_explicitly() {
        std::thread::spawn(|| {
            unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }
                .ok()
                .expect("initialize MTA test apartment");
            assert!(matches!(
                ComApartment::initialize_sta(),
                Err(FolderDialogError::ApartmentMismatch)
            ));
            unsafe { CoUninitialize() };
        })
        .join()
        .expect("MTA test thread");
    }
}

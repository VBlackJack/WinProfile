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

use std::ptr::null_mut;

use thiserror::Error;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Globalization::{GetUserPreferredUILanguages, MUI_LANGUAGE_NAME};

const MAX_LANGUAGE_BUFFER_UNITS: u32 = 65_536;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum LocaleError {
    #[error("GetUserPreferredUILanguages failed with Windows error {0}")]
    Windows(u32),
    #[error("Windows returned an invalid preferred-language buffer: {0}")]
    InvalidBuffer(&'static str),
    #[error("Windows returned an invalid UTF-16 preferred-language name")]
    InvalidUtf16,
}

pub type LocaleResult<T> = Result<T, LocaleError>;

trait PreferredUiLanguagesApi {
    fn query(
        &self,
        language_count: &mut u32,
        buffer: Option<&mut [u16]>,
        buffer_units: &mut u32,
    ) -> LocaleResult<()>;
}

struct WindowsPreferredUiLanguages;

impl PreferredUiLanguagesApi for WindowsPreferredUiLanguages {
    fn query(
        &self,
        language_count: &mut u32,
        buffer: Option<&mut [u16]>,
        buffer_units: &mut u32,
    ) -> LocaleResult<()> {
        let buffer_pointer = buffer.map_or(null_mut(), |values| values.as_mut_ptr());
        let succeeded = unsafe {
            GetUserPreferredUILanguages(
                MUI_LANGUAGE_NAME,
                language_count,
                buffer_pointer,
                buffer_units,
            )
        };
        if succeeded == 0 {
            return Err(LocaleError::Windows(unsafe { GetLastError() }));
        }
        Ok(())
    }
}

/// Returns Windows user UI languages in their declared preference order.
pub fn user_preferred_ui_languages() -> LocaleResult<Vec<String>> {
    query_user_preferred_ui_languages(&WindowsPreferredUiLanguages)
}

fn query_user_preferred_ui_languages(
    api: &impl PreferredUiLanguagesApi,
) -> LocaleResult<Vec<String>> {
    let mut language_count = 0;
    let mut buffer_units = 0;
    api.query(&mut language_count, None, &mut buffer_units)?;
    if buffer_units > MAX_LANGUAGE_BUFFER_UNITS {
        return Err(LocaleError::InvalidBuffer(
            "required length exceeds the safety limit",
        ));
    }
    if buffer_units < 2 {
        return Err(LocaleError::InvalidBuffer(
            "required length omits the MULTI_SZ terminator",
        ));
    }

    let mut buffer = vec![0_u16; buffer_units as usize];
    let allocated_units = buffer_units;
    api.query(
        &mut language_count,
        Some(buffer.as_mut_slice()),
        &mut buffer_units,
    )?;
    if buffer_units > allocated_units {
        return Err(LocaleError::InvalidBuffer(
            "returned length exceeds the allocated buffer",
        ));
    }
    buffer.truncate(buffer_units as usize);
    parse_language_multisz(&buffer, language_count)
}

fn parse_language_multisz(buffer: &[u16], expected_count: u32) -> LocaleResult<Vec<String>> {
    if buffer.len() < 2 || buffer[buffer.len() - 2..] != [0, 0] {
        return Err(LocaleError::InvalidBuffer(
            "MULTI_SZ is not double-NUL terminated",
        ));
    }

    let content = &buffer[..buffer.len() - 2];
    let mut languages = Vec::new();
    if !content.is_empty() {
        for language in content.split(|unit| *unit == 0) {
            if language.is_empty() {
                return Err(LocaleError::InvalidBuffer(
                    "MULTI_SZ contains an empty language name",
                ));
            }
            languages.push(String::from_utf16(language).map_err(|_| LocaleError::InvalidUtf16)?);
        }
    }
    if languages.len() != expected_count as usize {
        return Err(LocaleError::InvalidBuffer(
            "language count does not match the MULTI_SZ payload",
        ));
    }
    Ok(languages)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct FakeApi {
        payload: Vec<u16>,
        language_count: u32,
        failure: Option<u32>,
        calls: Cell<usize>,
    }

    impl PreferredUiLanguagesApi for FakeApi {
        fn query(
            &self,
            language_count: &mut u32,
            buffer: Option<&mut [u16]>,
            buffer_units: &mut u32,
        ) -> LocaleResult<()> {
            self.calls.set(self.calls.get() + 1);
            if let Some(error) = self.failure {
                return Err(LocaleError::Windows(error));
            }
            *language_count = self.language_count;
            *buffer_units = self.payload.len() as u32;
            if let Some(destination) = buffer {
                destination.copy_from_slice(&self.payload);
            }
            Ok(())
        }
    }

    fn multi_sz(value: &str) -> Vec<u16> {
        value.encode_utf16().collect()
    }

    #[test]
    fn two_pass_query_preserves_preference_order() {
        let api = FakeApi {
            payload: multi_sz("fr-CA\0en-US\0\0"),
            language_count: 2,
            failure: None,
            calls: Cell::new(0),
        };

        assert_eq!(
            query_user_preferred_ui_languages(&api).expect("valid preferred languages"),
            vec!["fr-CA", "en-US"]
        );
        assert_eq!(api.calls.get(), 2);
    }

    #[test]
    fn malformed_multisz_and_api_failure_are_explicit() {
        assert!(matches!(
            parse_language_multisz(&multi_sz("fr-CA\0"), 1),
            Err(LocaleError::InvalidBuffer(_))
        ));
        assert!(matches!(
            parse_language_multisz(&[0, 0], 1),
            Err(LocaleError::InvalidBuffer(_))
        ));

        let api = FakeApi {
            payload: Vec::new(),
            language_count: 0,
            failure: Some(5),
            calls: Cell::new(0),
        };
        assert_eq!(
            query_user_preferred_ui_languages(&api),
            Err(LocaleError::Windows(5))
        );
        assert_eq!(api.calls.get(), 1);
    }
}

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

use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::OnceLock;

use thiserror::Error;

static CURRENT_LOCALE: AtomicU8 = AtomicU8::new(0);
static INSTANCE: OnceLock<Result<I18nManager, I18nError>> = OnceLock::new();

const EN_JSON: &str = include_str!("../../../locales/en.json");
const FR_JSON: &str = include_str!("../../../locales/fr.json");
pub const ENGLISH_LOCALE: &str = "en";
pub const FRENCH_LOCALE: &str = "fr";

#[derive(Error, Debug, Clone)]
pub enum I18nError {
    #[error("Invalid {locale} translation bundle: {reason}")]
    InvalidBundle { locale: String, reason: String },
    #[error("Translation key parity mismatch: only_en={only_en:?}, only_fr={only_fr:?}")]
    KeyParity {
        only_en: Vec<String>,
        only_fr: Vec<String>,
    },
    #[error("Unsupported locale: {0}")]
    UnsupportedLocale(String),
}

/// Parsed and parity-validated embedded translation bundles.
pub struct I18nManager {
    locales: HashMap<String, HashMap<String, String>>,
}

impl I18nManager {
    /// Returns the validated global translation manager.
    pub fn global() -> Result<&'static I18nManager, I18nError> {
        match INSTANCE.get_or_init(Self::build) {
            Ok(manager) => Ok(manager),
            Err(error) => Err(error.clone()),
        }
    }

    /// Forces bundle parsing and parity validation during application startup.
    pub fn validate() -> Result<(), I18nError> {
        Self::global().map(|_| ())
    }

    /// Sets the active locale code.
    pub fn set_locale(locale: &str) -> Result<(), I18nError> {
        let code = match locale {
            ENGLISH_LOCALE => 0,
            FRENCH_LOCALE => 1,
            value => return Err(I18nError::UnsupportedLocale(value.to_string())),
        };
        CURRENT_LOCALE.store(code, Ordering::Release);
        Ok(())
    }

    /// Gets the active locale code.
    pub fn get_locale() -> &'static str {
        if CURRENT_LOCALE.load(Ordering::Acquire) == 1 {
            FRENCH_LOCALE
        } else {
            ENGLISH_LOCALE
        }
    }

    /// Translates a key for the selected locale, then falls back to English.
    pub fn translate(&self, key: &str) -> String {
        self.locales
            .get(Self::get_locale())
            .and_then(|map| map.get(key))
            .or_else(|| self.locales.get("en").and_then(|map| map.get(key)))
            .cloned()
            .unwrap_or_else(|| format!("[missing:{key}]"))
    }

    /// Translates a key and replaces named placeholders.
    pub fn translate_args(&self, key: &str, args: &[(&str, &str)]) -> String {
        let mut template = self.translate(key);
        for &(parameter, value) in args {
            template = template.replace(&format!("{{{parameter}}}"), value);
        }
        template
    }

    /// Returns sorted translation keys for verification tests.
    pub fn keys(&self) -> Vec<String> {
        self.locales
            .get("en")
            .map(|map| {
                let mut keys = map.keys().cloned().collect::<Vec<_>>();
                keys.sort();
                keys
            })
            .unwrap_or_default()
    }

    fn build() -> Result<Self, I18nError> {
        let en = parse_bundle("en", EN_JSON)?;
        let fr = parse_bundle("fr", FR_JSON)?;
        let en_keys = en.keys().cloned().collect::<BTreeSet<_>>();
        let fr_keys = fr.keys().cloned().collect::<BTreeSet<_>>();
        if en_keys != fr_keys {
            return Err(I18nError::KeyParity {
                only_en: en_keys.difference(&fr_keys).cloned().collect(),
                only_fr: fr_keys.difference(&en_keys).cloned().collect(),
            });
        }
        Ok(Self {
            locales: HashMap::from([("en".to_string(), en), ("fr".to_string(), fr)]),
        })
    }
}

/// Selects the first supported, well-formed Windows language tag.
///
/// Unsupported tags are skipped in preference order. Any malformed tag makes
/// the result fall back to English instead of guessing from partial input.
pub fn resolve_supported_locale<'a>(tags: impl IntoIterator<Item = &'a str>) -> &'static str {
    let tags = tags.into_iter().collect::<Vec<_>>();
    if tags.iter().any(|tag| !is_well_formed_language_tag(tag)) {
        return ENGLISH_LOCALE;
    }
    for tag in tags {
        let primary = tag.split('-').next().unwrap_or_default();
        if primary.eq_ignore_ascii_case(FRENCH_LOCALE) {
            return FRENCH_LOCALE;
        }
        if primary.eq_ignore_ascii_case(ENGLISH_LOCALE) {
            return ENGLISH_LOCALE;
        }
    }
    ENGLISH_LOCALE
}

fn is_well_formed_language_tag(tag: &str) -> bool {
    let mut parts = tag.split('-');
    let Some(primary) = parts.next() else {
        return false;
    };
    if !(2..=8).contains(&primary.len()) || !primary.bytes().all(|byte| byte.is_ascii_alphabetic())
    {
        return false;
    }
    parts.all(|part| {
        !part.is_empty() && part.len() <= 8 && part.bytes().all(|byte| byte.is_ascii_alphanumeric())
    })
}

fn parse_bundle(locale: &str, json: &str) -> Result<HashMap<String, String>, I18nError> {
    serde_json::from_str(json).map_err(|error| I18nError::InvalidBundle {
        locale: locale.to_string(),
        reason: error.to_string(),
    })
}

/// Global helper for key translation after startup validation.
pub fn t(key: &str) -> String {
    match I18nManager::global() {
        Ok(manager) => manager.translate(key),
        Err(error) => format!("[i18n:{error}]"),
    }
}

/// Global helper for key translation with named arguments.
pub fn t_args(key: &str, args: &[(&str, &str)]) -> String {
    match I18nManager::global() {
        Ok(manager) => manager.translate_args(key, args),
        Err(error) => format!("[i18n:{error}]"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_locale_resolver_follows_windows_preference_order() {
        assert_eq!(resolve_supported_locale(["fr-CA", "en-US"]), FRENCH_LOCALE);
        assert_eq!(resolve_supported_locale(["de-DE", "en-GB"]), ENGLISH_LOCALE);
    }

    #[test]
    fn default_empty_and_malformed_language_lists_fall_back_to_english() {
        assert_eq!(I18nManager::get_locale(), ENGLISH_LOCALE);
        assert_eq!(resolve_supported_locale(std::iter::empty()), ENGLISH_LOCALE);
        assert_eq!(resolve_supported_locale(["fr_CA"]), ENGLISH_LOCALE);
        assert_eq!(resolve_supported_locale([""]), ENGLISH_LOCALE);
        assert_eq!(
            resolve_supported_locale(["fr-CA", "bad_tag"]),
            ENGLISH_LOCALE
        );
        assert_eq!(
            resolve_supported_locale(["fr-FR-u-ca-gregory"]),
            FRENCH_LOCALE
        );
    }
}

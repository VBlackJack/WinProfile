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

use std::collections::HashMap;
use std::sync::RwLock;

static CURRENT_LOCALE: RwLock<String> = RwLock::new(String::new());

const EN_JSON: &str = include_str!("../../../locales/en.json");
const FR_JSON: &str = include_str!("../../../locales/fr.json");

/// Structure storing parsed translation maps.
pub struct I18nManager {
    locales: HashMap<String, HashMap<String, String>>,
}

impl I18nManager {
    /// Initializes and parses embedded JSON translation bundles.
    pub fn global() -> &'static I18nManager {
        static INSTANCE: std::sync::OnceLock<I18nManager> = std::sync::OnceLock::new();
        INSTANCE.get_or_init(|| {
            let mut locales = HashMap::new();

            if let Ok(en_map) = serde_json::from_str::<HashMap<String, String>>(EN_JSON) {
                locales.insert("en".to_string(), en_map);
            }
            if let Ok(fr_map) = serde_json::from_str::<HashMap<String, String>>(FR_JSON) {
                locales.insert("fr".to_string(), fr_map);
            }

            I18nManager { locales }
        })
    }

    /// Sets the active locale code (e.g. "fr" or "en").
    pub fn set_locale(locale: &str) {
        if let Ok(mut cur) = CURRENT_LOCALE.write() {
            *cur = locale.to_string();
        }
    }

    /// Gets the active locale code.
    pub fn get_locale() -> String {
        if let Ok(cur) = CURRENT_LOCALE.read() {
            if !cur.is_empty() {
                return cur.clone();
            }
        }
        "fr".to_string() // French default as specified
    }

    /// Translates a key for the currently selected locale with fallback.
    pub fn translate(&self, key: &str) -> String {
        let active = Self::get_locale();
        if let Some(map) = self.locales.get(&active) {
            if let Some(val) = map.get(key) {
                return val.clone();
            }
        }

        // Fallback to English
        if active != "en" {
            if let Some(en_map) = self.locales.get("en") {
                if let Some(val) = en_map.get(key) {
                    return val.clone();
                }
            }
        }

        key.to_string()
    }

    /// Translates a key and replaces `{name}` placeholders with provided argument values.
    pub fn translate_args(&self, key: &str, args: &[(&str, &str)]) -> String {
        let mut template = self.translate(key);
        for &(param, val) in args {
            let pattern = format!("{{{}}}", param);
            template = template.replace(&pattern, val);
        }
        template
    }
}

/// Global helper for key translation.
pub fn t(key: &str) -> String {
    I18nManager::global().translate(key)
}

/// Global helper for key translation with named parameter arguments.
pub fn t_args(key: &str, args: &[(&str, &str)]) -> String {
    I18nManager::global().translate_args(key, args)
}

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

fn main() {
    slint_build::compile("ui/main-window.slint").expect("Failed to compile Slint UI definitions");

    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_env == "msvc" {
        let manifest_path = std::path::Path::new("../../resources/app.manifest");
        if manifest_path.exists() {
            let abs_path = std::fs::canonicalize(manifest_path).unwrap_or_else(|_| manifest_path.to_path_buf());
            println!("cargo:rustc-link-arg-bins=/MANIFESTINPUT:{}", abs_path.display());
            println!("cargo:rustc-link-arg-bins=/MANIFEST:EMBED");
        }
    }
}

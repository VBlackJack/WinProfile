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

pub mod constants;
pub mod i18n;
pub mod migration;
pub mod models;
pub mod repair;
pub mod scanner;

pub use i18n::{t, t_args, I18nError, I18nManager};
pub use migration::{MigrationError, MigrationReceipt, MigrationResult, ProfileMigrationEngine};
pub use models::{
    DiagnosticReport, MigrationPlan, ProfileAnomaly, ProfileHealth, RepairPlan, UserProfile,
};
pub use repair::{ProfileRepairEngine, RepairError, RepairResult};
pub use scanner::{ProfileScanner, ScannerError, ScannerResult};

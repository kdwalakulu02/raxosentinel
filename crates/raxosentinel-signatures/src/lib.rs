/*
 * RaxoSentinel Core — Malware Detection Engine
 * Copyright (C) 2026 RaxoSentinel Contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

pub mod builtin;
pub mod database;
pub mod loader;
pub mod models;
pub mod rsidb;

pub use builtin::{default_hash_rules, default_pattern_rules};
pub use database::SignatureDatabase;
pub use loader::{load_rules_from_file, load_rules_from_str, RuleSetFile};
pub use models::{HashRule, PatternRule};

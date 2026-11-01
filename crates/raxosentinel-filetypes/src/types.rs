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

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileCategory {
    Executable,
    Email,
    Document,
    Archive,
    Script,
    Image,
    Text,
    Unknown,
}

impl std::fmt::Display for FileCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileCategory::Executable => write!(f, "Executable"),
            FileCategory::Email => write!(f, "Email"),
            FileCategory::Document => write!(f, "Document"),
            FileCategory::Archive => write!(f, "Archive"),
            FileCategory::Script => write!(f, "Script"),
            FileCategory::Image => write!(f, "Image"),
            FileCategory::Text => write!(f, "Text"),
            FileCategory::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Detailed file type representation determined from content inspection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileType {
    /// Canonical MIME type (e.g. "application/vnd.microsoft.portable-executable", "message/rfc822")
    pub mime_type: String,
    /// Broad category
    pub category: FileCategory,
    /// Human-friendly description (e.g. "Windows PE Executable / DLL", "RFC 822 Email Message")
    pub description: String,
    /// Typical file extensions associated with this format
    pub typical_extensions: Vec<String>,
    /// Security indicator: whether this format represents native executable machine code
    pub is_executable: bool,
    /// Security indicator: whether this format can contain active macros or scripts
    pub can_contain_code: bool,
    /// Security indicator: whether this format is an archive/container requiring unpacking
    pub is_archive: bool,
}

impl FileType {
    pub fn new(
        mime_type: impl Into<String>,
        category: FileCategory,
        description: impl Into<String>,
        typical_extensions: &[&str],
        is_executable: bool,
        can_contain_code: bool,
        is_archive: bool,
    ) -> Self {
        Self {
            mime_type: mime_type.into(),
            category,
            description: description.into(),
            typical_extensions: typical_extensions.iter().map(|s| s.to_string()).collect(),
            is_executable,
            can_contain_code,
            is_archive,
        }
    }

    pub fn unknown() -> Self {
        Self::new(
            "application/octet-stream",
            FileCategory::Unknown,
            "Unknown Binary Data",
            &[],
            false,
            false,
            false,
        )
    }

    pub fn plain_text() -> Self {
        Self::new(
            "text/plain",
            FileCategory::Text,
            "Plain Text Document",
            &["txt", "log", "cfg", "ini"],
            false,
            false,
            false,
        )
    }

    pub fn matches_extension(&self, ext: &str) -> bool {
        let clean_ext = ext.trim_start_matches('.').to_lowercase();
        self.typical_extensions
            .iter()
            .any(|e| e.eq_ignore_ascii_case(&clean_ext))
    }
}

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

use crate::models::{HashRule, PatternRule};
use raxosentinel_core::{Severity, ThreatCategory};

/// Returns built-in hash signatures (EICAR standard hashes, synthetic test hashes).
pub fn default_hash_rules() -> Vec<HashRule> {
    vec![
        // Standard EICAR Antivirus Test File (68 bytes exact SHA-256)
        HashRule::new(
            "EICAR-Standard-Antivirus-Test-File",
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            ThreatCategory::TestSignature,
            Severity::High,
            "Standard EICAR antivirus test file (68 bytes)",
        ),
        // EICAR Antivirus Test File with CRLF (70 bytes exact SHA-256)
        HashRule::new(
            "EICAR-Standard-Antivirus-Test-File-CRLF",
            "3395856ce81f2b7382dee72602f798b642f14140",
            ThreatCategory::TestSignature,
            Severity::High,
            "Standard EICAR antivirus test file with CRLF line ending",
        ),
        // Synthetic test hash for automated tests
        HashRule::new(
            "Test.Synthetic.HashMatch",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            ThreatCategory::TestSignature,
            Severity::Info,
            "Synthetic signature match for automated engine validation",
        ),
    ]
}

/// Returns built-in byte-pattern signatures (EICAR pattern, synthetic pattern, macro abuse, suspicious scripts).
pub fn default_pattern_rules() -> Vec<PatternRule> {
    vec![
        // EICAR standard byte pattern
        PatternRule::new(
            "EICAR-Standard-Antivirus-Test-File",
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*".to_vec(),
            ThreatCategory::TestSignature,
            Severity::High,
            "Matches the standard EICAR test string across any file or attachment",
        ),
        // Synthetic test pattern for unit/integration tests
        PatternRule::new(
            "Test.Synthetic.BytePattern",
            b"RAXOSENTINEL-SYNTHETIC-TEST-SIGNATURE".to_vec(),
            ThreatCategory::TestSignature,
            Severity::Info,
            "Synthetic byte-pattern match for automated testing",
        ),
        // Suspicious encoded PowerShell commands commonly used in phishing mail attachments
        PatternRule::new(
            "Suspicious.Script.EncodedPowerShell",
            b"powershell -enc".to_vec(),
            ThreatCategory::SuspiciousScript,
            Severity::High,
            "Obfuscated / encoded PowerShell execution command detected",
        ),
        PatternRule::new(
            "Suspicious.Script.EncodedPowerShell.Long",
            b"powershell.exe -encodedcommand".to_vec(),
            ThreatCategory::SuspiciousScript,
            Severity::High,
            "Encoded PowerShell command detected",
        ),
        // Suspicious Certutil download command
        PatternRule::new(
            "Suspicious.Tool.CertutilDownload",
            b"certutil -urlcache -split -f".to_vec(),
            ThreatCategory::SuspiciousScript,
            Severity::High,
            "Certutil URL download and cache evasion pattern detected",
        ),
        // MSHTA script execution pattern
        PatternRule::new(
            "Suspicious.Script.MshtaVBScript",
            b"mshta vbscript:CreateObject".to_vec(),
            ThreatCategory::SuspiciousScript,
            Severity::High,
            "MSHTA VBScript payload execution detected",
        ),
        // Document Auto-execute macro triggers
        PatternRule::new(
            "Suspicious.Macro.AutoOpen",
            b"Sub AutoOpen()".to_vec(),
            ThreatCategory::MacroMalware,
            Severity::Medium,
            "AutoOpen automatic macro execution procedure detected in document",
        ),
        PatternRule::new(
            "Suspicious.Macro.DocumentOpen",
            b"Sub Document_Open()".to_vec(),
            ThreatCategory::MacroMalware,
            Severity::Medium,
            "Document_Open automatic macro execution procedure detected in document",
        ),
    ]
}

// Copyright (C) 2026 RaxoSentinel Contributors
// SPDX-License-Identifier: GPL-2.0-or-later
//! Source provider adapters.

pub mod clamav;
pub mod malwarebazaar;

pub use clamav::ClamAvProvider;
pub use malwarebazaar::MalwareBazaarProvider;

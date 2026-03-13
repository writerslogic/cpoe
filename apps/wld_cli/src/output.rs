// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

/// Controls how command output is formatted.
#[derive(Clone, Copy)]
pub struct OutputMode {
    pub json: bool,
    pub quiet: bool,
}

impl OutputMode {
    pub fn new(json: bool, quiet: bool) -> Self {
        Self { json, quiet }
    }
}

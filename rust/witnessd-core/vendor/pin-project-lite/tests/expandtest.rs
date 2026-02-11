// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial OR MIT

#![cfg(not(miri))]

#[rustversion::attr(not(nightly), ignore)]
#[test]
fn expandtest() {
    let args = &["--all-features"];
    macrotest::expand_args("tests/expand/**/*.rs", args);
}

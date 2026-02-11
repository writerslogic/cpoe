// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial OR MIT

#![cfg(not(miri))]

#[rustversion::attr(not(nightly), ignore)]
#[test]
fn ui() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/**/*.rs");
    t.pass("tests/run-pass/**/*.rs");
}

// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial OR MIT

use pin_project_lite::pin_project;

pin_project! {
    struct Foo {
        #[pin]
        inner: u8,
    }
}

impl Unpin for __Origin {} //~ ERROR E0412,E0321

fn main() {}

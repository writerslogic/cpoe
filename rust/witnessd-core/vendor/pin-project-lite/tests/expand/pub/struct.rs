// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial OR MIT

use pin_project_lite::pin_project;

pin_project! {
    pub struct Struct<T, U> {
        #[pin]
        pub pinned: T,
        pub unpinned: U,
    }
}

fn main() {}

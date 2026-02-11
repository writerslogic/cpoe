// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial OR MIT

use pin_project_lite::pin_project;

pin_project! {
    #[project = StructProj]
    struct Struct<T, U> {
        #[pin]
        pinned: T,
        unpinned: U,
    }
}

fn main() {}

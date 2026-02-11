// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial OR MIT

use pin_project_lite::pin_project;

pin_project! {
    #[project = StructProj]
    #[project(!Unpin)]
    #[project_ref = StructProjRef]
    struct Struct<T, U> {
        #[pin]
        pinned: T,
        unpinned: U,
    }
}

fn main() {}

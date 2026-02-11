// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial OR MIT

use pin_project_lite::pin_project;

pin_project! {
    struct Struct<T, U> {
        #[pin]
        pinned: T,
        unpinned: U,
    }
    impl<T, U> PinnedDrop for Struct<T, U> {
        fn drop(this: Pin<&mut Self>) {
            let _ = this;
        }
    }
}

fn main() {}

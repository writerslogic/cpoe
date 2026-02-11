// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial OR MIT

use pin_project_lite::pin_project;

pin_project! {
    #[project = EnumProj]
    #[project_ref = EnumProjRef]
    enum Enum<T, U> {
        Struct {
            #[pin]
            pinned: T,
            unpinned: U,
        },
        Unit,
    }
    impl<T, U> PinnedDrop for Enum<T, U> {
        fn drop(this: Pin<&mut Self>) {
            let _ = this;
        }
    }
}

fn main() {}

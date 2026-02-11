// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial OR MIT

use pin_project_lite::pin_project;

pin_project! {
    pub struct S {
        #[pin]
        field: u8,
    }
    impl PinnedDrop for S {
        fn drop(this: Pin<&mut Self>) {
            __drop_inner(this);
        }
    }
}

fn main() {
    let _x = S { field: 0 };
}

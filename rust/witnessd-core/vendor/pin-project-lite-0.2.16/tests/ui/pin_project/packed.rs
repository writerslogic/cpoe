// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial OR MIT

use pin_project_lite::pin_project;

pin_project! { //~ ERROR reference to packed field is unaligned
    #[repr(packed, C)]
    struct Packed {
        #[pin]
        field: u16,
    }
}

pin_project! { //~ ERROR reference to packed field is unaligned
    #[repr(packed(2))]
    struct PackedN {
        #[pin]
        field: u32,
    }
}

fn main() {}

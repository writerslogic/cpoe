// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial OR MIT

#![allow(dead_code, unused_macros)]

macro_rules! assert_unpin {
    ($ty:ty) => {
        static_assertions::assert_impl_all!($ty: Unpin);
    };
}
macro_rules! assert_not_unpin {
    ($ty:ty) => {
        static_assertions::assert_not_impl_all!($ty: Unpin);
    };
}

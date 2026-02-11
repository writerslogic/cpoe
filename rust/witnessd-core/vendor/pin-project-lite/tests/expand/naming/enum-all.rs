// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial OR MIT

use pin_project_lite::pin_project;

pin_project! {
    #[project = EnumProj]
    #[project_ref = EnumProjRef]
    #[project_replace = EnumProjReplace]
    enum Enum<T, U> {
        Struct {
            #[pin]
            pinned: T,
            unpinned: U,
        },
        Unit,
    }
}

fn main() {}

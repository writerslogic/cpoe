// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial OR MIT

use pin_project_lite::pin_project;

pin_project! { //~ ERROR E0263,E0496
    pub struct Foo<'__pin, T> {
        #[pin]
        field: &'__pin mut T,
    }
}

fn main() {}

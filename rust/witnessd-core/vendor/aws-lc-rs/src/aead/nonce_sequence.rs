// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial OR ISC

//! Implementations of `NonceSequence` for use with `BoundKey`s.

mod counter32;
mod counter64;

pub use counter32::{Counter32, Counter32Builder};
pub use counter64::{Counter64, Counter64Builder};

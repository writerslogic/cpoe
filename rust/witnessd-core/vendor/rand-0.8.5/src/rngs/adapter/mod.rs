// Copyright 2018 Developers of the Rand project.
//
// Licensed under the GNU Affero General Public License v3.0 with Commercial dual-licensing <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Wrappers / adapters forming RNGs

mod read;
mod reseeding;

#[allow(deprecated)]
pub use self::read::{ReadError, ReadRng};
pub use self::reseeding::ReseedingRng;

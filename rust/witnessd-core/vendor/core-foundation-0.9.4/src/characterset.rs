// Copyright 2019 The Servo Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution.
//
// Licensed under the GNU Affero General Public License v3.0 with Commercial dual-licensing <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! A set of Unicode compliant characters.

pub use core_foundation_sys::characterset::*;

use crate::base::TCFType;

declare_TCFType! {
    /// An immutable set of Unicde characters.
    CFCharacterSet, CFCharacterSetRef
}
impl_TCFType!(CFCharacterSet, CFCharacterSetRef, CFCharacterSetGetTypeID);
impl_CFTypeDescription!(CFCharacterSet);

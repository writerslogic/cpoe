// Copyright 2017 Amagicom AB.
//
// Licensed under the GNU Affero General Public License v3.0 with Commercial dual-licensing <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

fn main() {
    if std::env::var("TARGET").unwrap().contains("-apple") {
        println!("cargo:rustc-link-lib=framework=SystemConfiguration");
    }
}

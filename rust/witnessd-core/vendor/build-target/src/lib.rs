#![allow(clippy::needless_doctest_main, clippy::should_implement_trait)]

//! A crate that provides programmatic access to information about the current build target inside `build.rs`.
//!
//! ## Examples
//! Prints all available information about the current build target.
//! ```rust no_run
//! // inside build.rs
//!
//! fn main() {
//!     // The panic is just used to print the information to the console.
//!     panic!("current build target: {:#?}",
//!         build_target::target().unwrap()
//!     );
//! }
//! ```
//!
//! Gets the parts of the current build target individually.
//! ```rust no_run
//! // inside build.rs
//!
//! fn main() {
//!     let arch   = build_target::target_arch().unwrap();   // eg. "x86_64", "aarch64", ...
//!     let env    = build_target::target_env().unwrap();    // eg. "gnu", "msvc", ...
//!     let family = build_target::target_family().unwrap(); // eg. "windows", "unix", ...
//!     let os     = build_target::target_os().unwrap();     // eg. "android", "linux", ...
//!     let triple = build_target::target_triple().unwrap(); // eg. "x86_64-unknown-linux-gnu", ...
//! }
//! ```

mod arch;
pub use arch::*;

mod env;
pub use env::*;

mod os;
pub use os::*;

mod family;
pub use family::*;

mod target;
pub use target::*;

mod profile;
pub use profile::*;

mod utils;

/// Gets the current target [`Arch`]. This function is equivalent to [`Arch::target()`].
pub fn target_arch() -> Result<Arch<'static>, std::env::VarError> {
    Arch::target()
}
/// Gets the current target [`Env`]. This function is equivalent to [`Env::target()`].
pub fn target_env() -> Result<Env<'static>, std::env::VarError> {
    Env::target()
}
/// Gets the current target [`Os`]. This function is equivalent to [`Os::target()`].
pub fn target_os() -> Result<Os<'static>, std::env::VarError> {
    Os::target()
}
/// Gets the current target [`Family`]. This function is equivalent to [`Family::target()`].
pub fn target_family() -> Result<Family<'static>, std::env::VarError> {
    Family::target()
}
/// Gets the current target triple.
pub fn target_triple() -> Result<String, std::env::VarError> {
    std::env::var("TARGET")
}
/// Gets the current target information as a [`Target`]. This function is equivalent to [`Target::current()`].
pub fn target() -> Result<Target<'static>, std::env::VarError> {
    Target::current()
}

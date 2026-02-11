use std::{
    borrow::Cow,
    env::{self, VarError},
    fmt,
};

use crate::utils;

/// A a more generic description of a target, such as the family of
/// the operating systems or architectures that the target generally falls into.
#[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Family<'a> {
    /// `unix`: Unix based operating systems
    Unix,

    /// `windows`: Microsoft's Windows operating system
    Windows,

    /// `wasm`: WebAssembly
    Wasm,

    /// Operating system family we don't know about
    Other(Cow<'a, str>),
}

impl<'a> Family<'a> {
    /// String representing this target family which matches `#[cfg(target_family)]`
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Family::Unix => "unix",
            Family::Windows => "windows",
            Family::Wasm => "wasm",
            Family::Other(s) => s,
        }
    }

    /// Tries to parse the given string as an [`Family`] falling back to [`Family::Other`] for unknown values.
    pub fn from_str(os_family: impl Into<Cow<'a, str>>) -> Self {
        let os_family = utils::into_ascii_lowercase(os_family.into());
        match os_family.as_ref() {
            "unix" => Family::Unix,
            "windows" => Family::Windows,
            "wasm" => Family::Wasm,
            _ => Family::Other(os_family),
        }
    }

    /// Gets the current target [`Family`].
    pub fn target() -> Result<Self, VarError> {
        env::var("CARGO_CFG_TARGET_FAMILY").map(Self::from_str)
    }
}

impl<'a> fmt::Display for Family<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

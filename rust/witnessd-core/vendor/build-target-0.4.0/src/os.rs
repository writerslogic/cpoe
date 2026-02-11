use std::{
    borrow::Cow,
    env::{self, VarError},
    fmt,
};

use crate::utils;

// adapted from target/os.rs from platforms crate
/// Operating system of the target.
///
/// # Note
/// This value is closely related to the second
/// and third element of the platform target triple, though it is not identical.
#[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Os<'a> {
    /// `android`: Google's Android mobile operating system
    Android,

    /// `bitrig`: OpenBSD-based operating system
    Bitrig,

    /// `cloudabi`: Nuxi CloudABI runtime environment
    CloudABI,

    /// `dragonfly`: DragonflyBSD
    Dragonfly,

    /// `emscripten`: The emscripten JavaScript transpiler
    Emscripten,

    /// `freebsd`: The FreeBSD operating system
    FreeBSD,

    /// `fuchsia`: Google's next-gen Rust Os
    Fuchsia,

    /// `haiku`: Haiku, an open source BeOs clone
    Haiku,

    /// `ios`: Apple's iOs mobile operating system
    #[allow(non_camel_case_types)]
    iOs,

    /// `linux`: Linux
    Linux,

    /// `macos`: Apple's Mac Os X
    MacOs,

    /// `netbsd`: The NetBSD operating system
    NetBSD,

    /// `openbsd`: The OpenBSD operating system
    OpenBSD,

    /// `redox`: Redox, a Unix-like Os written in Rust
    Redox,

    /// `solaris`: Oracle's (formerly Sun) Solaris operating system
    Solaris,

    /// `windows`: Microsoft's Windows operating system
    Windows,

    /// Operating systems we don't know about
    Other(Cow<'a, str>),
}

impl<'a> Os<'a> {
    /// String representing this target OS which matches `#[cfg(target_os)]`
    pub fn as_str(&self) -> &str {
        match self {
            Os::Android => "android",
            Os::Bitrig => "bitrig",
            Os::CloudABI => "cloudabi",
            Os::Dragonfly => "dragonfly",
            Os::Emscripten => "emscripten",
            Os::FreeBSD => "freebsd",
            Os::Fuchsia => "fuchsia",
            Os::Haiku => "haiku",
            Os::iOs => "ios",
            Os::Linux => "linux",
            Os::MacOs => "macos",
            Os::NetBSD => "netbsd",
            Os::OpenBSD => "openbsd",
            Os::Redox => "redox",
            Os::Solaris => "solaris",
            Os::Windows => "windows",
            Os::Other(s) => s,
        }
    }

    /// Tries to parse the given string as an [`Os`] falling back to [`Os::Other`] for unknown values.
    pub fn from_str(os: impl Into<Cow<'a, str>>) -> Self {
        let os = utils::into_ascii_lowercase(os.into());
        match os.as_ref() {
            "android" => Os::Android,
            "bitrig" => Os::Bitrig,
            "cloudabi" => Os::CloudABI,
            "dragonfly" => Os::Dragonfly,
            "emscripten" => Os::Emscripten,
            "freebsd" => Os::FreeBSD,
            "fuchsia" => Os::Fuchsia,
            "haiku" => Os::Haiku,
            "ios" => Os::iOs,
            "linux" => Os::Linux,
            "macos" => Os::MacOs,
            "netbsd" => Os::NetBSD,
            "openbsd" => Os::OpenBSD,
            "redox" => Os::Redox,
            "solaris" => Os::Solaris,
            "windows" => Os::Windows,
            _ => Os::Other(os),
        }
    }

    /// Gets the current target [`Os`].
    pub fn target() -> Result<Self, VarError> {
        env::var("CARGO_CFG_TARGET_OS").map(Self::from_str)
    }
}

impl<'a> fmt::Display for Os<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

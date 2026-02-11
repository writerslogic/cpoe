use std::{
    borrow::Cow,
    env::{self, VarError},
    fmt,
};

use crate::utils;

// adapted from target/env.rs from platforms crate
/// Target enviroment that disambiguates the target platform by ABI / libc.
///
/// # Note
/// This value is closely related to the fourth element of the platform target triple,
/// though it is not identical. For example, embedded ABIs such as `gnueabihf` will simply
/// define `target_env` as `"gnu"` (i.e. [`Env::GNU`])
#[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Env<'a> {
    /// `gnu`: The GNU C Library (glibc)
    GNU,

    /// `msvc`: Microsoft Visual C(++)
    MSVC,

    /// `musl`: Clean, efficient, standards-conformant libc implementation.
    Musl,

    /// `sgx`: Intel Software Guard Extensions (SGX) Enclave
    SGX,

    /// `uclibc`: C library for developing embedded Linux systems
    #[allow(non_camel_case_types)]
    uClibc,

    /// Unknown target environment
    Other(Cow<'a, str>),
}

impl<'a> Env<'a> {
    /// String representing this environment which matches `#[cfg(target_env)]`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Env::GNU => "gnu",
            Env::MSVC => "msvc",
            Env::Musl => "musl",
            Env::SGX => "sgx",
            Env::uClibc => "uclibc",
            Env::Other(s) => s,
        }
    }

    /// Tries to parse the given string as an [`Env`] falling back to [`Env::Other`] for unknown values.
    pub fn from_str(env_name: impl Into<Cow<'a, str>>) -> Self {
        let env_name = utils::into_ascii_lowercase(env_name.into());
        match env_name.as_ref() {
            "gnu" => Env::GNU,
            "msvc" => Env::MSVC,
            "musl" => Env::Musl,
            "sgx" => Env::SGX,
            "uclibc" => Env::uClibc,
            _ => Env::Other(env_name),
        }
    }

    /// Gets the current target [`Env`].
    pub fn target() -> Result<Self, VarError> {
        env::var("CARGO_CFG_TARGET_ENV").map(Self::from_str)
    }
}

impl<'a> fmt::Display for Env<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

use std::{
    borrow::Cow,
    env::{self, VarError},
    fmt,
};

use crate::utils;

/// Profile of the current build.
#[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Profile<'a> {
    /// `dev`: The dev profile is used for normal development and debugging.
    /// It is the default for build commands like `cargo build`.
    Dev,

    /// `release`: The release profile is intended for optimized artifacts used for releases and in production.
    /// This profile is used when the `--release` flag is used, and is the default for `cargo install`.
    Release,

    /// `test`: The test profile is used for building tests, or when benchmarks are built in debug mode with `cargo build`.
    Test,

    /// `bench`: The bench profile is used for building benchmarks, or when tests are built with the `--release` flag.
    Bench,

    /// Custom or unknown profile.
    Other(Cow<'a, str>),
}

impl<'a> Profile<'a> {
    /// String representing this target profile.
    pub fn as_str(&self) -> &str {
        match self {
            Profile::Dev => "dev",
            Profile::Release => "release",
            Profile::Test => "test",
            Profile::Bench => "bench",
            Profile::Other(s) => s,
        }
    }

    /// Tries to parse the given string as an [`Profile`] falling back to [`Profile::Other`] for unknown values.
    pub fn from_str(profile: impl Into<Cow<'a, str>>) -> Self {
        let profile = utils::into_ascii_lowercase(profile.into());
        match profile.as_ref() {
            "dev" => Profile::Dev,
            "release" => Profile::Release,
            "test" => Profile::Test,
            "bench" => Profile::Bench,
            _ => Profile::Other(profile),
        }
    }

    /// Gets the current [`Profile`].
    pub fn current() -> Result<Self, VarError> {
        env::var("PROFILE").map(Self::from_str)
    }
}

impl<'a> fmt::Display for Profile<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

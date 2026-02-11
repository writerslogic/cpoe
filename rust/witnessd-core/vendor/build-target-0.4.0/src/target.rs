use std::{borrow::Cow, env::VarError};

use crate::{target_triple, Arch, Env, Family, Os};

/// Combined information about a build target.
#[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct Target<'a> {
    pub arch: Arch<'a>,
    pub env: Env<'a>,
    pub os: Os<'a>,
    pub family: Family<'a>,
    pub triple: Cow<'a, str>,
}

impl<'a> Target<'a> {
    /// Gets the current build target as a [`Target`].
    pub fn current() -> Result<Self, VarError> {
        Ok(Self {
            arch: Arch::target()?,
            env: Env::target()?,
            os: Os::target()?,
            family: Family::target()?,
            triple: target_triple()?.into(),
        })
    }
}

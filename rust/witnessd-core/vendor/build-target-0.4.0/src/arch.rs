use std::{
    borrow::Cow,
    env::{self, VarError},
    fmt,
};

use crate::utils;

// adapted from target/arch.rs from platforms crate
/// Target CPU architecture
#[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Arch<'a> {
    /// `aarch64`: ARMv8 64-bit architecture
    AARCH64,

    /// `arm`: 32-bit ARM architecture
    ARM,

    /// `asm`: asm.js output
    ASMJS,

    /// `mips`: 32-bit MIPS CPU architecture
    MIPS,

    /// `mips64`: 32-bit MIPS CPU architecture
    MIPS64,

    /// `msp430`: 16-bit MSP430 microcontrollers
    MSP430,

    /// `powerpc`: 32-bit POWERPC platform
    POWERPC,

    /// `powerpc64`: 64-bit POWERPC platform
    POWERPC64,

    /// `riscv`: RISC-V CPU architecture
    RISCV,

    /// `s390x`: 64-bit IBM z/Architecture
    S390X,

    /// `sparc`: 32-bit SPARC CPU architecture
    SPARC,

    /// `sparc64`: 64-bit SPARC CPU architecture
    SPARC64,

    /// `thumbv6`: 16-bit ARM CPU architecture subset
    THUMBV6,

    /// `thumbv7`: 16-bit ARM CPU architecture subset
    THUMBV7,

    /// `wasm32`: Web Assembly (32-bit)
    WASM32,

    /// `x86`: Generic x86 CPU architecture
    X86,

    /// `x86_64`: "AMD64" CPU architecture
    X86_64,

    /// Unknown CPU architecture
    Other(Cow<'a, str>),
}

impl<'a> Arch<'a> {
    /// String representing this target architecture which matches `#[cfg(target_arch)]`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Arch::AARCH64 => "aarch64",
            Arch::ARM => "arm",
            Arch::ASMJS => "asmjs",
            Arch::MIPS => "mips",
            Arch::MIPS64 => "mips64",
            Arch::MSP430 => "msp430",
            Arch::POWERPC => "powerpc",
            Arch::POWERPC64 => "powerpc64",
            Arch::RISCV => "riscv",
            Arch::S390X => "s390x",
            Arch::SPARC => "sparc",
            Arch::SPARC64 => "sparc64",
            Arch::THUMBV6 => "thumbv6",
            Arch::THUMBV7 => "thumbv7",
            Arch::WASM32 => "wasm32",
            Arch::X86 => "x86",
            Arch::X86_64 => "x86_64",
            Arch::Other(s) => s,
        }
    }

    /// Tries to parse the given string as an [`Arch`] falling back to [`Arch::Other`] for unknown values.
    pub fn from_str(arch_name: impl Into<Cow<'a, str>>) -> Self {
        let arch_name = utils::into_ascii_lowercase(arch_name.into());
        match arch_name.as_ref() {
            "aarch64" => Arch::AARCH64,
            "arm" => Arch::ARM,
            "asmjs" => Arch::ASMJS,
            "mips" => Arch::MIPS,
            "mips64" => Arch::MIPS64,
            "msp430" => Arch::MSP430,
            "powerpc" => Arch::POWERPC,
            "powerpc64" => Arch::POWERPC64,
            "riscv" => Arch::RISCV,
            "s390x" => Arch::S390X,
            "sparc" => Arch::SPARC,
            "sparc64" => Arch::SPARC64,
            "thumbv6" => Arch::THUMBV6,
            "thumbv7" => Arch::THUMBV7,
            "wasm32" => Arch::WASM32,
            "x86" => Arch::X86,
            "x86_64" => Arch::X86_64,
            _ => Arch::Other(arch_name),
        }
    }

    /// Gets the current target [`Arch`].
    pub fn target() -> Result<Self, VarError> {
        env::var("CARGO_CFG_TARGET_ARCH").map(Self::from_str)
    }
}

impl<'a> fmt::Display for Arch<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

# build-target

[![CI](https://github.com/OpenByteDev/build-target/actions/workflows/ci.yml/badge.svg)](https://github.com/OpenByteDev/build-target/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/build-target.svg)](https://crates.io/crates/build-target)
[![Documentation](https://docs.rs/build-target/badge.svg)](https://docs.rs/build-target)
[![dependency status](https://deps.rs/repo/github/openbytedev/build-target/status.svg)](https://deps.rs/repo/github/openbytedev/build-target)
[![MIT](https://img.shields.io/crates/l/build-target.svg)](https://github.com/OpenByteDev/build-target/blob/master/LICENSE)

A crate that provides programmatic access to information about the current build target inside `build.rs`.

## Examples
Prints all available information about the current build target.
```rust
// inside build.rs

fn main() {
    // The panic is just used to print the information to the console.
    panic!("current build target: {:#?}",
        build_target::target().unwrap()
    );
}
```

Gets the parts of the current build target individually.
```rust
// inside build.rs

fn main() {
    let arch   = build_target::target_arch().unwrap();   // eg. "x86_64", "aarch64", ...
    let env    = build_target::target_env().unwrap();    // eg. "gnu", "msvc", ...
    let family = build_target::target_family().unwrap(); // eg. "windows", "unix", ...
    let os     = build_target::target_os().unwrap();     // eg. "android", "linux", ...
    let triple = build_target::target_triple().unwrap(); // eg. "x86_64-unknown-linux-gnu", ...
}
```

## Attribution
This crate is inspired by and partially based on [`platforms`](https://crates.io/crates/platforms).

## License
Licensed under MIT license ([LICENSE](https://github.com/OpenByteDev/build-target/blob/master/LICENSE) or http://opensource.org/licenses/MIT)

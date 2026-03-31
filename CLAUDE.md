# CPOP - Cryptographic Authorship Witnessing

## What This Project Is

CPOP is a cryptographic engine for **proof-of-process authorship attestation**. It captures behavioral evidence (keystrokes, timing jitter, mouse movements, focus events) during document creation and packages it into cryptographically signed evidence packets that prove a human authored content. The project implements the **draft-condrey-rats-pop** IETF protocol specification.

## Repository Structure

```
writerslogic/
├── crates/
│   ├── cpop-engine/     # Core engine (SSPL-1.0) - main crate
│   ├── cpop-jitter/     # Timing jitter entropy primitive (Apache-2.0, no_std capable)
│   └── cpop-protocol/   # Wire protocol (CBOR/COSE, Apache-2.0, wasm-ready)
├── apps/
│   ├── cpop_cli/        # CLI + native messaging host (AGPL-3.0-only)
│   ├── cpop_macos/      # macOS GUI app (submodule)
│   └── cpop_windows/    # Windows GUI app (submodule)
└── docs/                    # Documentation
```

### Why 3 Crates?

The crates are split by **compilation target**, not by size:

| Crate | Target | Why separate |
|-------|--------|-------------|
| `cpop-jitter` | `no_std` (bare-metal, embedded) | Runs on microcontrollers with no OS. Zero platform dependencies, alloc only. |
| `cpop-protocol` | `wasm32` (browsers) | Runs in browser extensions for client-side evidence verification. No platform-specific code. |
| `cpop-engine` | Native (macOS/Windows/Linux) | Requires OS APIs (CGEventTap, TPM, SQLite, Unix sockets). Cannot compile to wasm or no_std. |

Merging them would break wasm and no_std compilation because the engine's platform dependencies (macOS frameworks, Windows hooks, SQLite) don't exist in those environments. The dependency graph is strictly one-directional: `engine -> protocol -> jitter`.

## Build & Test Commands

```sh
# Run engine tests (fastest feedback loop)
cargo test -p cpop-engine --lib

# Run full workspace tests
cargo test --workspace

# Clippy (zero warnings maintained)
cargo clippy --workspace -- -D warnings

# Format check
cargo fmt --all -- --check

# Build with all features
cargo build --workspace --all-features
```

## Key Architecture Decisions

### Module Organization
- **Directory-based submodules** for large modules: `forensics/`, `keyhierarchy/`, `ipc/`, `evidence/`, `sentinel/`
- Each has a `mod.rs` that re-exports public types
- Platform-specific `cfg` gates go in `mod.rs`, NOT in the submodule files themselves
- Factory functions in `platform/mod.rs` select implementations per-platform

### Error Handling
- Unified `Error` enum in `crates/cpop-engine/src/error.rs` using `thiserror`
- Subsystem errors wrap via `#[from]`, common errors use `String` constructors
- Constructor helpers: `Error::checkpoint("msg")`, `Error::crypto("msg")`, etc.
- Use `crate::error::{Error, Result}` throughout the engine crate

### Platform Support
- **macOS**: CGEventTap + IOKit HID (dual-layer validation), Secure Enclave
- **Windows**: WH_KEYBOARD_LL / WH_MOUSE_LL hooks, TPM 2.0
- **Linux**: evdev + X11/Wayland, TPM via tss-esapi
- Platform traits: `KeystrokeCapture`, `FocusMonitor`, `MouseCapture`, `HIDEnumerator`

### Cryptography
- Ed25519 (ed25519-dalek) for signing
- ChaCha20-Poly1305 for IPC secure channels
- SHA-256 / BLAKE3 for hashing
- HMAC-SHA256 for event integrity
- HKDF for key derivation
- Zeroize all key material after use (`zeroize` crate with `Drop` impl)
- BIP-39 mnemonic for identity seed phrases

### Serialization
- **Wire format**: CBOR (ciborium) with COSE signatures (coset) per RFC 8949
- **Storage**: SQLite (rusqlite with bundled), bincode for internal
- **Config**: TOML
- **API**: serde_json

### Concurrency Model
- Tokio async runtime for IPC server and network operations
- `std::sync::mpsc` channels for platform event capture → sentinel bridge
- `Arc<RwLock<>>` for shared state in sentinel daemon
- `DashMap` for concurrent collections

## Coding Conventions

- **Dead code**: Use targeted `#[allow(dead_code)]` on specific items, never blanket `#![allow(dead_code)]` at file level
- **IPC constants**: Reference `super::messages::MAX_MESSAGE_SIZE`, don't hardcode `1024 * 1024`
- **Formatting**: `rustfmt.toml` → edition 2021, max_width 100
- **Indentation**: 4 spaces for Rust (see `.editorconfig`)
- **MSRV**: Rust 1.75.0
- **Linting**: A linter runs on file save and may auto-fix; always re-read files immediately before editing
- **License headers**: `// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial` at top of engine/protocol/CLI files

## Important Subsystems

| Module | Purpose |
|--------|---------|
| `sentinel/` | Daemon that monitors keystrokes, focus, mouse; manages sessions |
| `keyhierarchy/` | Key derivation tree, session certificates, PUF binding |
| `evidence/` | Evidence packet builder and types (30+ evidence fields) |
| `forensics/` | Post-hoc analysis: velocity, cadence, behavioral assessment |
| `checkpoint/` | Checkpoint chain with VDF proofs and entanglement modes |
| `ipc/` | Unix socket IPC with encrypted channels and rate limiting |
| `jitter/` | Timing jitter analysis, typing profiles, zone-based detection |
| `platform/` | OS-specific keystroke/mouse/focus capture |
| `tpm/` | TPM/Secure Enclave attestation (software fallback for tests) |
| `vdf/` | Verifiable delay functions, Roughtime client, Merkle VDF |
| `mmr/` | Merkle Mountain Range for efficient append-only proofs |
| `wal/` | Write-ahead log with signed entries |
| `store/` | SQLite secure event storage with HMAC integrity |
| `ffi/` | UniFFI bindings for Swift/Kotlin (feature-gated) |

## Feature Flags

- `default` — no optional features
- `cpop_jitter` — enable hardware entropy jitter integration
- `secure-enclave` — macOS Secure Enclave support
- `x11` — Linux X11 focus detection
- `ffi` — UniFFI bindings for Swift/Kotlin GUI apps

## Dependencies to Know

- `cargo-deny` configured in `deny.toml` for license and advisory auditing
- `cpop_jitter` is `no_std` compatible (alloc only) for embedded use
- `cpop_protocol` supports wasm target (feature `wasm`)

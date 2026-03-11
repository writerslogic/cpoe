# Changelog

All notable changes to the WritersLogic project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-03-10

### Added
- Unified CLI: `wld <file>` tracks keystrokes, `wld <folder>` watches for changes
- Graceful Ctrl+C shutdown in watch mode with `ctrlc` handler
- Atomic file operations (tmp+rename) for identity backup
- PID file locking with stale-PID detection for daemon
- Homebrew tap and Scoop bucket auto-update via CI release pipeline
- Build attestation and SBOM generation in release workflow
- Cross-compilation for 4 targets (Linux x86_64, macOS ARM/x86_64, Windows x86_64)
- Ephemeral checkpoint hash, canary seed, and identity mnemonic FFI bindings

### Changed
- CLI commands reviewed and hardened for production use
- `wld verify` now exits with code 1 on verification failure
- Export no longer requires unused `session_id` parameter
- `wld identity` (no flags) shows fingerprint + DID + public key
- Monorepo architecture consolidating engine, protocol, jitter, and CLI
- Workspace-level dependency management

### Fixed
- Commit stored message in wrong field (`context_type` instead of `context_note`)
- Log displayed wrong field for checkpoint messages
- File existence checked after `canonicalize` (crashed on missing files)
- Non-regular files (devices, sockets) accepted by track command
- Verify returned exit 0 on verification failure
- Config edit accepted invalid config without re-prompting
- Duplicate `writerslogic` binary target removed (only `wld` binary)
- Permission-denied errors in status command now show diagnostic message
- Empty files and oversized files now handled gracefully in commit/watch

### Security
- Anti-forgery hardening: cross-modal consistency checks, forgery cost estimation
- Browser extension: session nonce, monotonic ordinals, rate limiting
- Key zeroization on error paths across engine crate
- Lock unwrap patterns replaced with MutexRecover/RwLockRecover traits
- NaN/Inf guards on all division results

## [0.2.0] - 2026-02-22

### Added
- wld_protocol crate for PoP wire format (CBOR/COSE)
- wld_jitter `no_std` support and security hardening
- Fuzz targets for VDF and protocol components
- Browser extension with native messaging host
- IPC server/client architecture for daemon communication

### Changed
- Wire format aligned with draft-condrey-rats-pop CDDL schema
- Evidence module refactored into submodules
- Key hierarchy module refactored into submodules

## [0.1.0] - 2026-02-01

### Added
- Initial release of wld_engine
- Merkle Mountain Range (MMR) for tamper-evident event storage
- Ed25519 signing with domain separation
- VDF-based time proofs
- Keystroke dynamics behavioral analysis
- TPM 2.0 integration (Linux)
- Secure Enclave support (macOS)
- SQLite-backed persistent storage with WAL/WAR
- UniFFI bindings for Swift/Kotlin

[Unreleased]: https://github.com/writerslogic/witnessd/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/writerslogic/witnessd/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/writerslogic/witnessd/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/writerslogic/writerslogic/releases/tag/v0.1.0

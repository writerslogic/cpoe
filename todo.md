# CPOP — Unified Todo

## Session State
<!-- suggest | Updated: 2026-03-18 | Domain: code | Languages: rust | Files: 20 CLI | Issues: 42 -->

## Summary
| Severity | Open | Fixed | Skipped |
|----------|------|-------|---------|
| CRITICAL | 0    | 6     | 0       |
| HIGH     | 18   | 0     | 0       |
| MEDIUM   | 18   | 0     | 0       |

## Systemic Issues
- [x] **SYS-001** `non_atomic_key_write` — 3 files — CRITICAL
  Files: `cmd_identity.rs:92`, `cmd_init.rs:54`, `util.rs:172`
  fs::write() then restrict_permissions() is non-atomic. If chmod fails, key file is world-readable.
  Fix: Write to temp file with restrictive umask, then atomic rename.

- [ ] **SYS-002** `toctou_file_ops` — 4 files — HIGH
  Files: `cmd_track.rs:238`, `cmd_track.rs:678`, `cmd_presence.rs:240`, `cmd_export.rs:560`
  File metadata checked, then file read without locking. Race window for replacement/deletion.

- [ ] **SYS-003** `silent_error_swallow` — 4 files — HIGH
  Files: `native_messaging_host.rs:381`, `cmd_track.rs:517`, `cmd_daemon.rs:96`, `native_messaging_host.rs:270`
  Errors converted to defaults or logged without propagation.

## Critical
- [x] **C-001** `[security]` `cmd_track.rs:1266` — Export paths relative, arbitrary file write if CWD controlled
  Impact: Evidence files written to attacker-controlled location | Fix: tracking_dir.join() | Effort: small

- [x] **C-002** `[security]` `native_messaging_host.rs:381` — hex::decode error returns empty vec, bypassing commitment
  Impact: Browser commitment chain bypass | Fix: Return error on decode failure | Effort: small

- [x] **C-003** `[security]` `native_messaging_host.rs:608` — Division by zero in compute_jitter_stats
  Impact: NaN/panic | Fix: Guard with is_empty() | Effort: small

## High
- [ ] **H-001** `[security]` `cmd_export.rs:732` — Wire packet profile_uri hardcoded ignoring spec parameter
  Impact: Wrong profile URI for enhanced/maximum tiers | Effort: medium

- [ ] **H-002** `[security]` `cmd_export.rs:33` — Session lookup string contains() fallback = path injection
  Impact: Wrong session selected | Effort: medium

- [ ] **H-003** `[concurrency]` `cmd_track.rs:323` — Keystroke thread panics silently, evidence lost
  Impact: All keystroke data lost | Effort: medium

- [ ] **H-004** `[concurrency]` `cmd_track.rs:374` — Mutex poison at finalization = entire session lost
  Impact: Complete session loss | Fix: into_inner() recovery | Effort: small

- [ ] **H-005** `[concurrency]` `cmd_track.rs:512` — Database unsynchronized across watcher callbacks
  Impact: SQLite BUSY, checkpoint loss | Fix: Wrap in Mutex | Effort: medium

- [ ] **H-006** `[performance]` `cmd_track.rs:551` — Debounce HashMap unbounded (memory leak)
  Impact: RAM grows unbounded | Fix: LRU eviction | Effort: small

- [ ] **H-007** `[security]` `cmd_track.rs:567` — Symlink attack in watcher events
  Impact: Checkpoint arbitrary files | Fix: fs::canonicalize() | Effort: small

- [ ] **H-008** `[concurrency]` `native_messaging_host.rs:256` — Mutex poison recovery silences corruption
  Impact: Corrupted session state used | Effort: small

- [ ] **H-009** `[security]` `cmd_verify.rs:352` — HMAC key truncation ambiguous for 64-byte keys
  Impact: Wrong key material used | Effort: small

- [ ] **H-010** `[error_handling]` `cmd_verify.rs:23` — Unknown extension routes to db verification
  Impact: Wrong verification path | Fix: Return error | Effort: small

- [ ] **H-011** `[error_handling]` `cmd_track.rs:517` — Initial checkpoint errors ignored, zero evidence
  Impact: User unaware | Effort: small

- [ ] **H-012** `[security]` `util.rs:113` — HMAC key not zeroized after SecureStore::open()
  Impact: Key material in memory | Effort: small

- [ ] **H-013** `[error_handling]` `main.rs:171` — print_long_help().unwrap() panics on IO failure
  Impact: CLI crash | Fix: .ok() | Effort: small

- [ ] **H-014** `[error_handling]` `cmd_daemon.rs:86` — Child process never awaited
  Impact: Daemon failure undetected | Effort: medium

- [ ] **H-015** `[concurrency]` `cmd_presence.rs:240` — TOCTOU in session modification detection
  Impact: Stale session data | Effort: medium

- [ ] **H-016** `[error_handling]` `cmd_presence.rs:104` — debug_assert only, silent in release
  Impact: Counter inconsistency | Fix: assert!() | Effort: small

- [ ] **H-017** `[security]` `cmd_config.rs:211` — Editor path relative, $PATH injection
  Impact: Arbitrary code execution | Fix: Resolve absolute | Effort: small

- [ ] **H-018** `[error_handling]` `cmd_export.rs:85` — SQLite lock contention with daemon
  Impact: Export fails during tracking | Fix: Retry with backoff | Effort: medium

## Quick Wins (effort=small, CRITICAL or HIGH)
| ID | Sev | File:Line | Issue |
|----|-----|-----------|-------|
| C-001 | CRIT | cmd_track.rs:1266 | Relative path write |
| C-002 | CRIT | native_messaging_host.rs:381 | hex::decode bypass |
| C-003 | CRIT | native_messaging_host.rs:608 | Division by zero |
| H-004 | HIGH | cmd_track.rs:374 | Mutex poison recovery |
| H-006 | HIGH | cmd_track.rs:551 | Unbounded HashMap |
| H-007 | HIGH | cmd_track.rs:567 | Symlink attack |
| H-010 | HIGH | cmd_verify.rs:23 | Format confusion |
| H-012 | HIGH | util.rs:113 | Key zeroize leak |
| H-013 | HIGH | main.rs:171 | unwrap on IO |
| H-016 | HIGH | cmd_presence.rs:104 | debug_only_assert |
| H-017 | HIGH | cmd_config.rs:211 | PATH injection |

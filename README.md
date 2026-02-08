<p align="center">
  <img src="assets/logo.svg" alt="witnessd" width="400">
</p>

<p align="center">
  <strong>Tamper-evident documentation of authorship process through cryptographic attestation</strong>
</p>

<p align="center">
  <a href="https://github.com/writerslogic/witnessd/actions/workflows/ci.yml"><img src="https://github.com/writerslogic/witnessd/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/writerslogic/witnessd/actions/workflows/release.yml"><img src="https://github.com/writerslogic/witnessd/actions/workflows/release.yml/badge.svg" alt="Release"></a>
  <a href="https://slsa.dev/spec/v1.0/levels#build-l3"><img src="https://slsa.dev/images/gh-badge-level3.svg" alt="SLSA Level 3"></a>
  <a href="https://github.com/writerslogic/witnessd/releases/latest"><img src="https://img.shields.io/github/v/release/writerslogic/witnessd?label=release" alt="Release"></a>
  <a href="https://goreportcard.com/report/github.com/writerslogic/witnessd"><img src="https://goreportcard.com/badge/github.com/writerslogic/witnessd" alt="Go Report Card"></a>
  <a href="https://pkg.go.dev/github.com/writerslogic/witnessd"><img src="https://pkg.go.dev/badge/github.com/writerslogic/witnessd.svg" alt="Go Reference"></a>
  <a href="https://github.com/writerslogic/witnessd/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-dual-blue" alt="License"></a>
</p>

<p align="center">
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#how-it-works">How It Works</a> •
  <a href="#commands">Commands</a> •
  <a href="#evidence-tiers">Evidence Tiers</a> •
  <a href="#legal">Legal & Licensing</a>
</p>

---

> **Patent Pending:** The system and method for falsifiable process evidence via cryptographic causality locks and behavioral attestation is the subject of USPTO Application No. 19/460,364.

---

## Overview

**witnessd** generates tamper-evident cryptographic records of document authorship through commit-based temporal witnessing. Unlike detection-based approaches that attempt to distinguish human from AI content, witnessd provides a **documentation framework** where authors commit to content states over time and declare their creative process.

### The Forensic Triad

The system achieves "adversarial collapse" by combining three independent mechanisms:

1. **Causality Locks (Temporal)**: Uses **Verifiable Delay Functions (VDFs)** to prove minimum elapsed time between states, ensuring checkpoints cannot be silently back-dated.
2. **Behavioral & Hardware Binding (Identity)**: Uses **Cryptographic Jitter Seals** (keystroke timing) and **TPM/PUF attestations** to tie evidence to real-time human activity and specific hardware.
3. **Ratcheted Evidence Log (Integrity)**: Appends checkpoints to a **Merkle Mountain Range (MMR)** log using keys that are ratcheted and destroyed after use to ensure forward secrecy.

### Key Features

- **Capture Environment Declaration (CED)** — Explicitly records OS, kernel, and security state at session start to prevent environment spoofing.
- **Jitter Seals** — Supporting signal of real-time human interaction through zone-based keystroke timing without capturing content.
- **Hardened Keystroke Capture** — Dual-layer validation (CGEventTap/IOKit) to detect synthetic events and automated scripts.
- **Evidence Strength Tiers** — Basic → Standard → Enhanced → Maximum.
- **External Trust Anchors** — Integration with OpenTimestamps (Bitcoin) and RFC 3161 TSA.

## Installation

**Homebrew (macOS/Linux):**
```bash
brew install writerslogic/tap/witnessd
```

**From source:**
```bash
git clone https://github.com/writerslogic/witnessd
cd witnessd
make install
```

**Binary releases:**
Download from [GitHub Releases](https://github.com/writerslogic/witnessd/releases)

## Configuration

By default, witnessd reads `~/.witnessd/config.toml`. If it doesn't exist,
defaults are used.

Example config:

```bash
cp configs/config.example.toml ~/.witnessd/config.toml
```

## Quick Start

```bash
# 1. Initialize and calibrate
witnessd init && witnessd calibrate

# 2. Start tracking for your document
witnessd track start manuscript.md

# 3. Create checkpoints as you write
witnessd commit manuscript.md -m "Completed chapter 1"

# 4. Export evidence packet
witnessd export manuscript.md -tier enhanced
```

## Enhanced Workflow (with Keystroke Tracking)

For stronger evidence, enable real-time keystroke tracking during writing:

```bash
# 1. Initialize and calibrate (one-time)
witnessd init && witnessd calibrate

# 2. Start keystroke tracking for your document
witnessd track start manuscript.md

# 3. Write your document (keystrokes are counted, NOT captured)
#    - Only keystroke counts and timing are recorded
#    - Zone transitions (which finger) are tracked
#    - This is NOT a keylogger

# 4. Check tracking status
witnessd track status

# 5. Create checkpoints as you write
witnessd commit manuscript.md -m "Draft complete"

# 6. Stop tracking when done
witnessd track stop

# 7. Export with jitter evidence
witnessd export manuscript.md -tier standard
```

**Privacy Guarantee:** Keystroke tracking records ONLY:
- Event counts and timing (not which keys)
- Zone transitions (which finger typed each key)
- Jitter samples (cryptographic proof of real typing)

No actual keystrokes or text content is captured.

Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                         WITNESSD SYSTEM                          │
├──────────────────────────────────────────────────────────────────┤
│    CAUSALITY LOCKS      BEHAVIORAL BINDING      RATCHETED LOG    │
│    (VDF Timeline)      (Jitter / TPM / PUF)     (MMR Structure)  │
└──────────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **witnessd** commands create events (init, commit, track)
2. Events are stored in tamper-evident SQLite database
3. **witnessctl** reads events for status, verification, forensics
4. **Export** bundles events into portable evidence packets
5. **Verify** validates evidence packets independently

### macOS Menu Bar App

The macOS menu bar app is a convenience interface only. It does not implement evidence logic, verification logic, or trust decisions.

This UI invokes the witnessd CLI. All security invariants and evidence semantics live in the CLI.

## How It Works

```
CREATION:
┌─────────────────────────────────────────────────────────────────┐
│  Author writes in any application                               │
│                    ↓                                            │
│  Author runs `witnessd commit` at chosen intervals              │
│                    ↓                                            │
│  Checkpoint created: content_hash + VDF proof + chain link      │
│                    ↓                                            │
│  Chain grows over days/weeks/months                             │
└─────────────────────────────────────────────────────────────────┘

EXPORT:
┌─────────────────────────────────────────────────────────────────┐
│  Author requests evidence export                                │
│                    ↓                                            │
│  System prompts for Process Declaration                         │
│                    ↓                                            │
│  Author declares modalities, AI usage, collaboration            │
│                    ↓                                            │
│  Declaration signed, bound to chain                             │
│                    ↓                                            │
│  Evidence packet generated at requested tier                    │
└─────────────────────────────────────────────────────────────────┘

VERIFICATION:
┌─────────────────────────────────────────────────────────────────┐
│  Verifier receives evidence packet                              │
│                    ↓                                            │
│  Verify chain integrity (hash links)                            │
│                    ↓                                            │
│  Verify VDF proofs (time elapsed)                               │
│                    ↓                                            │
│  Evaluate declaration plausibility against evidence             │
│                    ↓                                            │
│  Decision: Accept, investigate further, or reject               │
└─────────────────────────────────────────────────────────────────┘
```

## Commands

```bash
# Core workflow
witnessd init                    # Initialize witnessd
witnessd calibrate               # Calibrate VDF for your machine
witnessd commit <file> [-m msg]  # Create checkpoint
witnessd log <file>              # Show checkpoint history
witnessd export <file> [-tier T] # Export evidence packet
witnessd verify <file|json>      # Verify chain or evidence
witnessd status                  # Show status

# Keystroke tracking (for jitter evidence)
witnessd track start <file>      # Start tracking keystrokes
witnessd track status            # Show tracking status
witnessd track stop              # Stop tracking and save evidence
witnessd track list              # List saved tracking sessions
witnessd track export <id>       # Export jitter evidence

# Presence verification (optional)
witnessd presence start          # Start presence session
witnessd presence challenge      # Take a presence challenge
witnessd presence stop           # End presence session

# Status
witnessctl status                # Show full system status
witnessctl history               # Show witness history
witnessctl verify <file>         # Verify a file
witnessctl forensics <file>      # Analyze authorship patterns
```

### Creating Checkpoints

```bash
# Basic commit
witnessd commit essay.md

# With message
witnessd commit essay.md -m "Added methodology section"
```

### Presence Verification (Optional)

For stronger evidence, run presence verification during writing sessions:

```bash
# Start a presence session
witnessd presence start

# Periodically verify your presence
witnessd presence challenge

# End the session
witnessd presence stop
```

### Exporting Evidence

```bash
# Basic tier (commits + declaration)
witnessd export essay.md

# Standard tier (+ presence verification)
witnessd export essay.md -tier standard

# Enhanced tier (+ TPM attestation)
witnessd export essay.md -tier enhanced
```

## Evidence Tiers

| Tier | Components | Evidence Signals |
|------|------------|--------|
| **Basic** | Commits + Declaration | Chain integrity, time elapsed, process declared |
| **Standard** | + Presence Verification | Author was physically present during sessions |
| **Enhanced** | + Hardware Attestation | TPM attestation provides hardware-backed signals against rollback andn key misuse |
| **Maximum** | + Behavioral + External | Full forensic analysis + blockchain anchors |

## Process Declaration

When exporting evidence, you must declare your creative process:

```
=== Process Declaration ===
You must declare how this document was created.

Input modality (how was this written?):
  1. Keyboard (typing)
  2. Dictation (voice)
  3. Mixed
Choice [1]: 1

Did you use any AI tools? (y/n)
Choice [n]: y

Which AI tool? (e.g., Claude, ChatGPT, Copilot): Claude
How was it used?
  1. Research/ideation only
  2. Feedback on drafts
  3. Editing assistance
  4. Drafting assistance
Choice [1]: 2

Provide a brief statement about your process:
> I wrote this essay over two weeks, using Claude for feedback on early drafts.
```

The declaration is cryptographically signed and bound to your evidence.

## Jitter Evidence

The keystroke tracking system builds cryptographic proof of real-time typing:

```
┌─────────────────────────────────────────────────────────────────┐
│                     JITTER EVIDENCE CHAIN                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  For each keystroke:                                            │
│    1. Zone detected (which finger: 0-7 from pinky to pinky)     │
│    2. Document hash computed (current content state)             │
│    3. Jitter delay calculated (zone-dependent, entropy-based)    │
│    4. Sample added to chain: zone + delay + doc_hash + prev_hash │
│                                                                  │
│  The chain proves:                                               │
│    • Real keystrokes occurred (zone transitions are realistic)   │
│    • Document evolved over time (hash progression)               │
│    • Timing is consistent with human typing                      │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Zone Layout (QWERTY):**
```
Zone 0 (left pinky):  Q A Z
Zone 1 (left ring):   W S X
Zone 2 (left middle): E D C
Zone 3 (left index):  R T F G V B
Zone 4 (right index): Y U H J N M
Zone 5 (right middle): I K ,
Zone 6 (right ring):  O L .
Zone 7 (right pinky): P ; /
```

Human typing has characteristic patterns between zones. The jitter evidence provides supporting signals consistent with human typing over the documented time period.

## Keystroke Security

The keystroke tracking system uses multiple layers of protection to prevent tampering:

### Primary: CGEventTap (macOS) / evdev (Linux)

```
┌─────────────────────────────────────────────────────────────────┐
│                    HARDENED KEYSTROKE CAPTURE                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. DUAL-LAYER VALIDATION (macOS)                               │
│     • CGEventTap captures keyboard events at system level        │
│     • IOKit HID monitors hardware-level input below CGEventTap   │
│     • Cross-validation detects synthetic events                  │
│                                                                  │
│  2. SYNTHETIC EVENT DETECTION                                    │
│     • Source state ID verification                               │
│     • Keyboard type checking                                     │
│     • Source PID validation                                      │
│     • Timestamp monotonicity                                     │
│                                                                  │
│  3. TIMING ANOMALY DETECTION                                     │
│     • Superhuman speed detection (<20ms intervals)               │
│     • Consecutive identical intervals (scripted)                 │
│     • Low variance detection (robotic typing)                    │
│     • Repeating pattern detection                                │
│                                                                  │
│  4. INTEGRITY PROTECTION                                         │
│     • HMAC on all counter state                                  │
│     • Cryptographic chaining of updates                          │
│     • Tamper-evident sealed checkpoints                          │
│                                                                  │
│  5. TPM BINDING (when available)                                 │
│     • Hardware monotonic counter (prevents rollback)             │
│     • TPM attestation quotes                                     │
│     • Key sealing to platform state (PCRs)                       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Legitimate Copy/Paste Handling

The system properly handles legitimate copy/paste operations:
- **Detection**: Large content changes with few keystrokes are flagged as paste events
- **Transparency**: Paste events are recorded and included in evidence export
- **No Penalty**: Copy/paste from your own content or citations is legitimate authorship

```bash
# Check tracking status including paste detection
witnessd track status

# Example output:
# Keystrokes: 15234
# Paste events: 3 (legitimate copy/paste detected)
```

### Backup: IME Integration (Future)

For users who decline accessibility permissions or on mobile platforms, an optional
Input Method Engine (IME) provides keystroke counting without system-level access:
- Requires installing witnessd as a keyboard
- Privacy-focused: counts only, no text capture
- Lower security tier (cannot detect synthetic events)

## What This Proves

The evidence packet makes explicit claims:

**Cryptographic (tamper-evident, independently verifiable):**
- “Content states form a cryptographically linked, append-only chain”
- “At least 12h 34m of wall-clock time elapsed between committed states”
- “Presence challenges were responded to during 89% of challenge windows”

**Attestation (legal accountability):**
- "Author signed declaration of creative process"
- "No AI tools declared" or "AI assistance declared: moderate extent"

**Limitations (explicitly stated):**
- "Cannot prove cognitive origin of ideas"
- "Cannot prove absence of AI involvement in ideation"

## Why Documentation Over Detection

Traditional approaches try to **detect** AI involvement through behavioral analysis. This creates an arms race: as AI improves, detection becomes harder.

witnessd takes a different approach:
- **Prove what's provable**: Time elapsed (VDF), chain integrity (hashes)
- **Declare what's not**: AI usage, collaboration, input modalities
- **Let institutions handle false declarations**: This is how affidavits, notarization, and signatures work

False declarations are the author's legal risk, not a technical detection problem.

## Security Model

**Threat Model:**
- Adversary controls filesystem after the fact
- Adversary cannot break SHA-256, Ed25519, or VDF
- Adversary cannot retroactively modify Bitcoin blockchain

As with all user-space systems, compromise of the operating system kernel prior to evidence capture invalidates downstream guarantees; this is an explicit and irreducible limitation.

**Storage Security:**

The event database (`~/.witnessd/events.db`) is tamper-evident:

```
┌────────────────────────────────────────────────────────────────┐
│                    SECURE SQLITE STORAGE                        │
├────────────────────────────────────────────────────────────────┤
│  • HMAC Integrity: Each record has HMAC derived from signing   │
│    key - modifications are detectable                          │
│                                                                │
│  • Chain Linking: Each event references previous event hash    │
│    - insertions/deletions break the chain                      │
│                                                                │
│  • Append-Only: Events cannot be modified after insertion      │
│                                                                │
│  • File Permissions: Database has 0600 permissions (owner      │
│    read/write only)                                            │
│                                                                │
│  • Integrity Verification: Full chain verified on every open   │
└────────────────────────────────────────────────────────────────┘
```

Check integrity status:
```bash
witnessctl status  # Shows "Integrity: VERIFIED" or "FAILED"
```

**The "Drip Attack" Problem:**
An adversary could generate AI content and slowly feed it through the system. Under witnessd:
1. They must spend real wall-clock time (VDF proves it)
2. They must sign a false declaration (legal risk)
3. The economic cost approaches honest work
4. With keystroke tracking: Multiple layers of protection:
   - **Timing anomaly detection**: Scripts show low variance, identical intervals, or superhuman speed
   - **Synthetic event detection**: CGEventPost injections are flagged by source state validation
   - **Dual-layer validation**: IOKit HID cross-validates CGEventTap counts
   - **USB-HID spoofing detection**: Hardware keyboard type checking
   - **TPM binding**: Hardware counters prevent replay attacks
5. Copy/paste is tracked: Large content changes with few keystrokes are recorded

## Configuration

Configuration is stored in `~/.witnessd/config.json`:

```json
{
  "version": 2,
  "vdf": {
    "iterations_per_second": 1500000,
    "calibrated": true
  },
  "presence": {
    "challenge_interval_seconds": 600,
    "response_window_seconds": 60
  }
}
```

## Citation

If you use witnessd in academic or forensic work, please cite:

```bibtex
@article{condrey2026witnessd,
  title={Falsifiable Process Evidence via Cryptographic Causality Locks and Behavioral Attestation},
  author={Condrey, David Lee},
  publisher={WritersLogic, Inc.},
  year={2026},
  note={U.S. Patent Pending}
}
```

<!-- TODO: Update with arXiv ID once published -->

## License

This software is licensed under the **Polyform Non-Commercial License 1.0.0**.

**Commercial Use Restricted:** Any commercial use of this software, including use by or on behalf of a for-profit organization, requires a separate commercial license from **WritersLogic, Inc.**

---

## Intellectual Property Notice

**Patent Pending:** The technologies implemented in this repository—including but not limited to **Cryptographic Jitter Seals**, **VDF Causality Locks**, and **Ratcheted Merkle Mountain Range Logs**—are the subject of pending U.S. and international patent applications.

© 2026 WritersLogic, Inc. All rights reserved.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

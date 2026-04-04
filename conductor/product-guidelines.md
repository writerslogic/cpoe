# Product Guidelines

## Core Principles
1. **Security & Cryptographic Integrity:** All operations must prioritize cryptographic correctness and tamper-evidence.
2. **Offline-First & Privacy:** User data and activity capture must remain local and private by default.
3. **Transparency:** The verification process must be open, explainable, and accessible to non-technical users.
4. **Resilience:** The system must handle hardware jitter and clock drift gracefully without compromising proof validity.

## Prose & Communication
- **Tone:** Professional, authoritative, yet accessible.
- **Clarity:** Avoid jargon where possible; when using technical terms (e.g., VDF, jitter, ratcheting), provide clear context or references.
- **Formatting:** Use structured headers, bulleted lists, and clear summaries to improve readability of complex reports.

## UX & Interaction (CLI/Apps)
- **Non-Intrusiveness:** Background witnessing should have minimal impact on system performance.
- **Immediate Feedback:** Users should receive clear status updates for tracking, commits, and verification results.
- **Machine-Readable:** Support standard formats (JSON, CBOR) for interoperability and automation.

## Implementation Standards
- **Strict Adherence to IETF Specs:** Follow the `draft-condrey-rats-pop` protocol meticulously.
- **Cross-Platform Consistency:** Ensure core cryptographic logic behaves identically across all targets (macOS, Windows, Linux).
- **Comprehensive Verification:** Every feature must be verifiable against the protocol's security invariants.

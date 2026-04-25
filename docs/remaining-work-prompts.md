# Remaining Work — Focused Prompts

Use these prompts in order. Each is self-contained with full context.

---

## Prompt 1: Native Messaging Handler for Browser Extension Text Attestation

```
The browser extension sends a `text_attestation` message via native messaging
when the user right-clicks and selects "Attest Authorship with WritersProof".
The desktop app's native messaging host needs to handle this message type.

Context:
- Browser extension sends via `chrome.runtime.connectNative("com.writerslogic.witnessd")`
- Message format: `{ type: "text_attestation", content_hash: "hex64", tier: "verified|corroborated|declared", writersproof_id: "hex8", attested_at: "ISO8601", app_bundle_id: "hostname" }`
- The native messaging host is in `apps/cpoe_cli/src/` (search for native_messaging or nativemessaging)
- The handler should call `ffi_attest_text()` from `crates/cpoe/src/ffi/text_fragment.rs` to store locally, then `ffi_sync_text_attestation()` from `crates/cpoe/src/ffi/writersproof_ffi.rs` to sync to the API
- If sync fails, the offline queue in `crates/cpoe/src/writersproof/queue.rs` will automatically queue it for retry
- Follow the existing message handling pattern in the native messaging host for other message types (start_session, checkpoint, stop_session)

Tasks:
1. Find and read the native messaging host code (search apps/cpoe_cli/ for native messaging)
2. Add a handler for the `text_attestation` message type
3. The handler should: validate the message fields, call ffi_attest_text with the content (empty string is fine since the hash is precomputed by the browser), then call ffi_sync_text_attestation
4. Return a response message: `{ type: "text_attestation_result", success: true/false, error: "..." }`
5. Verify it compiles with `cargo check -p cpoe-cli` or equivalent

Be thorough. Read the existing native messaging code completely before making changes. Match the existing patterns exactly. Verify your work compiles.
```

---

## Prompt 2: Supabase TTL Cleanup for Stale Text Attestations

```
The `wp_text_attestations` table in Supabase needs a cleanup function to
remove stale attestations. The project already has a cleanup pattern for
nonces in migration 00008.

Context:
- Supabase project: aswcfxodrgcnjbwrcjrl
- Existing cleanup pattern: `supabase/migrations/` in ~/workspace_local/Writerslogic/writersproof/ — read migration 00008 for the nonce cleanup function pattern
- Text attestations table: `wp_text_attestations` (created in migration 20260424073637)
- The writersproof API worker has a cron trigger every 5 minutes (wrangler.toml `[triggers] crons`)
- The cron handler is in `apps/api/src/cron.ts`

Tasks:
1. Read migration 00008 to understand the nonce cleanup pattern
2. Create a new migration that adds a `wp_cleanup_stale_text_attestations()` PostgreSQL function
3. The function should: delete attestations older than 1 year that have never been looked up (no KV cache hit implies unused)
4. Actually, simpler: add a `last_verified_at` column to `wp_text_attestations` (nullable, updated by the GET endpoint when a lookup succeeds), then the cleanup function deletes rows where `created_at < NOW() - INTERVAL '1 year'` AND `last_verified_at IS NULL`
5. Update the API GET route in `apps/api/src/routes/textAttestation.ts` to update `last_verified_at` on successful lookup (use Supabase PATCH)
6. Add the cleanup function call to the cron handler in `apps/api/src/cron.ts`
7. Run `supabase db push` to apply the migration

Be thorough. Read existing patterns before writing. Ensure the migration is idempotent. Test that the API typecheck passes after changes.
```

---

## Prompt 3: Integration Tests for Text Attestation API

```
The WritersProof API at ~/workspace_local/Writerslogic/writersproof/ needs
integration tests for the text attestation endpoints.

Context:
- API framework: Hono on Cloudflare Workers
- Test patterns: check if there are existing tests in `apps/api/src/__tests__/` or `apps/api/tests/` or `apps/api/*.test.ts`
- If no test infrastructure exists, set up vitest (already in the monorepo's dev deps likely) with a miniflare-based test environment for Cloudflare Workers
- Endpoints to test:
  - POST /v1/text-attestation — requires auth (combinedAuthMiddleware), validates Zod schema, verifies Ed25519 signature with domain tag "witnessd-text-attest-v1", stores in Supabase, caches in KV
  - GET /v1/text-attestation/:hash — public, returns from KV cache or Supabase fallback

Tasks:
1. Check existing test infrastructure in the writersproof monorepo
2. Create test file `apps/api/src/routes/__tests__/textAttestation.test.ts`
3. Test cases for POST:
   - Valid submission → 201 with writersproof_id
   - Missing auth → 401
   - Invalid content_hash (wrong length) → 400
   - Invalid signature (verification fails) → 403
   - writersproof_id doesn't match hash prefix → 400
   - Rate limiting (if testable)
4. Test cases for GET:
   - Known hash → 200 with attestation details
   - Unknown hash → 404
   - Invalid hash format → 400
   - KV cache hit vs Supabase fallback (mock KV)
5. Use @noble/ed25519 to generate real Ed25519 keypairs and sign with the correct DST for valid test cases
6. Verify tests pass

Be thorough. Generate real cryptographic test fixtures, not mocks. Each test should be independent and deterministic.
```

---

## Prompt 4: Verify Portal End-to-End Flow Validation

```
The verify portal at ~/workspace_local/Writerslogic/writersproof/apps/verify/
needs validation that the "Verify Text" tab works correctly end-to-end.

Context:
- The verify page is at `apps/verify/src/pages/VerifyTextPage.tsx`
- It imports `normalizeForAttestation` and `sha256` from `@writersproof/crypto`
- The normalization must produce identical output to the Rust function in `crates/cpoe/src/ffi/text_fragment.rs`
- The API is at `api.writersproof.com/v1/text-attestation/:hash`

Tasks:
1. Read VerifyTextPage.tsx completely
2. Read the Rust normalize_for_attestation function in text_fragment.rs
3. Create a test file `packages/crypto/src/__tests__/hash.test.ts` that verifies normalizeForAttestation produces correct output for:
   - ASCII: "Hello, World!" → "helloworld"
   - Unicode precomposed: "café résumé" → "caférésumé"  
   - NFC/NFD equivalence: "caf\u00e9" and "cafe\u0301" produce identical output
   - CJK: "写作 证明" → "写作证明"
   - Digits: "I wrote 5 chapters" → "iwrote5chapters"
   - Empty after strip: "!@#$%" → ""
   - Whitespace stripped: "Hello\n\n  World\t!!" → "helloworld"
4. Verify hashTextForAttestation produces deterministic 64-char hex output
5. Add a cross-validation test that computes the hash of "Hello, World!" and compares it to the known SHA-256 of "helloworld" (precomputed)
6. Run the tests

Be thorough. The normalization MUST match Rust exactly — any divergence breaks the entire verification system. Test edge cases with combining characters, emoji, RTL text.
```

---

## Prompt 5: Dead Letter Notification for Offline Queue

```
When text attestation queue entries hit the max retry limit (10 retries),
they're silently discarded. The user should be notified.

Context:
- Queue implementation: `crates/cpoe/src/writersproof/queue.rs` — `drain_text_attestations` method
- The drain is called from Swift via `ffiDrainTextAttestationQueue()` in `crates/cpoe/src/ffi/writersproof_ffi.rs`
- The Swift caller is in `apps/cpoe_macos/cpoe/AuthService+OAuth.swift` — `drainTextAttestationQueue()`
- macOS notifications use `NotificationManager.shared.send(title:body:)` in `apps/cpoe_macos/cpoe/NotificationManager.swift`

Tasks:
1. Modify `drain_text_attestations` in queue.rs to return both success count AND discard count: change return type to `Result<(usize, usize)>` (submitted, discarded)
2. Update `ffi_drain_text_attestation_queue` in writersproof_ffi.rs to include the discard count in the result message
3. Update the Swift `drainTextAttestationQueue()` to parse the discard count from the result message and send a notification if > 0: "N text attestations could not be synced and were discarded after 10 retries."
4. Verify Rust compiles with `cargo check -p cpoe`

Be thorough. Don't change the FfiResult type — just encode the counts in the message string (e.g., "Drained 3/5, discarded 2") and parse it in Swift.
```

---

## Prompt 6: Anchor Retry on Failure

```
The transparency log anchoring in `ffi_sync_text_attestation` is fire-and-forget.
If the anchor call fails, the attestation is synced but not anchored, and
there's no retry.

Context:
- Current code: `crates/cpoe/src/ffi/writersproof_ffi.rs` — after successful text attestation sync, anchor is attempted with 10s timeout. On failure, `log::warn` and return success.
- The offline queue at `crates/cpoe/src/writersproof/queue.rs` has text attestation queuing.

Tasks:
1. Add a `QueuedAnchorRequest` type to `crates/cpoe/src/writersproof/types.rs` (evidence_hash, signature, tier)
2. Add `enqueue_anchor`, `list_anchors`, `drain_anchors` methods to queue.rs using an `anchors/` subdirectory (same pattern as text/ subdirectory)
3. In `ffi_sync_text_attestation`, when anchor fails, queue it for retry instead of just logging
4. In `ffi_drain_text_attestation_queue`, also drain pending anchors after draining text attestations
5. Add max retries (5) and exponential backoff matching the text attestation queue
6. Verify Rust compiles with `cargo check -p cpoe`

Be thorough. Follow the exact same patterns established in the text attestation queue code. Use the same atomic_write, validate_id, and error handling patterns.
```

---

## Prompt 7: Final Quality Gate and Honest Scoring

```
Run a complete quality gate across all text attestation code and produce
an honest feature-by-feature quality report.

Tasks:
1. Run `cargo check -p cpoe` and `cargo clippy -p cpoe -- -D warnings`
2. Run `cargo test -p cpoe --lib --features ffi -- ffi::text_fragment::tests` (this takes ~10 min, run once)
3. In the writersproof monorepo at ~/workspace_local/Writerslogic/writersproof/:
   - `npx tsc --noEmit -p packages/crypto/tsconfig.json`
   - `npx tsc --noEmit -p apps/api/tsconfig.json`
   - Build verify portal: `cd apps/verify && npm run build`
4. Read each file that was modified and audit for:
   - Correctness: does the code do what it claims?
   - Security: are all signing operations domain-tagged? Are keys zeroized? Are inputs validated?
   - Error handling: are errors propagated, not swallowed?
   - Consistency: do all implementations of normalizeForAttestation match?
5. Produce a final honest quality report scoring each feature 1-10 with specific justification for any deduction.
6. If any feature scores below 9, list the exact changes needed to reach 9+.

Be brutally honest. A 10/10 means zero known issues, not "good enough".
```

---

## Execution Order

1. **Prompt 1** (native messaging) → enables browser extension → desktop sync
2. **Prompt 4** (crypto tests) → validates normalization correctness across JS/Rust
3. **Prompt 2** (Supabase TTL) → production hygiene
4. **Prompt 3** (API integration tests) → confidence in API correctness
5. **Prompt 5** (dead letter notification) → UX completeness
6. **Prompt 6** (anchor retry) → reliability completeness
7. **Prompt 7** (final quality gate) → honest assessment

Prompts 1-4 can be run in parallel if using separate sessions.
Prompts 5-6 depend on the queue code from prompt 1 being stable.
Prompt 7 should always be last.

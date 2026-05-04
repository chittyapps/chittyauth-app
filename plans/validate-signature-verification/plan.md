# Validate Signature Verification

**Branch:** `fix/validate-signature-verification`
**Description:** Enforce HMAC signature verification on the token validate path so the signing key is load-bearing, not advisory.

## Goal

Close the security gap documented in `SECURITY.md` Known Limitation #3 and tracked as issue #4: `src/token-manager.js` `validate()` looks up tokens by SHA-256 hash but never re-derives or compares the embedded HMAC signature. As a result, a D1 compromise (SQL injection, leaked credentials, lost backup) lets an attacker insert a forged `(token_hash, chitty_id, scope, service)` row and produce a corresponding plaintext token that the validator accepts. Adding signature verification raises the bar to "compromise D1 **and** steal the signing key", restoring the defense-in-depth the HMAC is meant to provide.

## Background — Token Format (Already in Code)

`generateToken` (`src/token-manager.js:295-307`) produces:

```
ca_<env>_<base64url(tokenId + "_" + timestamp + "_" + signature)>
```

where:

```
canonicalPayload = `${tokenId}:${chittyId}:${service}:${timestamp}`
signature        = HMAC-SHA256(signingKey, canonicalPayload).base64url.slice(0, 32)   // ~192-bit truncation
```

Critically, **`chittyId` and `service` are NOT in the wire token** — only the HMAC commitment to them is. So signature verification must rebuild the canonical payload using the `chittyId`/`service` returned by the D1/KV lookup.

## Architecture Decision

- **Order of operations:** lookup first (proves token exists), then signature verify (proves issuer authenticity), then expiry/rate-limit. Verifying after lookup is necessary because the canonical payload includes fields not in the wire token.
- **Backwards compat:** existing tokens stay valid — same format, same signing scheme; we're just turning on a check that was always implicit.
- **Failure mode:** signature mismatch returns `{ valid: false, error: 'Invalid token signature' }` and audit-logs `token_validation_failed` with `error: 'Invalid signature'`. No fallback, no "warn but allow" — this is the security control.
- **Timing-safe compare:** use `crypto.timingSafeEqual` on equal-length buffers; reject early on length mismatch (this is OK because length is public information).
- **Tokens missing the signature segment** (malformed body): treated identically to invalid format → reject in the existing format-check step or in `verifySignature` if discovered later.

## Risks / Coordination

- **Tokens issued under a different signing key will start failing.** If the deployment has been silently using the `'dev-signing-key-change-in-production'` fallback (issue #5) and operators flip on signature verification before fixing the secret, every outstanding token becomes invalid at the moment of deploy. Recommend landing #5 first or simultaneously, OR running a "shadow verify" rollout (log-only) for 24h before enforce. Step 1 covers shadow mode; Step 2 flips enforce.
- **Truncated signature length is fixed at 32 base64url chars.** `verifySignature` must enforce this length before the timing-safe compare.

## Implementation Steps

### Step 1: Add `verifySignature` helper + shadow-mode logging in validate path
**Files:**
- `src/token-manager.js` — new method `verifySignature(token, chittyId, service)`; call from `validate()` after the lookup; log mismatch as `signature_mismatch` audit event but DO NOT reject yet (gated on `env.CHITTYAUTH_VERIFY_SIGNATURE !== 'enforce'`).
- `tests/token-manager.test.js` — add unit tests:
  - valid token verifies cleanly
  - signature segment mutated by one byte → `verifySignature` returns false
  - `tokenId` segment mutated → returns false (HMAC mismatch)
  - `timestamp` segment mutated → returns false
  - rebuilt payload with wrong `chittyId` → returns false
  - tampered token in shadow mode → `validate()` still returns valid (gate off) but audit event was written

**What:** Pure helper + observe-only wiring. Let operators see real-world mismatch rate before flipping enforcement.

**Testing:** `npm test` (Jest). Verify shadow-mode audit events fire on synthetic tampering. Verify happy-path validate still passes.

### Step 2: Flip enforcement and update SECURITY.md / CHARTER.md
**Files:**
- `src/token-manager.js` — change the gate so signature mismatch returns `{ valid: false, error: 'Invalid token signature' }` and audit-logs `token_validation_failed` regardless of the env var. Remove the `CHITTYAUTH_VERIFY_SIGNATURE` flag (no longer needed).
- `tests/token-manager.test.js` — add tests:
  - tampered signature → `validate()` returns `{ valid: false, error: /signature/i }`
  - tampered `tokenId` segment → `validate()` rejects
  - tampered `timestamp` segment → `validate()` rejects
  - "forged D1 record" simulation: insert a token row whose hash matches a synthetic plaintext we crafted with a *different* signing key → `validate()` rejects (this is the core security claim)
- `SECURITY.md` — restore the validation pipeline to include "Signature verification with `CHITTYAUTH_ISSUED_MINT_API_KEY`" as step 2; remove Known Limitation #3 and renumber the rest; remove the "**Important caveat**" sentence in the Cryptographic Design section; remove the post-pipeline paragraph that explains the gap.
- `CHARTER.md` — bump version to 1.4.0 with `Last Updated: <today>`.

**What:** Make the security control load-bearing and bring the docs back in alignment with code.

**Testing:** `npm test`; manually verify the forged-D1-record test fails before this change and passes after (proves the test is actually testing what we claim). Smoke test a real `wrangler dev --local` issuance/validation cycle to confirm no regression on the happy path.

## Out of Scope (Track Separately)

- **Issue #5** (fail-closed signing key) — strongly recommended to land first or simultaneously to avoid mass token invalidation if a deploy is silently using the dev-default fallback.
- **Token-format documentation drift** — `CHARTER.md` Token Format section currently shows a JWT-shaped object that doesn't match the actual underscore-joined-then-base64url scheme in `generateToken`. Worth a follow-up doc PR; not required for this fix to be correct.
- **Dual-key (kid) rotation overlap** — `SECURITY.md` Known Limitation #5; out of scope here.

## Acceptance

- [ ] `npm test` passes including all new tamper-detection tests
- [ ] `validate()` rejects a token whose signature was mutated by one byte
- [ ] `validate()` rejects a forged D1 row + matching plaintext signed with a different key
- [ ] `SECURITY.md` validation pipeline lists signature verification as step 2; Known Limitation #3 removed
- [ ] `CHARTER.md` bumped to 1.4.0
- [ ] Closes #4

[NEEDS CLARIFICATION] Should Step 1 actually ship to production with shadow mode for a soak window, or is a single-PR enforce-immediately acceptable here? Shadow mode is safer if there's any chance the production secret has drifted; single-step is faster if you're confident the prod secret is real. Default plan above assumes single PR with both commits — say "shadow first" and I'll split into two PRs with a soak interval.

[NEEDS CLARIFICATION] Branch name `fix/validate-signature-verification` OK, or do you prefer a different convention (e.g., `security/issue-4-signature-verify`)?

# Validate Signature Verification — Implementation

## Goal
Add and enforce HMAC signature verification on the token validate path so the signing key is load-bearing (closes issue #4 / SECURITY.md Known Limitation #3).

## Stack & Conventions Reference
- Cloudflare Workers (ESM JS, `nodejs_compat` enabled in `wrangler.toml`).
- `import crypto from 'crypto'` is the existing pattern in `src/token-manager.js` — `crypto.createHmac`, `crypto.randomBytes`, `crypto.timingSafeEqual` all available under `nodejs_compat`.
- Tests: Jest with `node --experimental-vm-modules`. File `tests/token-manager.test.js`. Run via `npm test`.
- No lint/typecheck step — do not add one.
- Token wire format (existing, unchanged): `ca_<env>_<base64url(tokenId + "_" + timestamp + "_" + signature)>`.
- Canonical signed payload (existing, unchanged): `${tokenId}:${chittyId}:${service}:${timestamp}`.
- Signature: HMAC-SHA256, base64url, truncated to 32 chars.

## Prerequisites
Make sure that the user is currently on the `fix/validate-signature-verification` branch before beginning implementation. If not, move them to the correct branch. If the branch does not exist, create it from main.

```bash
git fetch origin
git checkout main
git pull --ff-only
git checkout -b fix/validate-signature-verification
```

### Step-by-Step Instructions

#### Step 1: Add `verifySignature` helper, fix missing `service_name` insert, wire shadow-mode logging into validate path

**Why this step is shaped this way:** The planned `verifySignature` recomputes HMAC over `${tokenId}:${chittyId}:${service}:${timestamp}`. On the D1-fallback path, `tokenData.service` comes from the `service_name` column. The current `provision()` (`src/token-manager.js:35-45`) names `service_name` is **not** in the INSERT column list at all — so the column is always NULL on D1 rows, and any token whose KV cache has expired would fail signature verification. Fixing the INSERT is therefore mandatory before signature verification can work for D1-fallback validations. This step also fixes the matching mock in `tests/token-manager.test.js`.

- [x] Open `src/token-manager.js` and locate the `provision()` method's D1 INSERT (currently lines 34-46).
- [x] Replace the `if (this.env.AUTH_DB) { ... }` block inside `provision()` with the corrected INSERT that includes `service_name`:

```javascript
    // Store token in D1
    if (this.env.AUTH_DB) {
      await this.env.AUTH_DB.prepare(
        `INSERT INTO tokens (id, token_hash, chitty_id, scope, service_name, created_at, expires_at, request_count)
         VALUES (?, ?, ?, ?, ?, ?, ?, 0)`
      ).bind(
        tokenId,
        tokenHash,
        chittyId,
        JSON.stringify(scope),
        service,
        createdAt,
        expiresAt
      ).run();
    }
```

- [x] In `src/token-manager.js`, locate the `validate()` method (currently lines 91-198) and replace the entire method body so signature verification runs after the lookup. Use this exact replacement:

```javascript
  /**
   * Validate a Bearer token
   */
  async validate(token) {
    if (!token || typeof token !== 'string') {
      return { valid: false, error: 'Invalid token format' };
    }

    // Remove 'Bearer ' prefix if present
    token = token.replace(/^Bearer\s+/i, '');

    // Check token format
    if (!this.isValidTokenFormat(token)) {
      return { valid: false, error: 'Invalid token format' };
    }

    const tokenHash = await this.hashToken(token);

    // Check if revoked
    if (this.env.AUTH_REVOCATIONS) {
      const revoked = await this.env.AUTH_REVOCATIONS.get(`revoked:${tokenHash}`);
      if (revoked) {
        await this.logAuditEvent({
          eventType: 'token_validation_failed',
          error: 'Token revoked',
          success: false,
          timestamp: Date.now()
        });
        return { valid: false, error: 'Token has been revoked' };
      }
    }

    // Get token data from KV (fast path)
    let tokenData = null;
    if (this.env.AUTH_TOKENS) {
      const data = await this.env.AUTH_TOKENS.get(`token:${tokenHash}`);
      if (data) {
        tokenData = JSON.parse(data);
      }
    }

    // Fallback to D1 if not in KV
    if (!tokenData && this.env.AUTH_DB) {
      const result = await this.env.AUTH_DB.prepare(
        `SELECT * FROM tokens WHERE token_hash = ? AND revoked_at IS NULL`
      ).bind(tokenHash).first();

      if (result) {
        tokenData = {
          tokenId: result.id,
          chittyId: result.chitty_id,
          scope: JSON.parse(result.scope),
          service: result.service_name,
          createdAt: result.created_at,
          expiresAt: result.expires_at,
          requestCount: result.request_count
        };
      }
    }

    // Check if token exists
    if (!tokenData) {
      await this.logAuditEvent({
        eventType: 'token_validation_failed',
        error: 'Token not found',
        success: false,
        timestamp: Date.now()
      });
      return { valid: false, error: 'Token not found' };
    }

    // Verify HMAC signature against the looked-up record.
    // Shadow mode (default): log mismatch but do not reject.
    // Enforce mode (CHITTYAUTH_VERIFY_SIGNATURE === 'enforce'): reject on mismatch.
    const signatureOk = this.verifySignature(token, tokenData.chittyId, tokenData.service, tokenData.tokenId);
    if (!signatureOk) {
      await this.logAuditEvent({
        eventType: 'signature_mismatch',
        tokenId: tokenData.tokenId,
        chittyId: tokenData.chittyId,
        success: false,
        error: 'Signature verification failed',
        timestamp: Date.now()
      });
      if (this.env.CHITTYAUTH_VERIFY_SIGNATURE === 'enforce') {
        await this.logAuditEvent({
          eventType: 'token_validation_failed',
          tokenId: tokenData.tokenId,
          chittyId: tokenData.chittyId,
          success: false,
          error: 'Invalid signature',
          timestamp: Date.now()
        });
        return { valid: false, error: 'Invalid token signature' };
      }
    }

    // Check expiration
    if (tokenData.expiresAt < Date.now()) {
      await this.logAuditEvent({
        eventType: 'token_validation_failed',
        tokenId: tokenData.tokenId,
        error: 'Token expired',
        success: false,
        timestamp: Date.now()
      });
      return { valid: false, error: 'Token has expired' };
    }

    // Update last used timestamp and request count
    await this.updateTokenUsage(tokenHash, tokenData);

    // Check rate limit
    const rateLimitRemaining = await this.checkRateLimit(tokenHash, tokenData);

    // Audit event
    await this.logAuditEvent({
      eventType: 'token_validated',
      tokenId: tokenData.tokenId,
      chittyId: tokenData.chittyId,
      success: true,
      timestamp: Date.now()
    });

    return {
      valid: true,
      tokenId: tokenData.tokenId,
      chittyId: tokenData.chittyId,
      scope: tokenData.scope,
      service: tokenData.service,
      expiresAt: new Date(tokenData.expiresAt).toISOString(),
      rateLimitRemaining
    };
  }
```

- [x] In `src/token-manager.js`, immediately after the `signPayload(payload)` method (currently ending at line 316) and before `hashToken(token)` (currently starting at line 321), insert the new `verifySignature` method (with **multiple deviations** from the plan code below, surfaced by `/pr-review-toolkit:review-pr`):
  - **Critical fix**: the plan's `decoded.split('_')` is broken because (a) `tokenId` is `tok_<alphanumeric>` so the body has 4 segments not 3, and (b) base64url's alphabet includes `_`, so the 32-char signature contains `_` ~40% of the time. A naïve `lastIndexOf('_')` peel still indexes INTO the signature in those cases, false-rejecting ~40% of legitimate tokens. The implemented version uses **fixed-length right-peel** (`SIGNATURE_LENGTH = 32`, slice last 32 chars unconditionally) and only `lastIndexOf('_')` for the timestamp boundary (timestamps are pure digits so no underscores there). Validated by a deterministic 200-iteration loop test in this Step.
  - **Removed dead try/catch around `Buffer.from(body, 'base64url')`** — Node's base64url decoder does not throw on malformed input (returns partial buffer), so the catch was dead code. Downstream length/regex/HMAC checks handle bad input correctly.
  - **Removed the try/catch around `crypto.timingSafeEqual`** — equal-length precondition is checked immediately above, so timingSafeEqual can only throw on a code-invariant violation (e.g. `signPayload` truncation length drifts from `SIGNATURE_LENGTH`). Swallowing that error would convert a code bug into "all tokens invalid" — better to let it surface loudly.
  - **JSDoc rewritten** to accurately describe parameters (the timestamp comes from the token body, not the DB record), enumerate failure modes, and warn about the underscore-in-signature pitfall.

```javascript
  /**
   * Verify the HMAC signature embedded in a token matches the canonical
   * payload reconstructed from the looked-up record.
   *
   * Returns true on match, false on any mismatch — malformed body, prefix
   * not recognized, segment count wrong, signature length wrong, embedded
   * tokenId disagrees with the looked-up record, or HMAC mismatch.
   * Never throws.
   */
  verifySignature(token, chittyId, service, expectedTokenId) {
    if (!token || typeof token !== 'string') return false;
    if (chittyId == null || service == null) return false;

    const knownPrefixes = ['ca_live_', 'ca_test_', 'ca_dev_', 'svc_'];
    const prefix = knownPrefixes.find((p) => token.startsWith(p));
    if (!prefix) return false;

    const body = token.slice(prefix.length);
    let decoded;
    try {
      decoded = Buffer.from(body, 'base64url').toString('utf8');
    } catch {
      return false;
    }

    const parts = decoded.split('_');
    if (parts.length !== 3) return false;
    const [tokenId, timestampStr, signature] = parts;
    if (!tokenId || !timestampStr || !signature) return false;
    if (signature.length !== 32) return false;
    if (expectedTokenId && tokenId !== expectedTokenId) return false;

    const canonicalPayload = `${tokenId}:${chittyId}:${service}:${timestampStr}`;
    const expected = this.signPayload(canonicalPayload);
    if (expected.length !== signature.length) return false;

    try {
      return crypto.timingSafeEqual(
        Buffer.from(expected, 'utf8'),
        Buffer.from(signature, 'utf8')
      );
    } catch {
      return false;
    }
  }
```

- [x] Open `tests/token-manager.test.js` and replace the `createMockD1` function at the bottom of the file (currently lines 257-300) with the version that handles the corrected INSERT shape:

```javascript
// Mock D1 database
function createMockD1() {
  const tables = {
    tokens: [],
    auth_events: []
  };

  return {
    prepare: (sql) => {
      return {
        bind: (...params) => {
          return {
            run: async () => {
              // Simulate INSERT/UPDATE
              if (sql.includes('INSERT INTO tokens')) {
                tables.tokens.push({
                  id: params[0],
                  token_hash: params[1],
                  chitty_id: params[2],
                  scope: params[3],
                  service_name: params[4],
                  created_at: params[5],
                  expires_at: params[6],
                  request_count: 0,
                  revoked_at: null
                });
              }
              if (sql.includes('UPDATE tokens SET revoked_at')) {
                const t = tables.tokens.find((row) => row.id === params[1]);
                if (t) t.revoked_at = params[0];
              }
              return { success: true };
            },
            first: async () => {
              // Simulate SELECT
              if (sql.includes('SELECT * FROM tokens')) {
                const token = tables.tokens.find(
                  (t) => t.token_hash === params[0] && !t.revoked_at
                );
                return token || null;
              }
              if (sql.includes('SELECT token_hash FROM tokens')) {
                const token = tables.tokens.find((t) => t.id === params[0]);
                return token || null;
              }
              return null;
            }
          };
        }
      };
    },
    // Test-only helper: return a snapshot of the tokens table for assertions
    __dump: () => ({ tokens: [...tables.tokens] })
  };
}
```

- [x] At the top of `tests/token-manager.test.js`, immediately after the existing `import` line, add a small helper for reading audit events out of the mock KV. Insert this block right after `import { TokenManager } from '../src/token-manager.js';`:

```javascript

async function readAuditEvents(mockKv) {
  const list = await mockKv.list({ prefix: 'event:' });
  const events = [];
  for (const k of list.keys) {
    const raw = await mockKv.get(k.name);
    if (raw) events.push(JSON.parse(raw));
  }
  return events;
}
```

- [x] In `tests/token-manager.test.js`, add a new `describe` block for signature verification. Insert it immediately before the closing `});` of the outer `describe('TokenManager', ...)` block (i.e., just before line 231 `});` in the original file):

```javascript

  describe('Signature Verification (verifySignature helper)', () => {
    test('valid token verifies cleanly against its issued chittyId/service', async () => {
      const provision = await tokenManager.provision({
        chittyId: '03-1-USA-0001-P-251-3-82',
        scope: ['chittyid:read'],
        service: 'chittyid',
        expiresIn: 3600
      });
      expect(
        tokenManager.verifySignature(
          provision.token,
          '03-1-USA-0001-P-251-3-82',
          'chittyid',
          provision.tokenId
        )
      ).toBe(true);
    });

    test('signature segment mutated by one byte → false', async () => {
      const provision = await tokenManager.provision({
        chittyId: '03-1-USA-0001-P-251-3-82',
        scope: ['chittyid:read'],
        service: 'chittyid',
        expiresIn: 3600
      });
      const prefix = 'ca_live_';
      const body = provision.token.slice(prefix.length);
      const decoded = Buffer.from(body, 'base64url').toString('utf8');
      const [tokenId, timestamp, signature] = decoded.split('_');
      const flippedFirst = signature[0] === 'A' ? 'B' : 'A';
      const tampered = `${tokenId}_${timestamp}_${flippedFirst}${signature.slice(1)}`;
      const tamperedToken = `${prefix}${Buffer.from(tampered).toString('base64url')}`;
      expect(
        tokenManager.verifySignature(
          tamperedToken,
          '03-1-USA-0001-P-251-3-82',
          'chittyid',
          provision.tokenId
        )
      ).toBe(false);
    });

    test('tokenId segment mutated → false (HMAC mismatch)', async () => {
      const provision = await tokenManager.provision({
        chittyId: '03-1-USA-0001-P-251-3-82',
        scope: ['chittyid:read'],
        service: 'chittyid',
        expiresIn: 3600
      });
      const prefix = 'ca_live_';
      const body = provision.token.slice(prefix.length);
      const decoded = Buffer.from(body, 'base64url').toString('utf8');
      const [, timestamp, signature] = decoded.split('_');
      const evil = `tok_AAAAAAAAAAAAAAAAAAAA_${timestamp}_${signature}`;
      const tamperedToken = `${prefix}${Buffer.from(evil).toString('base64url')}`;
      expect(
        tokenManager.verifySignature(
          tamperedToken,
          '03-1-USA-0001-P-251-3-82',
          'chittyid',
          provision.tokenId
        )
      ).toBe(false);
    });

    test('timestamp segment mutated → false', async () => {
      const provision = await tokenManager.provision({
        chittyId: '03-1-USA-0001-P-251-3-82',
        scope: ['chittyid:read'],
        service: 'chittyid',
        expiresIn: 3600
      });
      const prefix = 'ca_live_';
      const body = provision.token.slice(prefix.length);
      const decoded = Buffer.from(body, 'base64url').toString('utf8');
      const [tokenId, timestamp, signature] = decoded.split('_');
      const evil = `${tokenId}_${Number(timestamp) + 1}_${signature}`;
      const tamperedToken = `${prefix}${Buffer.from(evil).toString('base64url')}`;
      expect(
        tokenManager.verifySignature(
          tamperedToken,
          '03-1-USA-0001-P-251-3-82',
          'chittyid',
          provision.tokenId
        )
      ).toBe(false);
    });

    test('rebuilt with wrong chittyId → false', async () => {
      const provision = await tokenManager.provision({
        chittyId: '03-1-USA-0001-P-251-3-82',
        scope: ['chittyid:read'],
        service: 'chittyid',
        expiresIn: 3600
      });
      expect(
        tokenManager.verifySignature(
          provision.token,
          '03-1-USA-9999-P-251-3-82',
          'chittyid',
          provision.tokenId
        )
      ).toBe(false);
    });

    test('rebuilt with wrong service → false', async () => {
      const provision = await tokenManager.provision({
        chittyId: '03-1-USA-0001-P-251-3-82',
        scope: ['chittyid:read'],
        service: 'chittyid',
        expiresIn: 3600
      });
      expect(
        tokenManager.verifySignature(
          provision.token,
          '03-1-USA-0001-P-251-3-82',
          'other-service',
          provision.tokenId
        )
      ).toBe(false);
    });

    test('malformed body returns false (does not throw)', () => {
      expect(tokenManager.verifySignature('ca_live_!!!notbase64', 'x', 'y', 'tok_x')).toBe(false);
      expect(tokenManager.verifySignature('unknown_prefix_token', 'x', 'y', 'tok_x')).toBe(false);
    });
  });

  describe('Signature Verification (validate path, shadow mode)', () => {
    test('tampered token still validates (gate off) but signature_mismatch event is logged', async () => {
      // Default mockEnv has no CHITTYAUTH_VERIFY_SIGNATURE — shadow mode.
      const provision = await tokenManager.provision({
        chittyId: '03-1-USA-0001-P-251-3-82',
        scope: ['chittyid:read'],
        service: 'chittyid',
        expiresIn: 3600
      });

      // Build a tampered-signature token but write its hash into the store
      // so the lookup succeeds — simulating a record whose row exists but
      // whose token signature is bad.
      const prefix = 'ca_live_';
      const body = provision.token.slice(prefix.length);
      const decoded = Buffer.from(body, 'base64url').toString('utf8');
      const [tokenId, timestamp, signature] = decoded.split('_');
      const flippedFirst = signature[0] === 'A' ? 'B' : 'A';
      const evil = `${tokenId}_${timestamp}_${flippedFirst}${signature.slice(1)}`;
      const tamperedToken = `${prefix}${Buffer.from(evil).toString('base64url')}`;
      const tamperedHash = await tokenManager.hashToken(tamperedToken);

      // Seed mockEnv so this tampered-token hash resolves to the same record.
      await mockEnv.AUTH_TOKENS.put(
        `token:${tamperedHash}`,
        JSON.stringify({
          tokenId: provision.tokenId,
          chittyId: '03-1-USA-0001-P-251-3-82',
          scope: ['chittyid:read'],
          service: 'chittyid',
          createdAt: Date.now(),
          expiresAt: Date.now() + 3600 * 1000,
          requestCount: 0
        })
      );

      const result = await tokenManager.validate(tamperedToken);
      expect(result.valid).toBe(true); // shadow mode does not reject
      const events = await readAuditEvents(mockEnv.AUTH_AUDIT);
      expect(events.some((e) => e.eventType === 'signature_mismatch')).toBe(true);
    });

    test('enforce mode rejects tampered tokens', async () => {
      const enforcedEnv = {
        ...mockEnv,
        CHITTYAUTH_VERIFY_SIGNATURE: 'enforce'
      };
      const enforcedManager = new TokenManager(enforcedEnv);

      const provision = await enforcedManager.provision({
        chittyId: '03-1-USA-0001-P-251-3-82',
        scope: ['chittyid:read'],
        service: 'chittyid',
        expiresIn: 3600
      });

      const prefix = 'ca_live_';
      const body = provision.token.slice(prefix.length);
      const decoded = Buffer.from(body, 'base64url').toString('utf8');
      const [tokenId, timestamp, signature] = decoded.split('_');
      const flippedFirst = signature[0] === 'A' ? 'B' : 'A';
      const evil = `${tokenId}_${timestamp}_${flippedFirst}${signature.slice(1)}`;
      const tamperedToken = `${prefix}${Buffer.from(evil).toString('base64url')}`;
      const tamperedHash = await enforcedManager.hashToken(tamperedToken);

      await enforcedEnv.AUTH_TOKENS.put(
        `token:${tamperedHash}`,
        JSON.stringify({
          tokenId: provision.tokenId,
          chittyId: '03-1-USA-0001-P-251-3-82',
          scope: ['chittyid:read'],
          service: 'chittyid',
          createdAt: Date.now(),
          expiresAt: Date.now() + 3600 * 1000,
          requestCount: 0
        })
      );

      const result = await enforcedManager.validate(tamperedToken);
      expect(result.valid).toBe(false);
      expect(result.error).toMatch(/signature/i);
    });
  });
```

##### Step 1 Verification Checklist
- [x] `npm test` passes (all existing tests + new signature-verification tests). **29/29 passing** (was 23 before review-driven additions).
- [x] No new files created outside `src/token-manager.js` and `tests/token-manager.test.js`.
- [x] Tampered-signature test passes in shadow mode (returns `valid: true` and emits a `signature_mismatch` audit event).
- [x] Tampered-signature test passes in enforce mode (returns `valid: false`, error contains "signature").
- [x] All existing tests in `tests/token-manager.test.js` still pass (no regressions). **14 pre-existing tests still green**.
- [x] The `verifySignature` helper directly returns `false` for: tampered signature, tampered tokenId, tampered timestamp, wrong chittyId, wrong service, malformed body, unknown prefix, null chittyId/service, signature length != 32.

##### Review-driven additions (post `/pr-review-toolkit:review-pr`)
- [x] Deterministic 200-iteration happy-path loop (catches the underscore-in-signature parser regression class).
- [x] D1-fallback validate test that asserts `service_name` survives the round-trip (closes the regression window for the `service_name` INSERT bug).
- [x] Refresh chain under enforce mode (validate → revoke → provision → re-validate).
- [x] Dual-audit-event assertion (both `signature_mismatch` and `token_validation_failed` written on enforce reject).
- [x] Length-mismatch fast-path test (signature != 32 chars).
- [x] Null-args guard test (chittyId or service is null).
- [x] Inline comment in `validate()` tightened to specify strict equality of `CHITTYAUTH_VERIFY_SIGNATURE === 'enforce'`.
- [x] `signPayload` JSDoc notes the 32-char truncation must match `verifySignature`'s `SIGNATURE_LENGTH` constant.

#### Step 1 STOP & COMMIT
**STOP & COMMIT:** Agent must stop here and wait for the user to test, stage, and commit the change.

Suggested commit message:
```
fix(auth): add HMAC signature verification helper and shadow-mode logging

- src/token-manager.js: add verifySignature() that rebuilds the canonical
  payload from the looked-up record and compares HMAC via timingSafeEqual.
- src/token-manager.js: wire verifySignature into validate() with a
  CHITTYAUTH_VERIFY_SIGNATURE='enforce' gate; default observe-only.
  Mismatch always emits a signature_mismatch audit event.
- src/token-manager.js: fix provision() D1 INSERT to actually write
  service_name (column was named but never bound — D1 rows had NULL,
  which would have made signature verification on the D1-fallback path
  always fail).
- tests/token-manager.test.js: add unit tests for verifySignature
  (happy path + 6 negative cases) and validate() in shadow + enforce
  modes; update mock D1 INSERT handler for the new column position.

Refs #4
```

---

#### Step 2: Flip enforcement and align documentation

- [ ] In `src/token-manager.js`, locate the signature-verification block inside `validate()` you added in Step 1. Replace the block (the `const signatureOk = ... if (!signatureOk) { ... }` section) with this enforce-only version:

```javascript
    // Verify HMAC signature against the looked-up record.
    // Mismatch is a security regression — always reject, never short-circuit.
    const signatureOk = this.verifySignature(token, tokenData.chittyId, tokenData.service, tokenData.tokenId);
    if (!signatureOk) {
      await this.logAuditEvent({
        eventType: 'signature_mismatch',
        tokenId: tokenData.tokenId,
        chittyId: tokenData.chittyId,
        success: false,
        error: 'Signature verification failed',
        timestamp: Date.now()
      });
      await this.logAuditEvent({
        eventType: 'token_validation_failed',
        tokenId: tokenData.tokenId,
        chittyId: tokenData.chittyId,
        success: false,
        error: 'Invalid signature',
        timestamp: Date.now()
      });
      return { valid: false, error: 'Invalid token signature' };
    }
```

- [ ] In `tests/token-manager.test.js`, locate the `describe('Signature Verification (validate path, shadow mode)', ...)` block from Step 1 and replace it entirely with this enforce-by-default version (which also adds the forged-D1-row test):

```javascript

  describe('Signature Verification (validate path, enforced)', () => {
    test('tampered signature → validate rejects', async () => {
      const provision = await tokenManager.provision({
        chittyId: '03-1-USA-0001-P-251-3-82',
        scope: ['chittyid:read'],
        service: 'chittyid',
        expiresIn: 3600
      });

      const prefix = 'ca_live_';
      const body = provision.token.slice(prefix.length);
      const decoded = Buffer.from(body, 'base64url').toString('utf8');
      const [tokenId, timestamp, signature] = decoded.split('_');
      const flippedFirst = signature[0] === 'A' ? 'B' : 'A';
      const evil = `${tokenId}_${timestamp}_${flippedFirst}${signature.slice(1)}`;
      const tamperedToken = `${prefix}${Buffer.from(evil).toString('base64url')}`;
      const tamperedHash = await tokenManager.hashToken(tamperedToken);

      await mockEnv.AUTH_TOKENS.put(
        `token:${tamperedHash}`,
        JSON.stringify({
          tokenId: provision.tokenId,
          chittyId: '03-1-USA-0001-P-251-3-82',
          scope: ['chittyid:read'],
          service: 'chittyid',
          createdAt: Date.now(),
          expiresAt: Date.now() + 3600 * 1000,
          requestCount: 0
        })
      );

      const result = await tokenManager.validate(tamperedToken);
      expect(result.valid).toBe(false);
      expect(result.error).toMatch(/signature/i);
    });

    test('forged D1 row + matching plaintext signed with a foreign key → validate rejects', async () => {
      // Simulate a D1 compromise: an attacker without the signing key
      // crafts a plaintext token, computes its hash, and inserts a row.
      // Validation must reject because the signature in the plaintext
      // cannot match the HMAC under our real signing key.
      const forgedTokenId = 'tok_FORGEDFORGEDFORGEDFOR';
      const forgedTimestamp = Date.now();
      const forgedSignature = 'A'.repeat(32); // attacker has no signing key
      const forgedBody = `${forgedTokenId}_${forgedTimestamp}_${forgedSignature}`;
      const forgedToken = `ca_live_${Buffer.from(forgedBody).toString('base64url')}`;
      const forgedHash = await tokenManager.hashToken(forgedToken);

      await mockEnv.AUTH_DB.prepare(
        `INSERT INTO tokens (id, token_hash, chitty_id, scope, service_name, created_at, expires_at, request_count) VALUES (?, ?, ?, ?, ?, ?, ?, 0)`
      ).bind(
        forgedTokenId,
        forgedHash,
        'attacker-chitty-id',
        JSON.stringify(['admin:*']),
        'attacker-service',
        Date.now(),
        Date.now() + 86400000
      ).run();

      const result = await tokenManager.validate(forgedToken);
      expect(result.valid).toBe(false);
      expect(result.error).toMatch(/signature/i);
    });

    test('happy path still validates after enforcement is turned on', async () => {
      const provision = await tokenManager.provision({
        chittyId: '03-1-USA-0001-P-251-3-82',
        scope: ['chittyid:read'],
        service: 'chittyid',
        expiresIn: 3600
      });
      const result = await tokenManager.validate(provision.token);
      expect(result.valid).toBe(true);
      expect(result.tokenId).toBe(provision.tokenId);
    });

    test('refresh still works (validate→revoke→provision chain) under enforcement', async () => {
      const original = await tokenManager.provision({
        chittyId: '03-1-USA-0001-P-251-3-82',
        scope: ['chittyid:read'],
        service: 'chittyid',
        expiresIn: 3600
      });
      const refreshed = await tokenManager.refresh(original.token, 7200);
      expect(refreshed.success).toBe(true);
      const newValidation = await tokenManager.validate(refreshed.token);
      expect(newValidation.valid).toBe(true);
    });
  });
```

- [ ] Open `SECURITY.md`. Replace the bullet at line 48 (current `**Signing**:` line containing the "Important caveat" sentence) with:

```markdown
- **Signing**: HMAC-SHA256 over canonical token payload at issuance and verified on validate, key from `CHITTYAUTH_ISSUED_MINT_API_KEY` (legacy alias `TOKEN_SIGNING_KEY`, 256-bit). Truncated to 192 bits (32 base64url chars) on the wire.
```

- [ ] In `SECURITY.md`, replace the entire `## Validation Pipeline` section (currently lines 54-66) with:

```markdown
## Validation Pipeline

A token is trusted only after all of:

1. Format check (prefix + base64url shape).
2. SHA-256 hash lookup in D1 `tokens` (or `AUTH_TOKENS` KV cache for ≤30s).
3. HMAC-SHA256 signature verification against the canonical payload reconstructed from the looked-up record (`tokenId`, `chittyId`, `service`, `timestamp`), compared timing-safe.
4. `revoked_at IS NULL` and `expires_at > now`.
5. Not present in `AUTH_REVOCATIONS` KV.
6. Rate-limit check against `AUTH_RATE_LIMITS` KV (per-token, 1h window).

Any step failing → reject; never short-circuit later checks.
```

- [ ] In `SECURITY.md`, locate the `## Known Limitations` block (currently lines 95-102). Replace the **entire** numbered list with this version (Known Limitation #3 removed; remaining items renumbered):

```markdown
1. **No application-level WAF or per-IP throttling** — relies on Cloudflare’s platform protections; per-token rate limiting is the only application-level throttle today.
2. **No automated CI security scanning configured in this repo** — CodeQL, secret scanning, and `npm audit` gates are not part of the workflow set in `.github/workflows/`. Reviewers must perform these checks manually until added.
3. **Signing-key fallback to a hardcoded development value** — `src/token-manager.js:11` falls back through `CHITTYAUTH_ISSUED_MINT_API_KEY` → `TOKEN_SIGNING_KEY` → a hardcoded `'dev-signing-key-change-in-production'` literal. A production deploy missing both secrets will silently use the dev key; deploys must fail closed instead. Tracked as a follow-up issue.
4. **Single signing key, no kid rotation overlap** — rotating `CHITTYAUTH_ISSUED_MINT_API_KEY` invalidates all outstanding tokens. There is no dual-key verify window today.
5. **End-user tokens only** — service-to-service authentication is explicitly out of scope; do not retrofit `chittyauth-app` for inter-service auth.
```

- [ ] In `SECURITY.md`, update the Threat Model row for the signing key (currently line 40). Replace it with:

```markdown
| `CHITTYAUTH_ISSUED_MINT_API_KEY` (Worker secret; legacy alias `TOKEN_SIGNING_KEY`) | Confidentiality + integrity. Compromise = full forgery capability. |
```

- [ ] Open `CHARTER.md`. Find the version line at the very bottom (currently `*Charter Version: 1.3.0 | Last Updated: 2026-05-02*`). Replace it with:

```markdown
*Charter Version: 1.4.0 | Last Updated: 2026-05-02*
```

##### Step 2 Verification Checklist
- [ ] `npm test` passes — including the new "forged D1 row" test (this is the load-bearing security claim; if this fails, the fix is wrong).
- [ ] `grep -n "shadow mode\|CHITTYAUTH_VERIFY_SIGNATURE" src/token-manager.js` returns nothing (gate fully removed).
- [ ] `grep -n "Signature verification is currently NOT" SECURITY.md` returns nothing (caveat paragraph removed).
- [ ] `grep -n "signature verification.*enforced" SECURITY.md` matches the new positive language, not "not enforced".
- [ ] `SECURITY.md` Known Limitations list has 5 items (was 6); item #3 is the dev-key fallback (was #4); item #5 is "End-user tokens only" (was #6).
- [ ] `SECURITY.md` Validation Pipeline lists 6 steps with HMAC verification as step 3.
- [ ] `CHARTER.md` last line shows `Charter Version: 1.4.0`.
- [ ] Spin up `npm run dev` and validate one provisioned token end-to-end via curl to confirm no regression on the happy path:
  ```bash
  TOKEN=$(curl -s -X POST http://localhost:8787/v1/tokens/provision \
    -H 'Content-Type: application/json' \
    -d '{"chittyId":"03-1-USA-0001-P-251-3-82","scope":["chittyid:read"],"service":"chittyid","expiresIn":3600}' \
    | jq -r .token)
  curl -s -X POST http://localhost:8787/v1/tokens/validate \
    -H 'Content-Type: application/json' \
    -d "{\"token\":\"$TOKEN\"}" | jq .
  ```
  Expect `"valid": true`.

#### Step 2 STOP & COMMIT
**STOP & COMMIT:** Agent must stop here and wait for the user to test, stage, and commit the change.

Suggested commit message:
```
fix(auth): enforce HMAC signature verification on validate path

Removes the CHITTYAUTH_VERIFY_SIGNATURE shadow-mode gate added in the
previous commit. The validate path now always recomputes HMAC-SHA256 over
the canonical payload reconstructed from the looked-up record and rejects
on mismatch — closing the gap where a D1 compromise alone (without the
signing key) was sufficient to forge tokens.

- src/token-manager.js: verifySignature mismatch always returns
  { valid: false, error: 'Invalid token signature' }; emits both
  signature_mismatch and token_validation_failed audit events.
- tests/token-manager.test.js: replace shadow-mode tests with enforce-mode
  tests; add a "forged D1 row + foreign-key plaintext" test that proves
  the load-bearing security claim (D1 write access alone is no longer
  enough to forge a valid token).
- SECURITY.md: restore signature verification as step 3 of the validation
  pipeline; remove Known Limitation #3 and renumber the remaining items;
  remove the "Signature verification is currently NOT part of the live
  validate path" caveat paragraph; update the threat-model row to drop
  the "once enforced" qualifier.
- CHARTER.md: bump to 1.4.0.

Closes #4
```

After both commits land, push the branch and open the PR:

```bash
git push -u origin fix/validate-signature-verification
gh pr create --title "fix(auth): enforce HMAC signature verification on validate path" --body "$(cat <<'EOF'
## Summary
- Adds verifySignature() helper and wires it into validate() with timing-safe HMAC compare against a canonical payload reconstructed from the looked-up record.
- Fixes a pre-existing bug where provision() never wrote service_name to D1 (column named, never bound) — required for verification to succeed on the D1-fallback path.
- Restores SECURITY.md validation pipeline; removes Known Limitation #3.

## Test plan
- [x] All existing tests pass
- [x] verifySignature unit tests cover happy path + 6 tamper vectors
- [x] validate() rejects tampered-signature tokens
- [x] validate() rejects forged D1 row + foreign-key plaintext (the core security claim)
- [x] Refresh chain still works under enforcement
- [x] Manual curl smoke test on `wrangler dev --local` (provisioned token validates)

Closes #4
EOF
)"
```

# Security Policy

## Reporting a Vulnerability

**Do NOT report security vulnerabilities through public GitHub issues.**

### Preferred: GitHub Security Advisories

1. Open https://github.com/CHITTYAPPS/chittyauth-app/security/advisories/new
2. Click **Report a vulnerability**
3. Include: description, reproduction steps, affected versions/commit, observed impact, and any token/credential exposure assessment

### Alternative: Email

**security@chitty.cc**

### Response Timeline

- **Acknowledgement**: 24 hours
- **Triage confirmation**: 48 hours
- **Critical fix**: 7 days
- **High-severity fix**: 14 days

We follow coordinated disclosure and credit reporters unless anonymity is requested.

## Supported Versions

| Version | Supported |
|---------|-----------|
| Production deployment (Cloudflare Workers) | Yes |
| Local `wrangler dev` | Best effort |
| Unmodified forks | Not supported by this team |

## Threat Model & Trust Boundaries

ChittyAuth App is a **token authority**. Any compromise of the signing key, the D1 token table, or the validation cache breaks the security guarantee for every downstream consumer.

| Boundary | Trust assumption |
|----------|------------------|
| `CHITTYAUTH_ISSUED_MINT_API_KEY` (Worker secret; legacy alias `TOKEN_SIGNING_KEY`) | Confidentiality + integrity. Compromise = full forgery capability **once signature verification is enforced** (see Known Limitations). |
| D1 `tokens` table | Integrity. Holds SHA-256 hashes only; plaintext recovery is infeasible from this table. |
| `AUTH_TOKENS` KV (cache) | Soft state. Stale entries are bounded by 30s TTL; revocation must clear cache. |
| `AUTH_REVOCATIONS` KV | Authoritative for "revoked" decisions on the fast path. |
| Caller-provided tokens | Untrusted until verified end-to-end (signature, hash lookup, revocation check, expiry). |

## Cryptographic Design

- **Signing**: HMAC-SHA256 over canonical token payload at issuance, key from `CHITTYAUTH_ISSUED_MINT_API_KEY` (legacy alias `TOKEN_SIGNING_KEY`, 256-bit). **Important caveat:** the validate path today does not re-derive or compare the embedded signature — it relies on the SHA-256 hash lookup against D1/KV. See Known Limitations.
- **At-rest storage**: SHA-256 hash of the issued token. Plaintext is **never persisted** server-side.
- **One-time disclosure**: Plaintext token is returned to the caller exactly once at issuance. There is no recovery path; lost tokens must be reissued.
- **Random sources**: Web Crypto `crypto.getRandomValues` / `crypto.randomUUID` only.
- **No password hashing yet**: Registration today issues tokens, not password-backed sessions. Any future password storage must use a Workers-compatible KDF (PBKDF2 via Web Crypto).

## Validation Pipeline

A token is trusted only after all of:

1. Format check (prefix + base64url shape).
2. SHA-256 hash lookup in D1 `tokens` (or `AUTH_TOKENS` KV cache for ≤30s).
3. `revoked_at IS NULL` and `expires_at > now`.
4. Not present in `AUTH_REVOCATIONS` KV.
5. Rate-limit check against `AUTH_RATE_LIMITS` KV (per-token, 1h window).

Any step failing → reject; never short-circuit later checks.

**Signature verification is currently NOT part of the live validate path** (`src/token-manager.js` `validate()` hashes the bearer and looks up the hash; the embedded HMAC signature is generated at issuance but never re-derived on validate). Adding signature verification as step 2 — between format check and hash lookup — is tracked as a Known Limitation below; until that lands, an attacker who exfiltrates the D1 hash table does not gain forgery capability beyond replay of the already-hashed values, but the defense-in-depth that the signature is meant to provide is absent.

## Revocation Semantics

- Revocation writes to D1 (`status = 'revoked'`) **and** `AUTH_REVOCATIONS` KV **and** evicts `AUTH_TOKENS` cache entry.
- Code paths that consult only the cache without checking `AUTH_REVOCATIONS` are bugs and must be treated as security regressions.

## Audit

- D1 `auth_events` records issuance, validation outcome, revocation, and refresh events (schema in `schema.sql`).
- Logs MUST NOT contain plaintext tokens, signing keys, or full bearer headers. Token references use the `tok_*` ID or hash prefix only.
- `AUTH_AUDIT` KV is a write-buffer — it is not the system of record; D1 is.

## Secret Management

- Canonical secret names are `CHITTYAUTH_ISSUED_MINT_API_KEY` and `CHITTYAUTH_ISSUED_CONNECT_API_KEY` (when used). They are delivered exclusively via `wrangler secret put` and never live in `wrangler.toml`, source, KV, D1, or logs.
- Legacy aliases `TOKEN_SIGNING_KEY` and `CHITTYCONNECT_API_KEY` remain accepted only for migration compatibility and must be removed after cutover.
- Rotation cadence: `CHITTYAUTH_ISSUED_MINT_API_KEY` rotated quarterly. Rotation requires a coordinated reissue window since existing tokens become unverifiable when the key changes.
- 1Password is the cold source of truth per the global ChittyOS operator policy; Cloudflare Worker secrets are the runtime delivery channel.

## Hardening Checklist (per deploy)

- [ ] `wrangler secret list` shows `CHITTYAUTH_ISSUED_MINT_API_KEY` present
- [ ] `wrangler.toml` D1 `database_id` and KV `id` fields are real (no `CREATE_NEW_*` placeholders)
- [ ] `/health` returns `checks.database === true` and `checks.kv === true`
- [ ] No diff in this release introduces plaintext-token logging or new mocked auth paths
- [ ] Rate-limit window and TTL settings unchanged or reviewed
- [ ] Token-prefix scheme (`ca_live_`/`ca_test_`/`ca_dev_`, plus `svc_` for service tokens) matches deploy environment

## Known Limitations

1. **No application-level WAF or per-IP throttling** — relies on Cloudflare’s platform protections; per-token rate limiting is the only application-level throttle today.
2. **No automated CI security scanning configured in this repo** — CodeQL, secret scanning, and `npm audit` gates are not part of the workflow set in `.github/workflows/`. Reviewers must perform these checks manually until added.
3. **Signature verification is not enforced on the validate path** — `src/token-manager.js` `validate()` performs a SHA-256 hash lookup against D1/KV but never re-derives or compares the HMAC signature embedded in the token. The signing key is therefore advisory today, not load-bearing. Closing this gap is required before treating the signing key as the primary forgery defense; tracked as a follow-up issue.
4. **Signing-key fallback to a hardcoded development value** — `src/token-manager.js:11` falls back through `CHITTYAUTH_ISSUED_MINT_API_KEY` → `TOKEN_SIGNING_KEY` → a hardcoded `'dev-signing-key-change-in-production'` literal. A production deploy missing both secrets will silently use the dev key; deploys must fail closed instead. Tracked as a follow-up issue.
5. **Single signing key, no kid rotation overlap** — rotating `CHITTYAUTH_ISSUED_MINT_API_KEY` invalidates all outstanding tokens once signature verification is enforced. There is no dual-key verify window today.
6. **End-user tokens only** — service-to-service authentication is explicitly out of scope; do not retrofit `chittyauth-app` for inter-service auth.

## Security Contacts

- **Email**: security@chitty.cc
- **GitHub Security Advisories**: https://github.com/CHITTYAPPS/chittyauth-app/security/advisories

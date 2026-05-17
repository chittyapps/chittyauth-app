# ChittyAuth App Charter

## Classification
- **Canonical URI**: `chittycanon://core/services/chittyauth-app`
- **Tier**: 1 (Core Identity) — function-based; same tier as `chittyauth`, distinguished by deployment model
- **Organization**: CHITTYAPPS
- **Domain**: Operator-chosen (no canonical default)

## Mission

ChittyAuth App is a **standalone authentication and token provisioning service** that delivers ChittyAuth-class token issuance without the ChittyOS shared-database backbone. It is a Cloudflare-native build (D1 + KV) intended for third-party deployments, isolated environments, and per-app token authorities.

## Scope

### IS Responsible For
- User registration and account lifecycle (`/v1/register`)
- API token provisioning, validation, refresh, and revocation
- HMAC-SHA256 signing + SHA-256 hashed-at-rest token storage
- KV-first validation cache (30s TTL) and revocation blocklist
- Per-token rate limiting via KV counters (1h window)
- Append-only audit logging (D1 `auth_events`)
- OAuth client registration

### IS NOT Responsible For
- Service-to-service tokens (end-user tokens only — use `chittyauth` for inter-service auth)
- Shared identity tables with `chittyos-core`
- ChittyID minting (this app authenticates, it does not issue ChittyIDs)
- Cross-service identity sharing (storage is isolated by design)

## Comparison to `chittyauth`

| Aspect | `chittyauth` (CHITTYFOUNDATION) | `chittyauth-app` (CHITTYAPPS) |
|--------|---------------------------------|------------------------------|
| Database | Neon PostgreSQL (chittyos-core) | D1 (SQLite) + KV |
| Dependencies | ChittyID, ChittyConnect required | Optional (ChittyConnect only) |
| Data Sharing | Shares identity data | Isolated storage |
| Domain | `auth.chitty.cc` | Operator-chosen |
| Token Audience | Service + user | End-user only |
| Use Case | Core ChittyOS services | Third-party apps, custom deployments |

## Architecture

### Storage Bindings
- **D1** (`AUTH_DB`): `tokens`, `service_credentials`, `auth_events`, `token_stats`, `service_health`, `registrations` (from `schema-update.sql`)
- **KV**:
  - `AUTH_TOKENS` — validation cache (30s TTL)
  - `AUTH_REVOCATIONS` — revoked-token blocklist
  - `AUTH_RATE_LIMITS` — per-token request counters (1h window)
  - `AUTH_AUDIT` — audit-log buffer

### Provider Modes
- `CHITTYAUTH_PROVIDER=local` (default) — D1+KV-backed token authority described above.
- `CHITTYAUTH_PROVIDER=neon` — Neon OAuth facade (`src/auth-provider.js`); `api-router.js` exposes authorize/exchange endpoints. The local validation flow below applies to provider=local; the Neon path delegates issuance to Neon's OAuth endpoint.

### Validation Flow (provider=local)
```
Request → KV cache (fast path) ──hit──→ return
                │ miss
                ▼
            D1 query → cache (30s) → return
```

### Token Format
JWT-like `header.payload.signature`:
```json
{
  "iss": "chittyauth-app",
  "sub": "<user_id>",
  "aud": ["<application>"],
  "scopes": ["<scope>:<action>"],
  "iat": 0, "exp": 0,
  "jti": "<unique_token_id>"
}
```
Hashed with SHA-256 before storage; plaintext returned to caller exactly once at issuance.

## API Contract

### Public (no auth)
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/register` | POST | Register a user and issue first token |
| `/health` | GET | Liveness + binding health |

### Protected (Bearer token)
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/tokens/provision` | POST | Issue a new token |
| `/v1/tokens/validate` | POST | Validate a token |
| `/v1/tokens/refresh` | POST | Refresh expiration |
| `/v1/tokens/revoke` | POST | Revoke immediately |
| `/v1/tokens/stats` | GET | Usage statistics |

## Dependencies

| Type | Component | Purpose |
|------|-----------|---------|
| Runtime | Cloudflare Workers | Edge serverless host |
| Storage | Cloudflare D1 | Primary persistent store |
| Storage | Cloudflare KV | Cache, rate limit, revocation, audit buffer |
| Optional | ChittyConnect | External identity verification (off by default) |

## Configuration

### Required Secrets
- `CHITTYAUTH_ISSUED_MINT_API_KEY` — canonical 256-bit HMAC key (rotate quarterly)

### Optional Secrets
- `CHITTYAUTH_ISSUED_CONNECT_API_KEY` — canonical connect service token if ChittyConnect integration is enabled
- `NEON_OAUTH_CLIENT_ID` / `NEON_OAUTH_CLIENT_SECRET` — when `CHITTYAUTH_PROVIDER=neon`
- Legacy alias support remains for migration: `TOKEN_SIGNING_KEY`, `CHITTYCONNECT_API_KEY`

### Environment Variables
- `ENVIRONMENT` — `development` | `production`
- `CHITTYAUTH_PROVIDER` — `local` | `neon`
- `NEON_OAUTH_HOST` — defaults to `https://oauth2.neon.tech`
- `DEFAULT_TOKEN_EXPIRY` — seconds (default 2592000 = 30d)
- `MAX_TOKENS_PER_USER` — integer cap

## Ownership

| Role | Owner |
|------|-------|
| Service Owner | ChittyApps |
| Technical Lead | @chittyapps-team |
| Security Contact | security@chitty.cc |
| Service Contact | auth-app@chitty.cc |

## Compliance

Operational gate (must be green before deploy):
- [ ] D1 database created and `schema.sql` applied
- [ ] All four KV namespaces created and bound in `wrangler.toml`
- [ ] `CHITTYAUTH_ISSUED_MINT_API_KEY` set via `wrangler secret put`
- [ ] If Neon-backed mode is enabled: `CHITTYAUTH_PROVIDER=neon` and Neon OAuth secrets are present
- [ ] `/health` returns `{"status":"healthy"}` with `dependencies.chittyConnect === "healthy"` (current shape per `api-router.js:392-403`; richer `checks.database`/`checks.kv` reporting is a future health-endpoint enhancement)
- [ ] `/v1/register` smoke test succeeds end-to-end
- [ ] `/v1/tokens/validate` confirms KV-cache hit on second call
- [ ] CHARTER.md, CHITTY.md, CLAUDE.md, AGENTS.md, SECURITY.md present and consistent

Documentation gate:
- [ ] No mocked/placeholder routes in committed code (per global no-mocks policy)
- [ ] No fake or seeded data in `schema.sql` (real shapes only)

---
*Charter Version: 1.3.0 | Last Updated: 2026-05-02*

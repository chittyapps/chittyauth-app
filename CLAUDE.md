# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> **🎯 Project Orchestration:** This project follows [ChittyCan™ Project Standards](../CHITTYCAN_PROJECT_ORCHESTRATOR.md)

## Project Overview

**ChittyAuth App** is the production authentication and token provisioning service for the ChittyOS ecosystem, deployed at `auth.chitty.cc`. It uses Cloudflare-native storage (D1 + KV) as the primary backend, with an optional Neon OAuth facade (`CHITTYAUTH_PROVIDER=neon`) for federation.

**Key characteristics:**
- Worker `name="chittyauth"`, deployed to `auth.chitty.cc/*` on the ChittyCorp account
- D1 (SQLite) as the primary token/event store; KV for hot-path caching and rate limits
- Optional ChittyConnect integration for credential brokerage
- Provider modes: `local` (D1+KV only) or `neon` (Neon OAuth facade enabled)
- Tail-consumed by `chittytrack` for observability per canonical Worker policy

## Architecture

### Storage Backend: D1 + KV

**D1 Database** (`AUTH_DB`, primary storage — schema in `schema.sql`):
- `tokens` - Token records and metadata
- `service_credentials` - Service-to-service credentials
- `auth_events` - Audit trail (issuance, validation, revocation)
- `token_stats` - Per-token usage counters
- `service_health` - Health snapshots
- `registrations` - Public-registration intake

**KV Namespaces** (Caching & fast access):
- `AUTH_TOKENS` - Token validation cache
- `AUTH_REVOCATIONS` - Revoked token list
- `AUTH_RATE_LIMITS` - Rate limiting counters
- `AUTH_AUDIT` - Audit log buffer

### Provider Modes

| Mode | When | What it enables |
|------|------|-----------------|
| `local` (default) | Self-contained Cloudflare deploy | D1+KV token lifecycle only |
| `neon` | Federated OAuth via Neon | Adds Neon OAuth facade in `src/auth-provider.js` (`/oauth/*`) on top of local D1+KV |

## Development Commands

### Local Development
```bash
npm install          # Install dependencies
npm run dev          # Start local dev server (localhost:8787)
```

### Database Management
```bash
# Create D1 database
wrangler d1 create chittyauth-db

# Initialize schema
wrangler d1 execute chittyauth-db --file=./schema.sql

# Query database
wrangler d1 execute chittyauth-db --command="SELECT * FROM api_tokens LIMIT 10"
```

### KV Namespace Management
```bash
# Create KV namespaces
wrangler kv:namespace create AUTH_TOKENS
wrangler kv:namespace create AUTH_REVOCATIONS
wrangler kv:namespace create AUTH_RATE_LIMITS
wrangler kv:namespace create AUTH_AUDIT

# List keys in namespace
wrangler kv:key list --binding=AUTH_TOKENS

# Get value
wrangler kv:key get "token_hash" --binding=AUTH_TOKENS
```

### Secrets Management
```bash
# Set required secrets
wrangler secret put TOKEN_SIGNING_KEY

# Optional secrets
wrangler secret put CHITTYCONNECT_API_KEY

# List configured secrets
wrangler secret list
```

### Deployment
```bash
npm run deploy              # Deploy to production
npm run deploy:dev          # Deploy to development
npm run tail                # Stream live logs
```

### Testing
```bash
npm test                    # Run all tests
npm run test:unit           # Unit tests only
npm run test:integration    # Integration tests
```

## Code Structure

### Entry Point
- `worker.js` - Cloudflare Workers fetch handler

### Core Services
- `src/api-router.js` - Main API router with endpoint handlers
- `src/token-manager.js` - Token generation, validation, lifecycle
- `src/registration-handler.js` - Public registration endpoint
- `src/chittyconnect-client.js` - Optional ChittyConnect integration

### Storage Layer
- D1 database accessed via `env.AUTH_DB` binding
- KV namespaces accessed via `env.AUTH_TOKENS`, `env.AUTH_REVOCATIONS`, etc.
- No ORM - uses raw SQL queries for simplicity

### Testing
- `tests/` - Test suites
- Test with local D1/KV: `wrangler dev --local`

## Key API Endpoints

### Public Endpoints (no authentication required)
- `POST /v1/register` - Register new user and get first token
- `GET /health` - Health check

### Protected Endpoints (require Bearer token)
- `POST /v1/tokens/provision` - Provision new API token
- `POST /v1/tokens/validate` - Validate token
- `POST /v1/tokens/refresh` - Refresh token expiration
- `POST /v1/tokens/revoke` - Revoke token
- `GET /v1/tokens/stats` - Token usage statistics

See [README.md](./README.md) for complete API documentation.

## Token Security

### Storage Strategy
1. **Never store plaintext tokens**
   - Generate token with HMAC-SHA256 signature
   - Hash token with SHA-256
   - Store only hash in D1 database
   - Return plaintext token to user (only time it's visible)

2. **Validation Flow**
   ```javascript
   // 1. Check KV cache first (fast path)
   const cached = await env.AUTH_TOKENS.get(tokenHash);
   if (cached) return JSON.parse(cached);

   // 2. Query D1 (slow path)
   const token = await env.AUTH_DB.prepare(
     'SELECT * FROM api_tokens WHERE token_hash = ?'
   ).bind(tokenHash).first();

   // 3. Cache valid token for 30 seconds
   if (token && token.status === 'active') {
     await env.AUTH_TOKENS.put(tokenHash, JSON.stringify(token), { expirationTtl: 30 });
   }
   ```

3. **Revocation**
   - Update status to 'revoked' in D1
   - Add to `AUTH_REVOCATIONS` KV (fast revocation check)
   - Clear from `AUTH_TOKENS` cache

### Token Format
JWT-like structure: `header.payload.signature`

Header:
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

Payload:
```json
{
  "iss": "chittyauth-app",
  "sub": "user_id or chitty_id",
  "aud": ["chittyid", "myapp"],
  "scopes": ["chittyid:read", "myapp:write"],
  "iat": 1700000000,
  "exp": 1700086400,
  "jti": "unique_token_id"
}
```

## Configuration

### wrangler.toml
```toml
name = "chittyauth-app"
main = "worker.js"
compatibility_date = "2024-09-23"

# D1 Database binding
[[d1_databases]]
binding = "AUTH_DB"
database_name = "chittyauth-db"
database_id = "..." # Set after creation

# KV Namespace bindings
[[kv_namespaces]]
binding = "AUTH_TOKENS"
id = "..." # Set after creation

[[kv_namespaces]]
binding = "AUTH_REVOCATIONS"
id = "..."

[[kv_namespaces]]
binding = "AUTH_RATE_LIMITS"
id = "..."

[[kv_namespaces]]
binding = "AUTH_AUDIT"
id = "..."
```

### Environment Variables
- `ENVIRONMENT` - "development" or "production"
- `CHITTYCONNECT_URL` - Optional ChittyConnect endpoint
- `DEFAULT_TOKEN_EXPIRY` - Default token lifetime (seconds)
- `MAX_TOKENS_PER_USER` - Max tokens per user

### Secrets (canonical names)
- `CHITTYAUTH_ISSUED_MINT_API_KEY` - Required, 256-bit key for HMAC signatures (legacy alias: `TOKEN_SIGNING_KEY`)
- `CHITTYAUTH_ISSUED_CONNECT_API_KEY` - Optional, ChittyConnect service token (legacy alias: `CHITTYCONNECT_API_KEY`)
- `NEON_OAUTH_CLIENT_ID` / `NEON_OAUTH_CLIENT_SECRET` - Required when `CHITTYAUTH_PROVIDER=neon`

## Troubleshooting

### "Database not found" errors
```bash
# Verify database exists
wrangler d1 list

# Check binding in wrangler.toml
[[d1_databases]]
binding = "AUTH_DB"
database_id = "your-database-id"

# Re-initialize schema
wrangler d1 execute chittyauth-db --file=./schema.sql
```

### "KV namespace not found" errors
```bash
# Verify namespaces exist
wrangler kv:namespace list

# Check bindings in wrangler.toml match namespace IDs
```

### Token validation slow
- Check KV cache hit rate: `wrangler kv:key list --binding=AUTH_TOKENS`
- Verify cache TTL is set (30 seconds recommended)
- Monitor D1 query performance: `wrangler tail`

### Rate limiting not working
- Verify `AUTH_RATE_LIMITS` KV namespace is bound
- Check TTL on rate limit keys (1 hour window)
- Test with: `wrangler kv:key get "rate_limit:user_id" --binding=AUTH_RATE_LIMITS`

## Security Best Practices

1. **Rotate `CHITTYAUTH_ISSUED_MINT_API_KEY` quarterly**
2. **Monitor audit logs for suspicious activity**
3. **Set appropriate token expiration (30 days max)**
4. **Implement rate limiting on all endpoints**
5. **Use HTTPS only in production**
6. **Never log token values (only hashes)**
7. **Regularly review and revoke unused tokens**

## Deployment Checklist

Before deploying to production:

- [ ] All KV namespaces created and bound
- [ ] D1 database created and schema initialized
- [ ] `CHITTYAUTH_ISSUED_MINT_API_KEY` secret set (256-bit)
- [ ] `wrangler.toml` updated with correct IDs
- [ ] Custom domain configured (if desired)
- [ ] Secrets verified: `wrangler secret list`
- [ ] Test health endpoint: `curl https://your-domain.com/health`
- [ ] Test registration: `curl -X POST https://your-domain.com/v1/register -d '{"name":"Test","email":"test@example.com"}'`

## Related Documentation

- [README.md](./README.md) - Complete project documentation
- [ARCHITECTURE.md](./ARCHITECTURE.md) - Detailed architecture guide
- [DEPLOYMENT.md](./DEPLOYMENT.md) - Step-by-step deployment instructions
- [API_SPEC.md](./API_SPEC.md) - (TBD) API contracts and schemas

## Implementation Notes

Working on this codebase, keep these load-bearing facts in mind:

1. **D1 is the primary store**; Neon is only reachable via the OAuth facade when `CHITTYAUTH_PROVIDER=neon`.
2. **KV is hot-path cache** for token validation (30s TTL) and revocation checks — never the source of truth.
3. **Canonical secrets** (`CHITTYAUTH_ISSUED_*`) are authoritative; legacy `TOKEN_SIGNING_KEY` / `CHITTYCONNECT_API_KEY` remain as migration aliases only.
4. **Signing-key fallback fails closed** in production (per #9). Dev still tolerates the dev fallback.
5. **Token validation is hash-lookup, not signature-verify** today — see SECURITY.md Known Limitation #3.
6. **Schema source of truth** is `schema.sql`. If a doc disagrees, the schema wins.

## Common Development Patterns

### Adding a New Endpoint
1. Add route handler in `src/api-router.js`
2. Implement business logic in appropriate service file
3. Add D1/KV queries as needed
4. Update API documentation
5. Add tests

### Modifying Token Format
1. Update token generation in `src/token-manager.js`
2. Update validation logic to handle both old and new formats (migration period)
3. Update schema if storing new fields
4. Document breaking changes

### Adding a New Scope
1. Add scope definition to token provisioning
2. Update validation logic in services that check scopes
3. Document scope in README.md
4. Add to scope checking tests

---

**Last Updated**: 2026-05-23
**Maintainer**: ChittyApps Team

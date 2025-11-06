# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> **🎯 Project Orchestration:** This project follows [ChittyCan™ Project Standards](../CHITTYCAN_PROJECT_ORCHESTRATOR.md)

## Project Overview

**ChittyAuth App** is a standalone authentication and token provisioning service designed for independent deployment without ChittyOS infrastructure dependencies. Unlike the OS-integrated `chittyauth` service, this app uses Cloudflare-native storage (D1 + KV) and requires no external database connections.

**Key characteristics:**
- Runs on Cloudflare Workers (serverless edge runtime)
- Uses D1 (SQLite) for primary storage
- Uses KV namespaces for caching and rate limiting
- Zero external dependencies (no Neon PostgreSQL, no chittyos-core)
- Fully isolated from ChittyOS ecosystem
- Can be deployed to any Cloudflare account

## Architecture

### Storage Backend: D1 + KV (Standalone)

**D1 Database** (Primary storage):
- `api_tokens` - Token records and metadata
- `users` - User accounts (if using registration)
- `audit_logs` - Complete audit trail
- `oauth_clients` - OAuth client registrations

**KV Namespaces** (Caching & fast access):
- `AUTH_TOKENS` - Token validation cache
- `AUTH_REVOCATIONS` - Revoked token list
- `AUTH_RATE_LIMITS` - Rate limiting counters
- `AUTH_AUDIT` - Audit log buffer

### Comparison to chittyauth (OS-integrated)

| Aspect | chittyauth (chittyfoundation) | chittyauth-app (chittyapps) |
|--------|------------------------------|---------------------------|
| Database | Neon PostgreSQL (chittyos-core) | D1 + KV |
| Dependencies | ChittyID, ChittyConnect required | Optional integrations |
| Data Sharing | Shares identity data | Isolated storage |
| Deployment | auth.chitty.cc | Any custom domain |
| Use Case | Core ChittyOS services | Third-party apps |

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

### Secrets
- `TOKEN_SIGNING_KEY` - Required, 256-bit key for HMAC signatures
- `CHITTYCONNECT_API_KEY` - Optional, for ChittyConnect integration

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

1. **Rotate TOKEN_SIGNING_KEY quarterly**
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
- [ ] `TOKEN_SIGNING_KEY` secret set (256-bit)
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

## Differences from chittyauth

When working on this codebase, remember these key differences from the OS-integrated `chittyauth`:

1. **No Neon PostgreSQL** - Uses D1 instead
2. **No shared tables** - All data is isolated
3. **No ChittyID dependency** - Can work standalone
4. **KV-first architecture** - Heavy caching for performance
5. **No service-to-service tokens** - Designed for end-user tokens only
6. **Simpler schema** - Fewer tables, focused on token management

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

**Last Updated**: 2025-11-06
**Maintainer**: ChittyApps Team

# ChittyAuth App Charter

## Classification
- **Tier**: 3 (Service Layer)
- **Organization**: CHITTYAPPS
- **Domain**: Custom (not auth.chitty.cc)

## Mission

ChittyAuth App is a **standalone authentication and token provisioning service** designed for independent deployment without ChittyOS infrastructure dependencies. Unlike the OS-integrated `chittyauth` service, this app uses Cloudflare-native storage (D1 + KV) and requires no external database connections.

## Scope

### IS Responsible For
- User registration and account management
- API token provisioning with HMAC-SHA256 signatures
- Token validation with KV caching (fast path)
- Token refresh and revocation
- Rate limiting via KV namespaces
- Complete audit logging
- OAuth client registration
- D1 SQLite primary storage
- KV-first caching architecture

### IS NOT Responsible For
- ChittyOS ecosystem integration
- Shared identity tables (uses isolated storage)
- Service-to-service tokens (end-user tokens only)
- ChittyID dependency (can work standalone)

## Comparison to chittyauth

| Aspect | chittyauth (CHITTYFOUNDATION) | chittyauth-app (CHITTYAPPS) |
|--------|-------------------------------|---------------------------|
| Database | Neon PostgreSQL (chittyos-core) | D1 + KV |
| Dependencies | ChittyID, ChittyConnect required | Optional integrations |
| Data Sharing | Shares identity data | Isolated storage |
| Deployment | auth.chitty.cc | Any custom domain |
| Use Case | Core ChittyOS services | Third-party apps |
| Token Type | Service + User tokens | End-user tokens only |

## Architecture

### Storage Backend
**D1 Database** (Primary):
- `api_tokens` - Token records and metadata
- `users` - User accounts
- `audit_logs` - Complete audit trail
- `oauth_clients` - OAuth client registrations

**KV Namespaces** (Caching):
- `AUTH_TOKENS` - Token validation cache (30s TTL)
- `AUTH_REVOCATIONS` - Revoked token list
- `AUTH_RATE_LIMITS` - Rate limiting counters (1h window)
- `AUTH_AUDIT` - Audit log buffer

### Token Security
1. Generate token with HMAC-SHA256 signature
2. Hash token with SHA-256
3. Store only hash in D1 (never plaintext)
4. Return plaintext to user (only time visible)

### Validation Flow
```
Request → Check KV cache (fast path)
    → If miss: Query D1 (slow path)
    → Cache valid token for 30 seconds
    → Return validation result
```

## API Endpoints

### Public (No Auth)
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/register` | POST | Register new user |
| `/health` | GET | Health check |

### Protected (Bearer Token)
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/tokens/provision` | POST | Provision new API token |
| `/v1/tokens/validate` | POST | Validate token |
| `/v1/tokens/refresh` | POST | Refresh token expiration |
| `/v1/tokens/revoke` | POST | Revoke token |
| `/v1/tokens/stats` | GET | Token usage statistics |

## Token Format

JWT-like structure: `header.payload.signature`

```json
{
  "iss": "chittyauth-app",
  "sub": "user_id",
  "aud": ["myapp"],
  "scopes": ["myapp:read", "myapp:write"],
  "iat": 1700000000,
  "exp": 1700086400,
  "jti": "unique_token_id"
}
```

## Dependencies

| Type | Service | Purpose |
|------|---------|---------|
| Optional | ChittyConnect | External integration |
| Storage | Cloudflare D1 | SQLite database |
| Storage | Cloudflare KV | Caching and rate limiting |
| Runtime | Cloudflare Workers | Serverless edge |

## Configuration

### Required Secrets
- `TOKEN_SIGNING_KEY` - 256-bit key for HMAC signatures

### Optional Secrets
- `CHITTYCONNECT_API_KEY` - For ChittyConnect integration

### Environment Variables
- `ENVIRONMENT` - "development" or "production"
- `DEFAULT_TOKEN_EXPIRY` - Token lifetime (seconds)
- `MAX_TOKENS_PER_USER` - Token limit per user

## Ownership

| Role | Owner |
|------|-------|
| Service Owner | ChittyApps |
| Technical Lead | @chittyapps-team |
| Contact | auth-app@chitty.cc |

## Compliance

- [ ] CLAUDE.md development guide present
- [ ] D1 database initialized with schema
- [ ] All KV namespaces created and bound
- [ ] TOKEN_SIGNING_KEY secret set (256-bit)
- [ ] Health endpoint operational
- [ ] Registration endpoint tested
- [ ] Rate limiting verified

## Security Checklist

- [ ] Rotate TOKEN_SIGNING_KEY quarterly
- [ ] Monitor audit logs for suspicious activity
- [ ] Token expiration set (30 days max)
- [ ] Rate limiting on all endpoints
- [ ] HTTPS only in production
- [ ] Never log token values (only hashes)

---
*Charter Version: 1.0.0 | Last Updated: 2026-01-13*

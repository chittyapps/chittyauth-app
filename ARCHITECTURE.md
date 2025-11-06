# ChittyAuth - Authentication & Token Provisioning Service

**Production Endpoint**: `https://auth.chitty.cc`
**Purpose**: Centralized authentication and API token provisioning for ChittyOS ecosystem
**Priority**: 0 (Highest - Core Infrastructure)

---

## 🏗️ Architecture Overview

ChittyAuth is the **authoritative authentication service** for the entire ChittyOS ecosystem. It provisions, validates, and manages API tokens for all services.

### Design Principles
- **Centralized Token Authority** - Single source of truth for all API tokens
- **Zero-Trust Architecture** - Every token is validated on every request
- **Service-to-Service Auth** - Manages inter-service authentication
- **ChittyConnect Integration** - Leverages existing OAuth/user identity from ChittyConnect
- **Audit Trail** - Complete lifecycle tracking for all tokens

---

## 🎯 Service Responsibilities

### What ChittyAuth DOES:
✅ Provision API tokens for ChittyID and other services
✅ Validate Bearer tokens on every request
✅ Manage token lifecycle (issue, refresh, revoke)
✅ Integrate with ChittyConnect for user identity
✅ Enforce rate limits and quotas per token
✅ Audit all authentication events

### What ChittyAuth DOES NOT DO:
❌ Generate ChittyIDs (that's ChittyID's job)
❌ Handle OAuth flows directly (ChittyConnect does this)
❌ Store user profiles (ChittyConnect does this)
❌ Business logic (services handle their own logic)

---

## 🔌 API Endpoints

### Token Provisioning

#### `POST /v1/tokens/provision`
Provision a new API token for a service or user.

**Request:**
```json
{
  "chittyId": "03-1-USA-0001-P-251-3-82",
  "scope": ["chittyid:read", "chittyid:generate"],
  "service": "chittyid",
  "expiresIn": 2592000
}
```

**Response:**
```json
{
  "success": true,
  "token": "ca_live_abc123xyz789...",
  "tokenId": "tok_abc123",
  "scope": ["chittyid:read", "chittyid:generate"],
  "expiresAt": "2025-12-02T00:00:00Z",
  "rateLimit": {
    "requests": 1000,
    "window": "1h"
  }
}
```

#### `POST /v1/tokens/validate`
Validate a Bearer token.

**Request:**
```json
{
  "token": "ca_live_abc123xyz789..."
}
```

**Response:**
```json
{
  "valid": true,
  "tokenId": "tok_abc123",
  "chittyId": "03-1-USA-0001-P-251-3-82",
  "scope": ["chittyid:read", "chittyid:generate"],
  "expiresAt": "2025-12-02T00:00:00Z",
  "rateLimitRemaining": 987
}
```

#### `POST /v1/tokens/refresh`
Refresh an existing token before expiration.

**Request:**
```json
{
  "token": "ca_live_abc123xyz789...",
  "expiresIn": 2592000
}
```

**Response:**
```json
{
  "success": true,
  "token": "ca_live_def456uvw012...",
  "tokenId": "tok_def456",
  "expiresAt": "2025-12-02T00:00:00Z"
}
```

#### `POST /v1/tokens/revoke`
Revoke a token immediately.

**Request:**
```json
{
  "tokenId": "tok_abc123",
  "reason": "Security incident"
}
```

**Response:**
```json
{
  "success": true,
  "tokenId": "tok_abc123",
  "revokedAt": "2025-11-02T12:34:56Z"
}
```

### Service Authentication

#### `POST /v1/service/authenticate`
Authenticate a service-to-service request.

**Request:**
```json
{
  "serviceToken": "svc_chittyrouter_abc123",
  "targetService": "chittyid",
  "action": "generate"
}
```

**Response:**
```json
{
  "authorized": true,
  "serviceId": "chittyrouter",
  "permissions": ["chittyid:generate", "chittyid:validate"],
  "sessionToken": "sess_temp_xyz789"
}
```

### Health & Monitoring

#### `GET /health`
Service health check.

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "timestamp": "2025-11-02T12:34:56Z"
}
```

#### `GET /v1/tokens/stats`
Token usage statistics (admin only).

**Response:**
```json
{
  "totalTokens": 1234,
  "activeTokens": 987,
  "revokedTokens": 247,
  "requestsToday": 45678,
  "topServices": [
    {"service": "chittyid", "requests": 12345},
    {"service": "chittyrouter", "requests": 8901}
  ]
}
```

---

## 🔐 Token Format

### Token Structure
```
ca_live_<base64url(tokenId + timestamp + signature)>
```

**Example:**
```
ca_live_dG9rX2FiYzEyM18xNzMwNTQzMjk2X3NpZ25hdHVyZQ
```

### Token Prefixes
- `ca_live_` - Production token
- `ca_test_` - Test/staging token
- `ca_dev_` - Development token
- `svc_` - Service-to-service token

### Token Scopes
- `chittyid:read` - Read ChittyID information
- `chittyid:generate` - Generate new ChittyIDs
- `chittyid:validate` - Validate ChittyIDs
- `chittyid:audit` - Access audit trails
- `admin:*` - Full administrative access

---

## 🔗 ChittyConnect Integration

ChittyAuth delegates user authentication to **ChittyConnect** (existing service):

```
┌─────────────────┐
│  ChittyConnect  │ ← OAuth flows, user identity
└────────┬────────┘
         │ (validates user)
         ▼
┌─────────────────┐
│   ChittyAuth    │ ← Issues API tokens
└────────┬────────┘
         │ (provides token)
         ▼
┌─────────────────┐
│    ChittyID     │ ← Validates token via ChittyAuth
└─────────────────┘
```

### Integration Flow:
1. User authenticates via **ChittyConnect** → receives ChittyID
2. User requests API token from **ChittyAuth** → provides ChittyID
3. ChittyAuth verifies ChittyID with ChittyConnect
4. ChittyAuth provisions token with appropriate scopes
5. User calls ChittyID with Bearer token
6. ChittyID validates token with ChittyAuth

---

## 💾 Storage Architecture

### KV Namespaces
- `AUTH_TOKENS` - Active token storage (TTL-based)
- `AUTH_REVOCATIONS` - Revoked token blacklist
- `AUTH_RATE_LIMITS` - Per-token rate limit counters
- `AUTH_AUDIT` - Authentication event logs

### D1 Database (AUTH_DB)
```sql
-- Tokens table
CREATE TABLE tokens (
  id TEXT PRIMARY KEY,
  token_hash TEXT UNIQUE NOT NULL,
  chitty_id TEXT NOT NULL,
  scope TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  last_used_at INTEGER,
  request_count INTEGER DEFAULT 0,
  revoked_at INTEGER
);

-- Service credentials table
CREATE TABLE service_credentials (
  service_name TEXT PRIMARY KEY,
  service_token_hash TEXT NOT NULL,
  permissions TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_rotated_at INTEGER
);

-- Audit log table
CREATE TABLE auth_events (
  id TEXT PRIMARY KEY,
  event_type TEXT NOT NULL,
  token_id TEXT,
  chitty_id TEXT,
  service_name TEXT,
  success INTEGER NOT NULL,
  error_message TEXT,
  ip_address TEXT,
  user_agent TEXT,
  timestamp INTEGER NOT NULL
);
```

---

## 🛡️ Security Features

### Token Security
- ✅ SHA-256 hashed storage (never store plain tokens)
- ✅ Cryptographic signatures (HMAC-SHA256)
- ✅ Time-based expiration (default: 30 days)
- ✅ Automatic revocation on suspicious activity
- ✅ Rate limiting per token (configurable)

### Request Security
- ✅ Bearer token validation on every request
- ✅ Scope-based authorization
- ✅ IP-based rate limiting
- ✅ Audit logging for all events
- ✅ Circuit breaker for failed validations

---

## 📊 Rate Limiting

### Default Limits
- **Standard Token**: 100 requests/hour
- **Authenticated Token**: 1,000 requests/hour
- **Premium Token**: 5,000 requests/hour
- **Service Token**: 10,000 requests/hour

### Rate Limit Headers
```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 987
X-RateLimit-Reset: 1730547600
```

---

## 🚀 Deployment

### Environment Variables
```bash
# Cloudflare Account
ACCOUNT_ID="0bc21e3a5a9de1a4cc843be9c3e98121"

# Secrets (via wrangler secret put)
TOKEN_SIGNING_KEY="<256-bit secret key>"
CHITTYCONNECT_API_KEY="<ChittyConnect service token>"

# Optional
DEFAULT_TOKEN_EXPIRY="2592000"  # 30 days in seconds
MAX_TOKENS_PER_USER="10"
```

### Deployment Commands
```bash
cd chittyauth
npm install
wrangler deploy --env production
```

---

## 🧪 Testing

### Unit Tests
```bash
npm run test:unit
```

### Integration Tests
```bash
npm run test:integration
```

### Security Tests
```bash
npm run test:security
```

---

## 📈 Monitoring & Alerts

### Key Metrics
- Token provisioning rate
- Token validation rate
- Failed validation rate
- Rate limit exceeded count
- Service authentication failures

### Alerts
- Failed validation rate > 5%
- Rate limit exceeded > 1000/hour
- Token revocation spike
- D1 database errors

---

## 🔄 Token Lifecycle

```
┌──────────────┐
│  Provision   │ → Token created with scope + expiry
└──────┬───────┘
       ▼
┌──────────────┐
│   Active     │ → Token validated on each request
└──────┬───────┘
       ▼
┌──────────────┐
│   Refresh    │ → Optional: extend expiration
└──────┬───────┘
       ▼
┌──────────────┐
│   Revoke     │ → Token invalidated (blacklisted)
└──────────────┘
```

---

## 🌐 ChittyOS Ecosystem Position

```
ChittyConnect ─→ ChittyAuth ─→ ChittyID
     (OAuth)      (API Tokens)   (Identity)
                       ↓
                  ChittyRouter
                  ChittyCore
                  ChittyCases
                  ... (51+ services)
```

ChittyAuth is the **authentication gateway** for the entire ecosystem.

---

## 📝 License

ChittyFoundation Official Service
© 2025 ChittyCorp LLC

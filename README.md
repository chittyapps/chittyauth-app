# ChittyAuth App

**Standalone Authentication & Token Provisioning Application**

ChittyAuth App is a fully independent, bolt-on authentication service that can be deployed without any external dependencies. Unlike the OS-integrated `chittyauth` service, this app uses Cloudflare-native storage (D1 + KV) and requires no external database connections.

---

## 🎯 Purpose

ChittyAuth App provides secure API token provisioning and validation for applications that need authentication without coupling to the ChittyOS infrastructure. It's designed for:

- **Third-party integrations** - Deploy your own auth service
- **Isolated environments** - No dependency on chittyos-core database
- **Custom deployments** - Run on your own Cloudflare account
- **Development/testing** - Standalone setup for local development

---

## ⚖️ ChittyAuth vs ChittyAuth App

| Feature | [chittyauth](https://github.com/chittyfoundation/chittyauth) (OS-Integrated) | chittyauth-app (Standalone) |
|---------|------------------------------------------------------------------------------|----------------------------|
| **Organization** | chittyfoundation | chittyapps |
| **Database** | Neon PostgreSQL (shared chittyos-core) | D1 + KV (Cloudflare-native) |
| **Dependencies** | Requires ChittyOS infrastructure | Zero external dependencies |
| **Use Case** | Core ChittyOS services | Third-party apps, custom deployments |
| **Deployment** | auth.chitty.cc | Your own domain |
| **Data Sharing** | Shares identity data with ChittyID, ChittyVerify, ChittyTrust | Isolated data storage |

**When to use which:**
- Use **chittyauth** if you're building ChittyOS services that need to share identity data
- Use **chittyauth-app** if you need standalone authentication without ChittyOS dependencies

---

## ✅ Success Criteria

ChittyAuth App is considered successful when it meets these measurable targets:

1. **Availability**: 99.9% uptime (measured monthly)
2. **Performance**:
   - Token validation < 100ms (p95)
   - Token provisioning < 500ms (p95)
   - Bootstrap registration < 2s (p95)
3. **Security**: Zero unauthorized token access incidents
4. **Reliability**: Token hash collision rate < 1 in 10^12
5. **Independence**: Deployable without any external services
6. **Auditability**: 100% of token operations logged with complete audit trail

---

## 🚫 Non-Goals

ChittyAuth App explicitly does NOT:

1. **Connect to chittyos-core database**: Uses D1/KV only
2. **Require ChittyID service**: Can provision tokens independently
3. **Share data with ChittyOS**: Isolated storage
4. **Provide ChittyConnect integration**: Standalone identity management
5. **Handle biometric verification**: Basic token-based auth only
6. **Sync with ChittyOS services**: No cross-service coordination

---

## 🚀 Quick Start

### 1. Provision an API Token

```bash
curl -X POST https://your-domain.com/v1/tokens/provision \
  -H "Content-Type: application/json" \
  -d '{
    "chittyId": "03-1-USA-0001-P-251-3-82",
    "scope": ["chittyid:read", "chittyid:generate"],
    "service": "chittyid",
    "expiresIn": 2592000
  }'
```

**Response:**
```json
{
  "success": true,
  "token": "ca_live_dG9rX2FiYzEyM18xNzMwNTQzMjk2X3NpZ25hdHVyZQ",
  "tokenId": "tok_abc123xyz",
  "scope": ["chittyid:read", "chittyid:generate"],
  "expiresAt": "2025-12-02T00:00:00Z",
  "rateLimit": {
    "requests": 1000,
    "window": "1h"
  }
}
```

### 2. Validate Token

```bash
curl -X POST https://your-domain.com/v1/tokens/validate \
  -H "Content-Type: application/json" \
  -d '{"token": "YOUR_TOKEN_HERE"}'
```

---

## 📋 API Endpoints

### Token Operations

- `POST /v1/register` - **PUBLIC** - Register new user and get first token
- `POST /v1/tokens/provision` - Provision new API token
- `POST /v1/tokens/validate` - Validate existing token
- `POST /v1/tokens/refresh` - Refresh token before expiration
- `POST /v1/tokens/revoke` - Revoke token immediately

### Service Authentication

- `POST /v1/service/authenticate` - Authenticate service-to-service requests

### Integration

- `POST /v1/connect/verify` - Verify ChittyID (if ChittyConnect configured)

### Monitoring

- `GET /health` - Health check
- `GET /v1/tokens/stats` - Token usage statistics

See [API_SPEC.md](./API_SPEC.md) for complete API contracts and schemas.

---

## 🛠️ Installation & Deployment

### Prerequisites

- Node.js 18+
- Cloudflare account with Workers enabled
- Wrangler CLI installed globally (`npm install -g wrangler`)

### Setup Steps

#### 1. Install Dependencies

```bash
cd chittyauth-app
npm install
```

#### 2. Create KV Namespaces

```bash
# Production
wrangler kv:namespace create AUTH_TOKENS --env production
wrangler kv:namespace create AUTH_REVOCATIONS --env production
wrangler kv:namespace create AUTH_RATE_LIMITS --env production
wrangler kv:namespace create AUTH_AUDIT --env production

# Development
wrangler kv:namespace create AUTH_TOKENS --env development
wrangler kv:namespace create AUTH_REVOCATIONS --env development
wrangler kv:namespace create AUTH_RATE_LIMITS --env development
wrangler kv:namespace create AUTH_AUDIT --env development
```

**Update `wrangler.toml` with the created namespace IDs.**

#### 3. Create D1 Database

```bash
# Production
wrangler d1 create chittyauth-db

# Development
wrangler d1 create chittyauth-dev-db
```

**Update `wrangler.toml` with the database IDs.**

#### 4. Initialize Database Schema

```bash
# Production
wrangler d1 execute chittyauth-db --env production --file=./schema.sql

# Development
wrangler d1 execute chittyauth-dev-db --env development --file=./schema.sql
```

#### 5. Set Secrets

```bash
# Generate a secure signing key (256-bit)
openssl rand -base64 32

# Set the signing key
wrangler secret put TOKEN_SIGNING_KEY --env production

# Optional: Set ChittyConnect API key (if integrating)
wrangler secret put CHITTYCONNECT_API_KEY --env production
```

#### 6. Deploy

```bash
# Deploy to production
npm run deploy

# Deploy to development
npm run deploy:dev
```

---

## 🔧 Local Development

```bash
npm run dev
```

The service will be available at `http://localhost:8787`

### Test Endpoints Locally

```bash
# Register new user (public endpoint)
curl -X POST http://localhost:8787/v1/register \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test User",
    "email": "test@example.com"
  }'

# Provision token
curl -X POST http://localhost:8787/v1/tokens/provision \
  -H "Content-Type: application/json" \
  -d '{
    "chittyId": "03-1-USA-0001-P-251-3-82",
    "scope": ["chittyid:read"],
    "service": "chittyid",
    "expiresIn": 3600
  }'

# Validate token
curl -X POST http://localhost:8787/v1/tokens/validate \
  -H "Content-Type: application/json" \
  -d '{"token": "YOUR_TOKEN_HERE"}'
```

---

## 🧪 Testing

```bash
# Run all tests
npm test

# Run unit tests only
npm run test:unit

# Run integration tests only
npm run test:integration
```

---

## 🔐 Security Features

- **SHA-256 Token Hashing** - Tokens never stored in plain text
- **HMAC-SHA256 Signatures** - Cryptographic token signatures
- **Time-based Expiration** - Configurable token TTL
- **Automatic Revocation** - Suspicious activity detection
- **Rate Limiting** - Per-token request limits
- **Audit Logging** - Complete event trail (stored in D1)
- **Isolated Storage** - No shared database vulnerabilities

---

## 📊 Token Scopes

### ChittyID Scopes
- `chittyid:read` - Read ChittyID information
- `chittyid:generate` - Generate new ChittyIDs
- `chittyid:validate` - Validate ChittyIDs
- `chittyid:audit` - Access audit trails

### Custom Scopes
You can define custom scopes for your application:
- `myapp:read` - Read access
- `myapp:write` - Write access
- `myapp:admin` - Admin access

### Administrative Scopes
- `admin:*` - Full administrative access

---

## 🏗️ Architecture

ChittyAuth App uses Cloudflare-native storage:

```
┌─────────────────────┐
│   User/Application  │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  ChittyAuth App     │ ← Cloudflare Worker
│  (auth.your-domain) │
└──────────┬──────────┘
           │
           ├──────────────┐
           │              │
           ▼              ▼
┌──────────────┐  ┌──────────────┐
│  D1 Database │  │  KV Storage  │
│  (Tokens,    │  │  (Cache,     │
│   Audit Log) │  │   Rate Limit)│
└──────────────┘  └──────────────┘
```

**Storage Strategy**:
- **D1**: Primary storage for tokens, users, audit logs
- **KV**: Fast cache for validation, rate limiting, revocation lists

---

## 📈 Monitoring

### Health Check

```bash
curl https://your-domain.com/health
```

**Response:**
```json
{
  "status": "healthy",
  "service": "chittyauth-app",
  "version": "1.0.0",
  "timestamp": "2025-11-06T10:00:00Z",
  "checks": {
    "database": true,
    "kv": true
  }
}
```

### Token Statistics

```bash
curl https://your-domain.com/v1/tokens/stats \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"
```

---

## 🔄 Token Lifecycle

1. **Register** - User registers via `/v1/register` (gets first token)
2. **Provision** - Additional tokens provisioned as needed
3. **Validate** - Service validates token on each request
4. **Use** - Token used to access protected resources
5. **Refresh** - Token refreshed before expiration (optional)
6. **Revoke** - Token revoked when no longer needed

---

## 📝 Environment Variables

### Required Secrets
- `TOKEN_SIGNING_KEY` - 256-bit key for token signatures (required)

### Optional Secrets
- `CHITTYCONNECT_API_KEY` - Service token for ChittyConnect integration

### Configuration (in wrangler.toml)
- `ENVIRONMENT` - "development" or "production"
- `CHITTYCONNECT_URL` - ChittyConnect endpoint (default: https://connect.chitty.cc)
- `DEFAULT_TOKEN_EXPIRY` - Default token lifetime in seconds (default: 2592000 = 30 days)
- `MAX_TOKENS_PER_USER` - Maximum tokens per user (default: 10)

---

## 🏛️ ChittyCan™ Compliance

This project follows the [ChittyCan™ Universal Infrastructure Interface](https://github.com/chittyfoundation/chittycan) for standardized project management.

### Project Links
- **Repository**: https://github.com/chittyapps/chittyauth-app (TBD)
- **Issues**: https://github.com/chittyapps/chittyauth-app/issues (TBD)
- **Decision Log**: [DECISIONS.md](./DECISIONS.md) (TBD)
- **API Contracts**: [API_SPEC.md](./API_SPEC.md) (TBD)

### ChittyOS Ecosystem Registration
- **ChittyID Token**: TBD (optional for standalone)
- **Registry Registration**: TBD (register at https://register.chitty.cc)
- **Service Discovery**: TBD (verify at https://registry.chitty.cc)
- **Schema Alignment**: Independent (no schema dependency)

### Deployment Status
- **Production**: Not yet deployed
- **Staging**: Not yet deployed
- **Development**: Local testing available

---

## 📚 Documentation

- [Architecture Overview](./ARCHITECTURE.md)
- [Deployment Guide](./DEPLOYMENT.md)
- [API Specification](./API_SPEC.md) (TBD - follow chittyauth API_SPEC.md)
- [Decision Log](./DECISIONS.md) (TBD)

---

## 🐛 Troubleshooting

### Token Validation Fails

1. Check token format (must start with `ca_live_`, `ca_test_`, etc.)
2. Verify token hasn't expired
3. Ensure token hasn't been revoked
4. Check rate limits
5. Verify D1 database is accessible

### Database Errors

1. Verify D1 database is created: `wrangler d1 list`
2. Check database binding in wrangler.toml
3. Ensure schema is initialized: `wrangler d1 execute chittyauth-db --file=./schema.sql`
4. Check database query logs: `wrangler tail`

### KV Namespace Issues

1. Verify KV namespaces are created: `wrangler kv:namespace list`
2. Check bindings in wrangler.toml match created namespace IDs
3. Test KV access: `wrangler kv:key list --binding=AUTH_TOKENS`

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

---

## 📄 License

ChittyApps Project
© 2025 ChittyCorp LLC

---

## 🆘 Support

For issues and questions:
- Create an issue in the repository
- Check [ARCHITECTURE.md](./ARCHITECTURE.md) for detailed documentation
- Contact ChittyCorp support

---

**Built with ❤️ for standalone deployments**

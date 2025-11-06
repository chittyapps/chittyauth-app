# ChittyAuth Deployment Guide

Complete step-by-step guide to deploy ChittyAuth to Cloudflare Workers.

---

## 📋 Pre-Deployment Checklist

- [ ] Cloudflare account with Workers enabled
- [ ] `wrangler` CLI installed and authenticated
- [ ] Access to ChittyCorp LLC Cloudflare account (ID: `0bc21e3a5a9de1a4cc843be9c3e98121`)
- [ ] DNS zone for `chitty.cc` configured
- [ ] ChittyConnect service running (for integration)

---

## 🚀 Deployment Steps

### 1. Install Dependencies

```bash
cd chittyauth
npm install
```

### 2. Create KV Namespaces

```bash
# Production KV namespaces
wrangler kv:namespace create AUTH_TOKENS --env production
wrangler kv:namespace create AUTH_REVOCATIONS --env production
wrangler kv:namespace create AUTH_RATE_LIMITS --env production
wrangler kv:namespace create AUTH_AUDIT --env production
```

**Output Example:**
```
✨ Success! Add the following to your wrangler.toml:
[[env.production.kv_namespaces]]
binding = "AUTH_TOKENS"
id = "abc123def456"
```

**Action**: Copy the IDs and update `wrangler.toml`.

### 3. Create D1 Database

```bash
# Production database
wrangler d1 create chittyauth-db
```

**Output Example:**
```
✅ Successfully created DB 'chittyauth-db'!

[[env.production.d1_databases]]
binding = "AUTH_DB"
database_name = "chittyauth-db"
database_id = "xyz789uvw012"
```

**Action**: Copy the database ID and update `wrangler.toml`.

### 4. Initialize Database Schema

```bash
wrangler d1 execute chittyauth-db --env production --file=./schema.sql
```

**Expected Output:**
```
🌀 Executing on chittyauth-db (xyz789uvw012):
🌀 To execute on your remote database, add a --remote flag to your wrangler command.
✅ Executed 7 commands in 0.234s
```

### 5. Generate & Set Secrets

#### Generate Token Signing Key

```bash
# Generate a secure 256-bit key
openssl rand -base64 32
```

**Output Example:**
```
K7mN9pQ2rS5tU8vW0xY3zA6bC9dE2fG5hJ8kL1mN4oP7
```

#### Set Secrets

```bash
# Set token signing key
echo "K7mN9pQ2rS5tU8vW0xY3zA6bC9dE2fG5hJ8kL1mN4oP7" | wrangler secret put TOKEN_SIGNING_KEY --env production

# Set ChittyConnect API key (get from ChittyConnect admin)
echo "YOUR_CHITTYCONNECT_KEY" | wrangler secret put CHITTYCONNECT_API_KEY --env production
```

### 6. Configure DNS Route

**Option A: Via Cloudflare Dashboard**
1. Go to Cloudflare Dashboard → DNS → `chitty.cc` zone
2. Ensure there's a route for `auth.chitty.cc/*` → `chittyauth-production` worker

**Option B: Via `wrangler.toml` (already configured)**
```toml
[[env.production.routes]]
pattern = "auth.chitty.cc/*"
zone_name = "chitty.cc"
```

### 7. Deploy to Production

```bash
npm run deploy
```

**Expected Output:**
```
⛅️ wrangler 3.78.12
-------------------
Total Upload: XX.XX KiB / gzip: XX.XX KiB
Uploaded chittyauth-production (X.XX sec)
Published chittyauth-production (X.XX sec)
  https://auth.chitty.cc
Current Deployment ID: abc-123-def-456
```

### 8. Verify Deployment

#### Health Check

```bash
curl https://auth.chitty.cc/health
```

**Expected Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "timestamp": "2025-11-02T12:34:56Z",
  "dependencies": {
    "chittyConnect": "healthy"
  }
}
```

#### Test Token Provisioning

```bash
curl -X POST https://auth.chitty.cc/v1/tokens/provision \
  -H "Content-Type: application/json" \
  -d '{
    "chittyId": "03-1-USA-0001-P-251-3-82",
    "scope": ["chittyid:read"],
    "service": "chittyid",
    "expiresIn": 3600
  }'
```

**Note**: This will require ChittyConnect verification to succeed.

---

## 🔧 Development Deployment

For development/staging environment:

```bash
# Create dev resources
wrangler kv:namespace create AUTH_TOKENS --env development
wrangler kv:namespace create AUTH_REVOCATIONS --env development
wrangler kv:namespace create AUTH_RATE_LIMITS --env development
wrangler kv:namespace create AUTH_AUDIT --env development

wrangler d1 create chittyauth-dev-db
wrangler d1 execute chittyauth-dev-db --env development --file=./schema.sql

# Set dev secrets
echo "DEV_SIGNING_KEY_CHANGE_IN_PROD" | wrangler secret put TOKEN_SIGNING_KEY --env development

# Deploy
npm run deploy:dev
```

---

## 📊 Post-Deployment Tasks

### 1. Register with Service Registry

If you have a ChittyBeacon service registry:

```bash
curl -X POST https://beacon.chitty.cc/v1/register \
  -H "Content-Type: application/json" \
  -d '{
    "serviceName": "chittyauth",
    "endpoint": "https://auth.chitty.cc",
    "priority": 0,
    "healthEndpoint": "/health"
  }'
```

### 2. Update ChittyID Configuration

Add ChittyAuth URL to ChittyID environment:

```bash
cd ../  # Back to chittyid directory
wrangler secret put CHITTYAUTH_URL --env production
# Enter: https://auth.chitty.cc
```

### 3. Provision Admin Token

Create an admin token for management operations:

```bash
# This requires manual database insertion initially
# Or provision via ChittyConnect with admin permissions
```

### 4. Setup Monitoring

Configure alerts for:
- Token provisioning failures
- High validation error rate
- D1 database errors
- KV namespace issues

---

## 🧪 Testing Deployment

### Run Integration Tests

```bash
# Set test environment variables
export CHITTYAUTH_URL="https://auth.chitty.cc"
export TEST_CHITTY_ID="03-1-USA-0001-P-251-3-82"

# Run tests
npm run test:integration
```

### Manual Smoke Tests

#### 1. Token Provisioning

```bash
TOKEN_RESPONSE=$(curl -s -X POST https://auth.chitty.cc/v1/tokens/provision \
  -H "Content-Type: application/json" \
  -d '{
    "chittyId": "03-1-USA-0001-P-251-3-82",
    "scope": ["chittyid:read"],
    "service": "chittyid",
    "expiresIn": 3600
  }')

echo $TOKEN_RESPONSE | jq '.'
```

#### 2. Token Validation

```bash
TOKEN=$(echo $TOKEN_RESPONSE | jq -r '.token')

curl -X POST https://auth.chitty.cc/v1/tokens/validate \
  -H "Content-Type: application/json" \
  -d "{\"token\": \"$TOKEN\"}" | jq '.'
```

#### 3. Token Usage with ChittyID

```bash
curl -X GET "https://id.chitty.cc/api/get-chittyid?for=person" \
  -H "Authorization: Bearer $TOKEN" | jq '.'
```

---

## 🔄 Rolling Updates

To deploy updates without downtime:

```bash
# Deploy new version
npm run deploy

# Monitor health
watch -n 5 'curl -s https://auth.chitty.cc/health | jq .'

# If issues, rollback via Cloudflare Dashboard
# Workers → chittyauth-production → Deployments → Rollback
```

---

## 📈 Monitoring & Observability

### Key Metrics to Monitor

1. **Token Operations**
   - Provisions per hour
   - Validations per hour
   - Revocations per hour

2. **Error Rates**
   - Failed validations %
   - Rate limit hits
   - Database errors

3. **Performance**
   - P50/P95/P99 latency
   - ChittyConnect integration latency

4. **Resources**
   - KV namespace usage
   - D1 database size
   - Worker execution time

### Setup Cloudflare Analytics

1. Go to Cloudflare Dashboard → Analytics → Workers
2. Add custom events for token operations
3. Configure alerts for anomalies

---

## 🆘 Troubleshooting

### Issue: "Database binding not found"

**Solution**:
```bash
# Verify database exists
wrangler d1 list

# Re-create if needed
wrangler d1 create chittyauth-db --env production

# Update wrangler.toml with correct database_id
```

### Issue: "KV namespace not found"

**Solution**:
```bash
# List KV namespaces
wrangler kv:namespace list

# Re-create if needed
wrangler kv:namespace create AUTH_TOKENS --env production

# Update wrangler.toml with correct id
```

### Issue: "ChittyConnect verification failed"

**Solution**:
1. Verify `CHITTYCONNECT_API_KEY` is set correctly
2. Check ChittyConnect service is running
3. Test ChittyConnect directly:
   ```bash
   curl https://connect.chitty.cc/health
   ```

### Issue: "Token validation always fails"

**Solution**:
1. Check `TOKEN_SIGNING_KEY` is set
2. Verify database schema is initialized
3. Check KV namespaces are accessible

---

## 🔐 Security Checklist

- [ ] `TOKEN_SIGNING_KEY` is cryptographically random (256-bit)
- [ ] Secrets are set via `wrangler secret put` (not in code)
- [ ] Database access is restricted to Worker
- [ ] CORS is properly configured
- [ ] Rate limiting is enabled
- [ ] Audit logging is active
- [ ] ChittyConnect integration uses secure tokens

---

## 📝 Rollback Procedure

If deployment has critical issues:

### Via Cloudflare Dashboard
1. Go to Workers → `chittyauth-production`
2. Click "Deployments" tab
3. Find last known good deployment
4. Click "Rollback to this deployment"

### Via Wrangler
```bash
# Get deployment list
wrangler deployments list --env production

# Rollback to specific deployment
wrangler rollback --deployment-id <DEPLOYMENT_ID> --env production
```

---

## ✅ Deployment Validation Checklist

After deployment, verify:

- [ ] `/health` endpoint returns 200 OK
- [ ] Token provisioning works
- [ ] Token validation works
- [ ] Token refresh works
- [ ] Token revocation works
- [ ] ChittyConnect integration works
- [ ] Rate limiting is enforced
- [ ] Audit logs are being created
- [ ] All KV namespaces are accessible
- [ ] D1 database is accessible
- [ ] DNS routing works correctly
- [ ] ChittyID can validate tokens via ChittyAuth

---

## 📞 Support

For deployment issues:
- Check Cloudflare Workers logs
- Review wrangler.toml configuration
- Verify all secrets are set
- Test each component individually
- Contact ChittyCorp infrastructure team

---

**Deployment Complete! 🎉**

ChittyAuth is now the authentication gateway for the entire ChittyOS ecosystem.

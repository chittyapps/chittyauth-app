/**
 * ChittyAuth Token Manager
 * Handles token provisioning, validation, and lifecycle management
 */

import crypto from 'crypto';

export class TokenManager {
  constructor(env) {
    this.env = env;
    this.signingKey = env.TOKEN_SIGNING_KEY || 'dev-signing-key-change-in-production';
    this.defaultExpiry = parseInt(env.DEFAULT_TOKEN_EXPIRY || '2592000'); // 30 days
  }

  /**
   * Provision a new API token
   */
  async provision({ chittyId, scope, service, expiresIn }) {
    // Validate inputs
    if (!chittyId || !scope || !service) {
      throw new Error('Missing required parameters: chittyId, scope, service');
    }

    // Generate unique token ID
    const tokenId = this.generateTokenId();
    const createdAt = Date.now();
    const expiresAt = createdAt + (expiresIn || this.defaultExpiry) * 1000;

    // Generate token
    const token = this.generateToken(tokenId, chittyId, service);
    const tokenHash = await this.hashToken(token);

    // Store token in D1
    if (this.env.AUTH_DB) {
      await this.env.AUTH_DB.prepare(
        `INSERT INTO tokens (id, token_hash, chitty_id, scope, created_at, expires_at, request_count)
         VALUES (?, ?, ?, ?, ?, ?, 0)`
      ).bind(
        tokenId,
        tokenHash,
        chittyId,
        JSON.stringify(scope),
        createdAt,
        expiresAt
      ).run();
    }

    // Store in KV for fast validation
    if (this.env.AUTH_TOKENS) {
      const tokenData = {
        tokenId,
        chittyId,
        scope,
        service,
        createdAt,
        expiresAt,
        requestCount: 0
      };

      const ttl = Math.floor((expiresAt - createdAt) / 1000);
      await this.env.AUTH_TOKENS.put(
        `token:${tokenHash}`,
        JSON.stringify(tokenData),
        { expirationTtl: ttl }
      );
    }

    // Determine rate limit based on scope
    const rateLimit = this.getRateLimit(scope);

    // Audit event
    await this.logAuditEvent({
      eventType: 'token_provision',
      tokenId,
      chittyId,
      service,
      success: true,
      timestamp: createdAt
    });

    return {
      success: true,
      token,
      tokenId,
      scope,
      expiresAt: new Date(expiresAt).toISOString(),
      rateLimit
    };
  }

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

  /**
   * Refresh an existing token
   */
  async refresh(token, expiresIn) {
    // Validate current token
    const validation = await this.validate(token);
    if (!validation.valid) {
      return { success: false, error: validation.error };
    }

    // Revoke old token
    await this.revoke(validation.tokenId, 'Token refreshed');

    // Provision new token with same scope
    const newToken = await this.provision({
      chittyId: validation.chittyId,
      scope: validation.scope,
      service: validation.service,
      expiresIn
    });

    // Audit event
    await this.logAuditEvent({
      eventType: 'token_refreshed',
      tokenId: validation.tokenId,
      newTokenId: newToken.tokenId,
      chittyId: validation.chittyId,
      success: true,
      timestamp: Date.now()
    });

    return newToken;
  }

  /**
   * Revoke a token
   */
  async revoke(tokenId, reason = 'Manual revocation') {
    const now = Date.now();

    // Update D1
    if (this.env.AUTH_DB) {
      await this.env.AUTH_DB.prepare(
        `UPDATE tokens SET revoked_at = ? WHERE id = ?`
      ).bind(now, tokenId).run();

      // Get token hash for KV operations
      const result = await this.env.AUTH_DB.prepare(
        `SELECT token_hash FROM tokens WHERE id = ?`
      ).bind(tokenId).first();

      if (result) {
        // Add to revocation list
        if (this.env.AUTH_REVOCATIONS) {
          await this.env.AUTH_REVOCATIONS.put(
            `revoked:${result.token_hash}`,
            JSON.stringify({ tokenId, reason, revokedAt: now }),
            { expirationTtl: 86400 * 90 } // Keep for 90 days
          );
        }

        // Remove from active tokens
        if (this.env.AUTH_TOKENS) {
          await this.env.AUTH_TOKENS.delete(`token:${result.token_hash}`);
        }
      }
    }

    // Audit event
    await this.logAuditEvent({
      eventType: 'token_revoked',
      tokenId,
      reason,
      success: true,
      timestamp: now
    });

    return {
      success: true,
      tokenId,
      revokedAt: new Date(now).toISOString(),
      reason
    };
  }

  /**
   * Generate a unique token ID
   */
  generateTokenId() {
    return `tok_${this.randomString(20)}`;
  }

  /**
   * Generate a token with cryptographic signature
   */
  generateToken(tokenId, chittyId, service) {
    const timestamp = Date.now();
    const payload = `${tokenId}:${chittyId}:${service}:${timestamp}`;
    const signature = this.signPayload(payload);
    const tokenData = `${tokenId}_${timestamp}_${signature}`;
    const encoded = Buffer.from(tokenData).toString('base64url');

    // Determine environment prefix
    const env = this.env.ENVIRONMENT || 'live';
    const prefix = env === 'production' ? 'ca_live_' : `ca_${env}_`;

    return `${prefix}${encoded}`;
  }

  /**
   * Sign a payload with HMAC-SHA256
   */
  signPayload(payload) {
    const hmac = crypto.createHmac('sha256', this.signingKey);
    hmac.update(payload);
    return hmac.digest('base64url').substring(0, 32);
  }

  /**
   * Hash a token with SHA-256
   */
  async hashToken(token) {
    const encoder = new TextEncoder();
    const data = encoder.encode(token);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Validate token format
   */
  isValidTokenFormat(token) {
    const validPrefixes = ['ca_live_', 'ca_test_', 'ca_dev_', 'svc_'];
    return validPrefixes.some(prefix => token.startsWith(prefix));
  }

  /**
   * Get rate limit for scope
   */
  getRateLimit(scope) {
    if (scope.includes('admin:*')) {
      return { requests: 10000, window: '1h' };
    }
    if (scope.includes('service:*')) {
      return { requests: 5000, window: '1h' };
    }
    if (scope.length > 3) {
      return { requests: 1000, window: '1h' };
    }
    return { requests: 100, window: '1h' };
  }

  /**
   * Check rate limit for token
   */
  async checkRateLimit(tokenHash, tokenData) {
    if (!this.env.AUTH_RATE_LIMITS) {
      return 999; // No rate limiting if KV not available
    }

    const window = 3600; // 1 hour in seconds
    const now = Math.floor(Date.now() / 1000);
    const windowStart = now - window;

    const rateLimit = this.getRateLimit(tokenData.scope);
    const key = `ratelimit:${tokenHash}:${windowStart}`;

    const current = await this.env.AUTH_RATE_LIMITS.get(key);
    const count = current ? parseInt(current) : 0;

    if (count >= rateLimit.requests) {
      throw new Error('Rate limit exceeded');
    }

    await this.env.AUTH_RATE_LIMITS.put(key, (count + 1).toString(), {
      expirationTtl: window
    });

    return rateLimit.requests - count - 1;
  }

  /**
   * Update token usage statistics
   */
  async updateTokenUsage(tokenHash, tokenData) {
    const now = Date.now();

    // Update D1
    if (this.env.AUTH_DB) {
      await this.env.AUTH_DB.prepare(
        `UPDATE tokens SET last_used_at = ?, request_count = request_count + 1 WHERE token_hash = ?`
      ).bind(now, tokenHash).run();
    }

    // Update KV cache
    if (this.env.AUTH_TOKENS) {
      tokenData.lastUsedAt = now;
      tokenData.requestCount = (tokenData.requestCount || 0) + 1;
      const ttl = Math.floor((tokenData.expiresAt - now) / 1000);
      if (ttl > 0) {
        await this.env.AUTH_TOKENS.put(
          `token:${tokenHash}`,
          JSON.stringify(tokenData),
          { expirationTtl: ttl }
        );
      }
    }
  }

  /**
   * Log audit event
   */
  async logAuditEvent(event) {
    const eventId = `evt_${this.randomString(20)}`;

    // Store in D1
    if (this.env.AUTH_DB) {
      await this.env.AUTH_DB.prepare(
        `INSERT INTO auth_events (id, event_type, token_id, chitty_id, service_name, success, error_message, timestamp)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      ).bind(
        eventId,
        event.eventType,
        event.tokenId || null,
        event.chittyId || null,
        event.service || null,
        event.success ? 1 : 0,
        event.error || null,
        event.timestamp
      ).run();
    }

    // Store in KV for recent events
    if (this.env.AUTH_AUDIT) {
      await this.env.AUTH_AUDIT.put(
        `event:${eventId}`,
        JSON.stringify(event),
        { expirationTtl: 86400 * 90 } // 90 days
      );
    }
  }

  /**
   * Generate random string
   */
  randomString(length) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    const randomBytes = crypto.randomBytes(length);
    for (let i = 0; i < length; i++) {
      result += chars[randomBytes[i] % chars.length];
    }
    return result;
  }

  /**
   * Get token statistics
   */
  async getStats() {
    if (!this.env.AUTH_DB) {
      return { error: 'Database not available' };
    }

    const stats = await this.env.AUTH_DB.prepare(`
      SELECT
        COUNT(*) as total_tokens,
        SUM(CASE WHEN revoked_at IS NULL AND expires_at > ? THEN 1 ELSE 0 END) as active_tokens,
        SUM(CASE WHEN revoked_at IS NOT NULL THEN 1 ELSE 0 END) as revoked_tokens,
        SUM(CASE WHEN expires_at <= ? THEN 1 ELSE 0 END) as expired_tokens
      FROM tokens
    `).bind(Date.now(), Date.now()).first();

    const requestsToday = await this.env.AUTH_DB.prepare(`
      SELECT SUM(request_count) as total_requests
      FROM tokens
      WHERE last_used_at >= ?
    `).bind(Date.now() - 86400000).first();

    return {
      totalTokens: stats.total_tokens || 0,
      activeTokens: stats.active_tokens || 0,
      revokedTokens: stats.revoked_tokens || 0,
      expiredTokens: stats.expired_tokens || 0,
      requestsToday: requestsToday?.total_requests || 0
    };
  }
}

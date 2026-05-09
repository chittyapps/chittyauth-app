/**
 * ChittyAuth Token Manager Tests
 * Unit tests for token provisioning, validation, and lifecycle
 */

import { TokenManager } from '../src/token-manager.js';

async function readAuditEvents(mockKv) {
  const list = await mockKv.list({ prefix: 'event:' });
  const events = [];
  for (const k of list.keys) {
    const raw = await mockKv.get(k.name);
    if (raw) events.push(JSON.parse(raw));
  }
  return events;
}

describe('TokenManager', () => {
  let tokenManager;
  let mockEnv;

  beforeEach(() => {
    // Mock environment
    mockEnv = {
      TOKEN_SIGNING_KEY: 'test-signing-key-for-unit-tests-only',
      DEFAULT_TOKEN_EXPIRY: '3600',
      AUTH_TOKENS: createMockKV(),
      AUTH_REVOCATIONS: createMockKV(),
      AUTH_RATE_LIMITS: createMockKV(),
      AUTH_AUDIT: createMockKV(),
      AUTH_DB: createMockD1()
    };

    tokenManager = new TokenManager(mockEnv);
  });

  describe('Token Provisioning', () => {
    test('should provision a new token successfully', async () => {
      const result = await tokenManager.provision({
        chittyId: '03-1-USA-0001-P-251-3-82',
        scope: ['chittyid:read', 'chittyid:generate'],
        service: 'chittyid',
        expiresIn: 3600
      });

      expect(result.success).toBe(true);
      expect(result.token).toBeDefined();
      expect(result.token).toMatch(/^ca_(live|test|dev)_/);
      expect(result.tokenId).toMatch(/^tok_/);
      expect(result.scope).toEqual(['chittyid:read', 'chittyid:generate']);
      expect(result.rateLimit).toBeDefined();
    });

    test('should reject provisioning without required parameters', async () => {
      await expect(tokenManager.provision({
        scope: ['chittyid:read']
      })).rejects.toThrow('Missing required parameters');
    });

    test('should use custom expiration time', async () => {
      const customExpiry = 7200; // 2 hours
      const result = await tokenManager.provision({
        chittyId: '03-1-USA-0001-P-251-3-82',
        scope: ['chittyid:read'],
        service: 'chittyid',
        expiresIn: customExpiry
      });

      expect(result.success).toBe(true);
      const expiresAt = new Date(result.expiresAt).getTime();
      const now = Date.now();
      const diff = expiresAt - now;

      // Allow 1 second tolerance
      expect(diff).toBeGreaterThanOrEqual((customExpiry - 1) * 1000);
      expect(diff).toBeLessThanOrEqual((customExpiry + 1) * 1000);
    });
  });

  describe('Token Validation', () => {
    test('should validate a valid token', async () => {
      // Provision token
      const provision = await tokenManager.provision({
        chittyId: '03-1-USA-0001-P-251-3-82',
        scope: ['chittyid:read'],
        service: 'chittyid',
        expiresIn: 3600
      });

      // Validate token
      const validation = await tokenManager.validate(provision.token);

      expect(validation.valid).toBe(true);
      expect(validation.tokenId).toBe(provision.tokenId);
      expect(validation.chittyId).toBe('03-1-USA-0001-P-251-3-82');
      expect(validation.scope).toEqual(['chittyid:read']);
    });

    test('should reject invalid token format', async () => {
      const validation = await tokenManager.validate('invalid-token-format');
      expect(validation.valid).toBe(false);
      expect(validation.error).toBeDefined();
    });

    test('should reject revoked token', async () => {
      // Provision and revoke token
      const provision = await tokenManager.provision({
        chittyId: '03-1-USA-0001-P-251-3-82',
        scope: ['chittyid:read'],
        service: 'chittyid',
        expiresIn: 3600
      });

      await tokenManager.revoke(provision.tokenId, 'Testing revocation');

      // Attempt validation
      const validation = await tokenManager.validate(provision.token);
      expect(validation.valid).toBe(false);
      expect(validation.error).toContain('revoked');
    });

    test('should handle Bearer prefix in token', async () => {
      const provision = await tokenManager.provision({
        chittyId: '03-1-USA-0001-P-251-3-82',
        scope: ['chittyid:read'],
        service: 'chittyid',
        expiresIn: 3600
      });

      const validation = await tokenManager.validate(`Bearer ${provision.token}`);
      expect(validation.valid).toBe(true);
    });
  });

  describe('Token Refresh', () => {
    test('should refresh a valid token', async () => {
      // Provision original token
      const original = await tokenManager.provision({
        chittyId: '03-1-USA-0001-P-251-3-82',
        scope: ['chittyid:read'],
        service: 'chittyid',
        expiresIn: 3600
      });

      // Refresh token
      const refreshed = await tokenManager.refresh(original.token, 7200);

      expect(refreshed.success).toBe(true);
      expect(refreshed.token).toBeDefined();
      expect(refreshed.token).not.toBe(original.token);
      expect(refreshed.tokenId).not.toBe(original.tokenId);

      // Original token should be revoked
      const originalValidation = await tokenManager.validate(original.token);
      expect(originalValidation.valid).toBe(false);

      // New token should be valid
      const newValidation = await tokenManager.validate(refreshed.token);
      expect(newValidation.valid).toBe(true);
    });

    test('should reject refresh of invalid token', async () => {
      const result = await tokenManager.refresh('invalid-token', 3600);
      expect(result.success).toBe(false);
    });
  });

  describe('Token Revocation', () => {
    test('should revoke a token successfully', async () => {
      const provision = await tokenManager.provision({
        chittyId: '03-1-USA-0001-P-251-3-82',
        scope: ['chittyid:read'],
        service: 'chittyid',
        expiresIn: 3600
      });

      const revocation = await tokenManager.revoke(provision.tokenId, 'User requested');

      expect(revocation.success).toBe(true);
      expect(revocation.tokenId).toBe(provision.tokenId);
      expect(revocation.revokedAt).toBeDefined();
      expect(revocation.reason).toBe('User requested');
    });
  });

  describe('Token Format', () => {
    test('should generate tokens with correct prefix', async () => {
      const result = await tokenManager.provision({
        chittyId: '03-1-USA-0001-P-251-3-82',
        scope: ['chittyid:read'],
        service: 'chittyid',
        expiresIn: 3600
      });

      expect(result.token).toMatch(/^ca_(live|test|dev)_/);
    });

    test('should validate token format correctly', () => {
      expect(tokenManager.isValidTokenFormat('ca_live_abc123')).toBe(true);
      expect(tokenManager.isValidTokenFormat('ca_test_abc123')).toBe(true);
      expect(tokenManager.isValidTokenFormat('ca_dev_abc123')).toBe(true);
      expect(tokenManager.isValidTokenFormat('svc_chittyrouter_abc123')).toBe(true);
      expect(tokenManager.isValidTokenFormat('invalid_token')).toBe(false);
    });
  });

  describe('Rate Limiting', () => {
    test('should set appropriate rate limits based on scope', () => {
      const adminLimit = tokenManager.getRateLimit(['admin:*']);
      expect(adminLimit.requests).toBe(10000);

      const serviceLimit = tokenManager.getRateLimit(['service:*']);
      expect(serviceLimit.requests).toBe(5000);

      const standardLimit = tokenManager.getRateLimit(['chittyid:read', 'chittyid:generate']);
      expect(standardLimit.requests).toBe(1000);

      const basicLimit = tokenManager.getRateLimit(['chittyid:read']);
      expect(basicLimit.requests).toBe(100);
    });
  });

  describe('Statistics', () => {
    test('should return token statistics', async () => {
      // Provision some tokens
      await tokenManager.provision({
        chittyId: '03-1-USA-0001-P-251-3-82',
        scope: ['chittyid:read'],
        service: 'chittyid',
        expiresIn: 3600
      });

      const stats = await tokenManager.getStats();

      expect(stats.totalTokens).toBeGreaterThanOrEqual(1);
      expect(stats.activeTokens).toBeDefined();
      expect(stats.revokedTokens).toBeDefined();
      expect(stats.requestsToday).toBeDefined();
    });
  });

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

    test('null chittyId or null service returns false', async () => {
      const provision = await tokenManager.provision({
        chittyId: '03-1-USA-0001-P-251-3-82',
        scope: ['chittyid:read'],
        service: 'chittyid',
        expiresIn: 3600
      });
      expect(
        tokenManager.verifySignature(provision.token, null, 'chittyid', provision.tokenId)
      ).toBe(false);
      expect(
        tokenManager.verifySignature(provision.token, '03-1-USA-0001-P-251-3-82', null, provision.tokenId)
      ).toBe(false);
    });

    test('signature length not 32 → false (does not reach HMAC compare)', async () => {
      const provision = await tokenManager.provision({
        chittyId: '03-1-USA-0001-P-251-3-82',
        scope: ['chittyid:read'],
        service: 'chittyid',
        expiresIn: 3600
      });
      const prefix = 'ca_live_';
      const decoded = Buffer.from(provision.token.slice(prefix.length), 'base64url').toString('utf8');
      // Drop the last char of the body — signature becomes 31 chars
      const truncated = decoded.slice(0, -1);
      const tampered = `${prefix}${Buffer.from(truncated).toString('base64url')}`;
      expect(
        tokenManager.verifySignature(
          tampered,
          '03-1-USA-0001-P-251-3-82',
          'chittyid',
          provision.tokenId
        )
      ).toBe(false);
    });

    test('verifies 200 fresh tokens reliably (no underscore-in-signature flakes)', async () => {
      // Regression test for the original parser bug: base64url signatures
      // contain `_` ~63% of the time, so any happy-path test that runs once
      // is a coin flip. Loop hard so a parser regression is impossible to
      // miss.
      for (let i = 0; i < 200; i++) {
        const provision = await tokenManager.provision({
          chittyId: '03-1-USA-0001-P-251-3-82',
          scope: ['chittyid:read'],
          service: 'chittyid',
          expiresIn: 3600
        });
        const ok = tokenManager.verifySignature(
          provision.token,
          '03-1-USA-0001-P-251-3-82',
          'chittyid',
          provision.tokenId
        );
        if (!ok) {
          throw new Error(
            `Iteration ${i}: verifySignature returned false for a freshly-issued token: ${provision.token}`
          );
        }
      }
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

    test('enforce mode emits both signature_mismatch and token_validation_failed audit events', async () => {
      const enforcedEnv = {
        ...mockEnv,
        AUTH_AUDIT: createMockKV(),
        AUTH_TOKENS: createMockKV(),
        AUTH_REVOCATIONS: createMockKV(),
        AUTH_RATE_LIMITS: createMockKV(),
        AUTH_DB: createMockD1(),
        CHITTYAUTH_VERIFY_SIGNATURE: 'enforce'
      };
      const enforcedManager = new TokenManager(enforcedEnv);

      const provision = await enforcedManager.provision({
        chittyId: '03-1-USA-0001-P-251-3-82',
        scope: ['chittyid:read'],
        service: 'chittyid',
        expiresIn: 3600
      });

      // Tamper: replace the last signature byte and re-seed KV under the tampered hash
      const prefix = 'ca_live_';
      const decoded = Buffer.from(provision.token.slice(prefix.length), 'base64url').toString('utf8');
      const lastChar = decoded.slice(-1);
      const flipped = lastChar === 'A' ? 'B' : 'A';
      const tamperedDecoded = `${decoded.slice(0, -1)}${flipped}`;
      const tamperedToken = `${prefix}${Buffer.from(tamperedDecoded).toString('base64url')}`;
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

      const events = await readAuditEvents(enforcedEnv.AUTH_AUDIT);
      const mismatch = events.find((e) => e.eventType === 'signature_mismatch');
      const failed = events.find(
        (e) => e.eventType === 'token_validation_failed' && /signature/i.test(e.error || '')
      );
      expect(mismatch).toBeDefined();
      expect(mismatch.tokenId).toBe(provision.tokenId);
      expect(mismatch.chittyId).toBe('03-1-USA-0001-P-251-3-82');
      expect(mismatch.success).toBe(false);
      expect(failed).toBeDefined();
    });

    test('validates via D1 fallback when KV cache misses (exercises service_name INSERT)', async () => {
      // The previous `service_name` INSERT bug was undetectable while KV
      // cache was populated. This test deletes the KV entry before validate()
      // so the D1 fallback path is taken — and asserts service round-trips
      // intact (NULL service_name would make verifySignature reject).
      const enforcedEnv = {
        ...mockEnv,
        AUTH_AUDIT: createMockKV(),
        AUTH_TOKENS: createMockKV(),
        AUTH_REVOCATIONS: createMockKV(),
        AUTH_RATE_LIMITS: createMockKV(),
        AUTH_DB: createMockD1(),
        CHITTYAUTH_VERIFY_SIGNATURE: 'enforce'
      };
      const enforcedManager = new TokenManager(enforcedEnv);

      const provision = await enforcedManager.provision({
        chittyId: '03-1-USA-0001-P-251-3-82',
        scope: ['chittyid:read'],
        service: 'chittyid',
        expiresIn: 3600
      });

      // Confirm D1 row was written with non-null service_name.
      const dump = enforcedEnv.AUTH_DB.__dump();
      expect(dump.tokens[dump.tokens.length - 1].service_name).toBe('chittyid');

      // Evict KV entry so validate() must fall through to D1.
      const tokenHash = await enforcedManager.hashToken(provision.token);
      await enforcedEnv.AUTH_TOKENS.delete(`token:${tokenHash}`);

      const result = await enforcedManager.validate(provision.token);
      expect(result.valid).toBe(true);
      expect(result.service).toBe('chittyid');
      expect(result.chittyId).toBe('03-1-USA-0001-P-251-3-82');
    });

    test('refresh chain works under enforce mode (validate → revoke → provision)', async () => {
      const enforcedEnv = {
        ...mockEnv,
        AUTH_AUDIT: createMockKV(),
        AUTH_TOKENS: createMockKV(),
        AUTH_REVOCATIONS: createMockKV(),
        AUTH_RATE_LIMITS: createMockKV(),
        AUTH_DB: createMockD1(),
        CHITTYAUTH_VERIFY_SIGNATURE: 'enforce'
      };
      const enforcedManager = new TokenManager(enforcedEnv);

      const original = await enforcedManager.provision({
        chittyId: '03-1-USA-0001-P-251-3-82',
        scope: ['chittyid:read'],
        service: 'chittyid',
        expiresIn: 3600
      });
      const refreshed = await enforcedManager.refresh(original.token, 7200);
      expect(refreshed.success).toBe(true);
      expect(refreshed.token).not.toBe(original.token);

      const reValidation = await enforcedManager.validate(refreshed.token);
      expect(reValidation.valid).toBe(true);
      expect(reValidation.service).toBe('chittyid');
    });
  });

  describe('verifySignature: additional edge cases and boundary conditions', () => {
    test('empty string token returns false', () => {
      expect(tokenManager.verifySignature('', 'chitty-id', 'svc', 'tok_x')).toBe(false);
    });

    test('non-string inputs return false without throwing', () => {
      expect(tokenManager.verifySignature(null, 'chitty-id', 'svc', 'tok_x')).toBe(false);
      expect(tokenManager.verifySignature(undefined, 'chitty-id', 'svc', 'tok_x')).toBe(false);
      expect(tokenManager.verifySignature(42, 'chitty-id', 'svc', 'tok_x')).toBe(false);
      expect(tokenManager.verifySignature({}, 'chitty-id', 'svc', 'tok_x')).toBe(false);
    });

    test('token with only valid prefix and empty body returns false', () => {
      // ca_live_ prefix but nothing after it — decoded body is empty
      expect(tokenManager.verifySignature('ca_live_', 'chitty-id', 'svc', 'tok_x')).toBe(false);
    });

    test('token with body too short (below SIGNATURE_LENGTH + 2) returns false', () => {
      // Construct a token whose decoded body is only 10 chars (< 34)
      const shortBody = Buffer.from('tooshort').toString('base64url');
      expect(tokenManager.verifySignature(`ca_live_${shortBody}`, 'chitty-id', 'svc', 'tok_x')).toBe(false);
    });

    test('separator before signature not an underscore returns false', () => {
      // Build a body where the char at position (len - SIGNATURE_LENGTH - 1) is not '_'
      // That means we need a body like: <tokenId>X<timestamp><32-char sig>
      // (replacing the _ before sig with a non-underscore char)
      const tokenId = tokenManager.generateTokenId();
      const timestamp = Date.now();
      const sig = tokenManager.signPayload(`${tokenId}:chitty-id:svc:${timestamp}`);
      // Use 'X' as separator instead of '_' before sig
      const body = `${tokenId}_${timestamp}X${sig}`;
      const token = `ca_live_${Buffer.from(body).toString('base64url')}`;
      expect(tokenManager.verifySignature(token, 'chitty-id', 'svc', tokenId)).toBe(false);
    });

    test('non-digit timestamp returns false', () => {
      const tokenId = tokenManager.generateTokenId();
      const nonDigitTs = 'notanumber';
      const sig = tokenManager.signPayload(`${tokenId}:chitty-id:svc:${nonDigitTs}`);
      const body = `${tokenId}_${nonDigitTs}_${sig}`;
      const token = `ca_live_${Buffer.from(body).toString('base64url')}`;
      expect(tokenManager.verifySignature(token, 'chitty-id', 'svc', tokenId)).toBe(false);
    });

    test('undefined expectedTokenId skips ID check (behaves like null)', async () => {
      // When expectedTokenId is undefined (falsy), the tokenId check is skipped;
      // a valid HMAC is still required.
      const provision = await tokenManager.provision({
        chittyId: '03-1-USA-0001-P-251-3-82',
        scope: ['chittyid:read'],
        service: 'chittyid',
        expiresIn: 3600
      });
      // Passing undefined for expectedTokenId — should still verify cleanly
      expect(
        tokenManager.verifySignature(provision.token, '03-1-USA-0001-P-251-3-82', 'chittyid', undefined)
      ).toBe(true);
    });

    test('empty string expectedTokenId is falsy — skips ID check, HMAC still validated', async () => {
      // '' is falsy; the expectedTokenId guard is `if (expectedTokenId && ...)`,
      // so an empty string skips the mismatch check while HMAC must still match.
      const provision = await tokenManager.provision({
        chittyId: '03-1-USA-0001-P-251-3-82',
        scope: ['chittyid:read'],
        service: 'chittyid',
        expiresIn: 3600
      });
      expect(
        tokenManager.verifySignature(provision.token, '03-1-USA-0001-P-251-3-82', 'chittyid', '')
      ).toBe(true);
    });

    test('ca_test_ prefix verifies correctly for token issued under test environment', () => {
      const testEnvManager = new TokenManager({ ...mockEnv, ENVIRONMENT: 'test' });
      const tokenId = testEnvManager.generateTokenId();
      const chittyId = '03-1-USA-0001-P-251-3-82';
      const service = 'testservice';
      const timestamp = Date.now();
      const sig = testEnvManager.signPayload(`${tokenId}:${chittyId}:${service}:${timestamp}`);
      const body = `${tokenId}_${timestamp}_${sig}`;
      const token = `ca_test_${Buffer.from(body).toString('base64url')}`;
      expect(testEnvManager.verifySignature(token, chittyId, service, tokenId)).toBe(true);
    });

    test('ca_dev_ prefix verifies correctly for token issued under dev environment', () => {
      const devEnvManager = new TokenManager({ ...mockEnv, ENVIRONMENT: 'dev' });
      const tokenId = devEnvManager.generateTokenId();
      const chittyId = '03-1-USA-0001-P-251-3-82';
      const service = 'devservice';
      const timestamp = Date.now();
      const sig = devEnvManager.signPayload(`${tokenId}:${chittyId}:${service}:${timestamp}`);
      const body = `${tokenId}_${timestamp}_${sig}`;
      const token = `ca_dev_${Buffer.from(body).toString('base64url')}`;
      expect(devEnvManager.verifySignature(token, chittyId, service, tokenId)).toBe(true);
    });

    test('svc_ prefix verifies correctly with manually constructed token', () => {
      // svc_ is in the accepted prefix list but never produced by generateToken;
      // this confirms the prefix acceptance path works end-to-end.
      const tokenId = tokenManager.generateTokenId();
      const chittyId = '03-1-USA-0001-P-251-3-82';
      const service = 'internal-service';
      const timestamp = Date.now();
      const sig = tokenManager.signPayload(`${tokenId}:${chittyId}:${service}:${timestamp}`);
      const body = `${tokenId}_${timestamp}_${sig}`;
      const token = `svc_${Buffer.from(body).toString('base64url')}`;
      expect(tokenManager.verifySignature(token, chittyId, service, tokenId)).toBe(true);
    });

    test('svc_ prefix token with wrong HMAC returns false', () => {
      const tokenId = tokenManager.generateTokenId();
      const chittyId = '03-1-USA-0001-P-251-3-82';
      const service = 'internal-service';
      const timestamp = Date.now();
      const badSig = 'A'.repeat(32);
      const body = `${tokenId}_${timestamp}_${badSig}`;
      const token = `svc_${Buffer.from(body).toString('base64url')}`;
      expect(tokenManager.verifySignature(token, chittyId, service, tokenId)).toBe(false);
    });

    test('empty chittyId string (non-null) produces HMAC mismatch → false', async () => {
      const provision = await tokenManager.provision({
        chittyId: '03-1-USA-0001-P-251-3-82',
        scope: ['chittyid:read'],
        service: 'chittyid',
        expiresIn: 3600
      });
      // Empty string is not null/undefined so the null guard passes,
      // but the canonical payload will differ → HMAC mismatch.
      expect(
        tokenManager.verifySignature(provision.token, '', 'chittyid', provision.tokenId)
      ).toBe(false);
    });

    test('empty service string (non-null) produces HMAC mismatch → false', async () => {
      const provision = await tokenManager.provision({
        chittyId: '03-1-USA-0001-P-251-3-82',
        scope: ['chittyid:read'],
        service: 'chittyid',
        expiresIn: 3600
      });
      expect(
        tokenManager.verifySignature(provision.token, '03-1-USA-0001-P-251-3-82', '', provision.tokenId)
      ).toBe(false);
    });

    test('token missing timestamp separator (only tokenId and sig in body) returns false', () => {
      // Body with no timestamp component: just tokenId_<32-char-sig> (no second underscore)
      const tokenId = tokenManager.generateTokenId();
      const sig = 'A'.repeat(32);
      // Build: tokenId_<sig> — no timestamp, so after peeling sig the remainder is tokenId
      // and lastIndexOf('_') on 'tok_XXXX' finds the underscore in tok_, giving
      // tsSep >= 0, but timestampStr = 'XXXX' which is alphanumeric, not all digits.
      // The /^\d+$/ test will fail, returning false.
      const body = `${tokenId}_${sig}`;
      const token = `ca_live_${Buffer.from(body).toString('base64url')}`;
      expect(tokenManager.verifySignature(token, 'chitty-id', 'svc', tokenId)).toBe(false);
    });
  });

  describe('signPayload: output properties', () => {
    test('always returns exactly 32 characters', () => {
      // SIGNATURE_LENGTH in verifySignature is 32; signPayload must match.
      const payloads = [
        'tok_abc:chitty:svc:1234567890',
        'tok_longertokenid:long-chitty-id:longer-service-name:9999999999999',
        'x:y:z:1',
        '',
        'a'.repeat(1000)
      ];
      for (const p of payloads) {
        const sig = tokenManager.signPayload(p);
        expect(sig).toHaveLength(32);
      }
    });

    test('is deterministic for the same payload and signing key', () => {
      const payload = 'tok_test:03-1-USA-0001-P-251-3-82:chittyid:1746000000000';
      const sig1 = tokenManager.signPayload(payload);
      const sig2 = tokenManager.signPayload(payload);
      expect(sig1).toBe(sig2);
    });

    test('changes when payload changes', () => {
      const sig1 = tokenManager.signPayload('tok_a:chittyId:svc:1000');
      const sig2 = tokenManager.signPayload('tok_a:chittyId:svc:1001');
      expect(sig1).not.toBe(sig2);
    });

    test('changes when signing key changes', () => {
      const managerA = new TokenManager({ ...mockEnv, TOKEN_SIGNING_KEY: 'key-alpha' });
      const managerB = new TokenManager({ ...mockEnv, TOKEN_SIGNING_KEY: 'key-beta' });
      const payload = 'tok_test:chittyId:svc:1000';
      expect(managerA.signPayload(payload)).not.toBe(managerB.signPayload(payload));
    });

    test('consists only of base64url characters', () => {
      for (let i = 0; i < 50; i++) {
        const sig = tokenManager.signPayload(`tok_x:id:svc:${i}`);
        expect(sig).toMatch(/^[A-Za-z0-9\-_]+$/);
      }
    });
  });

  describe('provision(): service_name D1 INSERT correctness', () => {
    test('stores service_name correctly in D1 for different services', async () => {
      const freshEnv = {
        ...mockEnv,
        AUTH_AUDIT: createMockKV(),
        AUTH_TOKENS: createMockKV(),
        AUTH_REVOCATIONS: createMockKV(),
        AUTH_RATE_LIMITS: createMockKV(),
        AUTH_DB: createMockD1()
      };
      const mgr = new TokenManager(freshEnv);

      await mgr.provision({ chittyId: 'cid-1', scope: ['r'], service: 'alpha', expiresIn: 60 });
      await mgr.provision({ chittyId: 'cid-2', scope: ['r'], service: 'beta', expiresIn: 60 });
      await mgr.provision({ chittyId: 'cid-3', scope: ['r'], service: 'gamma', expiresIn: 60 });

      const dump = freshEnv.AUTH_DB.__dump();
      expect(dump.tokens[0].service_name).toBe('alpha');
      expect(dump.tokens[1].service_name).toBe('beta');
      expect(dump.tokens[2].service_name).toBe('gamma');
    });

    test('D1 row has service_name at correct column position (not shifted by bug)', async () => {
      // Before the fix, service_name was absent from the INSERT column list,
      // causing created_at to appear in the service_name slot and all
      // subsequent columns to be off by one.
      const freshEnv = {
        ...mockEnv,
        AUTH_AUDIT: createMockKV(),
        AUTH_TOKENS: createMockKV(),
        AUTH_REVOCATIONS: createMockKV(),
        AUTH_RATE_LIMITS: createMockKV(),
        AUTH_DB: createMockD1()
      };
      const mgr = new TokenManager(freshEnv);
      const before = Date.now();

      const provision = await mgr.provision({
        chittyId: '03-1-USA-0001-P-251-3-82',
        scope: ['chittyid:read'],
        service: 'regression-check',
        expiresIn: 3600
      });

      const after = Date.now();
      const dump = freshEnv.AUTH_DB.__dump();
      const row = dump.tokens.find((t) => t.id === provision.tokenId);

      expect(row).toBeDefined();
      // service_name must be the service string, not a timestamp integer
      expect(row.service_name).toBe('regression-check');
      // created_at must be a timestamp, not the service string
      expect(typeof row.created_at).toBe('number');
      expect(row.created_at).toBeGreaterThanOrEqual(before);
      expect(row.created_at).toBeLessThanOrEqual(after);
      // expires_at must be greater than created_at
      expect(row.expires_at).toBeGreaterThan(row.created_at);
    });
  });

  describe('validate(): CHITTYAUTH_VERIFY_SIGNATURE gate strictness', () => {
    // The code comment says: ONLY 'enforce' flips to reject mode.
    // Other truthy strings ('true', '1', 'yes', 'enabled') stay in shadow mode.
    const shadowLikeTruthy = ['true', '1', 'yes', 'enabled', 'on'];

    test.each(shadowLikeTruthy)(
      'CHITTYAUTH_VERIFY_SIGNATURE="%s" keeps shadow mode (tampered token passes)',
      async (value) => {
        const envWithFlag = {
          ...mockEnv,
          AUTH_AUDIT: createMockKV(),
          AUTH_TOKENS: createMockKV(),
          AUTH_REVOCATIONS: createMockKV(),
          AUTH_RATE_LIMITS: createMockKV(),
          AUTH_DB: createMockD1(),
          CHITTYAUTH_VERIFY_SIGNATURE: value
        };
        const mgr = new TokenManager(envWithFlag);

        const provision = await mgr.provision({
          chittyId: '03-1-USA-0001-P-251-3-82',
          scope: ['chittyid:read'],
          service: 'chittyid',
          expiresIn: 3600
        });

        // Build tampered token using fixed-length right-peel (parser-safe)
        const SIGNATURE_LENGTH = 32;
        const prefix = provision.token.slice(0, provision.token.indexOf('_', provision.token.indexOf('_') + 1) + 1);
        const fullPrefix = ['ca_live_', 'ca_test_', 'ca_dev_', 'svc_'].find((p) => provision.token.startsWith(p));
        const decoded = Buffer.from(provision.token.slice(fullPrefix.length), 'base64url').toString('utf8');
        const sigStart = decoded.length - SIGNATURE_LENGTH;
        const origSig = decoded.slice(sigStart);
        const flippedFirst = origSig[0] === 'A' ? 'B' : 'A';
        const tamperedDecoded = `${decoded.slice(0, sigStart)}${flippedFirst}${origSig.slice(1)}`;
        const tamperedToken = `${fullPrefix}${Buffer.from(tamperedDecoded).toString('base64url')}`;
        const tamperedHash = await mgr.hashToken(tamperedToken);

        await envWithFlag.AUTH_TOKENS.put(
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

        const result = await mgr.validate(tamperedToken);
        // Non-'enforce' truthy values must NOT reject
        expect(result.valid).toBe(true);
        // But signature_mismatch must still be logged
        const events = await readAuditEvents(envWithFlag.AUTH_AUDIT);
        expect(events.some((e) => e.eventType === 'signature_mismatch')).toBe(true);
      }
    );

    test('signature_mismatch audit event in shadow mode contains expected fields', async () => {
      // Shadow mode: CHITTYAUTH_VERIFY_SIGNATURE absent. Verify audit event shape.
      const shadowEnv = {
        ...mockEnv,
        AUTH_AUDIT: createMockKV(),
        AUTH_TOKENS: createMockKV(),
        AUTH_REVOCATIONS: createMockKV(),
        AUTH_RATE_LIMITS: createMockKV(),
        AUTH_DB: createMockD1()
      };
      const mgr = new TokenManager(shadowEnv);

      const provision = await mgr.provision({
        chittyId: '03-1-USA-0001-P-251-3-82',
        scope: ['chittyid:read'],
        service: 'chittyid',
        expiresIn: 3600
      });

      const SIGNATURE_LENGTH = 32;
      const fullPrefix = 'ca_live_';
      const decoded = Buffer.from(provision.token.slice(fullPrefix.length), 'base64url').toString('utf8');
      const sigStart = decoded.length - SIGNATURE_LENGTH;
      const origSig = decoded.slice(sigStart);
      const flippedFirst = origSig[0] === 'A' ? 'B' : 'A';
      const tamperedDecoded = `${decoded.slice(0, sigStart)}${flippedFirst}${origSig.slice(1)}`;
      const tamperedToken = `${fullPrefix}${Buffer.from(tamperedDecoded).toString('base64url')}`;
      const tamperedHash = await mgr.hashToken(tamperedToken);

      await shadowEnv.AUTH_TOKENS.put(
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

      await mgr.validate(tamperedToken);

      const events = await readAuditEvents(shadowEnv.AUTH_AUDIT);
      const mismatch = events.find((e) => e.eventType === 'signature_mismatch');
      expect(mismatch).toBeDefined();
      expect(mismatch.tokenId).toBe(provision.tokenId);
      expect(mismatch.chittyId).toBe('03-1-USA-0001-P-251-3-82');
      expect(mismatch.success).toBe(false);
      expect(mismatch.error).toMatch(/signature/i);
    });

    test('valid token with no CHITTYAUTH_VERIFY_SIGNATURE set validates without mismatch event', async () => {
      // Happy path in shadow mode: no mismatch event should be emitted for a valid token.
      const shadowEnv = {
        ...mockEnv,
        AUTH_AUDIT: createMockKV(),
        AUTH_TOKENS: createMockKV(),
        AUTH_REVOCATIONS: createMockKV(),
        AUTH_RATE_LIMITS: createMockKV(),
        AUTH_DB: createMockD1()
      };
      const mgr = new TokenManager(shadowEnv);

      const provision = await mgr.provision({
        chittyId: '03-1-USA-0001-P-251-3-82',
        scope: ['chittyid:read'],
        service: 'chittyid',
        expiresIn: 3600
      });

      const result = await mgr.validate(provision.token);
      expect(result.valid).toBe(true);

      const events = await readAuditEvents(shadowEnv.AUTH_AUDIT);
      const mismatch = events.find((e) => e.eventType === 'signature_mismatch');
      expect(mismatch).toBeUndefined();
    });
  });
});

// Mock KV namespace

  const store = new Map();

  return {
    get: async (key) => store.get(key) || null,
    put: async (key, value, options) => {
      store.set(key, value);
      return;
    },
    delete: async (key) => {
      store.delete(key);
      return;
    },
    list: async (options) => {
      const keys = Array.from(store.keys())
        .filter(k => !options?.prefix || k.startsWith(options.prefix))
        .map(name => ({ name }));
      return { keys };
    }
  };
}

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

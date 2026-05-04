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
});

// Mock KV namespace
function createMockKV() {
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

/**
 * ChittyAuth Token Manager Tests
 * Unit tests for token provisioning, validation, and lifecycle
 */

import { TokenManager } from '../src/token-manager.js';

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
                  created_at: params[4],
                  expires_at: params[5],
                  request_count: params[6]
                });
              }
              return { success: true };
            },
            first: async () => {
              // Simulate SELECT
              if (sql.includes('SELECT * FROM tokens')) {
                const token = tables.tokens.find(t => t.token_hash === params[0] && !t.revoked_at);
                return token || null;
              }
              if (sql.includes('SELECT token_hash FROM tokens')) {
                const token = tables.tokens.find(t => t.id === params[0]);
                return token || null;
              }
              return null;
            }
          };
        }
      };
    }
  };
}

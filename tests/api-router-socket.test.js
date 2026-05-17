import { ChittyAuthAPI } from '../src/api-router.js';
import { jest } from '@jest/globals';

function createMockKV() {
  const store = new Map();
  return {
    get: async (key) => store.get(key) || null,
    put: async (key, value) => { store.set(key, value); },
    delete: async (key) => { store.delete(key); },
    list: async () => ({ keys: [] })
  };
}

function createMockD1() {
  return {
    prepare: () => ({
      bind: () => ({
        run: async () => ({ success: true }),
        first: async () => null
      })
    })
  };
}

describe('API Router Socket Consolidation', () => {
  let api;
  let originalFetch;

  beforeEach(() => {
    originalFetch = global.fetch;
    api = new ChittyAuthAPI({
      TOKEN_SIGNING_KEY: 'test-signing-key-for-unit-tests-only',
      AUTH_TOKENS: createMockKV(),
      AUTH_REVOCATIONS: createMockKV(),
      AUTH_RATE_LIMITS: createMockKV(),
      AUTH_AUDIT: createMockKV(),
      AUTH_DB: createMockD1(),
      CHITTYAUTH_PROVIDER: 'local'
    });

    api.chittyConnect = {
      healthCheck: async () => ({ healthy: true })
    };

    api.authProvider = {
      provider: 'local',
      getStatus: () => ({ providerGate: { ok: true }, provider: 'local' }),
      getOidcDiscovery: async () => ({ issuer: 'https://oauth2.neon.tech' }),
      getJwks: async () => ({ keys: [] }),
      enforceNeonScopes: () => {}
    };
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  test('returns socket contract', async () => {
    const req = new Request('https://auth.chitty.cc/v1/socket/contract', { method: 'GET' });
    const res = await api.route(req);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.endpoint).toBe('/v1/socket');
    expect(Array.isArray(body.transports)).toBe(true);
    expect(body.entries.health).toBeDefined();
  });

  test('legacy mcp host is routed with deprecation headers', async () => {
    const req = new Request('https://mcp.chitty.cc/mcp?entry=provider_status&transport=std', { method: 'GET' });
    const res = await api.route(req);
    expect(res.status).toBe(200);
    expect(res.headers.get('Deprecation')).toContain('true');
    expect(res.headers.get('Sunset')).toBe('2026-10-01');
    expect(res.headers.get('X-Chitty-Legacy-Surface')).toBe('mcp');
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.entry).toBe('provider_status');
  });

  test('socket std entry returns data', async () => {
    const req = new Request('https://auth.chitty.cc/v1/socket?entry=health&transport=std', { method: 'GET' });
    const res = await api.route(req);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.transport).toBe('std');
    expect(body.entry).toBe('health');
    expect(body.data.status).toBeDefined();
  });

  test('socket forwards to chittyrouter when CHITTYROUTER_URL is configured', async () => {
    global.fetch = jest.fn(async (url) => {
      expect(String(url)).toContain('https://router.chitty.cc/v1/socket');
      return new Response(JSON.stringify({
        success: true,
        transport: 'std',
        entry: 'health',
        data: { status: 'ok-from-router' }
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    });

    api = new ChittyAuthAPI({
      TOKEN_SIGNING_KEY: 'test-signing-key-for-unit-tests-only',
      AUTH_TOKENS: createMockKV(),
      AUTH_REVOCATIONS: createMockKV(),
      AUTH_RATE_LIMITS: createMockKV(),
      AUTH_AUDIT: createMockKV(),
      AUTH_DB: createMockD1(),
      CHITTYAUTH_PROVIDER: 'local',
      CHITTYROUTER_URL: 'https://router.chitty.cc'
    });

    const req = new Request('https://auth.chitty.cc/v1/socket?entry=health&transport=std', { method: 'GET' });
    const res = await api.route(req);
    expect(res.status).toBe(200);
    expect(res.headers.get('X-Chitty-Socket-Routed-By')).toBe('chittyrouter');
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.data.status).toBe('ok-from-router');
  });

  test('email namespace ingress requires router url', async () => {
    const req = new Request('https://auth.chitty.cc/v1/intake/email', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ messageId: 'm1', to: ['ops@chitty.cc'], from: 'sender@example.com' })
    });
    const res = await api.route(req);
    expect(res.status).toBe(503);
    const body = await res.json();
    expect(body.error).toContain('CHITTYROUTER_URL');
  });

  test('email namespace ingress forwards to chittyrouter when configured', async () => {
    global.fetch = jest.fn(async (url, init) => {
      expect(String(url)).toBe('https://router.chitty.cc/email/ingest');
      expect(init.method).toBe('POST');
      expect(init.headers.get('X-Chitty-Ingress-Namespace')).toBe('@chitty.cc');
      return new Response(JSON.stringify({ success: true, accepted: true }), {
        status: 202,
        headers: { 'Content-Type': 'application/json' }
      });
    });

    api = new ChittyAuthAPI({
      TOKEN_SIGNING_KEY: 'test-signing-key-for-unit-tests-only',
      AUTH_TOKENS: createMockKV(),
      AUTH_REVOCATIONS: createMockKV(),
      AUTH_RATE_LIMITS: createMockKV(),
      AUTH_AUDIT: createMockKV(),
      AUTH_DB: createMockD1(),
      CHITTYAUTH_PROVIDER: 'local',
      CHITTYROUTER_URL: 'https://router.chitty.cc'
    });

    const req = new Request('https://auth.chitty.cc/v1/intake/email', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ messageId: 'm2', to: ['ops@chitty.cc'], from: 'sender@external.com' })
    });
    const res = await api.route(req);
    expect(res.status).toBe(202);
    expect(res.headers.get('X-Chitty-Ingress-Routed-By')).toBe('chittyrouter');
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.accepted).toBe(true);
  });

  test('email ingress routes receipts mailbox to finance path', async () => {
    global.fetch = jest.fn(async (url, init) => {
      expect(String(url)).toBe('https://router.chitty.cc/email/ingest/finance');
      expect(init.headers.get('X-Chitty-Email-Localpart')).toBe('receipts');
      expect(init.headers.get('X-Chitty-Email-Placement')).toBe('to');
      return new Response(JSON.stringify({ success: true }), { status: 202 });
    });
    api = new ChittyAuthAPI({
      TOKEN_SIGNING_KEY: 'test-signing-key-for-unit-tests-only',
      AUTH_TOKENS: createMockKV(),
      AUTH_REVOCATIONS: createMockKV(),
      AUTH_RATE_LIMITS: createMockKV(),
      AUTH_AUDIT: createMockKV(),
      AUTH_DB: createMockD1(),
      CHITTYAUTH_PROVIDER: 'local',
      CHITTYROUTER_URL: 'https://router.chitty.cc'
    });
    const req = new Request('https://auth.chitty.cc/v1/intake/email', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ to: ['receipts@chitty.cc'], from: 'vendor@bank.com' })
    });
    const res = await api.route(req);
    expect(res.status).toBe(202);
  });

  test('email ingress routes addison and detects cc placement', async () => {
    global.fetch = jest.fn(async (url, init) => {
      expect(String(url)).toBe('https://router.chitty.cc/email/ingest/addison');
      expect(init.headers.get('X-Chitty-Email-Placement')).toBe('cc');
      return new Response(JSON.stringify({ success: true }), { status: 200 });
    });
    api = new ChittyAuthAPI({
      TOKEN_SIGNING_KEY: 'test-signing-key-for-unit-tests-only',
      AUTH_TOKENS: createMockKV(),
      AUTH_REVOCATIONS: createMockKV(),
      AUTH_RATE_LIMITS: createMockKV(),
      AUTH_AUDIT: createMockKV(),
      AUTH_DB: createMockD1(),
      CHITTYAUTH_PROVIDER: 'local',
      CHITTYROUTER_URL: 'https://router.chitty.cc'
    });
    const req = new Request('https://auth.chitty.cc/v1/intake/email', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        to: ['team@external.com'],
        cc: ['Addison <addison@chitty.cc>'],
        from: 'ceo@partner.org'
      })
    });
    const res = await api.route(req);
    expect(res.status).toBe(200);
  });

  test('email ingress bcc-only recipient routes to bcc path', async () => {
    global.fetch = jest.fn(async (url, init) => {
      expect(String(url)).toBe('https://router.chitty.cc/email/ingest/bcc');
      expect(init.headers.get('X-Chitty-Email-Placement')).toBe('bcc');
      return new Response(JSON.stringify({ success: true }), { status: 200 });
    });
    api = new ChittyAuthAPI({
      TOKEN_SIGNING_KEY: 'test-signing-key-for-unit-tests-only',
      AUTH_TOKENS: createMockKV(),
      AUTH_REVOCATIONS: createMockKV(),
      AUTH_RATE_LIMITS: createMockKV(),
      AUTH_AUDIT: createMockKV(),
      AUTH_DB: createMockD1(),
      CHITTYAUTH_PROVIDER: 'local',
      CHITTYROUTER_URL: 'https://router.chitty.cc'
    });
    const req = new Request('https://auth.chitty.cc/v1/intake/email', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        to: ['team@external.com'],
        bcc: ['audit@chitty.cc'],
        from: 'internal@chitty.cc'
      })
    });
    const res = await api.route(req);
    expect(res.status).toBe(200);
  });

  test('email ingress rejects payloads without @chitty.cc recipient', async () => {
    api = new ChittyAuthAPI({
      TOKEN_SIGNING_KEY: 'test-signing-key-for-unit-tests-only',
      AUTH_TOKENS: createMockKV(),
      AUTH_REVOCATIONS: createMockKV(),
      AUTH_RATE_LIMITS: createMockKV(),
      AUTH_AUDIT: createMockKV(),
      AUTH_DB: createMockD1(),
      CHITTYAUTH_PROVIDER: 'local',
      CHITTYROUTER_URL: 'https://router.chitty.cc'
    });
    const req = new Request('https://auth.chitty.cc/v1/intake/email', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ to: ['person@example.com'], from: 'x@y.com' })
    });
    const res = await api.route(req);
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toContain('No @chitty.cc recipient');
  });

  test('scrape ingress forwards to chittyrouter when configured', async () => {
    global.fetch = jest.fn(async (url, init) => {
      expect(String(url)).toBe('https://router.chitty.cc/scrape/ingest');
      expect(init.method).toBe('POST');
      expect(init.headers.get('X-Chitty-Ingress-Namespace')).toBe('chittyscrape');
      return new Response(JSON.stringify({ success: true, queued: true }), {
        status: 202,
        headers: { 'Content-Type': 'application/json' }
      });
    });

    api = new ChittyAuthAPI({
      TOKEN_SIGNING_KEY: 'test-signing-key-for-unit-tests-only',
      AUTH_TOKENS: createMockKV(),
      AUTH_REVOCATIONS: createMockKV(),
      AUTH_RATE_LIMITS: createMockKV(),
      AUTH_AUDIT: createMockKV(),
      AUTH_DB: createMockD1(),
      CHITTYAUTH_PROVIDER: 'local',
      CHITTYROUTER_URL: 'https://router.chitty.cc'
    });

    const req = new Request('https://auth.chitty.cc/v1/intake/scrape', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scrapeId: 's1' })
    });
    const res = await api.route(req);
    expect(res.status).toBe(202);
    expect(res.headers.get('X-Chitty-Ingress-Routed-By')).toBe('chittyrouter');
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.queued).toBe(true);
  });

  test('generic intake routes by source for chittyscrape', async () => {
    global.fetch = jest.fn(async (url, init) => {
      expect(String(url)).toBe('https://router.chitty.cc/scrape/ingest');
      expect(init.headers.get('X-Chitty-Ingress-Type')).toBe('chittyscrape');
      return new Response(JSON.stringify({ success: true }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    });

    api = new ChittyAuthAPI({
      TOKEN_SIGNING_KEY: 'test-signing-key-for-unit-tests-only',
      AUTH_TOKENS: createMockKV(),
      AUTH_REVOCATIONS: createMockKV(),
      AUTH_RATE_LIMITS: createMockKV(),
      AUTH_AUDIT: createMockKV(),
      AUTH_DB: createMockD1(),
      CHITTYAUTH_PROVIDER: 'local',
      CHITTYROUTER_URL: 'https://router.chitty.cc'
    });

    const req = new Request('https://auth.chitty.cc/v1/intake', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ source: 'chittyscrape', scrapeId: 's2' })
    });
    const res = await api.route(req);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);
  });

  test('generic intake rejects unknown source', async () => {
    const req = new Request('https://auth.chitty.cc/v1/intake', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ source: 'unknown' })
    });
    const res = await api.route(req);
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toContain('Unknown intake source');
  });

  test('evidence ingress forwards to chittyrouter when configured', async () => {
    global.fetch = jest.fn(async (url, init) => {
      expect(String(url)).toBe('https://router.chitty.cc/evidence/ingest');
      expect(init.headers.get('X-Chitty-Ingress-Namespace')).toBe('chittyevidence');
      return new Response(JSON.stringify({ success: true }), { status: 202 });
    });
    api = new ChittyAuthAPI({
      TOKEN_SIGNING_KEY: 'test-signing-key-for-unit-tests-only',
      AUTH_TOKENS: createMockKV(),
      AUTH_REVOCATIONS: createMockKV(),
      AUTH_RATE_LIMITS: createMockKV(),
      AUTH_AUDIT: createMockKV(),
      AUTH_DB: createMockD1(),
      CHITTYAUTH_PROVIDER: 'local',
      CHITTYROUTER_URL: 'https://router.chitty.cc'
    });
    const req = new Request('https://auth.chitty.cc/v1/intake/evidence', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ evidenceId: 'e1' })
    });
    const res = await api.route(req);
    expect(res.status).toBe(202);
  });

  test('generic intake routes finance source', async () => {
    global.fetch = jest.fn(async (url, init) => {
      expect(String(url)).toBe('https://router.chitty.cc/finance/ingest');
      expect(init.headers.get('X-Chitty-Ingress-Type')).toBe('chittyfinance');
      return new Response(JSON.stringify({ success: true }), { status: 200 });
    });
    api = new ChittyAuthAPI({
      TOKEN_SIGNING_KEY: 'test-signing-key-for-unit-tests-only',
      AUTH_TOKENS: createMockKV(),
      AUTH_REVOCATIONS: createMockKV(),
      AUTH_RATE_LIMITS: createMockKV(),
      AUTH_AUDIT: createMockKV(),
      AUTH_DB: createMockD1(),
      CHITTYAUTH_PROVIDER: 'local',
      CHITTYROUTER_URL: 'https://router.chitty.cc'
    });
    const req = new Request('https://auth.chitty.cc/v1/intake', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ source: 'finance', batchId: 'f1' })
    });
    const res = await api.route(req);
    expect(res.status).toBe(200);
  });
});

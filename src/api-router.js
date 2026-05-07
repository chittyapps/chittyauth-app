/**
 * ChittyAuth API Router
 * Routes all API requests to appropriate handlers
 */

import { TokenManager } from './token-manager.js';
import { ChittyConnectClient } from './chittyconnect-client.js';
import { RegistrationHandler } from './registration-handler.js';
import { AuthProviderFacade } from './auth-provider.js';

export class ChittyAuthAPI {
  constructor(env) {
    this.env = env;
    // Capture TokenManager init failures (e.g. missing signing-key secret)
    // so /health stays reachable for monitoring even when the worker is
    // misconfigured. Other routes inspect tokenManagerInitError and return
    // 503 — see route() below.
    try {
      this.tokenManager = new TokenManager(env);
      this.tokenManagerInitError = null;
    } catch (err) {
      this.tokenManager = null;
      this.tokenManagerInitError = err.message;
      console.error('TokenManager initialization failed:', err.message);
    }
    this.chittyConnect = new ChittyConnectClient(env);
    this.registrationHandler = new RegistrationHandler(env);
    this.authProvider = new AuthProviderFacade(env);
    this.socketContractVersion = '2026-05-06.v1';
    this.socketDeprecationDate = '2026-07-01';
    this.socketRemovalDate = '2026-10-01';
    this.routerBaseUrl = env.CHITTYROUTER_URL || null;
  }

  /**
   * Route incoming request
   */
  async route(request) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // CORS preflight
    if (method === 'OPTIONS') {
      return this.corsResponse();
    }

    try {
      const host = url.hostname.toLowerCase();

      // Health check is always reachable so monitoring can detect
      // misconfiguration (signing-key missing, etc).
      if ((path === '/' || path === '/ui') && method === 'GET') {
        return this.handleUiPage();
      }
      if (path === '/health' && method === 'GET') {
        return await this.handleHealth();
      }

      // Backward-compatible consolidation layer.
      // Legacy domains/paths flow into the universal socket endpoint.
      if (
        host === 'chatgpt.chitty.cc' ||
        host === 'mcp.chitty.cc' ||
        path === '/mcp' ||
        path === '/chatgpt'
      ) {
        return await this.handleLegacySocketCompatibility(request, host, path);
      }

      // Fail closed when TokenManager could not initialize. Every
      // non-/health route either issues, validates, or relies on the
      // signing key indirectly, so refuse them all rather than guarding
      // each handler individually.
      if (this.tokenManagerInitError) {
        return this.jsonResponse({
          success: false,
          error: 'service_misconfigured',
          message: this.tokenManagerInitError
        }, 503);
      }

      // PUBLIC: Registration (no auth required)
      if (path === '/v1/register' && method === 'POST') {
        return await this.handleRegister(request);
      }

      // Token provisioning
      if (path === '/v1/tokens/provision' && method === 'POST') {
        return await this.handleProvision(request);
      }

      // Token validation
      if (path === '/v1/tokens/validate' && method === 'POST') {
        return await this.handleValidate(request);
      }

      // Token refresh
      if (path === '/v1/tokens/refresh' && method === 'POST') {
        return await this.handleRefresh(request);
      }

      // Token revocation
      if (path === '/v1/tokens/revoke' && method === 'POST') {
        return await this.handleRevoke(request);
      }

      // Service authentication
      if (path === '/v1/service/authenticate' && method === 'POST') {
        return await this.handleServiceAuth(request);
      }

      // Token statistics
      if (path === '/v1/tokens/stats' && method === 'GET') {
        return await this.handleStats(request);
      }

      // ChittyConnect integration endpoints
      if (path === '/v1/connect/verify' && method === 'POST') {
        return await this.handleConnectVerify(request);
      }

      // Auth provider status/facade endpoints
      if (path === '/v1/auth/provider/status' && method === 'GET') {
        return await this.handleProviderStatus();
      }
      if (path === '/v1/auth/neon/oauth/authorize-url' && method === 'POST') {
        return await this.handleNeonAuthorizeUrl(request);
      }
      if (path === '/v1/auth/neon/oauth/token-exchange' && method === 'POST') {
        return await this.handleNeonTokenExchange(request);
      }
      if (path === '/.well-known/openid-configuration' && method === 'GET') {
        return await this.handleOidcDiscovery();
      }
      if (path === '/.well-known/jwks.json' && method === 'GET') {
        return await this.handleOidcJwks();
      }
      if (path === '/v1/auth/internal-token' && method === 'POST') {
        return await this.handleInternalTokenIssue(request);
      }
      if (path === '/v1/intake/email' && method === 'POST') {
        return await this.handleEmailNamespaceIngress(request);
      }
      if (path === '/v1/intake/scrape' && method === 'POST') {
        return await this.handleScrapeIngress(request);
      }
      if (path === '/v1/intake/evidence' && method === 'POST') {
        return await this.handleEvidenceIngress(request);
      }
      if (path === '/v1/intake/storage' && method === 'POST') {
        return await this.handleStorageIngress(request);
      }
      if (path === '/v1/intake/finance' && method === 'POST') {
        return await this.handleFinanceIngress(request);
      }
      if (path === '/v1/intake' && method === 'POST') {
        return await this.handleGenericIngress(request);
      }
      if (path === '/v1/socket' && (method === 'GET' || method === 'POST')) {
        return await this.handleUniversalSocket(request);
      }
      if (path === '/v1/socket/contract' && method === 'GET') {
        return this.jsonResponse(this.getSocketContract(), 200);
      }

      // 404 for unknown routes
      return this.jsonResponse({
        success: false,
        error: 'Endpoint not found',
        availableEndpoints: [
          'POST /v1/register (PUBLIC - get your first ChittyID + token)',
          'POST /v1/tokens/provision',
          'POST /v1/tokens/validate',
          'POST /v1/tokens/refresh',
          'POST /v1/tokens/revoke',
          'POST /v1/service/authenticate',
          'GET /v1/tokens/stats',
          'POST /v1/connect/verify',
          'GET /v1/auth/provider/status',
          'POST /v1/auth/neon/oauth/authorize-url',
          'POST /v1/auth/neon/oauth/token-exchange',
          'GET /.well-known/openid-configuration',
          'GET /.well-known/jwks.json',
          'POST /v1/auth/internal-token',
          'POST /v1/intake/email',
          'POST /v1/intake/scrape',
          'POST /v1/intake/evidence',
          'POST /v1/intake/storage',
          'POST /v1/intake/finance',
          'POST /v1/intake',
          'GET|POST /v1/socket',
          'GET /v1/socket/contract',
          'GET /ui',
          'GET /health'
        ]
      }, 404);

    } catch (error) {
      console.error('API error:', error);
      return this.jsonResponse({
        success: false,
        error: error.message,
        timestamp: new Date().toISOString()
      }, 500);
    }
  }

  /**
   * Handle token provisioning
   */
  async handleProvision(request) {
    try {
      const body = await request.json();
      const { chittyId, scope, service, expiresIn } = body;

      // Validate inputs
      if (!chittyId || !scope || !service) {
        return this.jsonResponse({
          success: false,
          error: 'Missing required fields: chittyId, scope, service'
        }, 400);
      }

      // Verify ChittyID with ChittyConnect
      const verification = await this.chittyConnect.verifyChittyID(chittyId);
      if (!verification.verified) {
        return this.jsonResponse({
          success: false,
          error: 'ChittyID verification failed',
          details: verification.error
        }, 403);
      }

      // Check if requested scopes are authorized
      const permissions = await this.chittyConnect.getUserPermissions(chittyId);
      const authorizedScopes = await this.validateScopes(scope, permissions);

      if (authorizedScopes.length === 0) {
        return this.jsonResponse({
          success: false,
          error: 'No authorized scopes for this ChittyID',
          requestedScopes: scope,
          availablePermissions: permissions.permissions
        }, 403);
      }

      // Provision token
      const result = await this.tokenManager.provision({
        chittyId,
        scope: authorizedScopes,
        service,
        expiresIn
      });

      return this.jsonResponse(result, 201);

    } catch (error) {
      return this.jsonResponse({
        success: false,
        error: error.message
      }, 500);
    }
  }

  /**
   * Handle token validation
   */
  async handleValidate(request) {
    try {
      const body = await request.json();
      const { token } = body;

      if (!token) {
        return this.jsonResponse({
          success: false,
          error: 'Token is required'
        }, 400);
      }

      const result = await this.tokenManager.validate(token);

      if (!result.valid) {
        return this.jsonResponse({
          valid: false,
          error: result.error
        }, 401);
      }

      return this.jsonResponse(result, 200);

    } catch (error) {
      return this.jsonResponse({
        valid: false,
        error: error.message
      }, 500);
    }
  }

  /**
   * Handle token refresh
   */
  async handleRefresh(request) {
    try {
      const body = await request.json();
      const { token, expiresIn } = body;

      if (!token) {
        return this.jsonResponse({
          success: false,
          error: 'Token is required'
        }, 400);
      }

      const result = await this.tokenManager.refresh(token, expiresIn);

      if (!result.success) {
        return this.jsonResponse(result, 401);
      }

      return this.jsonResponse(result, 200);

    } catch (error) {
      return this.jsonResponse({
        success: false,
        error: error.message
      }, 500);
    }
  }

  /**
   * Handle token revocation
   */
  async handleRevoke(request) {
    try {
      const body = await request.json();
      const { tokenId, reason } = body;

      if (!tokenId) {
        return this.jsonResponse({
          success: false,
          error: 'Token ID is required'
        }, 400);
      }

      const result = await this.tokenManager.revoke(tokenId, reason);
      return this.jsonResponse(result, 200);

    } catch (error) {
      return this.jsonResponse({
        success: false,
        error: error.message
      }, 500);
    }
  }

  /**
   * Handle service authentication
   */
  async handleServiceAuth(request) {
    try {
      const body = await request.json();
      const { serviceToken, targetService, action } = body;

      if (!serviceToken || !targetService) {
        return this.jsonResponse({
          success: false,
          error: 'Service token and target service are required'
        }, 400);
      }

      // Validate service token
      const validation = await this.tokenManager.validate(serviceToken);
      if (!validation.valid) {
        return this.jsonResponse({
          authorized: false,
          error: 'Invalid service token'
        }, 401);
      }

      // Check if service has permission for action
      const requiredScope = `${targetService}:${action}`;
      const hasPermission = validation.scope.includes(requiredScope) ||
                           validation.scope.includes(`${targetService}:*`) ||
                           validation.scope.includes('admin:*');

      if (!hasPermission) {
        return this.jsonResponse({
          authorized: false,
          error: 'Insufficient permissions',
          required: requiredScope,
          available: validation.scope
        }, 403);
      }

      // Generate temporary session token
      const sessionToken = await this.generateSessionToken(validation, targetService);

      return this.jsonResponse({
        authorized: true,
        serviceId: validation.service,
        permissions: validation.scope,
        sessionToken,
        expiresIn: 300 // 5 minutes
      }, 200);

    } catch (error) {
      return this.jsonResponse({
        authorized: false,
        error: error.message
      }, 500);
    }
  }

  /**
   * Handle token statistics
   */
  async handleStats(request) {
    try {
      // Verify admin token
      const authHeader = request.headers.get('Authorization');
      if (!authHeader) {
        return this.jsonResponse({
          success: false,
          error: 'Authorization required'
        }, 401);
      }

      const validation = await this.tokenManager.validate(authHeader);
      if (!validation.valid || !validation.scope.includes('admin:*')) {
        return this.jsonResponse({
          success: false,
          error: 'Admin access required'
        }, 403);
      }

      const stats = await this.tokenManager.getStats();
      return this.jsonResponse({
        success: true,
        ...stats,
        timestamp: new Date().toISOString()
      }, 200);

    } catch (error) {
      return this.jsonResponse({
        success: false,
        error: error.message
      }, 500);
    }
  }

  /**
   * Handle ChittyConnect verification
   */
  async handleConnectVerify(request) {
    try {
      const body = await request.json();
      const { chittyId } = body;

      if (!chittyId) {
        return this.jsonResponse({
          success: false,
          error: 'ChittyID is required'
        }, 400);
      }

      const result = await this.chittyConnect.verifyChittyID(chittyId);
      return this.jsonResponse(result, 200);

    } catch (error) {
      return this.jsonResponse({
        success: false,
        error: error.message
      }, 500);
    }
  }

  /**
   * Handle health check.
   *
   * Returns 200 with status='degraded' when signing key is unconfigured so
   * monitoring can observe the misconfiguration without the load balancer
   * yanking the worker out of rotation entirely (every other route returns
   * 503 in that state, which is the actual user-facing failure signal).
   */
  async handleHealth() {
    const chittyConnectHealth = await this.chittyConnect.healthCheck();
    const signingKeyConfigured = !this.tokenManagerInitError;

    const body = {
      status: signingKeyConfigured ? 'healthy' : 'degraded',
      version: '1.0.0',
      timestamp: new Date().toISOString(),
      checks: {
        signing_key_configured: signingKeyConfigured
      },
      dependencies: {
        chittyConnect: chittyConnectHealth.healthy ? 'healthy' : 'unhealthy'
      }
    };
    if (this.tokenManagerInitError) {
      body.checks.signing_key_error = this.tokenManagerInitError;
    }
    return this.jsonResponse(body, 200);
  }

  async handleProviderStatus() {
    const status = this.authProvider.getStatus();
    const code = status.providerGate?.ok ? 200 : 503;
    return this.jsonResponse({ success: true, ...status }, code);
  }

  async handleNeonAuthorizeUrl(request) {
    try {
      const body = await request.json();
      const authorizeUrl = this.authProvider.buildNeonAuthorizeUrl({
        redirectUri: body.redirectUri,
        state: body.state,
        codeChallenge: body.codeChallenge,
        scope: body.scope
      });
      return this.jsonResponse({ success: true, authorizeUrl }, 200);
    } catch (error) {
      return this.jsonResponse({ success: false, error: error.message }, 400);
    }
  }

  async handleNeonTokenExchange(request) {
    try {
      const body = await request.json();
      const result = await this.authProvider.exchangeNeonCode({
        code: body.code,
        redirectUri: body.redirectUri,
        codeVerifier: body.codeVerifier
      });
      const status = result.success ? 200 : 400;
      return this.jsonResponse(result, status);
    } catch (error) {
      return this.jsonResponse({ success: false, error: error.message }, 500);
    }
  }

  async handleOidcDiscovery() {
    try {
      const discovery = await this.authProvider.getOidcDiscovery();
      return this.jsonResponse(discovery, 200);
    } catch (error) {
      return this.jsonResponse({ success: false, error: error.message }, 503);
    }
  }

  async handleOidcJwks() {
    try {
      const jwks = await this.authProvider.getJwks();
      return this.jsonResponse(jwks, 200);
    } catch (error) {
      return this.jsonResponse({ success: false, error: error.message }, 503);
    }
  }

  async handleInternalTokenIssue(request) {
    try {
      const body = await request.json();
      const {
        service,
        audience,
        scope,
        expiresIn,
        sovereigntyCert
      } = body;

      if (!service || !audience || !scope) {
        return this.jsonResponse({
          success: false,
          error: 'Missing required fields: service, audience, scope'
        }, 400);
      }

      const providerGate = this.authProvider.getStatus().providerGate;
      if (!providerGate?.ok) {
        return this.jsonResponse({
          success: false,
          error: providerGate?.error || 'Provider misconfigured'
        }, 503);
      }

      const scopeList = Array.isArray(scope) ? scope : String(scope).split(/\s+/).filter(Boolean);
      this.authProvider.enforceNeonScopes(scopeList);

      if (sovereigntyCert) {
        if (sovereigntyCert.status !== 'active') {
          return this.jsonResponse({
            success: false,
            error: 'sovereignty.cert must be active for internal token issuance'
          }, 403);
        }
      }

      const tokenName = `CHITTYAUTH_ISSUED_${String(service).replace(/[^a-zA-Z0-9]+/g, '_').toUpperCase()}_TOKEN`;
      const provision = await this.tokenManager.provision({
        chittyId: `internal:${audience}`,
        scope: scopeList,
        service,
        expiresIn
      });

      await this.tokenManager.logAuditEvent({
        eventType: 'internal_token_issued',
        tokenId: provision.tokenId,
        chittyId: `internal:${audience}`,
        service,
        success: true,
        timestamp: Date.now()
      });

      return this.jsonResponse({
        success: true,
        tokenName,
        provider: this.authProvider.provider,
        tokenType: 'internal',
        audience,
        scope: scopeList,
        expiresAt: provision.expiresAt,
        token: provision.token
      }, 201);
    } catch (error) {
      return this.jsonResponse({
        success: false,
        error: error.message
      }, 400);
    }
  }

  async resolveSocketEntry(entry, payload = {}) {
    const normalized = String(entry || 'health').toLowerCase();
    switch (normalized) {
      case 'health':
        return {
          entry: 'health',
          data: await this.handleHealth().then(async (r) => await r.json())
        };
      case 'provider_status':
        return {
          entry: 'provider_status',
          data: await this.authProvider.getStatus()
        };
      case 'oidc_discovery':
        return {
          entry: 'oidc_discovery',
          data: await this.authProvider.getOidcDiscovery()
        };
      case 'oidc_jwks':
        return {
          entry: 'oidc_jwks',
          data: await this.authProvider.getJwks()
        };
      case 'internal_token_policy':
        return {
          entry: 'internal_token_policy',
          data: {
            naming: 'CHITTYAUTH_ISSUED_<SERVICE>_TOKEN',
            requiresSovereigntyCertActive: true,
            provider: this.authProvider.provider,
            requestedService: payload.service || null
          }
        };
      case 'contract':
        return {
          entry: 'contract',
          data: this.getSocketContract()
        };
      default:
        throw new Error(`Unknown socket entry: ${normalized}`);
    }
  }

  getSocketContract() {
    return {
      success: true,
      endpoint: '/v1/socket',
      version: this.socketContractVersion,
      routedBy: this.routerBaseUrl ? 'chittyrouter' : 'chittyauth-local',
      routerBaseUrl: this.routerBaseUrl,
      transports: ['std', 'sse'],
      entries: {
        health: { method: 'GET|POST', auth: 'none', description: 'Service health snapshot' },
        provider_status: { method: 'GET|POST', auth: 'none', description: 'Provider gate/config status' },
        oidc_discovery: { method: 'GET|POST', auth: 'none', description: 'Provider OIDC discovery pass-through' },
        oidc_jwks: { method: 'GET|POST', auth: 'none', description: 'Provider JWKS pass-through' },
        internal_token_policy: { method: 'GET|POST', auth: 'none', description: 'Canonical internal token policy' },
        contract: { method: 'GET|POST', auth: 'none', description: 'Socket contract metadata' }
      },
      migration: {
        deprecatedSurfaces: [
          'chatgpt.chitty.cc',
          'mcp.chitty.cc',
          '/chatgpt',
          '/mcp'
        ],
        deprecationDate: this.socketDeprecationDate,
        removalDate: this.socketRemovalDate
      }
    };
  }

  getRouterForwardConfig() {
    if (!this.routerBaseUrl) {
      return { enabled: false, reason: 'CHITTYROUTER_URL not configured' };
    }
    try {
      const base = new URL(this.routerBaseUrl);
      return { enabled: true, base };
    } catch {
      return { enabled: false, reason: 'Invalid CHITTYROUTER_URL' };
    }
  }

  async forwardSocketToRouter(request, entry, transport, body) {
    const config = this.getRouterForwardConfig();
    if (!config.enabled) {
      return null;
    }

    const routerUrl = new URL('/v1/socket', config.base);
    routerUrl.searchParams.set('entry', entry);
    routerUrl.searchParams.set('transport', transport);
    if (transport === 'sse') {
      const reqUrl = new URL(request.url);
      const watch = reqUrl.searchParams.get('watch') || String(body.watch || '');
      if (watch) {
        routerUrl.searchParams.set('watch', watch);
      }
    }

    const headers = new Headers();
    headers.set('Accept', request.headers.get('Accept') || '*/*');
    headers.set('X-Chitty-Auth-Gateway', 'chittyauth');
    headers.set('X-Chitty-Socket-Entry', entry);
    headers.set('X-Chitty-Socket-Transport', transport);
    const authHeader = request.headers.get('Authorization');
    if (authHeader) {
      headers.set('Authorization', authHeader);
    }

    const method = request.method === 'POST' ? 'POST' : 'GET';
    if (method === 'POST') {
      headers.set('Content-Type', 'application/json');
    }
    const forwarded = await fetch(routerUrl.toString(), {
      method,
      headers,
      body: method === 'POST' ? JSON.stringify(body) : undefined
    });

    const responseHeaders = new Headers(forwarded.headers);
    responseHeaders.set('X-Chitty-Socket-Routed-By', 'chittyrouter');
    responseHeaders.set('X-Chitty-Socket-Router-Base', config.base.toString());
    return new Response(forwarded.body, {
      status: forwarded.status,
      headers: responseHeaders
    });
  }

  async handleEmailNamespaceIngress(request) {
    let payload = {};
    try {
      payload = await request.json();
    } catch {
      return this.jsonResponse({
        success: false,
        error: 'Invalid JSON body'
      }, 400);
    }

    const emailRouting = this.resolveEmailRoutingContext(payload);
    if (!emailRouting.ok) {
      return this.jsonResponse({
        success: false,
        error: emailRouting.error
      }, 400);
    }

    return this.handleIngressForward(request, {
      source: 'namespace-email',
      namespace: '@chitty.cc',
      defaultRouterPath: emailRouting.routerPath,
      missingConfigMessage: 'Email ingress requires CHITTYROUTER_URL',
      payload,
      extraHeaders: {
        'X-Chitty-Email-Recipient': emailRouting.recipient,
        'X-Chitty-Email-Localpart': emailRouting.localpart,
        'X-Chitty-Email-Placement': emailRouting.placement,
        'X-Chitty-Email-Sender': emailRouting.sender,
        'X-Chitty-Email-Sender-Domain': emailRouting.senderDomain,
        'X-Chitty-Email-Sender-Internal': String(emailRouting.senderInternal)
      }
    });
  }

  extractEmailList(input) {
    if (!input) return [];
    if (Array.isArray(input)) {
      return input.flatMap((item) => this.extractEmailList(item));
    }
    if (typeof input === 'object') {
      return this.extractEmailList(input.address || input.email || input.value || '');
    }
    if (typeof input === 'string') {
      const emails = input.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi) || [];
      if (emails.length > 0) return emails.map((e) => e.toLowerCase());
      const cleaned = input.trim().toLowerCase();
      return cleaned.includes('@') ? [cleaned] : [];
    }
    return [];
  }

  resolveEmailRoutingContext(payload) {
    const toList = this.extractEmailList(payload.to || payload.envelopeTo || payload.recipient);
    const ccList = this.extractEmailList(payload.cc);
    const bccList = this.extractEmailList(payload.bcc);
    const sender = this.extractEmailList(payload.from || payload.sender || payload.envelopeFrom)[0] || 'unknown@unknown';
    const senderDomain = sender.includes('@') ? sender.split('@').pop() : 'unknown';
    const senderInternal = senderDomain === 'chitty.cc';

    const findTarget = (list, placement) => {
      const match = list.find((email) => email.endsWith('@chitty.cc'));
      if (!match) return null;
      return { recipient: match, placement };
    };

    const target = findTarget(toList, 'to') || findTarget(ccList, 'cc') || findTarget(bccList, 'bcc');
    if (!target) {
      return {
        ok: false,
        error: 'No @chitty.cc recipient found in to/cc/bcc'
      };
    }

    const localpart = target.recipient.split('@')[0];
    return {
      ok: true,
      recipient: target.recipient,
      localpart,
      placement: target.placement,
      sender,
      senderDomain,
      senderInternal,
      routerPath: this.routeEmailMailboxToPath(localpart, target.placement)
    };
  }

  routeEmailMailboxToPath(localpart, placement) {
    const key = String(localpart || '').toLowerCase();
    if (key === 'receipts' || key === 'billing' || key === 'invoices') {
      return '/email/ingest/finance';
    }
    if (key === 'addison') {
      return '/email/ingest/addison';
    }
    if (key === 'evidence' || key === 'claims' || key === 'legal') {
      return '/email/ingest/evidence';
    }
    if (key === 'storage' || key === 'archive' || key === 'docs') {
      return '/email/ingest/storage';
    }
    if (placement === 'bcc') {
      return '/email/ingest/bcc';
    }
    return '/email/ingest';
  }

  async handleScrapeIngress(request) {
    return this.handleIngressForward(request, {
      source: 'chittyscrape',
      namespace: 'chittyscrape',
      defaultRouterPath: '/scrape/ingest',
      missingConfigMessage: 'Scrape ingress requires CHITTYROUTER_URL'
    });
  }

  async handleEvidenceIngress(request) {
    return this.handleIngressForward(request, {
      source: 'chittyevidence',
      namespace: 'chittyevidence',
      defaultRouterPath: '/evidence/ingest',
      missingConfigMessage: 'Evidence ingress requires CHITTYROUTER_URL'
    });
  }

  async handleStorageIngress(request) {
    return this.handleIngressForward(request, {
      source: 'chittystorage',
      namespace: 'chittystorage',
      defaultRouterPath: '/storage/ingest',
      missingConfigMessage: 'Storage ingress requires CHITTYROUTER_URL'
    });
  }

  async handleFinanceIngress(request) {
    return this.handleIngressForward(request, {
      source: 'chittyfinance',
      namespace: 'chittyfinance',
      defaultRouterPath: '/finance/ingest',
      missingConfigMessage: 'Finance ingress requires CHITTYROUTER_URL'
    });
  }

  async handleGenericIngress(request) {
    let payload = {};
    try {
      payload = await request.json();
    } catch {
      return this.jsonResponse({
        success: false,
        error: 'Invalid JSON body'
      }, 400);
    }

    const source = String(payload.source || '').trim().toLowerCase();
    if (source === 'chittyscrape' || source === 'scrape') {
      return this.handleIngressForward(request, {
        source: 'chittyscrape',
        namespace: 'chittyscrape',
        defaultRouterPath: '/scrape/ingest',
        missingConfigMessage: 'Scrape ingress requires CHITTYROUTER_URL',
        payload
      });
    }
    if (source === 'chittyevidence' || source === 'evidence') {
      return this.handleIngressForward(request, {
        source: 'chittyevidence',
        namespace: 'chittyevidence',
        defaultRouterPath: '/evidence/ingest',
        missingConfigMessage: 'Evidence ingress requires CHITTYROUTER_URL',
        payload
      });
    }
    if (source === 'chittystorage' || source === 'storage') {
      return this.handleIngressForward(request, {
        source: 'chittystorage',
        namespace: 'chittystorage',
        defaultRouterPath: '/storage/ingest',
        missingConfigMessage: 'Storage ingress requires CHITTYROUTER_URL',
        payload
      });
    }
    if (source === 'chittyfinance' || source === 'finance') {
      return this.handleIngressForward(request, {
        source: 'chittyfinance',
        namespace: 'chittyfinance',
        defaultRouterPath: '/finance/ingest',
        missingConfigMessage: 'Finance ingress requires CHITTYROUTER_URL',
        payload
      });
    }
    if (
      source === '@chitty.cc' ||
      source === 'namespace-email' ||
      source === 'email'
    ) {
      return this.handleIngressForward(request, {
        source: 'namespace-email',
        namespace: '@chitty.cc',
        defaultRouterPath: '/email/ingest',
        missingConfigMessage: 'Email ingress requires CHITTYROUTER_URL',
        payload
      });
    }

    return this.jsonResponse({
      success: false,
      error: 'Unknown intake source',
      allowedSources: [
        '@chitty.cc', 'namespace-email', 'email',
        'chittyscrape', 'scrape',
        'chittyevidence', 'evidence',
        'chittystorage', 'storage',
        'chittyfinance', 'finance'
      ]
    }, 400);
  }

  async handleIngressForward(request, options) {
    const config = this.getRouterForwardConfig();
    if (!config.enabled) {
      return this.jsonResponse({
        success: false,
        error: options.missingConfigMessage
      }, 503);
    }

    let payload = options.payload;
    if (!payload) {
      try {
        payload = await request.json();
      } catch {
        return this.jsonResponse({
          success: false,
          error: 'Invalid JSON body'
        }, 400);
      }
    }

    const routerPath = payload.routerPath || options.defaultRouterPath;
    const routerUrl = new URL(routerPath, config.base);
    const headers = new Headers({
      'Content-Type': 'application/json',
      'X-Chitty-Auth-Gateway': 'chittyauth',
      'X-Chitty-Ingress-Type': options.source,
      'X-Chitty-Ingress-Namespace': options.namespace
    });
    if (options.extraHeaders) {
      for (const [key, value] of Object.entries(options.extraHeaders)) {
        if (value !== undefined && value !== null) {
          headers.set(key, String(value));
        }
      }
    }
    const authHeader = request.headers.get('Authorization');
    if (authHeader) {
      headers.set('Authorization', authHeader);
    }

    const forwarded = await fetch(routerUrl.toString(), {
      method: 'POST',
      headers,
      body: JSON.stringify(payload)
    });

    const responseHeaders = new Headers(forwarded.headers);
    responseHeaders.set('X-Chitty-Ingress-Routed-By', 'chittyrouter');
    responseHeaders.set('X-Chitty-Ingress-Route', routerPath);
    return new Response(forwarded.body, {
      status: forwarded.status,
      headers: responseHeaders
    });
  }

  async handleLegacySocketCompatibility(request, host, path) {
    const url = new URL(request.url);
    const isMcp = host === 'mcp.chitty.cc' || path === '/mcp';
    const isChat = host === 'chatgpt.chitty.cc' || path === '/chatgpt';
    const entry = url.searchParams.get('entry') || (isMcp ? 'provider_status' : 'health');
    const transport = url.searchParams.get('transport') || (isMcp ? 'std' : 'sse');

    const rewrittenUrl = new URL(request.url);
    rewrittenUrl.pathname = '/v1/socket';
    rewrittenUrl.searchParams.set('entry', entry);
    rewrittenUrl.searchParams.set('transport', transport);
    if (transport === 'sse') {
      rewrittenUrl.searchParams.set('watch', url.searchParams.get('watch') || '1');
    }

    const rewrittenRequest = new Request(rewrittenUrl.toString(), request);
    const response = await this.handleUniversalSocket(rewrittenRequest);

    const headers = new Headers(response.headers);
    headers.set('Deprecation', `true; date="${this.socketDeprecationDate}"`);
    headers.set('Sunset', this.socketRemovalDate);
    headers.set(
      'Link',
      '</v1/socket>; rel="successor-version"; title="Unified Socket Endpoint"'
    );
    headers.set('X-Chitty-Legacy-Surface', isMcp ? 'mcp' : (isChat ? 'chatgpt' : 'unknown'));
    headers.set('X-Chitty-Migration-Contract', `/v1/socket/contract#${this.socketContractVersion}`);

    return new Response(response.body, {
      status: response.status,
      headers
    });
  }

  async handleUniversalSocket(request) {
    const url = new URL(request.url);
    const accept = request.headers.get('Accept') || '';
    const queryEntry = url.searchParams.get('entry');
    const queryTransport = url.searchParams.get('transport');
    const watch = url.searchParams.get('watch') === '1';
    let body = {};

    if (request.method === 'POST') {
      try {
        body = await request.json();
      } catch {
        return this.jsonResponse({
          success: false,
          error: 'Invalid JSON body'
        }, 400);
      }
    }

    const entry = queryEntry || body.entry || 'health';
    const transport = queryTransport || body.transport || (accept.includes('text/event-stream') ? 'sse' : 'std');

    const forwarded = await this.forwardSocketToRouter(request, entry, transport, body);
    if (forwarded) {
      return forwarded;
    }

    if (transport === 'sse') {
      const encoder = new TextEncoder();
      const stream = new ReadableStream({
        start: async (controller) => {
          const writeEvent = (event, data) => {
            controller.enqueue(encoder.encode(`event: ${event}\n`));
            controller.enqueue(encoder.encode(`data: ${JSON.stringify(data)}\n\n`));
          };

          try {
            writeEvent('ready', {
              entry,
              transport: 'sse',
              timestamp: new Date().toISOString()
            });

            const first = await this.resolveSocketEntry(entry, body);
            writeEvent('message', first);
          } catch (error) {
            writeEvent('error', { message: error.message });
            controller.close();
            return;
          }

          if (!watch) {
            controller.close();
            return;
          }

          const timer = setInterval(async () => {
            try {
              const next = await this.resolveSocketEntry(entry, body);
              writeEvent('message', next);
            } catch (error) {
              writeEvent('error', { message: error.message });
              clearInterval(timer);
              controller.close();
            }
          }, 15000);

          request.signal.addEventListener('abort', () => {
            clearInterval(timer);
            controller.close();
          });
        }
      });

      return new Response(stream, {
        status: 200,
        headers: {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache, no-transform',
          'Connection': 'keep-alive',
          'Access-Control-Allow-Origin': '*'
        }
      });
    }

    try {
      const resolved = await this.resolveSocketEntry(entry, body);
      return this.jsonResponse({
        success: true,
        transport: 'std',
        ...resolved
      }, 200);
    } catch (error) {
      return this.jsonResponse({
        success: false,
        transport: 'std',
        error: error.message
      }, 400);
    }
  }

  handleUiPage() {
    const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>ChittyAuth UI</title>
  <style>
    :root { --bg: #f5f7fb; --card: #ffffff; --ink: #122033; --muted: #5e6b7e; --line: #d8e0ec; --brand: #0f6fff; }
    body { margin: 0; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif; background: var(--bg); color: var(--ink); }
    .wrap { max-width: 900px; margin: 24px auto; padding: 0 16px; }
    .card { background: var(--card); border: 1px solid var(--line); border-radius: 12px; padding: 16px; margin-bottom: 16px; }
    h1 { font-size: 22px; margin: 0 0 12px; }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
    label { display: block; font-size: 12px; color: var(--muted); margin-bottom: 6px; }
    input, select, textarea { width: 100%; box-sizing: border-box; border: 1px solid var(--line); border-radius: 8px; padding: 10px; font: inherit; }
    textarea { min-height: 96px; resize: vertical; }
    .row { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 12px; }
    button { border: 0; border-radius: 8px; padding: 10px 14px; font-weight: 600; cursor: pointer; background: var(--brand); color: #fff; }
    button.alt { background: #e8eef8; color: #17304d; }
    pre { background: #0f1724; color: #dbe7ff; padding: 12px; border-radius: 10px; overflow: auto; min-height: 140px; }
    .muted { color: var(--muted); font-size: 12px; }
    @media (max-width: 720px) { .grid { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h1>ChittyAuth Socket Console</h1>
      <div class="muted">Use this to hit <code>/v1/socket</code> and provider endpoints from one place.</div>
    </div>
    <div class="card">
      <div class="grid">
        <div>
          <label>Entry</label>
          <select id="entry">
            <option value="health">health</option>
            <option value="provider_status">provider_status</option>
            <option value="oidc_discovery">oidc_discovery</option>
            <option value="oidc_jwks">oidc_jwks</option>
            <option value="contract">contract</option>
          </select>
        </div>
        <div>
          <label>Transport</label>
          <select id="transport">
            <option value="std">std</option>
            <option value="sse">sse</option>
          </select>
        </div>
      </div>
      <div style="margin-top:12px;">
        <label>POST Body (optional JSON)</label>
        <textarea id="payload">{}</textarea>
      </div>
      <div class="row">
        <button id="callSocket">Call /v1/socket</button>
        <button class="alt" id="providerStatus">GET /v1/auth/provider/status</button>
        <button class="alt" id="health">GET /health</button>
      </div>
    </div>
    <div class="card">
      <label>Output</label>
      <pre id="output">Ready.</pre>
    </div>
  </div>
  <script>
    const out = document.getElementById('output');
    const asJson = async (res) => {
      const text = await res.text();
      try { return JSON.stringify(JSON.parse(text), null, 2); } catch { return text; }
    };
    document.getElementById('health').onclick = async () => {
      const res = await fetch('/health');
      out.textContent = 'HTTP ' + res.status + '\\n' + await asJson(res);
    };
    document.getElementById('providerStatus').onclick = async () => {
      const res = await fetch('/v1/auth/provider/status');
      out.textContent = 'HTTP ' + res.status + '\\n' + await asJson(res);
    };
    document.getElementById('callSocket').onclick = async () => {
      const entry = document.getElementById('entry').value;
      const transport = document.getElementById('transport').value;
      let payload = {};
      try { payload = JSON.parse(document.getElementById('payload').value || '{}'); } catch { out.textContent = 'Invalid JSON in payload.'; return; }

      if (transport === 'sse') {
        const es = new EventSource('/v1/socket?entry=' + encodeURIComponent(entry) + '&transport=sse&watch=1');
        out.textContent = 'SSE stream opened...';
        es.onmessage = (evt) => { out.textContent += '\\n\\nmessage:\\n' + evt.data; };
        es.addEventListener('ready', (evt) => { out.textContent += '\\n\\nready:\\n' + evt.data; });
        es.addEventListener('error', (evt) => { out.textContent += '\\n\\nerror event'; console.error(evt); es.close(); });
        return;
      }

      const res = await fetch('/v1/socket?entry=' + encodeURIComponent(entry) + '&transport=std', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      out.textContent = 'HTTP ' + res.status + '\\n' + await asJson(res);
    };
  </script>
</body>
</html>`;
    return new Response(html, {
      status: 200,
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store',
        'Access-Control-Allow-Origin': '*'
      }
    });
  }

  /**
   * Handle registration (PUBLIC endpoint - no auth required)
   * Provisions both ChittyID and initial API token
   */
  async handleRegister(request) {
    try {
      const result = await this.registrationHandler.register(request);

      if (!result.success) {
        return this.jsonResponse(result, 400);
      }

      return this.jsonResponse(result, 201);

    } catch (error) {
      return this.jsonResponse({
        success: false,
        error: error.message
      }, 500);
    }
  }

  /**
   * Validate requested scopes against user permissions
   */
  async validateScopes(requestedScopes, permissions) {
    const authorizedScopes = [];

    for (const scope of requestedScopes) {
      // Admin scope requires admin permission
      if (scope === 'admin:*') {
        if (permissions.permissions.includes('admin')) {
          authorizedScopes.push(scope);
        }
        continue;
      }

      // Parse scope (e.g., "chittyid:generate")
      const [service, action] = scope.split(':');
      const permissionKey = `${service}.${action}`;

      // Check if user has this permission
      if (permissions.permissions.includes(permissionKey) ||
          permissions.permissions.includes(`${service}.*`)) {
        authorizedScopes.push(scope);
      }
    }

    return authorizedScopes;
  }

  /**
   * Generate temporary session token
   */
  async generateSessionToken(validation, targetService) {
    const sessionData = {
      serviceId: validation.service,
      targetService,
      permissions: validation.scope,
      expiresAt: Date.now() + 300000 // 5 minutes
    };

    const encoded = Buffer.from(JSON.stringify(sessionData)).toString('base64url');
    return `sess_temp_${encoded}`;
  }

  /**
   * JSON response helper
   */
  jsonResponse(data, status = 200) {
    return new Response(JSON.stringify(data), {
      status,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization'
      }
    });
  }

  /**
   * CORS preflight response
   */
  corsResponse() {
    return new Response(null, {
      status: 204,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Access-Control-Max-Age': '86400'
      }
    });
  }
}

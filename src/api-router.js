/**
 * ChittyAuth API Router
 * Routes all API requests to appropriate handlers
 */

import { TokenManager } from './token-manager.js';
import { ChittyConnectClient } from './chittyconnect-client.js';
import { RegistrationHandler } from './registration-handler.js';

export class ChittyAuthAPI {
  constructor(env) {
    this.env = env;
    this.tokenManager = new TokenManager(env);
    this.chittyConnect = new ChittyConnectClient(env);
    this.registrationHandler = new RegistrationHandler(env);
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
      // Health check
      if (path === '/health' && method === 'GET') {
        return await this.handleHealth();
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
   * Handle health check
   */
  async handleHealth() {
    const chittyConnectHealth = await this.chittyConnect.healthCheck();

    return this.jsonResponse({
      status: 'healthy',
      version: '1.0.0',
      timestamp: new Date().toISOString(),
      dependencies: {
        chittyConnect: chittyConnectHealth.healthy ? 'healthy' : 'unhealthy'
      }
    }, 200);
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

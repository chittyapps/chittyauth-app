/**
 * ChittyConnect Integration Client
 * Handles user identity validation via ChittyConnect service
 */

export class ChittyConnectClient {
  constructor(env) {
    this.env = env;
    this.baseUrl = env.CHITTYCONNECT_URL || 'https://connect.chitty.cc';
    this.apiKey = env.CHITTYCONNECT_API_KEY;
    this.timeout = 10000; // 10 seconds
  }

  /**
   * Verify a ChittyID with ChittyConnect
   * Ensures the ChittyID is valid and associated with a real user
   */
  async verifyChittyID(chittyId) {
    try {
      const response = await this.makeRequest('/v1/identity/verify', {
        method: 'POST',
        body: JSON.stringify({ chittyId })
      });

      if (!response.ok) {
        return {
          verified: false,
          error: `ChittyConnect verification failed: ${response.statusText}`
        };
      }

      const data = await response.json();

      return {
        verified: data.verified || false,
        chittyId: data.chittyId,
        userType: data.userType, // person, service, system
        trustLevel: data.trustLevel,
        metadata: data.metadata
      };
    } catch (error) {
      console.error('ChittyConnect verification error:', error);
      return {
        verified: false,
        error: error.message
      };
    }
  }

  /**
   * Get user permissions from ChittyConnect
   */
  async getUserPermissions(chittyId) {
    try {
      const response = await this.makeRequest('/v1/identity/permissions', {
        method: 'POST',
        body: JSON.stringify({ chittyId })
      });

      if (!response.ok) {
        return { permissions: [] };
      }

      const data = await response.json();
      return {
        permissions: data.permissions || [],
        roles: data.roles || [],
        organizations: data.organizations || []
      };
    } catch (error) {
      console.error('ChittyConnect permissions error:', error);
      return { permissions: [] };
    }
  }

  /**
   * Validate OAuth token with ChittyConnect
   */
  async validateOAuthToken(oauthToken) {
    try {
      const response = await this.makeRequest('/v1/oauth/validate', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${oauthToken}`
        }
      });

      if (!response.ok) {
        return { valid: false };
      }

      const data = await response.json();
      return {
        valid: true,
        chittyId: data.chittyId,
        expiresAt: data.expiresAt
      };
    } catch (error) {
      console.error('ChittyConnect OAuth validation error:', error);
      return { valid: false };
    }
  }

  /**
   * Get service credentials from ChittyConnect
   * Used for service-to-service authentication
   */
  async getServiceCredentials(serviceName) {
    try {
      const response = await this.makeRequest('/v1/services/credentials', {
        method: 'POST',
        body: JSON.stringify({ serviceName })
      });

      if (!response.ok) {
        return { authorized: false };
      }

      const data = await response.json();
      return {
        authorized: true,
        serviceId: data.serviceId,
        permissions: data.permissions,
        chittyId: data.chittyId
      };
    } catch (error) {
      console.error('ChittyConnect service credentials error:', error);
      return { authorized: false };
    }
  }

  /**
   * Check if a user has specific permissions
   */
  async checkPermission(chittyId, permission) {
    const userPermissions = await this.getUserPermissions(chittyId);
    return userPermissions.permissions.includes(permission);
  }

  /**
   * Get recommended scopes for a ChittyID based on their permissions
   */
  async getRecommendedScopes(chittyId, requestedService) {
    const permissions = await this.getUserPermissions(chittyId);
    const scopes = [];

    // Map ChittyConnect permissions to service scopes
    if (requestedService === 'chittyid') {
      if (permissions.permissions.includes('chittyid.read')) {
        scopes.push('chittyid:read');
      }
      if (permissions.permissions.includes('chittyid.generate')) {
        scopes.push('chittyid:generate');
      }
      if (permissions.permissions.includes('chittyid.validate')) {
        scopes.push('chittyid:validate');
      }
      if (permissions.permissions.includes('chittyid.admin')) {
        scopes.push('chittyid:audit', 'admin:*');
      }
    }

    // If no specific permissions, grant basic read access
    if (scopes.length === 0) {
      scopes.push(`${requestedService}:read`);
    }

    return scopes;
  }

  /**
   * Make HTTP request to ChittyConnect
   */
  async makeRequest(endpoint, options = {}) {
    const url = `${this.baseUrl}${endpoint}`;

    const headers = {
      'Content-Type': 'application/json',
      'User-Agent': 'ChittyAuth/1.0',
      ...(options.headers || {})
    };

    // Add service authentication if not using Bearer token
    if (this.apiKey && !headers['Authorization']) {
      headers['Authorization'] = `Bearer ${this.apiKey}`;
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(url, {
        ...options,
        headers,
        signal: controller.signal
      });

      clearTimeout(timeoutId);
      return response;
    } catch (error) {
      clearTimeout(timeoutId);
      throw error;
    }
  }

  /**
   * Health check for ChittyConnect
   */
  async healthCheck() {
    try {
      const response = await this.makeRequest('/health', {
        method: 'GET'
      });

      return {
        healthy: response.ok,
        status: response.status,
        statusText: response.statusText
      };
    } catch (error) {
      return {
        healthy: false,
        error: error.message
      };
    }
  }
}

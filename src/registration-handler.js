/**
 * ChittyAuth Registration Handler
 * Handles initial user registration and provisions ChittyID + API token together
 */

export class RegistrationHandler {
  constructor(env) {
    this.env = env;
    this.chittyIdService = env.CHITTYID_URL || 'https://id.chitty.cc';
  }

  /**
   * Register a new user - provisions ChittyID + API token in one flow
   * This is the ONLY public endpoint that doesn't require authentication
   */
  async register(request) {
    try {
      const body = await request.json();
      const {
        entityType = 'P',  // Person by default
        name,
        email,
        region = '1',      // North America default
        jurisdiction = 'USA',
        metadata = {}
      } = body;

      // Validate required fields
      if (!name || !email) {
        return {
          success: false,
          error: 'Name and email are required for registration',
          required: ['name', 'email']
        };
      }

      // Check if email already registered
      const existing = await this.checkExistingRegistration(email);
      if (existing) {
        return {
          success: false,
          error: 'Email already registered',
          message: 'This email is already associated with a ChittyID. Use token refresh instead.'
        };
      }

      // Step 1: Generate ChittyID via internal service call
      const chittyId = await this.generateChittyID({
        entityType,
        region,
        jurisdiction,
        trustLevel: '0', // Unverified for self-registration
        metadata: { name, email, ...metadata }
      });

      if (!chittyId.success) {
        return {
          success: false,
          error: 'ChittyID generation failed',
          details: chittyId.error
        };
      }

      // Step 2: Provision initial API token
      const { TokenManager } = await import('./token-manager.js');
      const tokenManager = new TokenManager(this.env);

      const token = await tokenManager.provision({
        chittyId: chittyId.id,
        scope: ['chittyid:read', 'chittyid:generate'], // Basic scopes
        service: 'chittyid',
        expiresIn: 2592000 // 30 days
      });

      // Step 3: Store registration record
      await this.storeRegistration({
        chittyId: chittyId.id,
        email,
        name,
        tokenId: token.tokenId,
        registeredAt: Date.now()
      });

      // Return both ChittyID and token
      return {
        success: true,
        registration: {
          chittyId: chittyId.id,
          name,
          email,
          entityType,
          trustLevel: '0',
          registeredAt: new Date().toISOString()
        },
        token: {
          accessToken: token.token,
          tokenId: token.tokenId,
          expiresAt: token.expiresAt,
          scope: token.scope
        },
        nextSteps: {
          message: 'Registration successful! Your ChittyID and API token are ready.',
          upgradeVerification: 'To increase trust level, verify your identity at https://connect.chitty.cc',
          documentation: 'https://docs.chitty.cc/getting-started',
          apiUsage: `Use your token in API requests: Authorization: Bearer ${token.token}`
        }
      };

    } catch (error) {
      console.error('Registration error:', error);
      return {
        success: false,
        error: 'Registration failed',
        message: error.message
      };
    }
  }

  /**
   * Generate ChittyID by calling ChittyID service directly (internal call)
   */
  async generateChittyID({ entityType, region, jurisdiction, trustLevel, metadata }) {
    try {
      // For internal service calls, we bypass auth and call generation directly
      // This is a special privilege only available to ChittyAuth service

      // Import ChittyID generation logic directly (service-to-service)
      // In production, this would use a service token or internal API

      const response = await fetch(`${this.chittyIdService}/internal/generate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Service-Token': this.env.CHITTYAUTH_SERVICE_TOKEN // Internal service token
        },
        body: JSON.stringify({
          entityType,
          region,
          jurisdiction,
          trustLevel,
          metadata
        })
      });

      if (!response.ok) {
        throw new Error('Failed to generate ChittyID');
      }

      const data = await response.json();

      return {
        success: true,
        id: data.chittyId
      };

    } catch (error) {
      console.error('ChittyID generation error:', error);

      // Fallback: Generate locally (temporary solution)
      // In production, this should always use the ChittyID service
      return this.generateLocalChittyID({ entityType, region, jurisdiction, trustLevel });
    }
  }

  /**
   * Fallback: Generate ChittyID locally (temporary)
   * This is a simplified version - production should use ChittyID service
   */
  generateLocalChittyID({ entityType, region, jurisdiction, trustLevel }) {
    const version = '03';
    const sequential = Math.floor(1000 + Math.random() * 9000).toString(); // Temporary random
    const yearMonth = new Date().toISOString().slice(2, 7).replace('-', '').slice(0, 3);

    const baseId = `${version}${region}${jurisdiction}${sequential}${entityType}${yearMonth}${trustLevel}`;
    const checksum = this.mod97Checksum(baseId).toString().padStart(2, '0');

    const chittyId = `${version}-${region}-${jurisdiction}-${sequential}-${entityType}-${yearMonth}-${trustLevel}-${checksum}`;

    return {
      success: true,
      id: chittyId
    };
  }

  /**
   * Check if email is already registered
   */
  async checkExistingRegistration(email) {
    if (!this.env.AUTH_DB) {
      return false;
    }

    const result = await this.env.AUTH_DB.prepare(
      `SELECT chitty_id FROM registrations WHERE email = ?`
    ).bind(email.toLowerCase()).first();

    return result !== null;
  }

  /**
   * Store registration record
   */
  async storeRegistration(registration) {
    // Store in D1 database
    if (this.env.AUTH_DB) {
      await this.env.AUTH_DB.prepare(
        `INSERT INTO registrations (chitty_id, email, name, token_id, registered_at)
         VALUES (?, ?, ?, ?, ?)`
      ).bind(
        registration.chittyId,
        registration.email.toLowerCase(),
        registration.name,
        registration.tokenId,
        registration.registeredAt
      ).run();
    }

    // Also store in KV for fast lookup
    if (this.env.AUTH_TOKENS) {
      await this.env.AUTH_TOKENS.put(
        `registration:${registration.email.toLowerCase()}`,
        JSON.stringify(registration),
        { expirationTtl: 86400 * 365 } // 1 year
      );
    }
  }

  /**
   * Mod-97 checksum calculation
   */
  mod97Checksum(str) {
    let checksum = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str[i];
      if (char >= '0' && char <= '9') {
        checksum = (checksum * 10 + parseInt(char)) % 97;
      } else if (char >= 'A' && char <= 'Z') {
        const value = char.charCodeAt(0) - 55;
        checksum = (checksum * 100 + value) % 97;
      }
    }
    return (98 - checksum) % 97;
  }
}

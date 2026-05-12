/**
 * Auth provider facade for ChittyAuth.
 * Keeps ChittyAuth provider-agnostic while enabling Neon-backed auth.
 */
export class AuthProviderFacade {
  constructor(env) {
    this.env = env;
    this.provider = env.AUTH_PROVIDER || env.CHITTYAUTH_PROVIDER || null;
    this.neonOAuthHost = env.NEON_OAUTH_HOST || 'https://oauth2.neon.tech';
    this.allowedProviders = new Set(['neon', 'neon-oauth', 'clerk', 'cf-access', 'local']);
    this.neonScopeAllowlist = new Set([
      'urn:neoncloud:projects:create',
      'urn:neoncloud:projects:read',
      'urn:neoncloud:projects:update',
      'urn:neoncloud:projects:delete',
      'urn:neoncloud:projects:permission',
      'urn:neoncloud:orgs:create',
      'urn:neoncloud:orgs:read',
      'urn:neoncloud:orgs:update',
      'urn:neoncloud:orgs:delete',
      'urn:neoncloud:orgs:permission',
      'offline',
      'offline_access',
      'openid'
    ]);
  }

  getStatus() {
    const gate = this.checkProviderConfig();
    return {
      provider: this.provider,
      neonEnabled: this.provider === 'neon' || this.provider === 'neon-oauth',
      oauthHost: this.neonOAuthHost,
      providerGate: gate,
      hasClientId: Boolean(this.env.NEON_OAUTH_CLIENT_ID),
      hasClientSecret: Boolean(this.env.NEON_OAUTH_CLIENT_SECRET),
      hasConnectKey: Boolean(this.env.CHITTYAUTH_ISSUED_CONNECT_API_KEY || this.env.CHITTYCONNECT_API_KEY),
      secretAliases: {
        signingKeyCanonical: Boolean(this.env.CHITTYAUTH_ISSUED_MINT_API_KEY),
        signingKeyLegacy: Boolean(this.env.TOKEN_SIGNING_KEY),
        connectKeyCanonical: Boolean(this.env.CHITTYAUTH_ISSUED_CONNECT_API_KEY),
        connectKeyLegacy: Boolean(this.env.CHITTYCONNECT_API_KEY)
      }
    };
  }

  checkProviderConfig() {
    if (!this.provider) {
      return {
        ok: false,
        error: 'Missing AUTH_PROVIDER (or legacy CHITTYAUTH_PROVIDER)',
        provider: null
      };
    }

    if (!this.allowedProviders.has(this.provider)) {
      return {
        ok: false,
        error: `Unsupported AUTH_PROVIDER: ${this.provider}`,
        provider: this.provider
      };
    }

    if (this.provider === 'neon' || this.provider === 'neon-oauth') {
      const missing = [];
      if (!this.env.NEON_OAUTH_CLIENT_ID) missing.push('NEON_OAUTH_CLIENT_ID');
      if (!this.env.NEON_OAUTH_CLIENT_SECRET) missing.push('NEON_OAUTH_CLIENT_SECRET');
      if (missing.length > 0) {
        return {
          ok: false,
          error: `Missing Neon OAuth env: ${missing.join(', ')}`,
          provider: this.provider
        };
      }
    }

    return { ok: true, provider: this.provider };
  }

  assertProviderReady() {
    const gate = this.checkProviderConfig();
    if (!gate.ok) {
      throw new Error(gate.error);
    }
  }

  enforceNeonScopes(scopeValue) {
    if (this.provider !== 'neon' && this.provider !== 'neon-oauth') {
      return;
    }
    if (!scopeValue) return;
    const parsed = Array.isArray(scopeValue) ? scopeValue : String(scopeValue).split(/\s+/);
    for (const scope of parsed.filter(Boolean)) {
      if (!this.neonScopeAllowlist.has(scope)) {
        throw new Error(`Unsupported Neon scope: ${scope}`);
      }
    }
  }

  buildNeonAuthorizeUrl({ redirectUri, state, codeChallenge, scope }) {
    this.assertProviderReady();
    if (this.provider !== 'neon' && this.provider !== 'neon-oauth') {
      throw new Error('Neon OAuth is disabled. Set AUTH_PROVIDER=neon-oauth.');
    }
    if (!redirectUri || !state || !codeChallenge) {
      throw new Error('redirectUri, state, and codeChallenge are required (PKCE/state enforced).');
    }

    const scopes = scope || [
      'openid',
      'offline',
      'offline_access',
      'urn:neoncloud:projects:read'
    ].join(' ');
    this.enforceNeonScopes(scopes);

    const url = new URL('/oauth2/auth', this.neonOAuthHost);
    url.searchParams.set('client_id', this.env.NEON_OAUTH_CLIENT_ID);
    url.searchParams.set('redirect_uri', redirectUri);
    url.searchParams.set('scope', scopes);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('grant_type', 'authorization_code');
    url.searchParams.set('state', state);
    url.searchParams.set('code_challenge', codeChallenge);
    url.searchParams.set('code_challenge_method', 'S256');
    return url.toString();
  }

  async exchangeNeonCode({ code, redirectUri, codeVerifier }) {
    this.assertProviderReady();
    if (this.provider !== 'neon' && this.provider !== 'neon-oauth') {
      throw new Error('Neon OAuth is disabled. Set AUTH_PROVIDER=neon-oauth.');
    }
    if (!code || !redirectUri) {
      throw new Error('code and redirectUri are required.');
    }

    const tokenUrl = new URL('/oauth2/token', this.neonOAuthHost).toString();
    const body = new URLSearchParams({
      client_id: this.env.NEON_OAUTH_CLIENT_ID,
      client_secret: this.env.NEON_OAUTH_CLIENT_SECRET,
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri
    });

    if (codeVerifier) {
      body.set('code_verifier', codeVerifier);
    }

    const response = await fetch(tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString()
    });

    const data = await response.json();
    if (!response.ok) {
      return {
        success: false,
        error: data?.error_description || data?.error || 'Neon token exchange failed'
      };
    }

    return {
      success: true,
      tokenType: data.token_type,
      expiresIn: data.expires_in,
      scope: data.scope,
      accessToken: data.access_token,
      refreshToken: data.refresh_token,
      idToken: data.id_token
    };
  }

  async getOidcDiscovery() {
    this.assertProviderReady();
    if (this.provider !== 'neon' && this.provider !== 'neon-oauth') {
      throw new Error(`OIDC discovery pass-through unavailable for provider: ${this.provider}`);
    }
    const response = await fetch(`${this.neonOAuthHost}/.well-known/openid-configuration`);
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data?.error_description || data?.error || 'OIDC discovery request failed');
    }
    return data;
  }

  async getJwks() {
    this.assertProviderReady();
    if (this.provider !== 'neon' && this.provider !== 'neon-oauth') {
      throw new Error(`JWKS pass-through unavailable for provider: ${this.provider}`);
    }
    const response = await fetch(`${this.neonOAuthHost}/.well-known/jwks.json`);
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data?.error_description || data?.error || 'JWKS request failed');
    }
    return data;
  }
}

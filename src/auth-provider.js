/**
 * Auth provider facade for ChittyAuth.
 * Keeps ChittyAuth provider-agnostic while enabling Neon-backed auth.
 */
export class AuthProviderFacade {
  constructor(env) {
    this.env = env;
    this.provider = env.CHITTYAUTH_PROVIDER || 'local';
    this.neonOAuthHost = env.NEON_OAUTH_HOST || 'https://oauth2.neon.tech';
  }

  getStatus() {
    return {
      provider: this.provider,
      neonEnabled: this.provider === 'neon',
      oauthHost: this.neonOAuthHost,
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

  buildNeonAuthorizeUrl({ redirectUri, state, codeChallenge, scope }) {
    if (this.provider !== 'neon') {
      throw new Error('Neon OAuth is disabled. Set CHITTYAUTH_PROVIDER=neon.');
    }
    if (!this.env.NEON_OAUTH_CLIENT_ID) {
      throw new Error('Missing NEON_OAUTH_CLIENT_ID.');
    }
    if (!redirectUri || !state || !codeChallenge) {
      throw new Error('redirectUri, state, and codeChallenge are required.');
    }

    const scopes = scope || [
      'openid',
      'offline',
      'offline_access',
      'urn:neoncloud:projects:read'
    ].join(' ');

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
    if (this.provider !== 'neon') {
      throw new Error('Neon OAuth is disabled. Set CHITTYAUTH_PROVIDER=neon.');
    }
    if (!this.env.NEON_OAUTH_CLIENT_ID || !this.env.NEON_OAUTH_CLIENT_SECRET) {
      throw new Error('Missing NEON_OAUTH_CLIENT_ID or NEON_OAUTH_CLIENT_SECRET.');
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
}

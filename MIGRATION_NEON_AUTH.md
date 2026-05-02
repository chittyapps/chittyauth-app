# ChittyAuth Neon Migration

This repo now supports a provider facade:
- `CHITTYAUTH_PROVIDER=local` (default)
- `CHITTYAUTH_PROVIDER=neon` (Neon OAuth-backed mode)

## Canonical secrets

Use these names for all new deployments:
- `CHITTYAUTH_ISSUED_MINT_API_KEY`
- `CHITTYAUTH_ISSUED_CONNECT_API_KEY`
- `NEON_OAUTH_CLIENT_ID` (Neon mode)
- `NEON_OAUTH_CLIENT_SECRET` (Neon mode)

Legacy aliases still resolve during migration:
- `TOKEN_SIGNING_KEY` -> `CHITTYAUTH_ISSUED_MINT_API_KEY`
- `CHITTYCONNECT_API_KEY` -> `CHITTYAUTH_ISSUED_CONNECT_API_KEY`

## New facade endpoints

- `GET /v1/auth/provider/status`
- `POST /v1/auth/neon/oauth/authorize-url`
- `POST /v1/auth/neon/oauth/token-exchange`

## Cutover sequence

1. Create canonical secrets first (chicken/egg bootstrap).
2. Keep legacy secrets for one deploy window.
3. Deploy with `CHITTYAUTH_PROVIDER=local` and verify token lifecycle still passes.
4. Set `CHITTYAUTH_PROVIDER=neon` and Neon OAuth secrets.
5. Validate Neon OAuth authorize URL and code exchange endpoints.
6. Remove legacy aliases from runtime once all services have migrated.

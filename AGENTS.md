# Repository Guidelines

## Project Structure & Module Organization

- ESM JavaScript Cloudflare Worker. No TypeScript build step.
- Entry point: `worker.js` (fetch handler).
- Source under `src/`:
  - `api-router.js` — request routing and endpoint dispatch
  - `token-manager.js` — token generation, hashing, validation, lifecycle
  - `registration-handler.js` — public `/v1/register` flow
  - `auth-provider.js` — provider facade selecting `local` (D1+KV) or `neon` (Neon OAuth) per `CHITTYAUTH_PROVIDER`
  - `chittyconnect-client.js` — optional ChittyConnect integration
- Schema: `schema.sql` (initial; defines `tokens`, `service_credentials`, `auth_events`, `token_stats`, `service_health`), `schema-update.sql` (adds `registrations` etc.).
- Tests: `tests/*.test.js` (Jest, currently flat — only `tests/token-manager.test.js`).
- Setup helpers: `scripts/` (currently `onboard.sh`).
- Config: `wrangler.toml`, `package.json`.

## Build, Test, and Development Commands

- `npm install` — install dev dependencies.
- `npm run dev` — local Worker via `wrangler dev` (defaults to `http://localhost:8787`).
- `npm test` — run Jest suite (`node --experimental-vm-modules`).
- `npm run test:unit` / `npm run test:integration` — **aspirational**: scripts exist but `tests/unit/` and `tests/integration/` directories do not yet. Until the suite is split, these run zero tests; use `npm test`.
- `npm run setup:db` — apply `schema.sql` to the production D1 database.
- `npm run setup:kv` — **broken**: invokes `scripts/setup-kv.js` which does not exist (only `scripts/onboard.sh` ships today). Provision KV manually via `wrangler kv:namespace create` until the script lands.
- `npm run setup` — runs the above two; will fail at `setup:kv` until the script is added.
- `npm run deploy` — deploy production environment.
- `npm run deploy:dev` — deploy development environment.

There is no `lint`, `typecheck`, `format`, or `build` script today. Do not invent them; either add them as a separate, scoped change or skip.

## Coding Style & Naming Conventions

- ESM (`"type": "module"`). 2-space indent, single quotes, semicolons.
- Files: lower-kebab (`api-router.js`, `token-manager.js`).
- Functions: `camelCase`. Classes: `PascalCase`. Constants: `UPPER_SNAKE_CASE`.
- Async-first; prefer `await` over `.then()` chains.
- No external runtime dependencies (`dependencies: {}` is intentional). Use Web Crypto, `fetch`, and Workers bindings only.

## Testing Guidelines

- Jest with `--experimental-vm-modules` (ESM). File pattern: `tests/**/*.test.js`.
- Tests must exercise real behavior. Per repo policy, do not introduce new `jest.mock()` on D1, KV, or service modules — use `wrangler dev --local` for storage-backed tests, or hit a disposable D1 branch.
- Token-related tests must cover: signature verification, hash determinism, revocation precedence, expiration boundary, KV cache hit/miss.

## Commit & Pull Request Guidelines

- Conventional Commits (`feat:`, `fix:`, `chore:`, `docs:`, `refactor:`, `test:`).
- Before pushing: `npm test` must pass; smoke-test `/health` and `/v1/register` against `wrangler dev --local`.
- PR body must include: scope of change, test evidence, any `wrangler.toml` binding deltas, and confirmation that no plaintext tokens or signing keys appear in diffs/logs.

## Security & Configuration Tips

- **Never commit any secret.** Canonical names: `CHITTYAUTH_ISSUED_MINT_API_KEY` (signing key) and `CHITTYAUTH_ISSUED_CONNECT_API_KEY` (when ChittyConnect is wired). Set via `wrangler secret put <NAME> --env <env>`. Legacy aliases `TOKEN_SIGNING_KEY` and `CHITTYCONNECT_API_KEY` remain accepted only for migration and must be retired post-cutover.
- The committed `wrangler.toml` still contains `CREATE_NEW_*` / `CREATE_DEV_*` placeholders for D1 and KV IDs. Do not deploy until those are replaced with real binding IDs.
- Tokens are returned to callers exactly once at issuance; storage is SHA-256 hash of the token only. Do not add code paths that log, return, or persist plaintext tokens.
- Rate limiting and revocation are correctness features, not best-effort: validate that new endpoints honor `AUTH_RATE_LIMITS` and check `AUTH_REVOCATIONS` before trusting a token.
- Optional ChittyConnect integration is gated on the connect secret; code paths should fall closed (deny) when the integration is configured but unreachable, and fall open only when integration is unconfigured by design. Verify behavior in `src/chittyconnect-client.js` before relying on this contract.

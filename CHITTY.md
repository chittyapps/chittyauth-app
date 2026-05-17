# ChittyAuth App

> `chittycanon://core/services/chittyauth-app` | Tier 1 (Core Identity) | operator-chosen domain

## What It Does

Standalone authentication and API token provisioning. Issues, validates, refreshes, and revokes end-user Bearer tokens with HMAC-SHA256 signatures and SHA-256 hashed-at-rest storage. No ChittyOS shared-database dependency.

## How It Works

Cloudflare Worker with two provider modes selected by `CHITTYAUTH_PROVIDER`:
- `local` (default) — D1 (`AUTH_DB`) + four KV namespaces (`AUTH_TOKENS`, `AUTH_REVOCATIONS`, `AUTH_RATE_LIMITS`, `AUTH_AUDIT`); validation hits KV first (30s cache), falls through to D1 on miss.
- `neon` — Neon OAuth facade; the worker fronts authorize/exchange endpoints and delegates issuance to Neon.

ChittyConnect integration is optional in either mode.

## Distinguished From `chittyauth`

Same tier, same function, different deployment: `chittyauth` (CHITTYFOUNDATION) shares identity data over Neon/`chittyos-core` for ecosystem services; `chittyauth-app` (CHITTYAPPS) is isolated D1+KV for third-party and custom deployments.

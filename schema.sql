-- ChittyAuth Database Schema
-- D1 Database for token persistence and audit logging

-- Tokens table
CREATE TABLE IF NOT EXISTS tokens (
  id TEXT PRIMARY KEY,
  token_hash TEXT UNIQUE NOT NULL,
  chitty_id TEXT NOT NULL,
  scope TEXT NOT NULL,
  service_name TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  last_used_at INTEGER,
  request_count INTEGER DEFAULT 0,
  revoked_at INTEGER,
  revocation_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_tokens_chitty_id ON tokens(chitty_id);
CREATE INDEX IF NOT EXISTS idx_tokens_token_hash ON tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_tokens_expires_at ON tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_tokens_revoked_at ON tokens(revoked_at);

-- Service credentials table
CREATE TABLE IF NOT EXISTS service_credentials (
  service_name TEXT PRIMARY KEY,
  service_token_hash TEXT NOT NULL,
  chitty_id TEXT NOT NULL,
  permissions TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_rotated_at INTEGER,
  rotation_interval INTEGER DEFAULT 2592000
);

CREATE INDEX IF NOT EXISTS idx_service_credentials_token ON service_credentials(service_token_hash);

-- Audit events table
CREATE TABLE IF NOT EXISTS auth_events (
  id TEXT PRIMARY KEY,
  event_type TEXT NOT NULL,
  token_id TEXT,
  chitty_id TEXT,
  service_name TEXT,
  success INTEGER NOT NULL,
  error_message TEXT,
  ip_address TEXT,
  user_agent TEXT,
  metadata TEXT,
  timestamp INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_auth_events_timestamp ON auth_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_auth_events_token_id ON auth_events(token_id);
CREATE INDEX IF NOT EXISTS idx_auth_events_chitty_id ON auth_events(chitty_id);
CREATE INDEX IF NOT EXISTS idx_auth_events_event_type ON auth_events(event_type);

-- Token usage statistics table
CREATE TABLE IF NOT EXISTS token_stats (
  date TEXT PRIMARY KEY,
  total_provisions INTEGER DEFAULT 0,
  total_validations INTEGER DEFAULT 0,
  failed_validations INTEGER DEFAULT 0,
  total_revocations INTEGER DEFAULT 0,
  rate_limit_hits INTEGER DEFAULT 0,
  unique_users INTEGER DEFAULT 0,
  updated_at INTEGER NOT NULL
);

-- Service health check table
CREATE TABLE IF NOT EXISTS service_health (
  service_name TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  last_check INTEGER NOT NULL,
  last_success INTEGER,
  last_failure INTEGER,
  failure_count INTEGER DEFAULT 0,
  metadata TEXT
);

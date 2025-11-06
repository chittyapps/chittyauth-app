-- ChittyAuth Schema Updates for chittyos-core database
-- Add these tables to the EXISTING chittyos-core database

-- Registrations table (links ChittyIDs to initial registration)
CREATE TABLE IF NOT EXISTS registrations (
  chitty_id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  token_id TEXT,
  registered_at INTEGER NOT NULL,
  verified_at INTEGER,
  verification_method TEXT
);

CREATE INDEX IF NOT EXISTS idx_registrations_email ON registrations(email);
CREATE INDEX IF NOT EXISTS idx_registrations_registered_at ON registrations(registered_at);

-- Note: tokens, service_credentials, auth_events tables can also go in chittyos-core
-- Or keep them separate if you prefer separation of concerns

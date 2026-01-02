-- Service account management for bots and applications
-- Enables API access without user login

CREATE TABLE IF NOT EXISTS service_accounts (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  owner_id TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  token_hash TEXT NOT NULL UNIQUE,
  scopes TEXT DEFAULT '[]', -- JSON array of permission scopes
  rate_limit INTEGER DEFAULT 100, -- requests per minute
  active INTEGER DEFAULT 1,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  last_used_at DATETIME,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE(owner_id, name)
);

-- Index for token lookup during verification
CREATE INDEX idx_service_accounts_token_hash ON service_accounts(token_hash) WHERE active = 1;

-- Index for user's service accounts
CREATE INDEX idx_service_accounts_owner_id ON service_accounts(owner_id, created_at DESC);

-- Index for rate limiting lookups
CREATE INDEX idx_service_accounts_owner_active ON service_accounts(owner_id, active);

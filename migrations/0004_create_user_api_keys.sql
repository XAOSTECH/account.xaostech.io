-- User API Keys for CLI and programmatic access
-- Allows authenticated users to generate API keys for non-browser access
-- Keys inherit user permissions but can have restricted scopes

CREATE TABLE IF NOT EXISTS user_api_keys (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id TEXT NOT NULL,
  name TEXT NOT NULL,                    -- User-friendly name (e.g., "CLI key", "CI/CD")
  key_prefix TEXT NOT NULL,              -- First 8 chars for identification (e.g., "xk_a1b2...")
  key_hash TEXT NOT NULL UNIQUE,         -- SHA-256 hash of the full key
  scopes TEXT DEFAULT '["read"]',        -- JSON array: ["read", "write", "admin", "lingua", "blog", etc.]
  rate_limit INTEGER DEFAULT 60,         -- Requests per minute (default: 60/min)
  allowed_ips TEXT DEFAULT NULL,         -- JSON array of allowed IPs/CIDRs (null = any)
  active INTEGER DEFAULT 1,
  expires_at DATETIME DEFAULT NULL,      -- Optional expiration (null = no expiry)
  last_used_at DATETIME DEFAULT NULL,
  last_used_ip TEXT DEFAULT NULL,
  use_count INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE(user_id, name)
);

-- Fast lookup by key hash during verification
CREATE INDEX idx_user_api_keys_hash ON user_api_keys(key_hash) WHERE active = 1;

-- List user's API keys
CREATE INDEX idx_user_api_keys_user ON user_api_keys(user_id, created_at DESC);

-- Prefix lookup for key identification
CREATE INDEX idx_user_api_keys_prefix ON user_api_keys(key_prefix);

-- Cleanup expired keys (can run periodically)
CREATE INDEX idx_user_api_keys_expires ON user_api_keys(expires_at) WHERE expires_at IS NOT NULL;

-- Account management tables for password reset, 2FA, GDPR

CREATE TABLE IF NOT EXISTS audit_logs (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id TEXT NOT NULL,
  action TEXT NOT NULL,
  ip TEXT,
  details TEXT,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS gdpr_exports (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  token TEXT UNIQUE NOT NULL,
  status TEXT DEFAULT 'pending', -- pending, ready, downloaded, expired
  requested_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  ready_at DATETIME,
  expires_at DATETIME DEFAULT (datetime('now', '+7 days')),
  FOREIGN KEY(user_id) REFERENCES users(id),
  UNIQUE(user_id, requested_at)
);

CREATE TABLE IF NOT EXISTS gdpr_deletions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  status TEXT DEFAULT 'requested', -- requested, confirmed, executed, cancelled
  requested_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  delete_at DATETIME NOT NULL,
  executed_at DATETIME,
  cancelled_at DATETIME,
  reason TEXT,
  FOREIGN KEY(user_id) REFERENCES users(id),
  UNIQUE(user_id, status) -- Only one active deletion per user
);

-- Indexes for performance
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id, timestamp DESC);
CREATE INDEX idx_audit_logs_action ON audit_logs(action, timestamp DESC);
CREATE INDEX idx_gdpr_exports_user_id ON gdpr_exports(user_id, requested_at DESC);
CREATE INDEX idx_gdpr_exports_token ON gdpr_exports(token);
CREATE INDEX idx_gdpr_deletions_user_id ON gdpr_deletions(user_id);
CREATE INDEX idx_gdpr_deletions_delete_at ON gdpr_deletions(delete_at) WHERE status = 'confirmed';

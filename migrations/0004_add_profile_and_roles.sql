-- Add profile management columns and role system

-- Add role column (owner > admin > user)
ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user';

-- Add GitHub profile tracking for "undo" functionality
ALTER TABLE users ADD COLUMN github_id TEXT;
ALTER TABLE users ADD COLUMN github_username TEXT;
ALTER TABLE users ADD COLUMN github_avatar_url TEXT;

-- Add 2FA columns
ALTER TABLE users ADD COLUMN two_fa_enabled INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN two_fa_secret TEXT;

-- Add is_admin for backwards compatibility
ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0;

-- Index for role-based queries
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_github_id ON users(github_id);

-- Update owner role for first user or known owner
-- You can run this manually for your account:
-- UPDATE users SET role = 'owner' WHERE email = 'your@email.com';

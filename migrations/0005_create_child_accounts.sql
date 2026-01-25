-- Child accounts system for parental controls
-- Enables parents to create and manage accounts for their children

-- Child account relationships
CREATE TABLE IF NOT EXISTS child_accounts (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  parent_id TEXT NOT NULL,
  child_id TEXT NOT NULL UNIQUE, -- Each child can only have one parent
  child_name TEXT NOT NULL, -- Display name set by parent
  birth_year INTEGER, -- For age-appropriate content filtering
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(parent_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(child_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Parental controls settings per child
CREATE TABLE IF NOT EXISTS parental_controls (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  child_id TEXT NOT NULL UNIQUE,
  
  -- Content filtering
  content_filter_level TEXT DEFAULT 'strict', -- strict, moderate, minimal
  blocked_topics TEXT DEFAULT '[]', -- JSON array of blocked content categories
  allowed_domains TEXT DEFAULT '["*.xaostech.io"]', -- JSON array of allowed domains
  
  -- Time limits (minutes per day, null = unlimited)
  daily_time_limit INTEGER DEFAULT 60,
  weekly_time_limit INTEGER DEFAULT 420, -- 7 hours/week
  
  -- Schedule restrictions (JSON: {day: {start: "HH:MM", end: "HH:MM"}})
  allowed_hours TEXT DEFAULT '{"weekday": {"start": "08:00", "end": "20:00"}, "weekend": {"start": "09:00", "end": "21:00"}}',
  
  -- Feature restrictions
  can_post_content INTEGER DEFAULT 0, -- Can create posts/comments
  can_message INTEGER DEFAULT 0, -- Can send messages
  can_join_groups INTEGER DEFAULT 0, -- Can join study groups
  require_approval INTEGER DEFAULT 1, -- Parent must approve actions
  
  -- Notifications
  notify_parent_on_login INTEGER DEFAULT 1,
  notify_parent_on_content INTEGER DEFAULT 1,
  weekly_activity_report INTEGER DEFAULT 1,
  
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(child_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Activity tracking for children
CREATE TABLE IF NOT EXISTS child_activity (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  child_id TEXT NOT NULL,
  activity_type TEXT NOT NULL, -- login, page_view, content_view, content_create, time_limit_reached
  activity_data TEXT, -- JSON with details
  duration_seconds INTEGER, -- For session tracking
  flagged INTEGER DEFAULT 0, -- Flagged for parent review
  reviewed_at DATETIME,
  reviewed_by TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(child_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(reviewed_by) REFERENCES users(id) ON DELETE SET NULL
);

-- Parent approval queue
CREATE TABLE IF NOT EXISTS parent_approvals (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  parent_id TEXT NOT NULL,
  child_id TEXT NOT NULL,
  approval_type TEXT NOT NULL, -- content_post, message_send, group_join, feature_request
  request_data TEXT NOT NULL, -- JSON with the content/action details
  status TEXT DEFAULT 'pending', -- pending, approved, denied
  parent_note TEXT, -- Note from parent to child
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  resolved_at DATETIME,
  FOREIGN KEY(parent_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(child_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Time tracking for daily/weekly limits
CREATE TABLE IF NOT EXISTS child_time_tracking (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  child_id TEXT NOT NULL,
  date TEXT NOT NULL, -- YYYY-MM-DD
  minutes_used INTEGER DEFAULT 0,
  sessions_count INTEGER DEFAULT 0,
  last_session_start DATETIME,
  last_session_end DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(child_id) REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE(child_id, date)
);

-- Indexes for performance
CREATE INDEX idx_child_accounts_parent_id ON child_accounts(parent_id);
CREATE INDEX idx_child_accounts_child_id ON child_accounts(child_id);
CREATE INDEX idx_parental_controls_child_id ON parental_controls(child_id);
CREATE INDEX idx_child_activity_child_id ON child_activity(child_id, created_at DESC);
CREATE INDEX idx_child_activity_flagged ON child_activity(child_id, flagged) WHERE flagged = 1;
CREATE INDEX idx_parent_approvals_parent_id ON parent_approvals(parent_id, status, created_at DESC);
CREATE INDEX idx_parent_approvals_child_id ON parent_approvals(child_id, created_at DESC);
CREATE INDEX idx_child_time_tracking_child_date ON child_time_tracking(child_id, date DESC);

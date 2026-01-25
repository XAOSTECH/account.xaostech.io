-- Parent notification system for child activity alerts
-- Stores notification preferences and queues outgoing notifications

-- Parent notification queue
CREATE TABLE IF NOT EXISTS parent_notifications (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  parent_id TEXT NOT NULL,
  child_id TEXT NOT NULL,
  
  -- Notification details
  notification_type TEXT NOT NULL, -- login, time_limit, content_flag, approval_request, daily_summary, weekly_summary
  title TEXT NOT NULL,
  message TEXT NOT NULL,
  data TEXT, -- JSON with additional context
  
  -- Delivery status
  status TEXT DEFAULT 'pending', -- pending, queued, sent, failed
  delivery_method TEXT DEFAULT 'email', -- email, push, in_app
  
  -- Timestamps
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  queued_at DATETIME,
  sent_at DATETIME,
  read_at DATETIME,
  
  FOREIGN KEY(parent_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(child_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Notification preferences (extends parental_controls)
CREATE TABLE IF NOT EXISTS notification_preferences (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id TEXT NOT NULL UNIQUE,
  
  -- Delivery preferences
  email_notifications INTEGER DEFAULT 1,
  push_notifications INTEGER DEFAULT 0,
  in_app_notifications INTEGER DEFAULT 1,
  
  -- Frequency settings
  instant_alerts INTEGER DEFAULT 1, -- Time limit, content flags
  batch_login_alerts INTEGER DEFAULT 1, -- Batch login notifications (rather than instant)
  daily_summary_time TEXT DEFAULT '20:00', -- When to send daily summary
  weekly_summary_day TEXT DEFAULT 'sunday', -- Which day for weekly summary
  
  -- Alert thresholds
  alert_on_time_limit INTEGER DEFAULT 1,
  alert_on_content_flag INTEGER DEFAULT 1,
  alert_on_approval_request INTEGER DEFAULT 1,
  alert_on_unusual_activity INTEGER DEFAULT 1, -- e.g., login from new location
  
  -- Quiet hours (don't send notifications during these times)
  quiet_hours_enabled INTEGER DEFAULT 0,
  quiet_hours_start TEXT DEFAULT '22:00',
  quiet_hours_end TEXT DEFAULT '07:00',
  
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Notification batching for login alerts
CREATE TABLE IF NOT EXISTS notification_batch (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  parent_id TEXT NOT NULL,
  batch_type TEXT NOT NULL, -- login_alerts, daily_summary
  notifications TEXT NOT NULL, -- JSON array of notification IDs
  scheduled_for DATETIME NOT NULL,
  status TEXT DEFAULT 'pending', -- pending, processing, sent
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  processed_at DATETIME,
  
  FOREIGN KEY(parent_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Indexes for efficient queries
CREATE INDEX idx_parent_notifications_parent ON parent_notifications(parent_id, status);
CREATE INDEX idx_parent_notifications_status ON parent_notifications(status, created_at);
CREATE INDEX idx_parent_notifications_child ON parent_notifications(child_id, created_at DESC);
CREATE INDEX idx_notification_batch_scheduled ON notification_batch(scheduled_for, status);
CREATE INDEX idx_notification_preferences_user ON notification_preferences(user_id);

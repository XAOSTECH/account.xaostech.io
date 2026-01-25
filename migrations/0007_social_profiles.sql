-- Social profiles system: About, Photos, Wall, Friends
-- With granular privacy controls per section

-- Extended user profiles
CREATE TABLE IF NOT EXISTS user_profiles (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id TEXT NOT NULL UNIQUE,
  
  -- About section
  display_name TEXT,
  bio TEXT,
  location TEXT,
  website TEXT,
  occupation TEXT,
  company TEXT,
  birthday TEXT, -- YYYY-MM-DD
  
  -- Display preferences
  theme TEXT DEFAULT 'default',
  cover_image_url TEXT,
  profile_music_url TEXT, -- Optional background music
  
  -- Stats
  profile_views INTEGER DEFAULT 0,
  last_active_at DATETIME,
  
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Profile photos/gallery
CREATE TABLE IF NOT EXISTS profile_photos (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id TEXT NOT NULL,
  photo_url TEXT NOT NULL,
  thumbnail_url TEXT,
  caption TEXT,
  album TEXT DEFAULT 'default', -- Album grouping
  sort_order INTEGER DEFAULT 0,
  is_profile_photo INTEGER DEFAULT 0, -- Current profile picture
  is_cover_photo INTEGER DEFAULT 0, -- Current cover image
  
  -- Metadata
  width INTEGER,
  height INTEGER,
  file_size INTEGER,
  
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Wall posts (like a mini blog/feed)
CREATE TABLE IF NOT EXISTS wall_posts (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id TEXT NOT NULL, -- Profile owner
  author_id TEXT NOT NULL, -- Who wrote the post (can be owner or visitor)
  
  content TEXT NOT NULL,
  content_type TEXT DEFAULT 'text', -- text, photo, video, link
  media_url TEXT,
  link_preview TEXT, -- JSON with title, description, image for links
  
  -- Engagement
  likes_count INTEGER DEFAULT 0,
  comments_count INTEGER DEFAULT 0,
  
  -- Cross-posting
  cross_post_to_blog INTEGER DEFAULT 0,
  blog_post_id TEXT, -- If cross-posted to blog.xaostech.io
  
  -- Moderation
  is_hidden INTEGER DEFAULT 0,
  is_pinned INTEGER DEFAULT 0,
  
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(author_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Wall post comments
CREATE TABLE IF NOT EXISTS wall_comments (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  post_id TEXT NOT NULL,
  author_id TEXT NOT NULL,
  parent_comment_id TEXT, -- For threaded replies
  
  content TEXT NOT NULL,
  
  likes_count INTEGER DEFAULT 0,
  is_hidden INTEGER DEFAULT 0,
  
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  
  FOREIGN KEY(post_id) REFERENCES wall_posts(id) ON DELETE CASCADE,
  FOREIGN KEY(author_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(parent_comment_id) REFERENCES wall_comments(id) ON DELETE CASCADE
);

-- Likes for posts and comments
CREATE TABLE IF NOT EXISTS social_likes (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id TEXT NOT NULL,
  target_type TEXT NOT NULL, -- 'post' or 'comment'
  target_id TEXT NOT NULL,
  
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE(user_id, target_type, target_id)
);

-- Friends/connections system
CREATE TABLE IF NOT EXISTS friendships (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  requester_id TEXT NOT NULL,
  addressee_id TEXT NOT NULL,
  
  status TEXT DEFAULT 'pending', -- pending, accepted, blocked
  
  -- Who initiated the block (if blocked)
  blocked_by TEXT,
  
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  
  FOREIGN KEY(requester_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(addressee_id) REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE(requester_id, addressee_id)
);

-- Friend groups (for organizing friends and setting group permissions)
CREATE TABLE IF NOT EXISTS friend_groups (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id TEXT NOT NULL,
  name TEXT NOT NULL,
  color TEXT, -- For UI display
  
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Friends in groups
CREATE TABLE IF NOT EXISTS friend_group_members (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  group_id TEXT NOT NULL,
  friend_user_id TEXT NOT NULL,
  
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  
  FOREIGN KEY(group_id) REFERENCES friend_groups(id) ON DELETE CASCADE,
  FOREIGN KEY(friend_user_id) REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE(group_id, friend_user_id)
);

-- Privacy settings (granular per-section)
CREATE TABLE IF NOT EXISTS profile_privacy (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id TEXT NOT NULL UNIQUE,
  
  -- Global default
  default_visibility TEXT DEFAULT 'friends', -- public, friends, friends-of-friends, private
  
  -- Per-section visibility
  -- Options: public, friends, friends-of-friends, custom, private
  about_visibility TEXT DEFAULT 'friends',
  photos_visibility TEXT DEFAULT 'friends',
  wall_visibility TEXT DEFAULT 'friends',
  friends_list_visibility TEXT DEFAULT 'friends',
  birthday_visibility TEXT DEFAULT 'friends',
  email_visibility TEXT DEFAULT 'private',
  location_visibility TEXT DEFAULT 'friends',
  
  -- Wall permissions
  who_can_post_on_wall TEXT DEFAULT 'friends', -- public, friends, nobody
  who_can_comment TEXT DEFAULT 'friends', -- public, friends, nobody
  
  -- Custom visibility groups (JSON arrays of group_ids or user_ids)
  -- Used when visibility is set to 'custom'
  about_allowed_groups TEXT DEFAULT '[]',
  about_allowed_users TEXT DEFAULT '[]',
  about_blocked_users TEXT DEFAULT '[]',
  
  photos_allowed_groups TEXT DEFAULT '[]',
  photos_allowed_users TEXT DEFAULT '[]',
  photos_blocked_users TEXT DEFAULT '[]',
  
  wall_allowed_groups TEXT DEFAULT '[]',
  wall_allowed_users TEXT DEFAULT '[]',
  wall_blocked_users TEXT DEFAULT '[]',
  
  -- Search & discoverability
  searchable INTEGER DEFAULT 1, -- Can be found in search
  show_online_status INTEGER DEFAULT 1,
  allow_friend_requests INTEGER DEFAULT 1,
  
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Profile visitors (who viewed the profile)
CREATE TABLE IF NOT EXISTS profile_visitors (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  profile_user_id TEXT NOT NULL,
  visitor_user_id TEXT NOT NULL,
  visit_count INTEGER DEFAULT 1,
  
  first_visit_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  last_visit_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  
  FOREIGN KEY(profile_user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(visitor_user_id) REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE(profile_user_id, visitor_user_id)
);

-- Indexes for efficient queries
CREATE INDEX idx_user_profiles_user ON user_profiles(user_id);
CREATE INDEX idx_profile_photos_user ON profile_photos(user_id, sort_order);
CREATE INDEX idx_profile_photos_album ON profile_photos(user_id, album);
CREATE INDEX idx_wall_posts_user ON wall_posts(user_id, created_at DESC);
CREATE INDEX idx_wall_posts_author ON wall_posts(author_id);
CREATE INDEX idx_wall_comments_post ON wall_comments(post_id, created_at);
CREATE INDEX idx_social_likes_target ON social_likes(target_type, target_id);
CREATE INDEX idx_friendships_requester ON friendships(requester_id, status);
CREATE INDEX idx_friendships_addressee ON friendships(addressee_id, status);
CREATE INDEX idx_friend_group_members_group ON friend_group_members(group_id);
CREATE INDEX idx_profile_visitors_profile ON profile_visitors(profile_user_id, last_visit_at DESC);

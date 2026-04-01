-- Views to expose wall_posts and wall_comments under the names
-- the source code queries (posts, comments). No data migration required —
-- the underlying tables already exist from 0007_social_profiles.sql.
--
-- wall_posts has both user_id (profile owner) and author_id (writer).
-- Source queries: SELECT * FROM posts WHERE author_id = ?
CREATE VIEW IF NOT EXISTS posts AS
  SELECT * FROM wall_posts;

-- wall_comments has author_id; source queries: SELECT * FROM comments WHERE user_id = ?
-- Alias author_id as user_id so the WHERE clause resolves.
CREATE VIEW IF NOT EXISTS comments AS
  SELECT
    id,
    post_id,
    author_id,
    author_id AS user_id,
    parent_comment_id,
    content,
    likes_count,
    is_hidden,
    created_at,
    updated_at
  FROM wall_comments;

-- Storage quota per user (used by GDPR data export handler).
CREATE TABLE IF NOT EXISTS user_quota (
  user_id   TEXT PRIMARY KEY,
  used_gb   REAL    NOT NULL DEFAULT 0,
  limit_gb  REAL    NOT NULL DEFAULT 10,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

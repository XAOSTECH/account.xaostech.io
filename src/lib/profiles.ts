/**
 * Social Profile Service for account.xaostech.io
 * Handles profile data, privacy, friends, and wall posts
 */

// Cloudflare Workers types
interface D1Database {
  prepare(query: string): D1PreparedStatement;
}

interface D1PreparedStatement {
  bind(...values: unknown[]): D1PreparedStatement;
  first<T = Record<string, unknown>>(colName?: string): Promise<T | null>;
  run(): Promise<D1Result>;
  all<T = Record<string, unknown>>(): Promise<D1Results<T>>;
}

interface D1Result {
  meta: { changes: number };
}

interface D1Results<T> {
  results?: T[];
}

// Types
export type Visibility = 'public' | 'friends' | 'friends-of-friends' | 'custom' | 'private';

export interface UserProfile {
  id: string;
  user_id: string;
  display_name: string | null;
  bio: string | null;
  location: string | null;
  website: string | null;
  occupation: string | null;
  company: string | null;
  birthday: string | null;
  theme: string;
  cover_image_url: string | null;
  profile_views: number;
  last_active_at: string | null;
}

export interface PrivacySettings {
  default_visibility: Visibility;
  about_visibility: Visibility;
  photos_visibility: Visibility;
  wall_visibility: Visibility;
  friends_list_visibility: Visibility;
  who_can_post_on_wall: 'public' | 'friends' | 'nobody';
  who_can_comment: 'public' | 'friends' | 'nobody';
  searchable: boolean;
  show_online_status: boolean;
  allow_friend_requests: boolean;
}

export interface FriendshipStatus {
  isFriend: boolean;
  isPending: boolean;
  isBlocked: boolean;
  requestDirection?: 'sent' | 'received';
}

/**
 * Get or create user profile
 */
export async function getProfile(db: D1Database, userId: string): Promise<UserProfile | null> {
  const profile = await db.prepare(`
    SELECT * FROM user_profiles WHERE user_id = ?
  `).bind(userId).first<UserProfile>();

  if (!profile) {
    // Create default profile
    try {
      await db.prepare(`
        INSERT INTO user_profiles (user_id, created_at, updated_at)
        VALUES (?, datetime('now'), datetime('now'))
      `).bind(userId).run();

      return await db.prepare(`
        SELECT * FROM user_profiles WHERE user_id = ?
      `).bind(userId).first<UserProfile>();
    } catch {
      return null;
    }
  }

  return profile;
}

/**
 * Update user profile
 */
export async function updateProfile(
  db: D1Database,
  userId: string,
  updates: Partial<UserProfile>
): Promise<boolean> {
  const allowedFields = [
    'display_name', 'bio', 'location', 'website',
    'occupation', 'company', 'birthday', 'theme', 'cover_image_url'
  ];

  const setters: string[] = [];
  const values: unknown[] = [];

  for (const field of allowedFields) {
    if (field in updates) {
      setters.push(`${field} = ?`);
      values.push((updates as Record<string, unknown>)[field]);
    }
  }

  if (setters.length === 0) return false;

  setters.push('updated_at = datetime(\'now\')');
  values.push(userId);

  try {
    await db.prepare(`
      UPDATE user_profiles SET ${setters.join(', ')} WHERE user_id = ?
    `).bind(...values).run();
    return true;
  } catch {
    return false;
  }
}

/**
 * Get privacy settings for a user
 */
export async function getPrivacySettings(db: D1Database, userId: string): Promise<PrivacySettings> {
  const privacy = await db.prepare(`
    SELECT * FROM profile_privacy WHERE user_id = ?
  `).bind(userId).first();

  if (!privacy) {
    // Create default privacy settings
    await db.prepare(`
      INSERT INTO profile_privacy (user_id, created_at, updated_at)
      VALUES (?, datetime('now'), datetime('now'))
    `).bind(userId).run();

    return {
      default_visibility: 'friends',
      about_visibility: 'friends',
      photos_visibility: 'friends',
      wall_visibility: 'friends',
      friends_list_visibility: 'friends',
      who_can_post_on_wall: 'friends',
      who_can_comment: 'friends',
      searchable: true,
      show_online_status: true,
      allow_friend_requests: true,
    };
  }

  return {
    default_visibility: (privacy.default_visibility as Visibility) || 'friends',
    about_visibility: (privacy.about_visibility as Visibility) || 'friends',
    photos_visibility: (privacy.photos_visibility as Visibility) || 'friends',
    wall_visibility: (privacy.wall_visibility as Visibility) || 'friends',
    friends_list_visibility: (privacy.friends_list_visibility as Visibility) || 'friends',
    who_can_post_on_wall: (privacy.who_can_post_on_wall as 'public' | 'friends' | 'nobody') || 'friends',
    who_can_comment: (privacy.who_can_comment as 'public' | 'friends' | 'nobody') || 'friends',
    searchable: !!privacy.searchable,
    show_online_status: !!privacy.show_online_status,
    allow_friend_requests: !!privacy.allow_friend_requests,
  };
}

/**
 * Update privacy settings
 */
export async function updatePrivacySettings(
  db: D1Database,
  userId: string,
  updates: Partial<PrivacySettings>
): Promise<boolean> {
  const allowedFields = [
    'default_visibility', 'about_visibility', 'photos_visibility',
    'wall_visibility', 'friends_list_visibility', 'who_can_post_on_wall',
    'who_can_comment', 'searchable', 'show_online_status', 'allow_friend_requests'
  ];

  const setters: string[] = [];
  const values: unknown[] = [];

  for (const field of allowedFields) {
    if (field in updates) {
      setters.push(`${field} = ?`);
      const value = (updates as Record<string, unknown>)[field];
      // Convert booleans to integers for SQLite
      values.push(typeof value === 'boolean' ? (value ? 1 : 0) : value);
    }
  }

  if (setters.length === 0) return false;

  setters.push('updated_at = datetime(\'now\')');
  values.push(userId);

  try {
    await db.prepare(`
      UPDATE profile_privacy SET ${setters.join(', ')} WHERE user_id = ?
    `).bind(...values).run();
    return true;
  } catch {
    return false;
  }
}

/**
 * Check if viewer can access a section of the profile
 */
export async function canViewSection(
  db: D1Database,
  profileUserId: string,
  viewerUserId: string | null,
  section: 'about' | 'photos' | 'wall' | 'friends'
): Promise<boolean> {
  // Owner can always view their own profile
  if (profileUserId === viewerUserId) return true;

  const privacy = await getPrivacySettings(db, profileUserId);
  const visibilityKey = `${section}_visibility` as keyof PrivacySettings;
  const visibility = privacy[visibilityKey] as Visibility;

  switch (visibility) {
    case 'public':
      return true;

    case 'private':
      return false;

    case 'friends':
      if (!viewerUserId) return false;
      return await areFriends(db, profileUserId, viewerUserId);

    case 'friends-of-friends':
      if (!viewerUserId) return false;
      return await areFriendsOfFriends(db, profileUserId, viewerUserId);

    case 'custom':
      // TODO: Check custom allowed/blocked lists
      if (!viewerUserId) return false;
      return await areFriends(db, profileUserId, viewerUserId);

    default:
      return false;
  }
}

/**
 * Check if two users are friends
 */
export async function areFriends(
  db: D1Database,
  userId1: string,
  userId2: string
): Promise<boolean> {
  const friendship = await db.prepare(`
    SELECT status FROM friendships
    WHERE ((requester_id = ? AND addressee_id = ?) OR (requester_id = ? AND addressee_id = ?))
    AND status = 'accepted'
  `).bind(userId1, userId2, userId2, userId1).first();

  return !!friendship;
}

/**
 * Check if two users are friends of friends
 */
export async function areFriendsOfFriends(
  db: D1Database,
  userId1: string,
  userId2: string
): Promise<boolean> {
  // First check if they're direct friends
  if (await areFriends(db, userId1, userId2)) return true;

  // Check for mutual friends
  const mutual = await db.prepare(`
    SELECT COUNT(*) as count FROM (
      SELECT addressee_id as friend_id FROM friendships 
      WHERE requester_id = ? AND status = 'accepted'
      UNION
      SELECT requester_id as friend_id FROM friendships 
      WHERE addressee_id = ? AND status = 'accepted'
    ) AS user1_friends
    INNER JOIN (
      SELECT addressee_id as friend_id FROM friendships 
      WHERE requester_id = ? AND status = 'accepted'
      UNION
      SELECT requester_id as friend_id FROM friendships 
      WHERE addressee_id = ? AND status = 'accepted'
    ) AS user2_friends
    ON user1_friends.friend_id = user2_friends.friend_id
    LIMIT 1
  `).bind(userId1, userId1, userId2, userId2).first();

  return (mutual?.count as number) > 0;
}

/**
 * Get friendship status between two users
 */
export async function getFriendshipStatus(
  db: D1Database,
  userId: string,
  otherUserId: string
): Promise<FriendshipStatus> {
  const friendship = await db.prepare(`
    SELECT * FROM friendships
    WHERE (requester_id = ? AND addressee_id = ?) OR (requester_id = ? AND addressee_id = ?)
  `).bind(userId, otherUserId, otherUserId, userId).first();

  if (!friendship) {
    return { isFriend: false, isPending: false, isBlocked: false };
  }

  const status = friendship.status as string;
  const requesterId = friendship.requester_id as string;

  return {
    isFriend: status === 'accepted',
    isPending: status === 'pending',
    isBlocked: status === 'blocked',
    requestDirection: requesterId === userId ? 'sent' : 'received',
  };
}

/**
 * Send friend request
 */
export async function sendFriendRequest(
  db: D1Database,
  requesterId: string,
  addresseeId: string
): Promise<{ success: boolean; message: string }> {
  // Check if blocked
  const existing = await db.prepare(`
    SELECT * FROM friendships
    WHERE (requester_id = ? AND addressee_id = ?) OR (requester_id = ? AND addressee_id = ?)
  `).bind(requesterId, addresseeId, addresseeId, requesterId).first();

  if (existing) {
    const status = existing.status as string;
    if (status === 'blocked') {
      return { success: false, message: 'Unable to send request' };
    }
    if (status === 'accepted') {
      return { success: false, message: 'Already friends' };
    }
    if (status === 'pending') {
      // If they sent us a request, accept it
      if (existing.requester_id !== requesterId) {
        await db.prepare(`
          UPDATE friendships SET status = 'accepted', updated_at = datetime('now')
          WHERE id = ?
        `).bind(existing.id).run();
        return { success: true, message: 'Friend request accepted' };
      }
      return { success: false, message: 'Request already pending' };
    }
  }

  // Check if addressee allows friend requests
  const privacy = await getPrivacySettings(db, addresseeId);
  if (!privacy.allow_friend_requests) {
    return { success: false, message: 'User is not accepting friend requests' };
  }

  // Create request
  try {
    await db.prepare(`
      INSERT INTO friendships (requester_id, addressee_id, status, created_at, updated_at)
      VALUES (?, ?, 'pending', datetime('now'), datetime('now'))
    `).bind(requesterId, addresseeId).run();
    return { success: true, message: 'Friend request sent' };
  } catch {
    return { success: false, message: 'Failed to send request' };
  }
}

/**
 * Accept or reject friend request
 */
export async function respondToFriendRequest(
  db: D1Database,
  addresseeId: string,
  requesterId: string,
  accept: boolean
): Promise<boolean> {
  if (accept) {
    const result = await db.prepare(`
      UPDATE friendships SET status = 'accepted', updated_at = datetime('now')
      WHERE requester_id = ? AND addressee_id = ? AND status = 'pending'
    `).bind(requesterId, addresseeId).run();
    return result.meta.changes > 0;
  } else {
    const result = await db.prepare(`
      DELETE FROM friendships
      WHERE requester_id = ? AND addressee_id = ? AND status = 'pending'
    `).bind(requesterId, addresseeId).run();
    return result.meta.changes > 0;
  }
}

/**
 * Remove friend or block user
 */
export async function unfriendOrBlock(
  db: D1Database,
  userId: string,
  otherUserId: string,
  block: boolean
): Promise<boolean> {
  if (block) {
    // Update or insert block
    await db.prepare(`
      INSERT INTO friendships (requester_id, addressee_id, status, blocked_by, created_at, updated_at)
      VALUES (?, ?, 'blocked', ?, datetime('now'), datetime('now'))
      ON CONFLICT(requester_id, addressee_id) DO UPDATE SET
        status = 'blocked', blocked_by = ?, updated_at = datetime('now')
    `).bind(userId, otherUserId, userId, userId).run();
    return true;
  } else {
    // Just remove friendship
    await db.prepare(`
      DELETE FROM friendships
      WHERE (requester_id = ? AND addressee_id = ?) OR (requester_id = ? AND addressee_id = ?)
    `).bind(userId, otherUserId, otherUserId, userId).run();
    return true;
  }
}

/**
 * Get friends list
 */
export async function getFriends(
  db: D1Database,
  userId: string,
  limit: number = 50,
  offset: number = 0
): Promise<{ id: string; username: string; email: string; avatar_url: string | null }[]> {
  const result = await db.prepare(`
    SELECT u.id, u.username, u.email, u.avatar_url
    FROM users u
    INNER JOIN friendships f ON (
      (f.requester_id = ? AND f.addressee_id = u.id) OR
      (f.addressee_id = ? AND f.requester_id = u.id)
    )
    WHERE f.status = 'accepted'
    ORDER BY u.username
    LIMIT ? OFFSET ?
  `).bind(userId, userId, limit, offset).all();

  return (result.results || []) as { id: string; username: string; email: string; avatar_url: string | null }[];
}

/**
 * Get pending friend requests
 */
export async function getPendingRequests(
  db: D1Database,
  userId: string
): Promise<{ id: string; username: string; email: string; created_at: string }[]> {
  const result = await db.prepare(`
    SELECT u.id, u.username, u.email, f.created_at
    FROM users u
    INNER JOIN friendships f ON f.requester_id = u.id
    WHERE f.addressee_id = ? AND f.status = 'pending'
    ORDER BY f.created_at DESC
  `).bind(userId).all();

  return (result.results || []) as { id: string; username: string; email: string; created_at: string }[];
}

/**
 * Create a wall post
 */
export async function createWallPost(
  db: D1Database,
  profileUserId: string,
  authorId: string,
  content: string,
  options: { contentType?: string; mediaUrl?: string; crossPostToBlog?: boolean } = {}
): Promise<string | null> {
  try {
    const result = await db.prepare(`
      INSERT INTO wall_posts (
        user_id, author_id, content, content_type, media_url, 
        cross_post_to_blog, created_at, updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
      RETURNING id
    `).bind(
      profileUserId,
      authorId,
      content,
      options.contentType || 'text',
      options.mediaUrl || null,
      options.crossPostToBlog ? 1 : 0
    ).first();

    return result?.id as string || null;
  } catch {
    return null;
  }
}

/**
 * Get wall posts for a profile
 */
export async function getWallPosts(
  db: D1Database,
  profileUserId: string,
  limit: number = 20,
  offset: number = 0
): Promise<any[]> {
  const result = await db.prepare(`
    SELECT wp.*, u.username as author_username, u.avatar_url as author_avatar
    FROM wall_posts wp
    JOIN users u ON wp.author_id = u.id
    WHERE wp.user_id = ? AND wp.is_hidden = 0
    ORDER BY wp.is_pinned DESC, wp.created_at DESC
    LIMIT ? OFFSET ?
  `).bind(profileUserId, limit, offset).all();

  return result.results || [];
}

/**
 * Record profile visit
 */
export async function recordProfileVisit(
  db: D1Database,
  profileUserId: string,
  visitorUserId: string
): Promise<void> {
  if (profileUserId === visitorUserId) return; // Don't record self-visits

  try {
    await db.prepare(`
      INSERT INTO profile_visitors (profile_user_id, visitor_user_id, visit_count, first_visit_at, last_visit_at)
      VALUES (?, ?, 1, datetime('now'), datetime('now'))
      ON CONFLICT(profile_user_id, visitor_user_id) DO UPDATE SET
        visit_count = visit_count + 1,
        last_visit_at = datetime('now')
    `).bind(profileUserId, visitorUserId).run();

    // Update profile view count
    await db.prepare(`
      UPDATE user_profiles SET profile_views = profile_views + 1 WHERE user_id = ?
    `).bind(profileUserId).run();
  } catch {
    // Silently fail visitor tracking
  }
}

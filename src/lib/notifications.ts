/**
 * Parent Notification Service for account.xaostech.io
 * Handles sending notifications to parents about child activity
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

interface Queue {
    send(message: unknown): Promise<void>;
}

interface Env {
    DB: D1Database;
    EMAIL_QUEUE?: Queue;
}

export type NotificationType =
    | 'login'
    | 'time_limit'
    | 'content_flag'
    | 'approval_request'
    | 'daily_summary'
    | 'weekly_summary';

export type DeliveryMethod = 'email' | 'push' | 'in_app';
export type NotificationStatus = 'pending' | 'queued' | 'sent' | 'failed';

interface NotificationData {
    childName?: string;
    childId?: string;
    activityType?: string;
    contentTitle?: string;
    flaggedReason?: string;
    minutesUsed?: number;
    timeLimit?: number;
    approvalType?: string;
    requestDetails?: string;
    activities?: Array<{
        type: string;
        count: number;
        details?: string;
    }>;
    [key: string]: unknown;
}

interface CreateNotificationParams {
    parentId: string;
    childId: string;
    type: NotificationType;
    title: string;
    message: string;
    data?: NotificationData;
    deliveryMethod?: DeliveryMethod;
}

interface NotificationPreferences {
    email_notifications: boolean;
    push_notifications: boolean;
    in_app_notifications: boolean;
    instant_alerts: boolean;
    batch_login_alerts: boolean;
    daily_summary_time: string;
    weekly_summary_day: string;
    alert_on_time_limit: boolean;
    alert_on_content_flag: boolean;
    alert_on_approval_request: boolean;
    alert_on_unusual_activity: boolean;
    quiet_hours_enabled: boolean;
    quiet_hours_start: string;
    quiet_hours_end: string;
}

const DEFAULT_PREFERENCES: NotificationPreferences = {
    email_notifications: true,
    push_notifications: false,
    in_app_notifications: true,
    instant_alerts: true,
    batch_login_alerts: true,
    daily_summary_time: '20:00',
    weekly_summary_day: 'sunday',
    alert_on_time_limit: true,
    alert_on_content_flag: true,
    alert_on_approval_request: true,
    alert_on_unusual_activity: true,
    quiet_hours_enabled: false,
    quiet_hours_start: '22:00',
    quiet_hours_end: '07:00',
};

/**
 * Get notification preferences for a user
 */
export async function getNotificationPreferences(
    db: D1Database,
    userId: string
): Promise<NotificationPreferences> {
    try {
        const prefs = await db.prepare(`
      SELECT * FROM notification_preferences WHERE user_id = ?
    `).bind(userId).first();

        if (!prefs) return DEFAULT_PREFERENCES;

        return {
            email_notifications: !!prefs.email_notifications,
            push_notifications: !!prefs.push_notifications,
            in_app_notifications: !!prefs.in_app_notifications,
            instant_alerts: !!prefs.instant_alerts,
            batch_login_alerts: !!prefs.batch_login_alerts,
            daily_summary_time: (prefs.daily_summary_time as string) || '20:00',
            weekly_summary_day: (prefs.weekly_summary_day as string) || 'sunday',
            alert_on_time_limit: !!prefs.alert_on_time_limit,
            alert_on_content_flag: !!prefs.alert_on_content_flag,
            alert_on_approval_request: !!prefs.alert_on_approval_request,
            alert_on_unusual_activity: !!prefs.alert_on_unusual_activity,
            quiet_hours_enabled: !!prefs.quiet_hours_enabled,
            quiet_hours_start: (prefs.quiet_hours_start as string) || '22:00',
            quiet_hours_end: (prefs.quiet_hours_end as string) || '07:00',
        };
    } catch {
        return DEFAULT_PREFERENCES;
    }
}

/**
 * Check if we're in quiet hours
 */
function isInQuietHours(prefs: NotificationPreferences): boolean {
    if (!prefs.quiet_hours_enabled) return false;

    const now = new Date();
    const currentTime = now.toTimeString().slice(0, 5); // HH:MM

    // Handle overnight quiet hours (e.g., 22:00 to 07:00)
    if (prefs.quiet_hours_start > prefs.quiet_hours_end) {
        return currentTime >= prefs.quiet_hours_start || currentTime <= prefs.quiet_hours_end;
    }

    return currentTime >= prefs.quiet_hours_start && currentTime <= prefs.quiet_hours_end;
}

/**
 * Should this notification type be sent instantly?
 */
function shouldSendInstantly(type: NotificationType, prefs: NotificationPreferences): boolean {
    if (!prefs.instant_alerts) return false;

    switch (type) {
        case 'time_limit':
            return prefs.alert_on_time_limit;
        case 'content_flag':
            return prefs.alert_on_content_flag;
        case 'approval_request':
            return prefs.alert_on_approval_request;
        case 'login':
            return !prefs.batch_login_alerts; // Batch if batching is enabled
        default:
            return false;
    }
}

/**
 * Create a notification in the database
 */
export async function createNotification(
    db: D1Database,
    params: CreateNotificationParams
): Promise<string | null> {
    try {
        const result = await db.prepare(`
      INSERT INTO parent_notifications (
        parent_id, child_id, notification_type, title, message, data, 
        status, delivery_method, created_at
      )
      VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, datetime('now'))
      RETURNING id
    `).bind(
            params.parentId,
            params.childId,
            params.type,
            params.title,
            params.message,
            params.data ? JSON.stringify(params.data) : null,
            params.deliveryMethod || 'email'
        ).first();

        return result?.id as string || null;
    } catch {
        return null;
    }
}

/**
 * Queue notification for email delivery
 */
async function queueEmailNotification(
    env: Env,
    notificationId: string,
    parentEmail: string,
    title: string,
    message: string
): Promise<boolean> {
    if (!env.EMAIL_QUEUE) {
        // Mark as failed if no queue available
        await env.DB.prepare(`
      UPDATE parent_notifications SET status = 'failed' WHERE id = ?
    `).bind(notificationId).run();
        return false;
    }

    try {
        await env.EMAIL_QUEUE.send({
            type: 'parent_notification',
            notificationId,
            to: parentEmail,
            subject: `[XAOSTECH Family] ${title}`,
            body: message,
            timestamp: Date.now(),
        });

        await env.DB.prepare(`
      UPDATE parent_notifications SET status = 'queued', queued_at = datetime('now') WHERE id = ?
    `).bind(notificationId).run();

        return true;
    } catch {
        await env.DB.prepare(`
      UPDATE parent_notifications SET status = 'failed' WHERE id = ?
    `).bind(notificationId).run();
        return false;
    }
}

/**
 * Get parent email for notifications
 */
async function getParentEmail(db: D1Database, parentId: string): Promise<string | null> {
    try {
        const user = await db.prepare(`
      SELECT email FROM users WHERE id = ?
    `).bind(parentId).first();
        return user?.email as string || null;
    } catch {
        return null;
    }
}

/**
 * Get child name for notification messages
 */
async function getChildName(db: D1Database, childId: string, parentId: string): Promise<string> {
    try {
        const child = await db.prepare(`
      SELECT child_name FROM child_accounts WHERE child_id = ? AND parent_id = ?
    `).bind(childId, parentId).first();
        return (child?.child_name as string) || 'Your child';
    } catch {
        return 'Your child';
    }
}

// ============ PUBLIC NOTIFICATION FUNCTIONS ============

/**
 * Notify parent when child logs in
 */
export async function notifyParentOfLogin(
    env: Env,
    parentId: string,
    childId: string,
    location?: string
): Promise<void> {
    const prefs = await getNotificationPreferences(env.DB, parentId);

    // Check if login notifications are enabled
    const controls = await env.DB.prepare(`
    SELECT notify_parent_on_login FROM parental_controls WHERE child_id = ?
  `).bind(childId).first();

    if (!controls?.notify_parent_on_login) return;
    if (isInQuietHours(prefs)) return;

    const childName = await getChildName(env.DB, childId, parentId);

    if (prefs.batch_login_alerts) {
        // Add to batch for later delivery
        const notificationId = await createNotification(env.DB, {
            parentId,
            childId,
            type: 'login',
            title: `${childName} logged in`,
            message: `${childName} logged in to XAOSTECH${location ? ` from ${location}` : ''}.`,
            data: { childName, childId, location },
        });

        if (notificationId) {
            // Add to daily batch
            await addToBatch(env.DB, parentId, 'login_alerts', notificationId);
        }
    } else if (prefs.email_notifications) {
        // Send immediately
        const notificationId = await createNotification(env.DB, {
            parentId,
            childId,
            type: 'login',
            title: `${childName} logged in`,
            message: `${childName} logged in to XAOSTECH${location ? ` from ${location}` : ''}.`,
            data: { childName, childId, location },
        });

        if (notificationId) {
            const parentEmail = await getParentEmail(env.DB, parentId);
            if (parentEmail) {
                await queueEmailNotification(
                    env,
                    notificationId,
                    parentEmail,
                    `${childName} logged in`,
                    formatEmailBody('login', childName, { location })
                );
            }
        }
    }
}

/**
 * Notify parent when child reaches time limit
 */
export async function notifyParentOfTimeLimit(
    env: Env,
    parentId: string,
    childId: string,
    minutesUsed: number,
    timeLimit: number
): Promise<void> {
    const prefs = await getNotificationPreferences(env.DB, parentId);

    if (!prefs.alert_on_time_limit) return;
    if (!prefs.email_notifications && !prefs.in_app_notifications) return;

    const childName = await getChildName(env.DB, childId, parentId);

    const notificationId = await createNotification(env.DB, {
        parentId,
        childId,
        type: 'time_limit',
        title: `${childName} reached daily time limit`,
        message: `${childName} has used all ${timeLimit} minutes of their daily learning time. Great job today!`,
        data: { childName, childId, minutesUsed, timeLimit },
    });

    // Time limit alerts are always instant (if not in quiet hours)
    if (notificationId && prefs.email_notifications && !isInQuietHours(prefs)) {
        const parentEmail = await getParentEmail(env.DB, parentId);
        if (parentEmail) {
            await queueEmailNotification(
                env,
                notificationId,
                parentEmail,
                `${childName} reached daily time limit`,
                formatEmailBody('time_limit', childName, { minutesUsed, timeLimit })
            );
        }
    }
}

/**
 * Notify parent when content is flagged
 */
export async function notifyParentOfContentFlag(
    env: Env,
    parentId: string,
    childId: string,
    contentTitle: string,
    flaggedReason: string
): Promise<void> {
    const prefs = await getNotificationPreferences(env.DB, parentId);

    // Check if content notifications are enabled
    const controls = await env.DB.prepare(`
    SELECT notify_parent_on_content FROM parental_controls WHERE child_id = ?
  `).bind(childId).first();

    if (!controls?.notify_parent_on_content) return;
    if (!prefs.alert_on_content_flag) return;

    const childName = await getChildName(env.DB, childId, parentId);

    const notificationId = await createNotification(env.DB, {
        parentId,
        childId,
        type: 'content_flag',
        title: `Content flagged for review`,
        message: `${childName} attempted to access content that was flagged: ${contentTitle}. Reason: ${flaggedReason}`,
        data: { childName, childId, contentTitle, flaggedReason },
    });

    // Content flags are always instant (if not in quiet hours)
    if (notificationId && prefs.email_notifications && !isInQuietHours(prefs)) {
        const parentEmail = await getParentEmail(env.DB, parentId);
        if (parentEmail) {
            await queueEmailNotification(
                env,
                notificationId,
                parentEmail,
                'Content flagged for review',
                formatEmailBody('content_flag', childName, { contentTitle, flaggedReason })
            );
        }
    }
}

/**
 * Notify parent of approval request
 */
export async function notifyParentOfApprovalRequest(
    env: Env,
    parentId: string,
    childId: string,
    approvalType: string,
    requestDetails: string
): Promise<void> {
    const prefs = await getNotificationPreferences(env.DB, parentId);

    if (!prefs.alert_on_approval_request) return;

    const childName = await getChildName(env.DB, childId, parentId);

    const notificationId = await createNotification(env.DB, {
        parentId,
        childId,
        type: 'approval_request',
        title: `Approval needed from ${childName}`,
        message: `${childName} is requesting approval for: ${approvalType}. ${requestDetails}`,
        data: { childName, childId, approvalType, requestDetails },
    });

    if (notificationId && prefs.email_notifications && !isInQuietHours(prefs)) {
        const parentEmail = await getParentEmail(env.DB, parentId);
        if (parentEmail) {
            await queueEmailNotification(
                env,
                notificationId,
                parentEmail,
                `Approval needed from ${childName}`,
                formatEmailBody('approval_request', childName, { approvalType, requestDetails })
            );
        }
    }
}

/**
 * Add notification to batch for later delivery
 */
async function addToBatch(
    db: D1Database,
    parentId: string,
    batchType: string,
    notificationId: string
): Promise<void> {
    try {
        // Check for existing pending batch
        const existing = await db.prepare(`
      SELECT id, notifications FROM notification_batch
      WHERE parent_id = ? AND batch_type = ? AND status = 'pending'
      ORDER BY scheduled_for DESC LIMIT 1
    `).bind(parentId, batchType).first();

        if (existing) {
            // Add to existing batch
            const notifications = JSON.parse((existing.notifications as string) || '[]');
            notifications.push(notificationId);
            await db.prepare(`
        UPDATE notification_batch SET notifications = ? WHERE id = ?
      `).bind(JSON.stringify(notifications), existing.id).run();
        } else {
            // Create new batch scheduled for end of day
            const scheduledFor = new Date();
            scheduledFor.setHours(20, 0, 0, 0); // 8 PM
            if (scheduledFor < new Date()) {
                scheduledFor.setDate(scheduledFor.getDate() + 1);
            }

            await db.prepare(`
        INSERT INTO notification_batch (parent_id, batch_type, notifications, scheduled_for, status, created_at)
        VALUES (?, ?, ?, ?, 'pending', datetime('now'))
      `).bind(parentId, batchType, JSON.stringify([notificationId]), scheduledFor.toISOString()).run();
        }
    } catch {
        // Silently fail batch operations
    }
}

/**
 * Format email body for different notification types
 */
function formatEmailBody(
    type: NotificationType,
    childName: string,
    data: Record<string, unknown>
): string {
    const header = `
<!DOCTYPE html>
<html>
<head>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; }
    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
    .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px 8px 0 0; }
    .content { background: #f9fafb; padding: 20px; border: 1px solid #e5e7eb; }
    .footer { text-align: center; padding: 20px; color: #6b7280; font-size: 12px; }
    .btn { display: inline-block; background: #667eea; color: white; padding: 12px 24px; border-radius: 6px; text-decoration: none; }
    .alert { background: #fef3c7; border-left: 4px solid #f59e0b; padding: 12px; margin: 16px 0; }
    .success { background: #d1fae5; border-left: 4px solid #10b981; padding: 12px; margin: 16px 0; }
  </style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>🏠 XAOSTECH Family</h1>
  </div>
  <div class="content">
`;

    const footer = `
  </div>
  <div class="footer">
    <p>You're receiving this because you have a family account on XAOSTECH.</p>
    <p><a href="https://account.xaostech.io/family">Manage family settings</a> | <a href="https://account.xaostech.io/notifications/settings">Notification preferences</a></p>
  </div>
</div>
</body>
</html>
`;

    let content = '';

    switch (type) {
        case 'login':
            content = `
        <h2>👋 ${childName} logged in</h2>
        <p>${childName} just logged in to their XAOSTECH account${data.location ? ` from ${data.location}` : ''}.</p>
        <div class="success">
          <strong>This is normal activity.</strong> We're just keeping you informed!
        </div>
        <p><a href="https://account.xaostech.io/family/activity/${data.childId}" class="btn">View Activity</a></p>
      `;
            break;

        case 'time_limit':
            content = `
        <h2>⏰ Daily Time Limit Reached</h2>
        <p><strong>${childName}</strong> has used all <strong>${data.timeLimit} minutes</strong> of their daily learning time.</p>
        <div class="success">
          <strong>Great job today!</strong> Consistent learning is the key to success.
        </div>
        <p>They can continue learning tomorrow. If you'd like to extend their time limit, you can do so in the family dashboard.</p>
        <p><a href="https://account.xaostech.io/family/child/${data.childId}" class="btn">Adjust Time Limit</a></p>
      `;
            break;

        case 'content_flag':
            content = `
        <h2>🚩 Content Flagged for Review</h2>
        <p>${childName} attempted to access content that was flagged by your parental controls.</p>
        <div class="alert">
          <strong>Content:</strong> ${data.contentTitle}<br>
          <strong>Reason:</strong> ${data.flaggedReason}
        </div>
        <p>This content was blocked based on your filter settings. You can review and adjust these settings in the family dashboard.</p>
        <p><a href="https://account.xaostech.io/family/activity/${data.childId}?filter=flagged" class="btn">Review Activity</a></p>
      `;
            break;

        case 'approval_request':
            content = `
        <h2>✋ Approval Needed</h2>
        <p>${childName} is requesting your approval for the following:</p>
        <div class="alert">
          <strong>Request Type:</strong> ${data.approvalType}<br>
          <strong>Details:</strong> ${data.requestDetails}
        </div>
        <p><a href="https://account.xaostech.io/family/approvals" class="btn">Review Request</a></p>
      `;
            break;

        case 'daily_summary':
            content = `
        <h2>📊 Daily Activity Summary</h2>
        <p>Here's what ${childName} did today:</p>
        ${formatActivitiesList(data.activities as NotificationData['activities'])}
        <p><a href="https://account.xaostech.io/family/activity/${data.childId}" class="btn">View Full Activity</a></p>
      `;
            break;

        case 'weekly_summary':
            content = `
        <h2>📈 Weekly Activity Report</h2>
        <p>Here's ${childName}'s learning summary for the week:</p>
        ${formatActivitiesList(data.activities as NotificationData['activities'])}
        <p><a href="https://account.xaostech.io/family/activity/${data.childId}?range=week" class="btn">View Detailed Report</a></p>
      `;
            break;

        default:
            content = `<p>You have a new notification about ${childName}.</p>`;
    }

    return header + content + footer;
}

function formatActivitiesList(activities: NotificationData['activities']): string {
    if (!activities || activities.length === 0) {
        return '<p>No significant activity recorded.</p>';
    }

    return `
    <ul>
      ${activities.map(a => `<li><strong>${a.type}:</strong> ${a.count} ${a.details || ''}</li>`).join('')}
    </ul>
  `;
}

/**
 * Generate and send daily summary
 */
export async function generateDailySummary(
    env: Env,
    parentId: string,
    childId: string
): Promise<void> {
    const prefs = await getNotificationPreferences(env.DB, parentId);

    // Check if weekly reports are enabled
    const controls = await env.DB.prepare(`
    SELECT weekly_activity_report FROM parental_controls WHERE child_id = ?
  `).bind(childId).first();

    if (!controls?.weekly_activity_report) return;

    const childName = await getChildName(env.DB, childId, parentId);
    const today = new Date().toISOString().split('T')[0];

    // Get today's activities
    const activities = await env.DB.prepare(`
    SELECT activity_type, COUNT(*) as count
    FROM child_activity
    WHERE child_id = ? AND DATE(created_at) = ?
    GROUP BY activity_type
  `).bind(childId, today).all();

    // Get time used today
    const timeTracking = await env.DB.prepare(`
    SELECT minutes_used FROM child_time_tracking
    WHERE child_id = ? AND date = ?
  `).bind(childId, today).first();

    const formattedActivities = activities.results?.map(a => ({
        type: formatActivityType(a.activity_type as string),
        count: a.count as number,
    })) || [];

    if (timeTracking?.minutes_used) {
        formattedActivities.unshift({
            type: 'Learning time',
            count: timeTracking.minutes_used as number,
            details: 'minutes',
        } as any);
    }

    const notificationId = await createNotification(env.DB, {
        parentId,
        childId,
        type: 'daily_summary',
        title: `Daily summary for ${childName}`,
        message: `${childName}'s activity summary for ${today}`,
        data: { childName, childId, activities: formattedActivities },
    });

    if (notificationId && prefs.email_notifications) {
        const parentEmail = await getParentEmail(env.DB, parentId);
        if (parentEmail) {
            await queueEmailNotification(
                env,
                notificationId,
                parentEmail,
                `Daily summary for ${childName}`,
                formatEmailBody('daily_summary', childName, { childId, activities: formattedActivities })
            );
        }
    }
}

function formatActivityType(type: string): string {
    const types: Record<string, string> = {
        login: 'Logins',
        page_view: 'Pages viewed',
        content_view: 'Lessons viewed',
        content_create: 'Content created',
        time_limit_reached: 'Time limit reached',
        exercise_complete: 'Exercises completed',
    };
    return types[type] || type;
}

/**
 * Mark notification as read
 */
export async function markNotificationRead(
    db: D1Database,
    notificationId: string,
    userId: string
): Promise<boolean> {
    try {
        const result = await db.prepare(`
      UPDATE parent_notifications 
      SET read_at = datetime('now')
      WHERE id = ? AND parent_id = ?
    `).bind(notificationId, userId).run();

        return result.meta.changes > 0;
    } catch {
        return false;
    }
}

/**
 * Get unread notification count for a user
 */
export async function getUnreadCount(
    db: D1Database,
    userId: string
): Promise<number> {
    try {
        const result = await db.prepare(`
      SELECT COUNT(*) as count FROM parent_notifications
      WHERE parent_id = ? AND read_at IS NULL
    `).bind(userId).first();

        return (result?.count as number) || 0;
    } catch {
        return 0;
    }
}

/**
 * Get notifications for a user
 */
export async function getNotifications(
    db: D1Database,
    userId: string,
    options: { limit?: number; offset?: number; unreadOnly?: boolean } = {}
): Promise<any[]> {
    const { limit = 20, offset = 0, unreadOnly = false } = options;

    try {
        const query = unreadOnly
            ? `SELECT * FROM parent_notifications WHERE parent_id = ? AND read_at IS NULL ORDER BY created_at DESC LIMIT ? OFFSET ?`
            : `SELECT * FROM parent_notifications WHERE parent_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`;

        const result = await db.prepare(query).bind(userId, limit, offset).all();

        return result.results || [];
    } catch {
        return [];
    }
}

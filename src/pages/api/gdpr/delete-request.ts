import type { APIRoute } from 'astro';
import { getSessionIdFromCookie, getSession } from '../../../lib/session';

export const POST: APIRoute = async ({ request, locals }) => {
    const runtime = locals.runtime;
    const cookie = request.headers.get('Cookie');
    const sessionId = getSessionIdFromCookie(cookie);

    if (!sessionId) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), {
            status: 401,
            headers: { 'Content-Type': 'application/json' },
        });
    }

    const session = await getSession(sessionId, runtime.env.SESSIONS_KV);
    if (!session) {
        return new Response(JSON.stringify({ error: 'Session expired' }), {
            status: 401,
            headers: { 'Content-Type': 'application/json' },
        });
    }

    const userId = session.user_id;

    try {
        // Check for existing deletion request (only one active at a time)
        const existing = await runtime.env.DB.prepare(
            `SELECT id FROM gdpr_deletions WHERE user_id = ? AND status = 'requested'`
        ).bind(userId).first();

        if (existing) {
            return new Response(JSON.stringify({
                error: 'Deletion already requested. 30-day grace period applies.'
            }), {
                status: 429,
                headers: { 'Content-Type': 'application/json' },
            });
        }

        // Create deletion record (30-day grace period)
        const deletionId = crypto.randomUUID();
        const deleteDate = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();

        await runtime.env.DB.prepare(`
      INSERT INTO gdpr_deletions (id, user_id, status, requested_at, delete_at)
      VALUES (?, ?, 'requested', datetime('now'), ?)
    `).bind(deletionId, userId, deleteDate).run();

        // Queue confirmation email
        if (runtime.env.EMAIL_QUEUE) {
            await runtime.env.EMAIL_QUEUE.send({
                type: 'gdpr_deletion_requested',
                user_id: userId,
                email: session.email,
                delete_date: deleteDate,
                cancel_link: `https://account.xaostech.io/gdpr/cancel-deletion/${deletionId}`
            });
        }

        // Audit log
        await runtime.env.DB.prepare(`
      INSERT INTO audit_logs (user_id, action, ip, timestamp, details)
      VALUES (?, 'gdpr_deletion_requested', ?, datetime('now'), ?)
    `).bind(
            userId,
            request.headers.get('CF-Connecting-IP') || 'unknown',
            `30-day grace until ${deleteDate}`
        ).run();

        return new Response(JSON.stringify({
            message: 'Account deletion requested. 30-day grace period starts now.',
            deletion_date: deleteDate,
            can_cancel_until: deleteDate
        }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
        });
    } catch (err) {
        console.error('GDPR deletion error:', err);
        return new Response(JSON.stringify({ error: 'Deletion request failed' }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' },
        });
    }
};

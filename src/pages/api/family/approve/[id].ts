import type { APIRoute } from 'astro';
import { getSessionIdFromCookie, getSession } from '../../../../lib/session';

export const POST: APIRoute = async ({ request, params, locals }) => {
    const runtime = locals.runtime;
    const contentId = params.id;

    if (!contentId) {
        return new Response(JSON.stringify({ error: 'Content ID required' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' }
        });
    }

    try {
        // Verify session
        const sessionId = getSessionIdFromCookie(request.headers.get('Cookie'));
        if (!sessionId) {
            return new Response(JSON.stringify({ error: 'Not authenticated' }), {
                status: 401,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        const session = await getSession(sessionId, runtime.env.SESSIONS_KV);
        if (!session) {
            return new Response(JSON.stringify({ error: 'Invalid session' }), {
                status: 401,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        // Find the pending content and verify ownership
        const pending = await runtime.env.DB.prepare(`
      SELECT pc.*, u.parent_id 
      FROM pending_content pc
      JOIN users u ON pc.author_id = u.id
      WHERE pc.id = ? AND u.parent_id = ?
    `).bind(contentId, session.user_id).first();

        if (!pending) {
            return new Response(JSON.stringify({ error: 'Pending content not found or access denied' }), {
                status: 403,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        const now = new Date().toISOString();

        // Approve the content - move to published
        if (pending.content_type === 'post') {
            await runtime.env.DB.prepare(`
        UPDATE posts SET status = 'published', updated_at = ? WHERE id = ?
      `).bind(now, pending.content_ref_id).run();
        } else if (pending.content_type === 'comment') {
            await runtime.env.DB.prepare(`
        UPDATE comments SET status = 'approved', updated_at = ? WHERE id = ?
      `).bind(now, pending.content_ref_id).run();
        }

        // Remove from pending
        await runtime.env.DB.prepare(
            'DELETE FROM pending_content WHERE id = ?'
        ).bind(contentId).run();

        // Log the action
        await runtime.env.DB.prepare(`
      INSERT INTO parental_activity_log (id, parent_id, child_id, action, content_id, created_at)
      VALUES (?, ?, ?, 'approved', ?, ?)
    `).bind(crypto.randomUUID(), session.user_id, pending.author_id, contentId, now).run();

        return new Response(null, {
            status: 302,
            headers: { 'Location': '/family?success=approved' }
        });

    } catch (err) {
        console.error('Approve content error:', err);
        return new Response(JSON.stringify({ error: 'Failed to approve content' }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' }
        });
    }
};

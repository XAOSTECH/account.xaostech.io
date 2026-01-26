import type { APIRoute } from 'astro';
import { getSessionIdFromCookie, getSession } from '../../../../lib/session';

export const POST: APIRoute = async ({ request, params, locals }) => {
    const runtime = locals.runtime;
    const childId = params.id;

    if (!childId) {
        return new Response(JSON.stringify({ error: 'Child ID required' }), {
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

        // Verify this user is the parent of the child
        const child = await runtime.env.DB.prepare(
            'SELECT * FROM users WHERE id = ? AND parent_id = ?'
        ).bind(childId, session.user_id).first();

        if (!child) {
            return new Response(JSON.stringify({ error: 'Child not found or access denied' }), {
                status: 403,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        const formData = await request.formData();
        const action = formData.get('action')?.toString();

        // Handle removal action
        if (action === 'remove') {
            // Delete parental controls
            await runtime.env.DB.prepare(
                'DELETE FROM parental_controls WHERE child_id = ?'
            ).bind(childId).run();

            // Delete child account
            await runtime.env.DB.prepare(
                'DELETE FROM users WHERE id = ?'
            ).bind(childId).run();

            return new Response(null, {
                status: 302,
                headers: { 'Location': '/family?success=child_removed' }
            });
        }

        // Update settings
        const content_filter_level = formData.get('content_filter_level')?.toString() || 'strict';
        const daily_time_limit = parseInt(formData.get('daily_limit')?.toString() || '60');
        const weekly_time_limit = parseInt(formData.get('weekly_limit')?.toString() || '420');

        // Toggle switches - if not present, they're off
        const can_post_content = formData.get('can_post_content') === 'on' || formData.get('can_post_content') === 'true';
        const can_comment = formData.get('can_comment') === 'on' || formData.get('can_comment') === 'true';
        const require_approval_for_posts = formData.get('require_approval_for_posts') === 'on' || formData.get('require_approval_for_posts') === 'true';
        const log_exercises = formData.get('log_exercises') === 'on' || formData.get('log_exercises') === 'true';
        const log_logins = formData.get('log_logins') === 'on' || formData.get('log_logins') === 'true';

        const now = new Date().toISOString();

        await runtime.env.DB.prepare(`
      UPDATE parental_controls SET
        content_filter_level = ?,
        daily_time_limit = ?,
        weekly_time_limit = ?,
        can_post_content = ?,
        can_comment = ?,
        require_approval_for_posts = ?,
        log_exercises = ?,
        log_logins = ?,
        updated_at = ?
      WHERE child_id = ?
    `).bind(
            content_filter_level,
            daily_time_limit,
            weekly_time_limit,
            can_post_content ? 1 : 0,
            can_comment ? 1 : 0,
            require_approval_for_posts ? 1 : 0,
            log_exercises ? 1 : 0,
            log_logins ? 1 : 0,
            now,
            childId
        ).run();

        return new Response(null, {
            status: 302,
            headers: { 'Location': `/family/child/${childId}?success=updated` }
        });

    } catch (err) {
        console.error('Update child settings error:', err);
        return new Response(JSON.stringify({ error: 'Failed to update settings' }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' }
        });
    }
};

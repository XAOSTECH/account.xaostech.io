import type { APIRoute } from 'astro';
import { getSessionIdFromCookie, getSession } from '../../../lib/session';

export const POST: APIRoute = async ({ request, locals }) => {
    const runtime = locals.runtime;

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

        const formData = await request.formData();

        // Extract form fields
        const name = formData.get('name')?.toString().trim();
        const username = formData.get('username')?.toString().trim().toLowerCase();
        const password = formData.get('password')?.toString();
        const birth_year = parseInt(formData.get('birth_year')?.toString() || '0');
        const content_filter_level = formData.get('content_filter_level')?.toString() || 'strict';
        const daily_time_limit = parseInt(formData.get('daily_limit')?.toString() || '60');
        const weekly_time_limit = parseInt(formData.get('weekly_limit')?.toString() || '420');

        // Permission checkboxes (unchecked = absent from formData)
        const can_post_content = formData.get('can_post_content') === 'on';
        const can_comment = formData.get('can_comment') === 'on';
        const require_approval_for_posts = formData.get('require_approval_for_posts') === 'on';
        const log_exercises = formData.get('log_exercises') === 'on';
        const log_logins = formData.get('log_logins') === 'on';

        // Validate required fields
        if (!name || !username || !password) {
            return new Response(JSON.stringify({ error: 'Name, username, and password are required' }), {
                status: 400,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        // Validate username format
        if (!/^[a-z0-9_]{3,20}$/.test(username)) {
            return new Response(JSON.stringify({ error: 'Username must be 3-20 characters, lowercase letters, numbers, and underscores only' }), {
                status: 400,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        // Check if username already exists
        const existing = await runtime.env.DB.prepare(
            'SELECT id FROM users WHERE username = ?'
        ).bind(username).first();

        if (existing) {
            return new Response(JSON.stringify({ error: 'Username already taken' }), {
                status: 400,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        // Hash password
        const encoder = new TextEncoder();
        const data = encoder.encode(password);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const password_hash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

        // Create child account
        const childId = crypto.randomUUID();
        const now = new Date().toISOString();

        await runtime.env.DB.prepare(`
      INSERT INTO users (id, username, email, password_hash, role, created_at, updated_at, parent_id)
      VALUES (?, ?, ?, ?, 'child', ?, ?, ?)
    `).bind(
            childId,
            username,
            `${username}@family.xaostech.io`, // Internal email for child accounts
            password_hash,
            now,
            now,
            session.user_id
        ).run();

        // Create parental control settings
        await runtime.env.DB.prepare(`
      INSERT INTO parental_controls (
        id, child_id, parent_id,
        content_filter_level, daily_time_limit, weekly_time_limit,
        can_post_content, can_comment, require_approval_for_posts,
        log_exercises, log_logins, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
            crypto.randomUUID(),
            childId,
            session.user_id,
            content_filter_level,
            daily_time_limit,
            weekly_time_limit,
            can_post_content ? 1 : 0,
            can_comment ? 1 : 0,
            require_approval_for_posts ? 1 : 0,
            log_exercises ? 1 : 0,
            log_logins ? 1 : 0,
            now,
            now
        ).run();

        // Update user's profile with display name
        await runtime.env.DB.prepare(`
      UPDATE users SET display_name = ?, birth_year = ? WHERE id = ?
    `).bind(name, birth_year, childId).run();

        // Redirect back to family page
        return new Response(null, {
            status: 302,
            headers: {
                'Location': '/family?success=child_added'
            }
        });

    } catch (err) {
        console.error('Add child error:', err);
        return new Response(JSON.stringify({ error: 'Failed to add child account' }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' }
        });
    }
};

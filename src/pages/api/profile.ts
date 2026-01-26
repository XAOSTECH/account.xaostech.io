import type { APIRoute } from 'astro';
import { getSessionIdFromCookie, getSession } from '../../lib/session';

export const PATCH: APIRoute = async ({ request, locals }) => {
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

    try {
        const { username } = await request.json();

        if (!username || username.length < 2 || username.length > 50) {
            return new Response(JSON.stringify({ error: 'Username must be 2-50 characters' }), {
                status: 400,
                headers: { 'Content-Type': 'application/json' },
            });
        }

        // Update username in database
        await runtime.env.DB.prepare(
            `UPDATE users SET username = ?, updated_at = datetime('now') WHERE id = ?`
        ).bind(username, session.user_id).run();

        // Update session
        session.username = username;
        await runtime.env.SESSIONS_KV.put(sessionId, JSON.stringify(session), {
            expirationTtl: Math.floor((session.expires - Date.now()) / 1000),
        });

        return new Response(JSON.stringify({ success: true, username }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
        });
    } catch (err) {
        console.error('Profile update error:', err);
        return new Response(JSON.stringify({ error: 'Failed to update profile' }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' },
        });
    }
};

export const GET: APIRoute = async ({ request, locals }) => {
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

    // Get full user data from DB
    const user = await runtime.env.DB.prepare(
        `SELECT id, username, email, role, avatar_url, github_id, github_username, created_at 
     FROM users WHERE id = ?`
    ).bind(session.user_id).first();

    if (!user) {
        return new Response(JSON.stringify({ error: 'User not found' }), {
            status: 404,
            headers: { 'Content-Type': 'application/json' },
        });
    }

    return new Response(JSON.stringify(user), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
    });
};

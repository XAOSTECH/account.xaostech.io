import type { APIRoute } from 'astro';
import { getSessionIdFromCookie, getSession, generateApiKey } from '../../../lib/session';

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

    try {
        const result = await runtime.env.DB.prepare(
            `SELECT id, name, key_prefix, scopes, rate_limit, active, created_at, last_used_at, use_count
       FROM user_api_keys WHERE user_id = ? ORDER BY created_at DESC`
        ).bind(session.user_id).all();

        return new Response(JSON.stringify({ keys: result.results || [] }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
        });
    } catch (err) {
        console.error('Error fetching API keys:', err);
        return new Response(JSON.stringify({ error: 'Failed to fetch API keys' }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' },
        });
    }
};

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

    try {
        const { name, scopes = ['read', 'write'] } = await request.json();

        if (!name || name.length < 1 || name.length > 100) {
            return new Response(JSON.stringify({ error: 'Invalid key name' }), {
                status: 400,
                headers: { 'Content-Type': 'application/json' },
            });
        }

        // Generate API key
        const { key, prefix, hash } = await generateApiKey();

        // Insert into database
        const keyId = crypto.randomUUID();
        await runtime.env.DB.prepare(`
      INSERT INTO user_api_keys (id, user_id, name, key_prefix, key_hash, scopes, rate_limit, active, created_at)
      VALUES (?, ?, ?, ?, ?, ?, 60, true, datetime('now'))
    `).bind(keyId, session.user_id, name, prefix, hash, JSON.stringify(scopes)).run();

        return new Response(JSON.stringify({
            id: keyId,
            key, // Only returned on creation
            name,
            key_prefix: prefix,
            scopes,
        }), {
            status: 201,
            headers: { 'Content-Type': 'application/json' },
        });
    } catch (err) {
        console.error('Error creating API key:', err);
        return new Response(JSON.stringify({ error: 'Failed to create API key' }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' },
        });
    }
};

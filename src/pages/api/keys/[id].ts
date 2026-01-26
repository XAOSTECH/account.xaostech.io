import type { APIRoute } from 'astro';
import { getSessionIdFromCookie, getSession } from '../../../lib/session';

export const PATCH: APIRoute = async ({ params, request, locals }) => {
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

    const keyId = params.id;

    try {
        // Verify ownership
        const key = await runtime.env.DB.prepare(
            'SELECT id, user_id FROM user_api_keys WHERE id = ?'
        ).bind(keyId).first();

        if (!key || key.user_id !== session.user_id) {
            return new Response(JSON.stringify({ error: 'API key not found' }), {
                status: 404,
                headers: { 'Content-Type': 'application/json' },
            });
        }

        const { active, name } = await request.json();

        const updates: string[] = [];
        const values: any[] = [];

        if (typeof active === 'boolean') {
            updates.push('active = ?');
            values.push(active);
        }
        if (name && name.length > 0 && name.length <= 100) {
            updates.push('name = ?');
            values.push(name);
        }

        if (updates.length === 0) {
            return new Response(JSON.stringify({ error: 'No valid updates provided' }), {
                status: 400,
                headers: { 'Content-Type': 'application/json' },
            });
        }

        values.push(keyId);
        await runtime.env.DB.prepare(
            `UPDATE user_api_keys SET ${updates.join(', ')} WHERE id = ?`
        ).bind(...values).run();

        return new Response(JSON.stringify({ success: true }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
        });
    } catch (err) {
        console.error('Error updating API key:', err);
        return new Response(JSON.stringify({ error: 'Failed to update API key' }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' },
        });
    }
};

export const DELETE: APIRoute = async ({ params, request, locals }) => {
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

    const keyId = params.id;

    try {
        // Verify ownership
        const key = await runtime.env.DB.prepare(
            'SELECT id, user_id FROM user_api_keys WHERE id = ?'
        ).bind(keyId).first();

        if (!key || key.user_id !== session.user_id) {
            return new Response(JSON.stringify({ error: 'API key not found' }), {
                status: 404,
                headers: { 'Content-Type': 'application/json' },
            });
        }

        await runtime.env.DB.prepare(
            'DELETE FROM user_api_keys WHERE id = ?'
        ).bind(keyId).run();

        return new Response(JSON.stringify({ success: true }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
        });
    } catch (err) {
        console.error('Error deleting API key:', err);
        return new Response(JSON.stringify({ error: 'Failed to delete API key' }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' },
        });
    }
};

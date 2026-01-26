import type { APIRoute } from 'astro';
import { getSessionIdFromCookie, clearSessionCookie, deleteSession } from '../../lib/session';

export const POST: APIRoute = async ({ request, locals }) => {
    const runtime = locals.runtime;
    const cookie = request.headers.get('Cookie');
    const sessionId = getSessionIdFromCookie(cookie);

    if (sessionId) {
        await deleteSession(runtime.env.SESSIONS_KV, sessionId);
    }

    return new Response(JSON.stringify({ success: true }), {
        status: 200,
        headers: {
            'Content-Type': 'application/json',
            'Set-Cookie': clearSessionCookie(),
        },
    });
};

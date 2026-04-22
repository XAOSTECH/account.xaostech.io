import type { APIRoute } from 'astro';
import { env as cfEnv } from 'cloudflare:workers';
import { getSessionIdFromCookie, clearSessionCookie, deleteSession } from '../../../server/session';

export const POST: APIRoute = async ({ request, locals }) => {
    const runtime = { env: cfEnv as any };
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

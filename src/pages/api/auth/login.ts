import type { APIRoute } from 'astro';
import { env as cfEnv } from 'cloudflare:workers';
import { getSessionIdFromCookie, getSession, createSessionCookie, createSession } from '../../../server/session';

async function parseBody(request: Request): Promise<{ email: string; password: string; isForm: boolean }> {
    const ct = request.headers.get('Content-Type') || '';
    if (ct.includes('application/x-www-form-urlencoded')) {
        const form = new URLSearchParams(await request.text());
        return { email: form.get('email') || '', password: form.get('password') || '', isForm: true };
    }
    const json = await request.json() as { email?: string; password?: string };
    return { email: json.email || '', password: json.password || '', isForm: false };
}

export const POST: APIRoute = async ({ request, locals }) => {
    const runtime = { env: cfEnv as any };
    const { email, password, isForm } = await parseBody(request);

    const fail = (msg: string, status: number) => {
        if (isForm) return Response.redirect(new URL(`/login?error=${encodeURIComponent(msg)}`, request.url).toString(), 303);
        return new Response(JSON.stringify({ error: msg }), { status, headers: { 'Content-Type': 'application/json' } });
    };

    if (!email || !password) {
        return fail('Email and password are required', 400);
    }

    try {
        // Find user by email
        const user = await runtime.env.DB.prepare(
            `SELECT id, username, email, password_hash, role, avatar_url, github_id, github_username 
       FROM users WHERE email = ?`
        ).bind(email.toLowerCase()).first();

        if (!user) {
            return fail('Invalid email or password', 401);
        }

        // Verify password
        const passwordValid = await verifyPassword(password, user.password_hash as string);
        if (!passwordValid) {
            return fail('Invalid email or password', 401);
        }

        // Create session
        const sessionId = await createSession(runtime.env.SESSIONS_KV, {
            user_id: user.id as string,
            username: user.username as string,
            email: user.email as string,
            role: user.role as string || 'user',
            avatar_url: user.avatar_url as string | undefined,
            github_id: user.github_id as string | undefined,
            github_username: user.github_username as string | undefined,
        });

        const cookie = createSessionCookie(sessionId);
        if (isForm) {
            return new Response(null, {
                status: 303,
                headers: { Location: '/', 'Set-Cookie': cookie },
            });
        }
        return new Response(JSON.stringify({ success: true, redirect: '/' }), {
            status: 200,
            headers: {
                'Content-Type': 'application/json',
                'Set-Cookie': cookie,
            },
        });
    } catch (err) {
        console.error('Login error:', err);
        return fail('Login failed', 500);
    }
};

// Simple password verification using Web Crypto
async function verifyPassword(password: string, hash: string): Promise<boolean> {
    // Parse stored hash format: $sha256$salt$hash
    const parts = hash.split('$');
    if (parts.length !== 4 || parts[1] !== 'sha256') {
        return false;
    }

    const salt = parts[2];
    const storedHash = parts[3];

    const encoder = new TextEncoder();
    const data = encoder.encode(salt + password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const computedHash = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');

    return computedHash === storedHash;
}

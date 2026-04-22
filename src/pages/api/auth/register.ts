import type { APIRoute } from 'astro';
import { env as cfEnv } from 'cloudflare:workers';
import { createSessionCookie, createSession } from '../../../server/session';

async function parseBody(request: Request): Promise<{ username: string; email: string; password: string; isForm: boolean }> {
    const ct = request.headers.get('Content-Type') || '';
    if (ct.includes('application/x-www-form-urlencoded')) {
        const form = new URLSearchParams(await request.text());
        return { username: form.get('username') || '', email: form.get('email') || '', password: form.get('password') || '', isForm: true };
    }
    const json = await request.json() as { username?: string; email?: string; password?: string };
    return { username: json.username || '', email: json.email || '', password: json.password || '', isForm: false };
}

export const POST: APIRoute = async ({ request, locals }) => {
    const runtime = { env: cfEnv as any };
    const { username, email, password, isForm } = await parseBody(request);

    const fail = (msg: string, status: number) => {
        if (isForm) return Response.redirect(new URL(`/register?error=${encodeURIComponent(msg)}`, request.url).toString(), 303);
        return new Response(JSON.stringify({ error: msg }), { status, headers: { 'Content-Type': 'application/json' } });
    };

    if (!username || !email || !password) {
        return fail('All fields are required', 400);
    }

    // Validate email
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return fail('Invalid email address', 400);
    }

    // Validate password
    if (password.length < 8) {
        return fail('Password must be at least 8 characters', 400);
    }

    // Validate username
    if (username.length < 2 || username.length > 50) {
        return fail('Username must be 2-50 characters', 400);
    }

    try {
        // Check if email already exists
        const existing = await runtime.env.DB.prepare(
            'SELECT id FROM users WHERE email = ?'
        ).bind(email.toLowerCase()).first();

        if (existing) {
            return fail('Email already registered', 409);
        }

        // Hash password
        const passwordHash = await hashPassword(password);

        // Create user
        const userId = crypto.randomUUID();
        await runtime.env.DB.prepare(`
      INSERT INTO users (id, username, email, password_hash, role, created_at, updated_at)
      VALUES (?, ?, ?, ?, 'user', datetime('now'), datetime('now'))
    `).bind(userId, username, email.toLowerCase(), passwordHash).run();

        // Create session
        const sessionId = await createSession(runtime.env.SESSIONS_KV, {
            user_id: userId,
            username,
            email: email.toLowerCase(),
            role: 'user',
            isNewUser: true,
        });

        const cookie = createSessionCookie(sessionId);
        if (isForm) {
            return new Response(null, {
                status: 303,
                headers: { Location: '/login?success=Account+created.+Please+check+your+email.', 'Set-Cookie': cookie },
            });
        }
        return new Response(JSON.stringify({ success: true, redirect: '/' }), {
            status: 201,
            headers: {
                'Content-Type': 'application/json',
                'Set-Cookie': cookie,
            },
        });
    } catch (err) {
        console.error('Registration error:', err);
        return fail('Registration failed', 500);
    }
};

// Hash password using Web Crypto
async function hashPassword(password: string): Promise<string> {
    // Generate salt
    const saltBytes = new Uint8Array(16);
    crypto.getRandomValues(saltBytes);
    const salt = Array.from(saltBytes).map((b) => b.toString(16).padStart(2, '0')).join('');

    // Hash password with salt
    const encoder = new TextEncoder();
    const data = encoder.encode(salt + password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hash = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');

    // Return in format: $sha256$salt$hash
    return `$sha256$${salt}$${hash}`;
}

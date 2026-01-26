import type { APIRoute } from 'astro';
import { getSessionIdFromCookie, getSession, createSessionCookie, createSession } from '../../lib/session';

export const POST: APIRoute = async ({ request, locals }) => {
    const runtime = locals.runtime;
    const { email, password } = await request.json();

    if (!email || !password) {
        return new Response(JSON.stringify({ error: 'Email and password are required' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' },
        });
    }

    try {
        // Find user by email
        const user = await runtime.env.DB.prepare(
            `SELECT id, username, email, password_hash, role, avatar_url, github_id, github_username 
       FROM users WHERE email = ?`
        ).bind(email.toLowerCase()).first();

        if (!user) {
            return new Response(JSON.stringify({ error: 'Invalid email or password' }), {
                status: 401,
                headers: { 'Content-Type': 'application/json' },
            });
        }

        // Verify password
        const passwordValid = await verifyPassword(password, user.password_hash as string);
        if (!passwordValid) {
            return new Response(JSON.stringify({ error: 'Invalid email or password' }), {
                status: 401,
                headers: { 'Content-Type': 'application/json' },
            });
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

        return new Response(JSON.stringify({ success: true, redirect: '/' }), {
            status: 200,
            headers: {
                'Content-Type': 'application/json',
                'Set-Cookie': createSessionCookie(sessionId),
            },
        });
    } catch (err) {
        console.error('Login error:', err);
        return new Response(JSON.stringify({ error: 'Login failed' }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' },
        });
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

import type { APIRoute } from 'astro';
import { createSessionCookie, createSession } from '../../../lib/session';

export const POST: APIRoute = async ({ request, locals }) => {
    const runtime = locals.runtime;
    const { username, email, password } = await request.json();

    if (!username || !email || !password) {
        return new Response(JSON.stringify({ error: 'All fields are required' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' },
        });
    }

    // Validate email
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return new Response(JSON.stringify({ error: 'Invalid email address' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' },
        });
    }

    // Validate password
    if (password.length < 8) {
        return new Response(JSON.stringify({ error: 'Password must be at least 8 characters' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' },
        });
    }

    // Validate username
    if (username.length < 2 || username.length > 50) {
        return new Response(JSON.stringify({ error: 'Username must be 2-50 characters' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' },
        });
    }

    try {
        // Check if email already exists
        const existing = await runtime.env.DB.prepare(
            'SELECT id FROM users WHERE email = ?'
        ).bind(email.toLowerCase()).first();

        if (existing) {
            return new Response(JSON.stringify({ error: 'Email already registered' }), {
                status: 409,
                headers: { 'Content-Type': 'application/json' },
            });
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

        return new Response(JSON.stringify({ success: true, redirect: '/' }), {
            status: 201,
            headers: {
                'Content-Type': 'application/json',
                'Set-Cookie': createSessionCookie(sessionId),
            },
        });
    } catch (err) {
        console.error('Registration error:', err);
        return new Response(JSON.stringify({ error: 'Registration failed' }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' },
        });
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

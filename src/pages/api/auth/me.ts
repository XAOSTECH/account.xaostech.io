import type { APIRoute } from 'astro';

/**
 * GET /api/auth/me
 * Returns current user data for the floating bubble and other cross-domain uses
 */
export const GET: APIRoute = async ({ locals, request }) => {
    const user = locals.user;

    // Handle CORS for cross-subdomain requests
    const origin = request.headers.get('origin');
    const allowedOrigins = [
        'https://xaostech.io',
        'https://blog.xaostech.io',
        'https://edu.xaostech.io',
        'https://lingua.xaostech.io',
        'https://chat.xaostech.io',
        'https://data.xaostech.io',
        'https://api.xaostech.io',
        'https://payments.xaostech.io',
        'http://localhost:4321', // Dev
    ];

    const corsOrigin = origin && allowedOrigins.some(o => origin.startsWith(o.replace('https://', '').replace('http://', '')))
        ? origin
        : allowedOrigins[0];

    const headers = {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': corsOrigin,
        'Access-Control-Allow-Credentials': 'true',
        'Cache-Control': 'private, no-cache',
    };

    if (!user) {
        return new Response(JSON.stringify({ error: 'Not authenticated' }), {
            status: 401,
            headers,
        });
    }

    // Return user data needed by bubble and other services
    return new Response(JSON.stringify({
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        avatar_url: user.avatar_url || null,
        github_username: user.github_username || null,
    }), {
        status: 200,
        headers,
    });
};

// Handle preflight requests
export const OPTIONS: APIRoute = async ({ request }) => {
    const origin = request.headers.get('origin') || 'https://xaostech.io';

    return new Response(null, {
        status: 204,
        headers: {
            'Access-Control-Allow-Origin': origin,
            'Access-Control-Allow-Methods': 'GET, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type',
            'Access-Control-Allow-Credentials': 'true',
            'Access-Control-Max-Age': '86400',
        },
    });
};

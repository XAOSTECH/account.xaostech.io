import type { APIRoute } from 'astro';

/**
 * GET /api/auth/me
 * Returns current user data for the floating bubble and other cross-domain uses
 */
export const GET: APIRoute = async ({ locals, request }) => {
    const user = locals.user;

    // Handle CORS for cross-subdomain requests.
    // Allow any *.xaostech.io subdomain (and the apex) plus localhost dev,
    // so adding a new subdomain (music, portfolio, ai, security, ...) never
    // regresses the floating bubble's logged-in state.
    const origin = request.headers.get('origin');
    const ORIGIN_RE = /^https:\/\/([a-z0-9-]+\.)*xaostech\.io$/;
    const isLocalDev = origin === 'http://localhost:4321' || origin === 'http://localhost:8788';
    const corsOrigin = origin && (ORIGIN_RE.test(origin) || isLocalDev)
        ? origin
        : 'https://xaostech.io';

    const headers = {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': corsOrigin,
        'Access-Control-Allow-Credentials': 'true',
        'Cache-Control': 'private, no-cache',
        'Vary': 'Origin',
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
    const origin = request.headers.get('origin') || '';
    const ORIGIN_RE = /^https:\/\/([a-z0-9-]+\.)*xaostech\.io$/;
    const isLocalDev = origin === 'http://localhost:4321' || origin === 'http://localhost:8788';
    const allowOrigin = (ORIGIN_RE.test(origin) || isLocalDev) ? origin : 'https://xaostech.io';

    return new Response(null, {
        status: 204,
        headers: {
            'Access-Control-Allow-Origin': allowOrigin,
            'Access-Control-Allow-Methods': 'GET, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type',
            'Access-Control-Allow-Credentials': 'true',
            'Access-Control-Max-Age': '86400',
            'Vary': 'Origin',
        },
    });
};

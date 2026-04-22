/**
 * GitHub OAuth — initiate flow.
 *
 * Ported from api.xaostech.io/src/routes/auth.ts. The api worker's callback
 * URL was hardcoded to account.xaostech.io/api/auth/github/callback but no
 * handler existed, so every "Continue with GitHub" silently 404'd. Owning
 * the flow here is the correct shape — account is the auth source of truth.
 */
import type { APIRoute } from 'astro';
import { env as cfEnv } from 'cloudflare:workers';

interface Env {
    GITHUB_CLIENT_ID?: string;
    COOKIE_DOMAIN?: string;
}

function isValidReturnTo(url: string): boolean {
    try {
        const u = new URL(url);
        return u.protocol === 'https:' && u.hostname.endsWith('.xaostech.io');
    } catch {
        return false;
    }
}

export const GET: APIRoute = async ({ url }) => {
    const env = cfEnv as unknown as Env;
    const clientId = env.GITHUB_CLIENT_ID;
    if (!clientId) {
        return new Response(JSON.stringify({ error: 'GITHUB_CLIENT_ID not configured' }), {
            status: 501,
            headers: { 'Content-Type': 'application/json' },
        });
    }

    const returnTo = url.searchParams.get('return_to') || 'https://account.xaostech.io';
    const safeReturnTo = isValidReturnTo(returnTo) ? returnTo : 'https://account.xaostech.io';
    const loginHint = url.searchParams.get('login') || '';

    const state = crypto.randomUUID();
    const redirectUri = 'https://account.xaostech.io/api/auth/github/callback';
    const cookieDomain = env.COOKIE_DOMAIN || '.xaostech.io';

    const stateCookie = `gh_oauth_state=${state}; Domain=${cookieDomain}; Path=/; Max-Age=300; SameSite=Lax; Secure; HttpOnly`;
    const returnCookie = `gh_return_to=${encodeURIComponent(safeReturnTo)}; Domain=${cookieDomain}; Path=/; Max-Age=300; SameSite=Lax; Secure; HttpOnly`;

    const authUrl = new URL('https://github.com/login/oauth/authorize');
    authUrl.searchParams.set('client_id', clientId);
    authUrl.searchParams.set('redirect_uri', redirectUri);
    authUrl.searchParams.set('scope', 'read:user user:email');
    authUrl.searchParams.set('state', state);
    if (loginHint) authUrl.searchParams.set('login', loginHint);

    return new Response(null, {
        status: 302,
        headers: [
            ['Location', authUrl.toString()],
            ['Set-Cookie', stateCookie],
            ['Set-Cookie', returnCookie],
        ],
    });
};

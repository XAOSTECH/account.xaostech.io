/**
 * GitHub OAuth — callback. Exchanges code for token, fetches user profile,
 * upserts in account D1, creates a session in SESSIONS_KV, redirects to
 * gh_return_to.
 *
 * Ported from api.xaostech.io. Database access is direct via the local DB
 * binding (no DATA service hop).
 */
import type { APIRoute } from 'astro';
import { env as cfEnv } from 'cloudflare:workers';
import { createSession, createSessionCookie } from '../../../../server/session';

interface Env {
    DB: D1Database;
    SESSIONS_KV: KVNamespace;
    GITHUB_CLIENT_ID?: string;
    GITHUB_CLIENT_SECRET?: string;
    COOKIE_DOMAIN?: string;
}

interface GitHubUser {
    id: number;
    login: string;
    avatar_url?: string;
}

interface GitHubEmail {
    email: string;
    primary: boolean;
    verified: boolean;
}

function isValidReturnTo(url: string): boolean {
    try {
        const u = new URL(url);
        return u.protocol === 'https:' && u.hostname.endsWith('.xaostech.io');
    } catch {
        return false;
    }
}

function jsonError(status: number, message: string, details?: unknown) {
    return new Response(JSON.stringify({ error: message, details }), {
        status,
        headers: { 'Content-Type': 'application/json' },
    });
}

export const GET: APIRoute = async ({ url, request }) => {
    const env = cfEnv as unknown as Env;
    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');
    const clientId = env.GITHUB_CLIENT_ID;
    const clientSecret = env.GITHUB_CLIENT_SECRET;

    if (!code || !state) return jsonError(400, 'code and state required');
    if (!clientId || !clientSecret) return jsonError(501, 'GitHub OAuth secrets not configured');

    const cookie = request.headers.get('Cookie') || '';
    const cookieMatch = cookie.match(/gh_oauth_state=([^;]+)/);
    const cookieState = cookieMatch ? cookieMatch[1] : null;
    if (!cookieState || cookieState !== state) {
        return jsonError(400, 'Invalid state (possible CSRF)');
    }

    const redirectUri = 'https://account.xaostech.io/api/auth/github/callback';

    try {
        // 1) Exchange code for access token
        const tokenResp = await fetch('https://github.com/login/oauth/access_token', {
            method: 'POST',
            headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
            body: JSON.stringify({
                client_id: clientId,
                client_secret: clientSecret,
                code,
                redirect_uri: redirectUri,
            }),
        });
        const tokenJson = await tokenResp.json() as { access_token?: string; error?: string; error_description?: string };
        const accessToken = tokenJson.access_token;
        if (!accessToken) {
            return jsonError(502, 'Failed to obtain access token', tokenJson.error_description || tokenJson.error);
        }

        // 2) Fetch user + emails
        const ghHeaders = { Authorization: `token ${accessToken}`, 'User-Agent': 'xaostech' };
        const userResp = await fetch('https://api.github.com/user', { headers: ghHeaders });
        if (!userResp.ok) return jsonError(502, 'Failed to fetch GitHub user');
        const ghUser = await userResp.json() as GitHubUser;

        const emailsResp = await fetch('https://api.github.com/user/emails', { headers: ghHeaders });
        let primaryEmail: string | null = null;
        if (emailsResp.ok) {
            const emails = await emailsResp.json() as GitHubEmail[];
            const primary = emails.find((e) => e.primary && e.verified);
            primaryEmail = primary ? primary.email : (emails[0]?.email ?? null);
        }

        // 3) Upsert user in local D1
        const ghIdStr = ghUser.id.toString();
        const existing = await env.DB.prepare(
            'SELECT id, username, email, avatar_url, role FROM users WHERE github_id = ?'
        ).bind(ghIdStr).first<{ id: string; username: string; email: string; avatar_url: string | null; role: string }>();

        let userId: string;
        let currentUsername: string;
        let currentEmail: string;
        let currentAvatarUrl: string | null;
        let userRole: string;
        let isNewUser = false;

        if (existing) {
            userId = existing.id;
            currentUsername = existing.username;
            currentEmail = existing.email;
            currentAvatarUrl = existing.avatar_url;
            userRole = existing.role || 'user';
            // Update github_* tracking + last_login; preserve user-customised username/avatar
            await env.DB.prepare(
                `UPDATE users
                 SET github_username = ?, github_avatar_url = ?, updated_at = CURRENT_TIMESTAMP
                 WHERE id = ?`
            ).bind(ghUser.login || '', ghUser.avatar_url || '', userId).run();
        } else {
            userId = crypto.randomUUID();
            isNewUser = true;
            currentUsername = ghUser.login || `user_${ghIdStr.slice(0, 8)}`;
            currentEmail = primaryEmail || `${ghIdStr}@users.noreply.github.com`;
            currentAvatarUrl = ghUser.avatar_url || null;
            userRole = 'user';

            await env.DB.prepare(
                `INSERT INTO users (id, email, username, avatar_url, provider, provider_user_id,
                                    github_id, github_username, github_avatar_url)
                 VALUES (?, ?, ?, ?, 'github', ?, ?, ?, ?)`
            ).bind(
                userId,
                currentEmail,
                currentUsername,
                currentAvatarUrl,
                ghIdStr,
                ghIdStr,
                ghUser.login || '',
                ghUser.avatar_url || ''
            ).run();
        }

        // 4) Create session
        const sessionId = await createSession(env.SESSIONS_KV, {
            id: userId,
            userId,
            username: currentUsername,
            email: currentEmail,
            avatar_url: currentAvatarUrl || undefined,
            github_id: ghIdStr,
            role: userRole,
            isNewUser,
        });

        // 5) Resolve return_to
        const cookieDomain = env.COOKIE_DOMAIN || '.xaostech.io';
        const returnToMatch = cookie.match(/gh_return_to=([^;]+)/);
        const returnTo = returnToMatch ? decodeURIComponent(returnToMatch[1]) : 'https://account.xaostech.io';
        const safeReturnTo = isValidReturnTo(returnTo) ? returnTo : 'https://account.xaostech.io';

        const sessionCookie = createSessionCookie(sessionId);
        const clearReturnCookie = `gh_return_to=; Domain=${cookieDomain}; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`;
        const clearStateCookie = `gh_oauth_state=; Domain=${cookieDomain}; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`;

        return new Response(null, {
            status: 302,
            headers: [
                ['Location', safeReturnTo],
                ['Set-Cookie', sessionCookie],
                ['Set-Cookie', clearReturnCookie],
                ['Set-Cookie', clearStateCookie],
            ],
        });
    } catch (err) {
        console.error('GitHub callback error', err);
        return jsonError(500, 'GitHub OAuth failed', err instanceof Error ? err.message : String(err));
    }
};

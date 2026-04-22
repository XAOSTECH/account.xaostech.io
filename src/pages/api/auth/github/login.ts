/**
 * Thin 302 proxy → api.xaostech.io/auth/github/login
 *
 * api.xaostech.io is the auth/programmatic gateway and holds GH OAuth secrets.
 * This route exists only so the link "/api/auth/github/login" used by
 * index.astro/login.astro/register.astro stays stable on the public account
 * subdomain.
 */
import type { APIRoute } from 'astro';

export const GET: APIRoute = ({ url }) => {
    const target = new URL('https://api.xaostech.io/auth/github/login');
    for (const [k, v] of url.searchParams) target.searchParams.set(k, v);
    // Use `new Response` (NOT `Response.redirect`): the latter returns an
    // immutable response, which crashes the security-headers middleware
    // when it tries to set CSP/etc on the way out.
    return new Response(null, {
        status: 302,
        headers: { Location: target.toString() },
    });
};

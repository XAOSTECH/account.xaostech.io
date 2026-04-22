/**
 * Thin 302 proxy → api.xaostech.io/auth/github/callback
 *
 * GitHub OAuth App registers callback URL as
 * `https://account.xaostech.io/api/auth/github/callback`. account is public;
 * api is the gated worker that holds GH secrets and does the code exchange.
 * This route forwards the browser to api with the same query so api can
 * complete the exchange. The CSRF state cookie and session cookie are scoped
 * to `Domain=.xaostech.io`, so both subdomains see them.
 */
import type { APIRoute } from 'astro';

export const GET: APIRoute = ({ url }) => {
    const target = new URL('https://api.xaostech.io/auth/github/callback');
    for (const [k, v] of url.searchParams) target.searchParams.set(k, v);
    return Response.redirect(target.toString(), 302);
};

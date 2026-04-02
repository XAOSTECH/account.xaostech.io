export const prerender = false;
import { createProxyHandler } from '../../shared/types/api-proxy';

const proxy = createProxyHandler();

export const GET = (async (context: any) => {
  const { request, locals } = context;
  const faviconUrl = new URL('/api/data/assets/XAOSTECH_LOGO.png', request.url).toString();
  const proxied = await proxy({ request: new Request(faviconUrl), locals });

  if (!proxied || !proxied.ok) {
    return new Response('Favicon not found', { status: 404 });
  }

  const headers = new Headers(proxied.headers);
  if (!headers.get('Content-Type')) headers.set('Content-Type', 'image/png');
  headers.set('Cache-Control', 'public, max-age=86400');

  return new Response(proxied.body, { status: proxied.status, headers });
}) as any;

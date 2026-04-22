import { defineConfig } from 'astro/config';
import cloudflare from '@astrojs/cloudflare';

export default defineConfig({
    output: 'server',
    adapter: cloudflare({
        platformProxy: {
            enabled: true
        },
        // Match the wrangler.toml KV binding name so the adapter's built-in
        // Astro Sessions feature merges into our explicit kv_namespaces entry
        // instead of creating a separate "SESSION" binding that hijacks the deploy.
        sessionKVBindingName: 'SESSIONS_KV',
        // Astro 6 default is 'workerd' which spins up miniflare during build to
        // prerender pages. Our prerendered routes don't need workerd APIs, and
        // miniflare trips on production binding placeholders. Use Node.
        prerenderEnvironment: 'node'
    }),
    integrations: [],
    // CSP is emitted from src/middleware.ts (single source of truth).
    // Astro's security.csp integration was tried and removed: it cannot hash
    // inline style="" attributes, and adding any hash makes browsers ignore
    // 'unsafe-inline'. See shared/types/security.ts for full rationale.
    vite: {
        ssr: {
            external: ['node:crypto']
        }
    }
});

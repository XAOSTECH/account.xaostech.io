import { defineConfig } from 'astro/config';
import cloudflare from '@astrojs/cloudflare';

export default defineConfig({
    output: 'server',
    adapter: cloudflare({
        platformProxy: {
            enabled: true
        }
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

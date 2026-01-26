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
    vite: {
        ssr: {
            external: ['node:crypto']
        }
    }
});

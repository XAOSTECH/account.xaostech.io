import { defineMiddleware } from 'astro:middleware';
import { getSession, getSessionIdFromCookie, type SessionUser } from './lib/session';

export const onRequest = defineMiddleware(async (context, next) => {
    const runtime = context.locals.runtime as { env: Env };

    // Get session from cookie
    const cookieHeader = context.request.headers.get('Cookie');
    const sessionId = getSessionIdFromCookie(cookieHeader);

    let user: SessionUser | null = null;

    if (sessionId && runtime?.env?.SESSIONS_KV) {
        user = await getSession(sessionId, runtime.env.SESSIONS_KV);
    }

    // Attach user to locals for use in pages
    context.locals.user = user;

    return next();
});

interface Env {
    DB: D1Database;
    SESSIONS_KV: KVNamespace;
    RECOVERY_CODES_KV: KVNamespace;
    PASSWORD_RESET_KV: KVNamespace;
    EMAIL_QUEUE?: Queue;
    MAX_LOGIN_ATTEMPTS: string;
    LOCKOUT_DURATION_MIN: string;
    SESSION_TTL: string;
}

interface D1Database {
    prepare(query: string): D1PreparedStatement;
}

interface D1PreparedStatement {
    bind(...values: unknown[]): D1PreparedStatement;
    first<T = unknown>(colName?: string): Promise<T | null>;
    run(): Promise<D1Result>;
    all<T = unknown>(): Promise<D1Result<T>>;
}

interface D1Result<T = unknown> {
    results?: T[];
    success: boolean;
}

interface KVNamespace {
    get(key: string): Promise<string | null>;
    put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>;
    delete(key: string): Promise<void>;
}

interface Queue {
    send(message: unknown): Promise<void>;
}

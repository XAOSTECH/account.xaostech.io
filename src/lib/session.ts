/**
 * Session management utilities for account.xaostech.io
 */

export interface SessionUser {
    id?: string;        // API worker uses 'id'
    user_id?: string;   // Legacy field
    userId?: string;    // API worker also uses 'userId'
    username: string;
    email: string;
    role: string;
    avatar_url?: string;
    created?: number;
    expires: number;
    isNewUser?: boolean;
    github_id?: string;
    github_username?: string;
}

// Normalize session data to have consistent 'id' field
function normalizeSession(parsed: any): SessionUser {
    return {
        ...parsed,
        id: parsed.id || parsed.user_id || parsed.userId,
        user_id: parsed.id || parsed.user_id || parsed.userId,
    };
}

export async function getSession(
    sessionId: string | null,
    sessionsKv: KVNamespace
): Promise<SessionUser | null> {
    if (!sessionId) return null;

    try {
        const sessionData = await sessionsKv.get(sessionId);
        if (!sessionData) return null;

        const parsed = JSON.parse(sessionData);
        if (parsed.expires && parsed.expires < Date.now()) {
            // Session expired
            await sessionsKv.delete(sessionId);
            return null;
        }

        return normalizeSession(parsed);
    } catch (e) {
        console.error('Session read error:', e);
        return null;
    }
}

export function getSessionIdFromCookie(cookieHeader: string | null): string | null {
    if (!cookieHeader) return null;
    const match = cookieHeader.match(/session_id=([^;]+)/);
    return match ? match[1] : null;
}

export function createSessionCookie(sessionId: string, maxAge: number = 604800): string {
    return `session_id=${sessionId}; Path=/; Domain=.xaostech.io; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

export function clearSessionCookie(): string {
    return 'session_id=; Path=/; Domain=.xaostech.io; HttpOnly; Secure; SameSite=Lax; Max-Age=0';
}

export async function createSession(
    sessionsKv: KVNamespace,
    user: Omit<SessionUser, 'created' | 'expires'>,
    ttlSeconds: number = 604800
): Promise<string> {
    const sessionId = crypto.randomUUID();
    const now = Date.now();

    const sessionData: SessionUser = {
        ...user,
        created: now,
        expires: now + ttlSeconds * 1000,
    };

    await sessionsKv.put(sessionId, JSON.stringify(sessionData), {
        expirationTtl: ttlSeconds,
    });

    return sessionId;
}

export async function deleteSession(
    sessionsKv: KVNamespace,
    sessionId: string
): Promise<void> {
    await sessionsKv.delete(sessionId);
}

/**
 * Generate API key with prefix and hash
 */
export async function generateApiKey(): Promise<{
    key: string;
    prefix: string;
    hash: string;
}> {
    // Generate random bytes for the key
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);

    // Create key string: xao_ + base64 encoded random bytes
    const keyBody = btoa(String.fromCharCode(...bytes))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
    const key = `xao_${keyBody}`;

    // Prefix is first 8 chars for display
    const prefix = key.substring(0, 12);

    // Hash for storage
    const encoder = new TextEncoder();
    const data = encoder.encode(key);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hash = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');

    return { key, prefix, hash };
}

/**
 * Verify API key against hash
 */
export async function verifyApiKey(
    key: string,
    storedHash: string
): Promise<boolean> {
    const encoder = new TextEncoder();
    const data = encoder.encode(key);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const computedHash = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');

    return computedHash === storedHash;
}


/// <reference path="../.astro/types.d.ts" />
/// <reference types="astro/client" />

interface Env {
    DB: D1Database;
    SESSIONS_KV: KVNamespace;
    RECOVERY_CODES_KV: KVNamespace;
    PASSWORD_RESET_KV: KVNamespace;
    EMAIL_QUEUE?: Queue;
    MAX_LOGIN_ATTEMPTS: string;
    LOCKOUT_DURATION_MIN: string;
    SESSION_TTL: string;
    GITHUB_CLIENT_ID?: string;
    GITHUB_CLIENT_SECRET?: string;
}

declare namespace App {
    interface Locals {
        user: SessionUser | null;
        runtime: {
            env: Env;
        };
    }
}

interface SessionUser {
    user_id: string;
    username: string;
    email: string;
    role: string;
    avatar_url?: string;
    created: number;
    expires: number;
    isNewUser?: boolean;
    github_id?: string;
    github_username?: string;
}

interface D1Database {
    prepare(query: string): D1PreparedStatement;
    batch<T>(statements: D1PreparedStatement[]): Promise<T[]>;
    exec(query: string): Promise<D1ExecResult>;
}

interface D1PreparedStatement {
    bind(...values: unknown[]): D1PreparedStatement;
    first<T = unknown>(colName?: string): Promise<T | null>;
    run(): Promise<D1Result>;
    all<T = unknown>(): Promise<D1Result<T>>;
    raw<T = unknown>(): Promise<T[]>;
}

interface D1Result<T = unknown> {
    results?: T[];
    success: boolean;
    meta: object;
}

interface D1ExecResult {
    count: number;
    duration: number;
}

interface KVNamespace {
    get(key: string, options?: { type?: 'text' | 'json' | 'arrayBuffer' | 'stream' }): Promise<string | null>;
    put(key: string, value: string | ReadableStream | ArrayBuffer, options?: { expirationTtl?: number; expiration?: number; metadata?: object }): Promise<void>;
    delete(key: string): Promise<void>;
    list(options?: { prefix?: string; limit?: number; cursor?: string }): Promise<{ keys: { name: string }[]; list_complete: boolean; cursor?: string }>;
}

interface Queue {
    send(message: unknown): Promise<void>;
}

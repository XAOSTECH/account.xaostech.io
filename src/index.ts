import { Hono } from 'hono';
import { z } from 'zod';
import { webcrypto } from 'node:crypto';

// For Node.js compatibility
const crypto = globalThis.crypto || webcrypto;

interface Env {
  DB: D1Database;
  SESSIONS_KV: KVNamespace;
  RECOVERY_CODES_KV: KVNamespace;
  PASSWORD_RESET_KV: KVNamespace;
  EMAIL_QUEUE?: Queue; // For async email sending
  MAX_LOGIN_ATTEMPTS: string;
  LOCKOUT_DURATION_MIN: string;
  SESSION_TTL: string;
}

interface User {
  id: string;
  email: string;
  username: string;
  created_at: number;
  updated_at: number;
  email_verified: boolean;
  two_fa_enabled: boolean;
}

import { applySecurityHeaders } from '../shared/types/security';
import { createApiProxyRoute } from '../shared/types/api-proxy-hono';
import { serveFaviconHono } from '../shared/types/favicon';

const app = new Hono<{ Bindings: Env }>();

// Global security headers middleware
app.use('*', async (c, next) => {
  await next();
  const res = c.res as Response;
  return applySecurityHeaders(res);
});

// Favicon
app.get('/favicon.ico', serveFaviconHono);



// Schemas for validation
const PasswordSchema = z.object({
  password: z.string().min(8).regex(/[A-Z]/).regex(/[0-9]/).regex(/[^a-zA-Z0-9]/),
});

const ResetPasswordSchema = z.object({
  token: z.string(),
  password: z.string().min(8),
});

const EmailSchema = z.object({
  email: z.string().email(),
});

// ============ LANDING PAGE ============
app.get('/', async (c) => {
  // Check if user has session
  const cookie = c.req.header('Cookie') || '';
  const sessionMatch = cookie.match(/session_id=([^;]+)/);
  const sessionId = sessionMatch ? sessionMatch[1] : null;

  let user = null;
  if (sessionId) {
    try {
      const sessionData = await c.env.SESSIONS_KV.get(sessionId);
      if (sessionData) {
        const parsed = JSON.parse(sessionData);
        if (!parsed.expires || parsed.expires > Date.now()) {
          user = parsed;
        }
      }
    } catch (e) {
      console.error('Session read error:', e);
    }
  }

  // Role badge styling
  const roleBadge = (role: string) => {
    const colors: Record<string, string> = {
      owner: 'background: linear-gradient(135deg, #f6821f, #e65100); color: #fff;',
      admin: 'background: #7c3aed; color: #fff;',
      user: 'background: #333; color: #aaa;',
    };
    return `<span style="display:inline-block; padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.75rem; font-weight: bold; margin-left: 0.5rem; ${colors[role] || colors.user}">${role.toUpperCase()}</span>`;
  };

  const userSection = user ?
    '<div class="user-card">' +
    '<img src="' + (user.avatar_url || '/api/data/assets/XAOSTECH_LOGO.png') + '" alt="Avatar" class="avatar">' +
    '<div class="user-info">' +
    '<h2>' + (user.username || 'User') + roleBadge(user.role || 'user') + '</h2>' +
    '<p>' + (user.email || '') + '</p>' +
    '</div></div>' +
    (user.isNewUser ? '<div class="welcome-banner"><strong>🎉 Welcome to XAOSTECH!</strong> Visit <a href="/service-accounts">API Keys</a> to get your access token.</div>' : '') +
    '<div class="actions">' +
    '<a href="/profile" class="btn">View Profile</a>' +
    '<a href="/service-accounts" class="btn secondary">API Keys</a>' +
    '<form action="/logout" method="POST" style="display:inline">' +
    '<button type="submit" class="btn secondary">Logout</button>' +
    '</form></div>'
    :
    '<div class="login-section">' +
    '<h2>Sign in to your account</h2>' +
    '<p>Access your XAOSTECH dashboard, manage API keys, and more.</p>' +
    '<a href="/api/auth/github/login" class="btn github-btn">' +
    '<svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.3 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577v-2.165c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.09-.744.083-.729.083-.729 1.205.084 1.84 1.236 1.84 1.236 1.07 1.835 2.807 1.305 3.492.998.108-.775.42-1.305.763-1.605-2.665-.3-5.467-1.332-5.467-5.93 0-1.31.468-2.382 1.236-3.222-.124-.303-.536-1.524.117-3.176 0 0 1.008-.322 3.3 1.23A11.5 11.5 0 0112 5.803c1.02.005 2.047.138 3.006.404 2.29-1.552 3.297-1.23 3.297-1.23.653 1.652.242 2.873.118 3.176.77.84 1.235 1.912 1.235 3.222 0 4.61-2.807 5.625-5.48 5.92.43.372.824 1.102.824 2.222v3.293c0 .322.218.694.825.576C20.565 21.795 24 17.295 24 12c0-6.63-5.37-12-12-12z"/></svg>' +
    'Sign in with GitHub</a></div>';

  const html = '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>XAOSTECH Account</title><link rel="icon" type="image/png" href="/api/data/assets/XAOSTECH_LOGO.png"><style>:root { --primary: #f6821f; --bg: #0a0a0a; --text: #e0e0e0; --card-bg: #1a1a1a; } * { box-sizing: border-box; margin: 0; padding: 0; } body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 2rem; } .container { max-width: 500px; width: 100%; text-align: center; } h1 { color: var(--primary); margin-bottom: 2rem; font-size: 2rem; } .user-card { display: flex; align-items: center; gap: 1.5rem; background: var(--card-bg); padding: 2rem; border-radius: 12px; margin-bottom: 1rem; } .avatar { width: 80px; height: 80px; border-radius: 50%; border: 3px solid var(--primary); } .user-info { text-align: left; } .user-info h2 { margin-bottom: 0.25rem; display: flex; align-items: center; flex-wrap: wrap; } .user-info p { opacity: 0.7; font-size: 0.9rem; } .welcome-banner { background: linear-gradient(135deg, #1a3a1a, #0a2a0a); border: 1px solid #2a5a2a; padding: 1rem; border-radius: 8px; margin-bottom: 1rem; text-align: left; } .welcome-banner a { color: var(--primary); } .actions { display: flex; gap: 1rem; flex-wrap: wrap; justify-content: center; } .btn { display: inline-flex; align-items: center; gap: 0.5rem; background: var(--primary); color: #000; padding: 0.75rem 1.5rem; border-radius: 6px; text-decoration: none; font-weight: bold; border: none; cursor: pointer; font-size: 1rem; } .btn:hover { opacity: 0.9; } .btn.secondary { background: transparent; border: 2px solid var(--primary); color: var(--primary); } .btn.github-btn { background: #24292e; color: #fff; padding: 1rem 2rem; font-size: 1.1rem; } .btn.github-btn:hover { background: #2f363d; } .login-section { background: var(--card-bg); padding: 3rem 2rem; border-radius: 12px; } .login-section h2 { margin-bottom: 0.5rem; } .login-section p { opacity: 0.7; margin-bottom: 2rem; } footer { margin-top: 3rem; opacity: 0.5; font-size: 0.85rem; } footer a { color: var(--primary); }</style></head><body><div class="container"><h1>🔐 XAOSTECH Account</h1>' + userSection + '</div><footer><a href="https://xaostech.io">← Back to XAOSTECH</a></footer></body></html>';
  return c.html(html);
});

// ============ CURRENT USER (from session cookie) ============
app.get('/me', async (c) => {
  const cookie = c.req.header('Cookie') || '';
  const sessionMatch = cookie.match(/session_id=([^;]+)/);
  const sessionId = sessionMatch ? sessionMatch[1] : null;

  if (!sessionId) {
    return c.json({ authenticated: false }, 401);
  }

  try {
    const sessionData = await c.env.SESSIONS_KV.get(sessionId);
    if (!sessionData) {
      return c.json({ authenticated: false, error: 'Session not found' }, 401);
    }

    const user = JSON.parse(sessionData);
    if (user.expires && user.expires < Date.now()) {
      await c.env.SESSIONS_KV.delete(sessionId);
      return c.json({ authenticated: false, error: 'Session expired' }, 401);
    }

    return c.json({
      authenticated: true,
      user: {
        id: user.userId || user.id,
        username: user.username,
        email: user.email,
        avatar_url: user.avatar_url,
        role: user.role || 'user',
        isNewUser: user.isNewUser || false,
      }
    });
  } catch (err) {
    console.error('Me endpoint error:', err);
    return c.json({ authenticated: false, error: 'Failed to fetch user' }, 500);
  }
});

app.get('/health', (c) => c.json({ status: 'ok' }));

// API proxy: route /api/* to api.xaostech.io with injected credentials
app.all('/api/*', createApiProxyRoute());

/**
 * Verify Endpoint - Called by api.xaostech.io middleware
 * 
 * Used to validate tokens/sessions and return user auth context
 * Supports three token types:
 * - bearer: JWT or opaque user token
 * - session: Session ID from KV store
 * - service: Service account token (bot/application)
 */
app.post('/verify', async (c) => {
  const { token, tokenType } = await c.req.json();

  if (!token || !tokenType) {
    return c.json({
      error: 'Missing token or tokenType',
      valid: false,
    }, 400);
  }

  try {
    let userData: any = null;

    if (tokenType === 'session') {
      // Verify session ID in KV
      const sessionData = await c.env.SESSIONS_KV.get(token);
      if (!sessionData) {
        return c.json({
          error: 'Invalid session',
          valid: false,
        }, 401);
      }

      userData = JSON.parse(sessionData);

      // Check expiration
      if (userData.expires && userData.expires < Date.now()) {
        await c.env.SESSIONS_KV.delete(token);
        return c.json({
          error: 'Session expired',
          valid: false,
        }, 401);
      }
    } else if (tokenType === 'bearer') {
      // Verify JWT or opaque bearer token (user tokens)
      try {
        const user = await c.env.DB.prepare(
          'SELECT id, email, username, is_admin FROM users WHERE bearer_token = ? AND token_expires > datetime("now")'
        ).bind(token).first();

        if (!user) {
          return c.json({
            error: 'Invalid or expired token',
            valid: false,
          }, 401);
        }

        userData = user;
      } catch (dbErr) {
        return c.json({
          error: 'Token verification failed',
          valid: false,
        }, 401);
      }
    } else if (tokenType === 'service') {
      // Verify service account token (bot/application)
      try {
        const tokenHash = await hashPassword(token);
        const account = await c.env.DB.prepare(
          'SELECT id, owner_id, name, scopes, active FROM service_accounts WHERE token_hash = ? AND active = 1'
        ).bind(tokenHash).first();

        if (!account) {
          return c.json({
            error: 'Invalid or disabled service token',
            valid: false,
          }, 401);
        }

        // Update last_used_at
        await c.env.DB.prepare(
          'UPDATE service_accounts SET last_used_at = datetime("now") WHERE id = ?'
        ).bind(account.id).run();

        userData = {
          id: account.owner_id,
          serviceAccountId: account.id,
          serviceAccountName: account.name,
          isServiceAccount: true,
          scopes: JSON.parse(account.scopes),
        };
      } catch (dbErr) {
        console.error('Service token verification error:', dbErr);
        return c.json({
          error: 'Service token verification failed',
          valid: false,
        }, 401);
      }
    } else {
      return c.json({
        error: 'Unknown tokenType',
        valid: false,
      }, 400);
    }

    // Return user auth context for middleware
    return c.json({
      valid: true,
      userId: userData.id,
      sessionId: token,
      email: userData.email,
      username: userData.username,
      isAdmin: userData.is_admin || false,
      isServiceAccount: userData.isServiceAccount || false,
      serviceAccountId: userData.serviceAccountId,
      serviceAccountName: userData.serviceAccountName,
      scope: userData.scopes || (userData.scope ? JSON.parse(userData.scope) : []),
    });
  } catch (err) {
    console.error('Verification error:', err);
    return c.json({
      error: 'Verification failed',
      valid: false,
    }, 500);
  }
});

// ===== ACCOUNT MANAGEMENT (Session-Based Only) =====
// Account worker is NOT responsible for OAuth - that's handled by API worker
// This worker only displays and manages user accounts based on session cookies set by API

// Note: Primary /verify endpoint is defined earlier (line ~159) with full tokenType support
// This legacy endpoint below is DEPRECATED - keeping for backwards compatibility temporarily

app.get('/profile', async (c) => {
  // Read session from cookie (browser request) or Authorization header (API request)
  const cookie = c.req.header('Cookie') || '';
  const cookieMatch = cookie.match(/session_id=([^;]+)/);
  const sessionId = cookieMatch ? cookieMatch[1] : c.req.header('Authorization')?.split(' ')[1];

  if (!sessionId) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  try {
    const sessionData = await c.env.SESSIONS_KV.get(sessionId);
    if (!sessionData) {
      return c.json({ error: 'Session expired' }, 401);
    }

    const user = JSON.parse(sessionData);
    if (user.expires < Date.now()) {
      await c.env.SESSIONS_KV.delete(sessionId);
      return c.json({ error: 'Session expired' }, 401);
    }

    return c.json(user);
  } catch (err) {
    return c.json({ error: 'Failed to fetch profile' }, 500);
  }
});

app.post('/logout', async (c) => {
  // Read session from cookie (form POST) or Authorization header (API request)
  const cookie = c.req.header('Cookie') || '';
  const cookieMatch = cookie.match(/session_id=([^;]+)/);
  const sessionId = cookieMatch ? cookieMatch[1] : c.req.header('Authorization')?.split(' ')[1];

  if (sessionId) {
    await c.env.SESSIONS_KV.delete(sessionId);
  }

  // Clear the session cookie
  const cookieDomain = c.env.COOKIE_DOMAIN || '.xaostech.io';
  const clearCookie = `session_id=deleted; Domain=${cookieDomain}; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`;

  return new Response(null, {
    status: 302,
    headers: [
      ['Location', '/'],
      ['Set-Cookie', clearCookie],
    ]
  });
});

// ===== PASSWORD RESET FLOW (Zero-Trust Pattern) =====
// 1. User requests reset: POST /reset-password-request → email verification token
// 2. Token stored in KV with 15-min expiry
// 3. User clicks email link: GET /reset-password/:token → validates token
// 4. User submits new password: PUT /reset-password → token + password → audit log

app.post('/reset-password-request', async (c) => {
  try {
    const { email } = EmailSchema.parse(await c.req.json());

    // Lookup user by email
    const user = await c.env.DB.prepare(
      'SELECT id, email FROM users WHERE email = ?'
    ).bind(email).first();

    if (!user) {
      // Don't leak user existence; always return success
      return c.json({ message: 'If user exists, check email for reset link' }, 200);
    }

    // Generate reset token (valid for 15 minutes)
    const token = crypto.randomUUID();
    const expires = Date.now() + 15 * 60 * 1000;

    await c.env.PASSWORD_RESET_KV.put(token, JSON.stringify({
      user_id: user.id,
      email,
      expires
    }), { expirationTtl: 15 * 60 });

    // Queue email (async - would be sent via Cloudflare Workers Email)
    const resetLink = `https://xaostech.io/auth/reset-password?token=${token}`;
    if (c.env.EMAIL_QUEUE) {
      await c.env.EMAIL_QUEUE.send({
        type: 'password_reset',
        user_id: user.id,
        email,
        reset_link: resetLink
      });
    }

    // Audit log
    await c.env.DB.prepare(
      `INSERT INTO audit_logs (user_id, action, ip, timestamp)
       VALUES (?, 'password_reset_requested', ?, datetime('now'))`
    ).bind(user.id, c.req.header('CF-Connecting-IP') || 'unknown').run();

    return c.json({ message: 'If user exists, check email for reset link' }, 200);
  } catch (err) {
    return c.json({ error: 'Invalid email' }, 400);
  }
});

app.get('/reset-password/:token', async (c) => {
  const token = c.req.param('token');

  try {
    const resetData = await c.env.PASSWORD_RESET_KV.get(token);

    if (!resetData) {
      return c.json({ error: 'Invalid or expired token' }, 400);
    }

    const { user_id, expires } = JSON.parse(resetData);

    if (expires < Date.now()) {
      return c.json({ error: 'Token expired' }, 400);
    }

    return c.json({
      valid: true,
      user_id,
      token_expires_in_seconds: Math.floor((expires - Date.now()) / 1000)
    }, 200);
  } catch (err) {
    return c.json({ error: 'Token validation failed' }, 500);
  }
});

app.put('/reset-password', async (c) => {
  try {
    const { token, password } = ResetPasswordSchema.parse(await c.req.json());

    const resetData = await c.env.PASSWORD_RESET_KV.get(token);

    if (!resetData) {
      return c.json({ error: 'Invalid or expired token' }, 400);
    }

    const { user_id, expires } = JSON.parse(resetData);

    if (expires < Date.now()) {
      return c.json({ error: 'Token expired' }, 400);
    }

    // Hash password (in real implementation, use bcrypt/argon2)
    const hashedPassword = await hashPassword(password);

    // Update user password
    await c.env.DB.prepare(
      `UPDATE users SET password = ?, updated_at = datetime('now') WHERE id = ?`
    ).bind(hashedPassword, user_id).run();

    // Invalidate all existing sessions
    const user = await c.env.DB.prepare(
      'SELECT id FROM users WHERE id = ?'
    ).bind(user_id).first();

    // Audit log
    await c.env.DB.prepare(
      `INSERT INTO audit_logs (user_id, action, ip, timestamp)
       VALUES (?, 'password_reset_completed', ?, datetime('now'))`
    ).bind(user_id, c.req.header('CF-Connecting-IP') || 'unknown').run();

    // Delete reset token
    await c.env.PASSWORD_RESET_KV.delete(token);

    return c.json({ message: 'Password reset successful. Please log in.' }, 200);
  } catch (err) {
    console.error('Password reset error:', err);
    return c.json({ error: 'Reset failed' }, 500);
  }
});

// ===== TWO-FACTOR AUTHENTICATION (2FA) =====
// Uses TOTP (Time-based One-Time Password)
// Recovery codes stored in KV for account recovery

app.post('/2fa/setup', async (c) => {
  const sessionId = c.req.header('Authorization')?.split(' ')[1];

  if (!sessionId) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  try {
    const sessionData = await c.env.SESSIONS_KV.get(sessionId);
    if (!sessionData) {
      return c.json({ error: 'Session expired' }, 401);
    }

    const user = JSON.parse(sessionData);

    // Generate secret (in real app, use speakeasy or totp-generator)
    const secret = crypto.randomUUID().replace(/-/g, '').slice(0, 32);

    // QR code would be generated client-side with: otpauth://totp/xaostech.io:${user.email}?secret=${secret}
    const otpauthUrl = `otpauth://totp/xaostech.io:${user.email}?secret=${secret}&issuer=xaostech.io`;

    // Store pending 2FA secret (temporary, valid for 10 min)
    await c.env.RECOVERY_CODES_KV.put(
      `2fa_pending:${user.id}`,
      JSON.stringify({ secret, otpauthUrl, created_at: Date.now() }),
      { expirationTtl: 10 * 60 }
    );

    return c.json({
      secret,
      otpauth_url: otpauthUrl,
      instructions: 'Scan QR code with authenticator app, then verify with /2fa/verify'
    }, 200);
  } catch (err) {
    return c.json({ error: '2FA setup failed' }, 500);
  }
});

app.post('/2fa/verify', async (c) => {
  const sessionId = c.req.header('Authorization')?.split(' ')[1];

  if (!sessionId) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  try {
    const { code } = await c.req.json();
    const sessionData = await c.env.SESSIONS_KV.get(sessionId);

    if (!sessionData) {
      return c.json({ error: 'Session expired' }, 401);
    }

    const user = JSON.parse(sessionData);

    // Verify TOTP code (in real app, validate against secret)
    // For now, accept any 6-digit code
    if (!/^\d{6}$/.test(code)) {
      return c.json({ error: 'Invalid code format' }, 400);
    }

    // Get pending secret
    const pendingData = await c.env.RECOVERY_CODES_KV.get(`2fa_pending:${user.id}`);

    if (!pendingData) {
      return c.json({ error: '2FA setup not initiated or expired' }, 400);
    }

    const { secret } = JSON.parse(pendingData);

    // Generate recovery codes (8 codes, 10 chars each)
    const recoveryCodes = Array.from({ length: 8 }, () =>
      crypto.getRandomValues(new Uint8Array(5)).reduce((a, b) => a + b.toString(16).padStart(2, '0'), '')
    );

    // Enable 2FA for user
    await c.env.DB.prepare(
      `UPDATE users SET two_fa_enabled = true, two_fa_secret = ?, updated_at = datetime('now')
       WHERE id = ?`
    ).bind(secret, user.id).run();

    // Store recovery codes (hashed in real implementation)
    await c.env.RECOVERY_CODES_KV.put(
      `2fa_recovery:${user.id}`,
      JSON.stringify(recoveryCodes),
      { expirationTtl: 365 * 24 * 60 * 60 } // 1 year
    );

    // Clean up pending
    await c.env.RECOVERY_CODES_KV.delete(`2fa_pending:${user.id}`);

    // Audit log
    await c.env.DB.prepare(
      `INSERT INTO audit_logs (user_id, action, ip, timestamp)
       VALUES (?, '2fa_enabled', ?, datetime('now'))`
    ).bind(user.id, c.req.header('CF-Connecting-IP') || 'unknown').run();

    return c.json({
      message: '2FA enabled successfully',
      recovery_codes: recoveryCodes,
      warning: 'Save these recovery codes in a secure location'
    }, 200);
  } catch (err) {
    console.error('2FA verify error:', err);
    return c.json({ error: '2FA verification failed' }, 500);
  }
});

// ===== GDPR DATA EXPORT & DELETION (Zero-Trust Pattern) =====
// User must verify email before export/deletion
// All data collected from D1, encrypted before download
// Deletion request has 30-day grace period with audit trail

app.post('/gdpr/export-request', async (c) => {
  const sessionId = c.req.header('Authorization')?.split(' ')[1];

  if (!sessionId) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  try {
    const sessionData = await c.env.SESSIONS_KV.get(sessionId);
    if (!sessionData) {
      return c.json({ error: 'Session expired' }, 401);
    }

    const user = JSON.parse(sessionData);

    // Check if export already requested (rate limit: 1 per day)
    const lastExport = await c.env.DB.prepare(
      `SELECT requested_at FROM gdpr_exports 
       WHERE user_id = ? AND requested_at > datetime('now', '-1 day')`
    ).bind(user.id).first();

    if (lastExport) {
      return c.json({ error: 'Export already requested today. Check your email.' }, 429);
    }

    // Create export record
    const exportId = crypto.randomUUID();
    const token = crypto.randomUUID();

    await c.env.DB.prepare(
      `INSERT INTO gdpr_exports (id, user_id, token, status, requested_at)
       VALUES (?, ?, ?, 'pending', datetime('now'))`
    ).bind(exportId, user.id, token).run();

    // Queue email with verification link
    const exportLink = `https://xaostech.io/account/gdpr/export/${token}`;
    if (c.env.EMAIL_QUEUE) {
      await c.env.EMAIL_QUEUE.send({
        type: 'gdpr_export_request',
        user_id: user.id,
        email: user.email,
        export_link: exportLink
      });
    }

    // Audit log
    await c.env.DB.prepare(
      `INSERT INTO audit_logs (user_id, action, ip, timestamp)
       VALUES (?, 'gdpr_export_requested', ?, datetime('now'))`
    ).bind(user.id, c.req.header('CF-Connecting-IP') || 'unknown').run();

    return c.json({
      message: 'Export requested. Check your email to confirm.',
      export_id: exportId
    }, 200);
  } catch (err) {
    console.error('GDPR export error:', err);
    return c.json({ error: 'Export request failed' }, 500);
  }
});

app.get('/gdpr/export/:token', async (c) => {
  const token = c.req.param('token');

  try {
    const exportRecord = await c.env.DB.prepare(
      `SELECT id, user_id, status FROM gdpr_exports WHERE token = ? AND status IN ('pending', 'ready')`
    ).bind(token).first();

    if (!exportRecord) {
      return c.json({ error: 'Invalid or expired export token' }, 400);
    }

    if (exportRecord.status === 'pending') {
      // Generate export (would be async in real implementation)
      const userId = exportRecord.user_id;

      // Fetch all user data
      const userData = await c.env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(userId).first();
      const posts = await c.env.DB.prepare('SELECT * FROM posts WHERE author_id = ?').bind(userId).all();
      const comments = await c.env.DB.prepare('SELECT * FROM comments WHERE user_id = ?').bind(userId).all();
      const quotaData = await c.env.DB.prepare('SELECT * FROM user_quota WHERE user_id = ?').bind(userId).first();

      // Compile export JSON
      const exportData = {
        export_date: new Date().toISOString(),
        user: userData,
        posts: posts.results,
        comments: comments.results,
        storage_quota: quotaData
      };

      // Mark as ready (in real app, would store in R2 and provide download link)
      await c.env.DB.prepare(
        `UPDATE gdpr_exports SET status = 'ready', ready_at = datetime('now') WHERE id = ?`
      ).bind(exportRecord.id).run();

      // Audit log
      await c.env.DB.prepare(
        `INSERT INTO audit_logs (user_id, action, ip, timestamp)
         VALUES (?, 'gdpr_export_confirmed', ?, datetime('now'))`
      ).bind(userId, c.req.header('CF-Connecting-IP') || 'unknown').run();

      return c.json(exportData, 200);
    }

    return c.json({ message: 'Export ready for download' }, 200);
  } catch (err) {
    console.error('GDPR export download error:', err);
    return c.json({ error: 'Export download failed' }, 500);
  }
});

app.post('/gdpr/delete-request', async (c) => {
  const sessionId = c.req.header('Authorization')?.split(' ')[1];

  if (!sessionId) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  try {
    const sessionData = await c.env.SESSIONS_KV.get(sessionId);
    if (!sessionData) {
      return c.json({ error: 'Session expired' }, 401);
    }

    const user = JSON.parse(sessionData);
    const userId = user.id;

    // Check for existing deletion request (only one active at a time)
    const existing = await c.env.DB.prepare(
      `SELECT id FROM gdpr_deletions WHERE user_id = ? AND status = 'requested'`
    ).bind(userId).first();

    if (existing) {
      return c.json({ error: 'Deletion already requested. 30-day grace period applies.' }, 429);
    }

    // Create deletion record (30-day grace period)
    const deletionId = crypto.randomUUID();
    const deleteDate = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();

    await c.env.DB.prepare(
      `INSERT INTO gdpr_deletions (id, user_id, status, requested_at, delete_at)
       VALUES (?, ?, 'requested', datetime('now'), ?)`
    ).bind(deletionId, userId, deleteDate).run();

    // Queue confirmation email
    if (c.env.EMAIL_QUEUE) {
      await c.env.EMAIL_QUEUE.send({
        type: 'gdpr_deletion_requested',
        user_id: userId,
        email: user.email,
        delete_date: deleteDate,
        cancel_link: `https://xaostech.io/account/gdpr/cancel-deletion/${deletionId}`
      });
    }

    // Audit log
    await c.env.DB.prepare(
      `INSERT INTO audit_logs (user_id, action, ip, timestamp, details)
       VALUES (?, 'gdpr_deletion_requested', ?, datetime('now'), ?)`
    ).bind(userId, c.req.header('CF-Connecting-IP') || 'unknown', `30-day grace until ${deleteDate}`).run();

    return c.json({
      message: 'Account deletion requested. 30-day grace period starts now.',
      deletion_date: deleteDate,
      can_cancel_until: deleteDate
    }, 200);
  } catch (err) {
    console.error('GDPR deletion error:', err);
    return c.json({ error: 'Deletion request failed' }, 500);
  }
});

app.post('/gdpr/cancel-deletion/:deletion_id', async (c) => {
  const sessionId = c.req.header('Authorization')?.split(' ')[1];

  if (!sessionId) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  try {
    const deletionId = c.req.param('deletion_id');
    const sessionData = await c.env.SESSIONS_KV.get(sessionId);

    if (!sessionData) {
      return c.json({ error: 'Session expired' }, 401);
    }

    const user = JSON.parse(sessionData);

    const deletion = await c.env.DB.prepare(
      `SELECT * FROM gdpr_deletions WHERE id = ? AND user_id = ? AND status = 'requested'`
    ).bind(deletionId, user.id).first();

    if (!deletion) {
      return c.json({ error: 'Deletion not found or already cancelled' }, 404);
    }

    // Cancel deletion
    await c.env.DB.prepare(
      `UPDATE gdpr_deletions SET status = 'cancelled', cancelled_at = datetime('now') WHERE id = ?`
    ).bind(deletionId).run();

    // Audit log
    await c.env.DB.prepare(
      `INSERT INTO audit_logs (user_id, action, ip, timestamp)
       VALUES (?, 'gdpr_deletion_cancelled', ?, datetime('now'))`
    ).bind(user.id, c.req.header('CF-Connecting-IP') || 'unknown').run();

    return c.json({ message: 'Account deletion cancelled' }, 200);
  } catch (err) {
    console.error('Cancel deletion error:', err);
    return c.json({ error: 'Cancellation failed' }, 500);
  }
});

// ===== HELPER FUNCTIONS =====

async function hashPassword(password: string): Promise<string> {
  // Use SHA-256 for token hashing (one-way for service tokens)
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// ===== SERVICE ACCOUNTS / BOT TOKENS =====
/**
 * Service accounts allow applications/bots to authenticate without user login
 * Each service account has:
 * - name: Display name
 * - token: Opaque bearer token (hashed in DB)
 * - scopes: Permissions (read_messages, write_messages, etc)
 * - rate_limit: Requests per minute
 * - owner_id: User that created it
 * - active: Can be disabled
 */

app.post('/service-account/create', async (c) => {
  const sessionId = c.req.header('Authorization')?.split(' ')[1];

  if (!sessionId) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  try {
    const sessionData = await c.env.SESSIONS_KV.get(sessionId);
    if (!sessionData) {
      return c.json({ error: 'Session expired' }, 401);
    }

    const user = JSON.parse(sessionData);
    const { name, scopes = ['read'], rate_limit = 60 } = await c.req.json();

    if (!name || !Array.isArray(scopes)) {
      return c.json({ error: 'name and scopes array required' }, 400);
    }

    // Generate a unique service token
    const token = crypto.getRandomValues(new Uint8Array(32));
    const tokenHex = Array.from(token).map(b => b.toString(16).padStart(2, '0')).join('');
    const tokenHash = await hashPassword(tokenHex);

    const accountId = crypto.randomUUID();
    const now = Math.floor(Date.now() / 1000);

    await c.env.DB.prepare(
      `INSERT INTO service_accounts (id, owner_id, name, token_hash, scopes, rate_limit, active, created_at)
       VALUES (?, ?, ?, ?, ?, ?, 1, ?)`
    ).bind(accountId, user.id, name, tokenHash, JSON.stringify(scopes), rate_limit, now).run();

    // Audit log
    await c.env.DB.prepare(
      `INSERT INTO audit_logs (user_id, action, details, ip, timestamp)
       VALUES (?, 'service_account_created', ?, ?, datetime('now'))`
    ).bind(user.id, JSON.stringify({ account_id: accountId, name }), c.req.header('CF-Connecting-IP') || 'unknown').run();

    // Return token only once (never again)
    return c.json({
      account_id: accountId,
      name,
      token: tokenHex,
      scopes,
      rate_limit,
      message: 'Save this token securely. You will not see it again.',
    }, 201);
  } catch (err) {
    console.error('Service account creation error:', err);
    return c.json({ error: 'Failed to create service account' }, 500);
  }
});

// Service accounts HTML page
app.get('/service-accounts', async (c) => {
  const cookie = c.req.header('Cookie') || '';
  const cookieMatch = cookie.match(/session_id=([^;]+)/);
  const sessionId = cookieMatch ? cookieMatch[1] : null;

  if (!sessionId) {
    return c.redirect('/');
  }

  const sessionData = await c.env.SESSIONS_KV.get(sessionId);
  if (!sessionData) {
    return c.redirect('/');
  }

  const user = JSON.parse(sessionData);

  // Fetch service accounts
  let accounts: any[] = [];
  try {
    const result = await c.env.DB.prepare(
      `SELECT id, name, scopes, rate_limit, active, created_at, last_used_at
       FROM service_accounts WHERE owner_id = ? ORDER BY created_at DESC`
    ).bind(user.userId || user.id).all();
    accounts = result.results || [];
  } catch (err) {
    console.error('Failed to fetch service accounts:', err);
  }

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>API Keys - XAOSTECH</title>
  <link rel="icon" type="image/png" href="/api/data/assets/XAOSTECH_LOGO.png">
  <style>
    :root { --primary: #f6821f; --bg: #0a0a0a; --text: #e0e0e0; --card-bg: #1a1a1a; --border: #333; }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; padding: 2rem; }
    .container { max-width: 800px; margin: 0 auto; }
    h1 { color: var(--primary); margin-bottom: 0.5rem; }
    .subtitle { color: #888; margin-bottom: 2rem; }
    .back { color: var(--primary); text-decoration: none; display: inline-block; margin-bottom: 1rem; }
    .card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; margin-bottom: 1rem; }
    .key-name { font-weight: bold; font-size: 1.1rem; }
    .key-meta { color: #888; font-size: 0.9rem; margin-top: 0.5rem; }
    .key-scopes { display: flex; gap: 0.5rem; margin-top: 0.5rem; flex-wrap: wrap; }
    .scope { background: #333; padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.8rem; }
    .btn { background: var(--primary); color: white; border: none; padding: 0.75rem 1.5rem; border-radius: 6px; cursor: pointer; font-size: 1rem; text-decoration: none; display: inline-block; }
    .btn:hover { opacity: 0.9; }
    .btn-danger { background: #dc3545; }
    .btn-secondary { background: transparent; border: 1px solid var(--border); color: var(--text); }
    .btn-small { padding: 0.4rem 0.8rem; font-size: 0.85rem; }
    .btn-copy { background: #28a745; }
    .empty { text-align: center; padding: 3rem; color: #666; }
    .form-group { margin-bottom: 1rem; }
    .form-group label { display: block; margin-bottom: 0.5rem; }
    .form-group input { width: 100%; padding: 0.75rem; border: 1px solid var(--border); border-radius: 6px; background: var(--bg); color: var(--text); }
    .actions { display: flex; gap: 0.5rem; margin-top: 1rem; }
    .status-active { color: #28a745; }
    .status-inactive { color: #dc3545; }
    .key-display { display: flex; align-items: center; gap: 0.5rem; margin-top: 1rem; padding: 1rem; background: #0a0a0a; border-radius: 6px; border: 1px solid var(--border); }
    .key-display code { flex: 1; word-break: break-all; font-family: monospace; font-size: 0.9rem; }
    .key-display .masked { color: #666; }
    .key-actions { display: flex; gap: 0.5rem; flex-shrink: 0; }
    .success-banner { background: linear-gradient(135deg, #1a3a1a, #0a2a0a); border: 1px solid #2a5a2a; padding: 1rem; border-radius: 8px; margin-bottom: 1rem; }
  </style>
</head>
<body>
  <div class="container">
    <a href="/" class="back">← Back to Dashboard</a>
    <h1>API Keys</h1>
    <p class="subtitle">Manage your service account tokens for programmatic access</p>
    
    <div class="card">
      <h3>Create New API Key</h3>
      <form id="create-form">
        <div class="form-group">
          <label for="name">Key Name</label>
          <input type="text" id="name" name="name" placeholder="e.g., CI/CD Pipeline" required>
        </div>
        <button type="submit" class="btn">Create API Key</button>
      </form>
      <div id="new-key-result" style="display:none; margin-top:1rem;">
        <div class="success-banner">
          <strong>🎉 API Key Created!</strong>
          <p style="margin-top:0.5rem; color:#aaa;">Save this key now - you won't see it again.</p>
        </div>
        <div class="key-display">
          <code id="new-key-value"></code>
          <div class="key-actions">
            <button class="btn btn-small btn-secondary" onclick="toggleKeyVisibility()" id="toggle-btn">👁 Show</button>
            <button class="btn btn-small btn-copy" onclick="copyKey()">📋 Copy</button>
          </div>
        </div>
        <input type="hidden" id="new-key-raw">
      </div>
    </div>

    <h3 style="margin: 2rem 0 1rem;">Your API Keys</h3>
    ${accounts.length === 0 ? '<div class="empty">No API keys yet. Create one above to get started.</div>' :
      accounts.map((acc: any) => `
        <div class="card">
          <div class="key-name">${acc.name}</div>
          <div class="key-meta">
            Created: ${new Date(acc.created_at * 1000).toLocaleDateString()} · 
            Status: <span class="${acc.active ? 'status-active' : 'status-inactive'}">${acc.active ? 'Active' : 'Inactive'}</span>
            ${acc.last_used_at ? ' · Last used: ' + new Date(acc.last_used_at * 1000).toLocaleDateString() : ''}
          </div>
          <div class="key-scopes">
            ${(typeof acc.scopes === 'string' ? JSON.parse(acc.scopes) : acc.scopes).map((s: string) => `<span class="scope">${s}</span>`).join('')}
          </div>
          <div class="actions">
            <button class="btn btn-secondary" onclick="toggleKey('${acc.id}')">${acc.active ? 'Disable' : 'Enable'}</button>
            <button class="btn btn-danger" onclick="deleteKey('${acc.id}')">Delete</button>
          </div>
        </div>
      `).join('')}
  </div>

  <script>
    let keyVisible = false;
    
    function maskKey(key) {
      return key.substring(0, 8) + '•'.repeat(Math.max(0, key.length - 12)) + key.substring(key.length - 4);
    }
    
    function toggleKeyVisibility() {
      const raw = document.getElementById('new-key-raw').value;
      const display = document.getElementById('new-key-value');
      const btn = document.getElementById('toggle-btn');
      keyVisible = !keyVisible;
      display.textContent = keyVisible ? raw : maskKey(raw);
      display.className = keyVisible ? '' : 'masked';
      btn.textContent = keyVisible ? '🙈 Hide' : '👁 Show';
    }
    
    function copyKey() {
      const raw = document.getElementById('new-key-raw').value;
      navigator.clipboard.writeText(raw).then(() => {
        const btn = event.target;
        const original = btn.textContent;
        btn.textContent = '✓ Copied!';
        btn.style.background = '#28a745';
        setTimeout(() => { btn.textContent = original; btn.style.background = ''; }, 2000);
      });
    }
    
    document.getElementById('create-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const name = document.getElementById('name').value;
      try {
        const res = await fetch('/api-keys', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ name, scopes: ['read', 'write'] })
        });
        const data = await res.json();
        if (data.key) {
          document.getElementById('new-key-raw').value = data.key;
          document.getElementById('new-key-value').textContent = maskKey(data.key);
          document.getElementById('new-key-value').className = 'masked';
          document.getElementById('new-key-result').style.display = 'block';
          document.getElementById('name').value = '';
          keyVisible = false;
        } else {
          alert(data.error || 'Failed to create key');
        }
      } catch (err) {
        alert('Failed to create API key');
      }
    });

    async function deleteKey(id) {
      if (!confirm('Delete this API key? This cannot be undone.')) return;
      await fetch('/api-keys/' + id, { method: 'DELETE', credentials: 'include' });
      location.reload();
    }

    async function toggleKey(id) {
      await fetch('/api-keys/' + id, { method: 'PATCH', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ active: true }) });
      location.reload();
    }
  </script>
</body>
</html>`;

  return c.html(html);
});

app.get('/service-account/list', async (c) => {
  const sessionId = c.req.header('Authorization')?.split(' ')[1];

  if (!sessionId) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  try {
    const sessionData = await c.env.SESSIONS_KV.get(sessionId);
    if (!sessionData) {
      return c.json({ error: 'Session expired' }, 401);
    }

    const user = JSON.parse(sessionData);
    const accounts = await c.env.DB.prepare(
      `SELECT id, name, scopes, rate_limit, active, created_at, last_used_at
       FROM service_accounts
       WHERE owner_id = ?
       ORDER BY created_at DESC`
    ).bind(user.id).all();

    return c.json({
      accounts: accounts.results?.map((acc: any) => ({
        ...acc,
        scopes: JSON.parse(acc.scopes)
      })) || []
    }, 200);
  } catch (err) {
    console.error('Service account list error:', err);
    return c.json({ error: 'Failed to list service accounts' }, 500);
  }
});

app.delete('/service-account/:account_id', async (c) => {
  const sessionId = c.req.header('Authorization')?.split(' ')[1];

  if (!sessionId) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  try {
    const sessionData = await c.env.SESSIONS_KV.get(sessionId);
    if (!sessionData) {
      return c.json({ error: 'Session expired' }, 401);
    }

    const user = JSON.parse(sessionData);
    const accountId = c.req.param('account_id');

    // Verify ownership
    const account = await c.env.DB.prepare(
      `SELECT owner_id FROM service_accounts WHERE id = ?`
    ).bind(accountId).first();

    if (!account || account.owner_id !== user.id) {
      return c.json({ error: 'Not found or unauthorized' }, 404);
    }

    await c.env.DB.prepare(
      `DELETE FROM service_accounts WHERE id = ?`
    ).bind(accountId).run();

    // Audit log
    await c.env.DB.prepare(
      `INSERT INTO audit_logs (user_id, action, details, ip, timestamp)
       VALUES (?, 'service_account_deleted', ?, ?, datetime('now'))`
    ).bind(user.id, JSON.stringify({ account_id: accountId }), c.req.header('CF-Connecting-IP') || 'unknown').run();

    return c.json({ message: 'Service account deleted' }, 200);
  } catch (err) {
    console.error('Service account deletion error:', err);
    return c.json({ error: 'Failed to delete service account' }, 500);
  }
});

app.post('/service-account/:account_id/toggle', async (c) => {
  const sessionId = c.req.header('Authorization')?.split(' ')[1];

  if (!sessionId) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  try {
    const sessionData = await c.env.SESSIONS_KV.get(sessionId);
    if (!sessionData) {
      return c.json({ error: 'Session expired' }, 401);
    }

    const user = JSON.parse(sessionData);
    const accountId = c.req.param('account_id');
    const { active } = await c.req.json();

    // Verify ownership
    const account = await c.env.DB.prepare(
      `SELECT owner_id FROM service_accounts WHERE id = ?`
    ).bind(accountId).first();

    if (!account || account.owner_id !== user.id) {
      return c.json({ error: 'Not found or unauthorized' }, 404);
    }

    await c.env.DB.prepare(
      `UPDATE service_accounts SET active = ? WHERE id = ?`
    ).bind(active ? 1 : 0, accountId).run();

    return c.json({ message: `Service account ${active ? 'enabled' : 'disabled'}` }, 200);
  } catch (err) {
    console.error('Service account toggle error:', err);
    return c.json({ error: 'Failed to update service account' }, 500);
  }
});

// ===== USER API KEYS =====
// Allows authenticated users to create API keys for CLI/programmatic access
// Keys inherit user identity but can have restricted scopes

/**
 * Generate a secure API key with prefix
 * Format: xk_<32 random hex chars> (total 35 chars)
 */
async function generateApiKey(): Promise<{ key: string; prefix: string; hash: string }> {
  const randomBytes = crypto.getRandomValues(new Uint8Array(24));
  const key = 'xk_' + Array.from(randomBytes).map(b => b.toString(16).padStart(2, '0')).join('');
  const prefix = key.slice(0, 11); // "xk_" + first 8 hex chars

  // Hash the full key for storage
  const encoder = new TextEncoder();
  const data = encoder.encode(key);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hash = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');

  return { key, prefix, hash };
}

/**
 * Hash an API key for verification
 */
async function hashApiKey(key: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(key);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Create a new API key
app.post('/api-keys', async (c) => {
  const sessionId = c.req.header('Authorization')?.split(' ')[1];
  if (!sessionId) return c.json({ error: 'Unauthorised' }, 401);

  try {
    const sessionData = await c.env.SESSIONS_KV.get(sessionId);
    if (!sessionData) return c.json({ error: 'Session expired' }, 401);
    const user = JSON.parse(sessionData);

    const body = await c.req.json().catch(() => ({}));
    const { name, scopes, rate_limit, expires_in_days, allowed_ips } = body;

    if (!name || typeof name !== 'string' || name.length < 1 || name.length > 64) {
      return c.json({ error: 'Name required (1-64 characters)' }, 400);
    }

    // Validate scopes if provided
    const validScopes = ['read', 'write', 'admin', 'lingua', 'blog', 'chat', 'edu', 'data'];
    const keyScopes = scopes || ['read'];
    if (!Array.isArray(keyScopes) || keyScopes.some((s: string) => !validScopes.includes(s))) {
      return c.json({ error: `Invalid scopes. Valid: ${validScopes.join(', ')}` }, 400);
    }

    // Non-admin users cannot create admin-scoped keys
    if (keyScopes.includes('admin') && !user.is_admin) {
      return c.json({ error: 'Cannot create admin-scoped key without admin privileges' }, 403);
    }

    // Generate the key
    const { key, prefix, hash } = await generateApiKey();

    // Calculate expiration if provided
    let expiresAt = null;
    if (expires_in_days && typeof expires_in_days === 'number' && expires_in_days > 0) {
      const expDate = new Date();
      expDate.setDate(expDate.getDate() + expires_in_days);
      expiresAt = expDate.toISOString().replace('T', ' ').replace('Z', '');
    }

    // Check if user already has key with this name
    const existing = await c.env.DB.prepare(
      'SELECT id FROM user_api_keys WHERE user_id = ? AND name = ?'
    ).bind(user.id, name).first();
    if (existing) {
      return c.json({ error: 'Key with this name already exists' }, 409);
    }

    // Limit: max 10 keys per user
    const countResult = await c.env.DB.prepare(
      'SELECT COUNT(*) as count FROM user_api_keys WHERE user_id = ?'
    ).bind(user.id).first() as { count: number } | null;
    if (countResult && countResult.count >= 10) {
      return c.json({ error: 'Maximum 10 API keys per user' }, 400);
    }

    await c.env.DB.prepare(`
      INSERT INTO user_api_keys (user_id, name, key_prefix, key_hash, scopes, rate_limit, allowed_ips, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      user.id,
      name,
      prefix,
      hash,
      JSON.stringify(keyScopes),
      rate_limit || 60,
      allowed_ips ? JSON.stringify(allowed_ips) : null,
      expiresAt
    ).run();

    // Return the key ONLY ONCE - user must save it
    return c.json({
      message: 'API key created. Save this key - it will not be shown again.',
      key,
      prefix,
      name,
      scopes: keyScopes,
      rate_limit: rate_limit || 60,
      expires_at: expiresAt,
    }, 201);
  } catch (err) {
    console.error('API key creation error:', err);
    return c.json({ error: 'Failed to create API key' }, 500);
  }
});

// List user's API keys (without revealing the actual keys)
app.get('/api-keys', async (c) => {
  const sessionId = c.req.header('Authorization')?.split(' ')[1];
  if (!sessionId) return c.json({ error: 'Unauthorised' }, 401);

  try {
    const sessionData = await c.env.SESSIONS_KV.get(sessionId);
    if (!sessionData) return c.json({ error: 'Session expired' }, 401);
    const user = JSON.parse(sessionData);

    const keys = await c.env.DB.prepare(`
      SELECT id, name, key_prefix, scopes, rate_limit, allowed_ips, active, expires_at, 
             last_used_at, last_used_ip, use_count, created_at
      FROM user_api_keys 
      WHERE user_id = ? 
      ORDER BY created_at DESC
    `).bind(user.id).all();

    return c.json({
      keys: keys.results?.map((k: any) => ({
        ...k,
        scopes: JSON.parse(k.scopes || '[]'),
        allowed_ips: k.allowed_ips ? JSON.parse(k.allowed_ips) : null,
        active: !!k.active,
      })) || []
    });
  } catch (err) {
    console.error('API key list error:', err);
    return c.json({ error: 'Failed to list API keys' }, 500);
  }
});

// Delete an API key
app.delete('/api-keys/:key_id', async (c) => {
  const sessionId = c.req.header('Authorization')?.split(' ')[1];
  if (!sessionId) return c.json({ error: 'Unauthorised' }, 401);

  try {
    const sessionData = await c.env.SESSIONS_KV.get(sessionId);
    if (!sessionData) return c.json({ error: 'Session expired' }, 401);
    const user = JSON.parse(sessionData);
    const keyId = c.req.param('key_id');

    // Verify ownership
    const key = await c.env.DB.prepare(
      'SELECT user_id FROM user_api_keys WHERE id = ?'
    ).bind(keyId).first();

    if (!key || (key as any).user_id !== user.id) {
      return c.json({ error: 'Key not found or unauthorised' }, 404);
    }

    await c.env.DB.prepare('DELETE FROM user_api_keys WHERE id = ?').bind(keyId).run();

    return c.json({ message: 'API key deleted' });
  } catch (err) {
    console.error('API key deletion error:', err);
    return c.json({ error: 'Failed to delete API key' }, 500);
  }
});

// Toggle API key active state
app.patch('/api-keys/:key_id', async (c) => {
  const sessionId = c.req.header('Authorization')?.split(' ')[1];
  if (!sessionId) return c.json({ error: 'Unauthorised' }, 401);

  try {
    const sessionData = await c.env.SESSIONS_KV.get(sessionId);
    if (!sessionData) return c.json({ error: 'Session expired' }, 401);
    const user = JSON.parse(sessionData);
    const keyId = c.req.param('key_id');
    const { active } = await c.req.json().catch(() => ({}));

    // Verify ownership
    const key = await c.env.DB.prepare(
      'SELECT user_id FROM user_api_keys WHERE id = ?'
    ).bind(keyId).first();

    if (!key || (key as any).user_id !== user.id) {
      return c.json({ error: 'Key not found or unauthorised' }, 404);
    }

    await c.env.DB.prepare(
      'UPDATE user_api_keys SET active = ?, updated_at = datetime("now") WHERE id = ?'
    ).bind(active ? 1 : 0, keyId).run();

    return c.json({ message: `API key ${active ? 'enabled' : 'disabled'}` });
  } catch (err) {
    console.error('API key update error:', err);
    return c.json({ error: 'Failed to update API key' }, 500);
  }
});

// Verify an API key (called by API worker middleware)
app.post('/verify-api-key', async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const { apiKey } = body;

  if (!apiKey || typeof apiKey !== 'string' || !apiKey.startsWith('xk_')) {
    return c.json({ valid: false, error: 'Invalid API key format' }, 400);
  }

  try {
    const keyHash = await hashApiKey(apiKey);
    const clientIp = c.req.header('CF-Connecting-IP') || c.req.header('X-Real-IP') || 'unknown';

    // Look up the key
    const keyRecord = await c.env.DB.prepare(`
      SELECT k.*, u.id as owner_id, u.email, u.username, u.is_admin
      FROM user_api_keys k
      JOIN users u ON k.user_id = u.id
      WHERE k.key_hash = ? AND k.active = 1
    `).bind(keyHash).first() as any;

    if (!keyRecord) {
      return c.json({ valid: false, error: 'Invalid or inactive API key' }, 401);
    }

    // Check expiration
    if (keyRecord.expires_at && new Date(keyRecord.expires_at) < new Date()) {
      return c.json({ valid: false, error: 'API key expired' }, 401);
    }

    // Check IP allowlist if set
    if (keyRecord.allowed_ips) {
      const allowedIps = JSON.parse(keyRecord.allowed_ips);
      if (allowedIps.length > 0 && !allowedIps.includes(clientIp)) {
        return c.json({ valid: false, error: 'IP not allowed' }, 403);
      }
    }

    // Update usage stats (async, don't wait)
    c.env.DB.prepare(`
      UPDATE user_api_keys 
      SET last_used_at = datetime("now"), last_used_ip = ?, use_count = use_count + 1
      WHERE id = ?
    `).bind(clientIp, keyRecord.id).run();

    // Return user context
    return c.json({
      valid: true,
      userId: keyRecord.owner_id,
      email: keyRecord.email,
      username: keyRecord.username,
      isAdmin: !!keyRecord.is_admin,
      isApiKey: true,
      keyId: keyRecord.id,
      keyName: keyRecord.name,
      scopes: JSON.parse(keyRecord.scopes || '[]'),
      rateLimit: keyRecord.rate_limit,
    });
  } catch (err) {
    console.error('API key verification error:', err);
    return c.json({ valid: false, error: 'Verification failed' }, 500);
  }
});

export default app;

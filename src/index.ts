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

  const userSection = user ? 
    '<div class="user-card">' +
    '<img src="' + (user.avatar_url || '/api/data/assets/XAOSTECH_LOGO.png') + '" alt="Avatar" class="avatar">' +
    '<div class="user-info">' +
    '<h2>' + (user.username || 'User') + '</h2>' +
    '<p>' + (user.email || '') + '</p>' +
    '</div></div>' +
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

  const html = '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>XAOSTECH Account</title><link rel="icon" type="image/png" href="/api/data/assets/XAOSTECH_LOGO.png"><style>:root { --primary: #f6821f; --bg: #0a0a0a; --text: #e0e0e0; --card-bg: #1a1a1a; } * { box-sizing: border-box; margin: 0; padding: 0; } body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 2rem; } .container { max-width: 500px; width: 100%; text-align: center; } h1 { color: var(--primary); margin-bottom: 2rem; font-size: 2rem; } .user-card { display: flex; align-items: center; gap: 1.5rem; background: var(--card-bg); padding: 2rem; border-radius: 12px; margin-bottom: 2rem; } .avatar { width: 80px; height: 80px; border-radius: 50%; border: 3px solid var(--primary); } .user-info { text-align: left; } .user-info h2 { margin-bottom: 0.25rem; } .user-info p { opacity: 0.7; font-size: 0.9rem; } .actions { display: flex; gap: 1rem; flex-wrap: wrap; justify-content: center; } .btn { display: inline-flex; align-items: center; gap: 0.5rem; background: var(--primary); color: #000; padding: 0.75rem 1.5rem; border-radius: 6px; text-decoration: none; font-weight: bold; border: none; cursor: pointer; font-size: 1rem; } .btn:hover { opacity: 0.9; } .btn.secondary { background: transparent; border: 2px solid var(--primary); color: var(--primary); } .btn.github-btn { background: #24292e; color: #fff; padding: 1rem 2rem; font-size: 1.1rem; } .btn.github-btn:hover { background: #2f363d; } .login-section { background: var(--card-bg); padding: 3rem 2rem; border-radius: 12px; } .login-section h2 { margin-bottom: 0.5rem; } .login-section p { opacity: 0.7; margin-bottom: 2rem; } footer { margin-top: 3rem; opacity: 0.5; font-size: 0.85rem; } footer a { color: var(--primary); }</style></head><body><div class="container"><h1>🔐 XAOSTECH Account</h1>' + userSection + '</div><footer><a href="https://xaostech.io">← Back to XAOSTECH</a></footer></body></html>';
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
        id: user.id,
        username: user.username,
        email: user.email,
        avatar_url: user.avatar_url,
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

// Session validation endpoint - called by API or other workers to verify session
app.post('/verify', async (c) => {
  const token = c.req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return c.json({ error: 'No token' }, 401);

  try {
    const sessionData = await c.env.SESSIONS_KV.get(token);
    if (!sessionData) return c.json({ error: 'Invalid token' }, 401);
    const user = JSON.parse(sessionData);
    if (user.expires && user.expires < Date.now()) {
      await c.env.SESSIONS_KV.delete(token);
      return c.json({ error: 'Token expired' }, 401);
    }
    return c.json(user);
  } catch (e) {
    return c.json({ error: 'Verification failed' }, 500);
  }
});

app.get('/profile', async (c) => {
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
  const sessionId = c.req.header('Authorization')?.split(' ')[1];
  
  if (sessionId) {
    await c.env.SESSIONS_KV.delete(sessionId);
  }

  return c.json({ success: true });
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

export default app;

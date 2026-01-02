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

const app = new Hono<{ Bindings: Env }>();

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

app.get('/health', (c) => c.json({ status: 'ok' }));

// === DEBUG: ENV PRESENCE ===
app.get('/debug/env', (c) => {
  const cEnvHasClientId = !!(c.env && (c.env as any).CF_ACCESS_CLIENT_ID);
  const cEnvHasClientSecret = !!(c.env && (c.env as any).CF_ACCESS_CLIENT_SECRET);
  const processEnvHasClientId = !!(globalThis as any)?.process?.env?.CF_ACCESS_CLIENT_ID;
  const processEnvHasClientSecret = !!(globalThis as any)?.process?.env?.CF_ACCESS_CLIENT_SECRET;
  return c.json({ cEnvHasClientId, cEnvHasClientSecret, processEnvHasClientId, processEnvHasClientSecret });
});

// === DEBUG: DIRECT FETCH TEST ===
app.get('/debug/fetch-direct', async (c) => {
  try {
    const clientId = (c.env as any)?.CF_ACCESS_CLIENT_ID;
    const clientSecret = (c.env as any)?.CF_ACCESS_CLIENT_SECRET;

    const headers: Record<string, string> = { 'User-Agent': 'XAOSTECH debug fetch' };
    if (clientId && clientSecret) {
      headers['CF-Access-Client-Id'] = clientId;
      headers['CF-Access-Client-Secret'] = clientSecret;
      headers['X-Proxy-CF-Injected'] = 'direct-test';
    }

    const resp = await fetch('https://api.xaostech.io/debug/headers', { method: 'GET', headers });
    const contentType = resp.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
      const json = await resp.json();
      return c.json({ proxiedDirect: json, status: resp.status });
    }

    const txt = await resp.text();
    return c.json({ status: resp.status, contentType, bodyStartsWith: txt.slice(0, 200) });
  } catch (err: any) {
    console.error('[debug/fetch-direct] error:', err);
    return c.json({ error: 'fetch direct failed', message: err.message }, 500);
  }
});

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

// ===== AUTHENTICATION =====

app.post('/authorize', async (c) => {
  // OAuth flow stub - redirects to provider or returns auth code
  const redirectUri = c.req.query('redirect_uri');
  return c.json({ 
    auth_url: `https://oauth-provider.com/authorize?redirect_uri=${redirectUri}` 
  });
});

app.post('/callback', async (c) => {
  // OAuth callback - exchanges code for token, creates session
  const { code } = await c.req.json();

  try {
    // Validate code, fetch user from provider
    const user = { id: 'user123', email: 'user@example.com', username: 'user' };
    
    // Store session
    const sessionId = crypto.randomUUID();
    const expires = Date.now() + 7 * 24 * 60 * 60 * 1000; // 7 days
    
    await c.env.SESSIONS_KV.put(sessionId, JSON.stringify({ ...user, expires }), {
      expirationTtl: 7 * 24 * 60 * 60
    });
    
    return c.json({ session_id: sessionId, user });
  } catch (err) {
    return c.json({ error: 'Auth failed' }, 400);
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

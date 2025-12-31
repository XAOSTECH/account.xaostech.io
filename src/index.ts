import { Hono } from 'hono';

const app = new Hono();

app.get('/health', (c) => c.json({ status: 'ok' }));

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
  const db = c.env.DB;

  try {
    // Validate code, fetch user from provider
    const user = { id: 'user123', email: 'user@example.com', username: 'user' };
    
    // Store session
    const sessionId = crypto.randomUUID();
    const expires = Date.now() + 7 * 24 * 60 * 60 * 1000; // 7 days
    
    await c.env.SESSIONS_KV.put(sessionId, JSON.stringify({ ...user, expires }));
    
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

export default app;

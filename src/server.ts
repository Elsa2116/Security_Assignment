import express from 'express';
import helmet from 'helmet';
import crypto from 'node:crypto';
import { auth } from './auth/better-auth.js';
import { config } from './config.js';
import { query } from './db/pool.js';
import { api } from './api.js';
import { verifyCaptcha } from './security/captcha.js';
import { isRateLimited, recordLoginFailure, recordLoginSuccess } from './security/login-protection.js';

const app = express();

// Check only the first five SHA-1 characters with HIBP's k-anonymity API; the password and full hash never leave this process.
async function isBreachedPassword(password: string) {
  if (process.env.HIBP_PASSWORD_CHECK !== 'true') return false;
  const digest = crypto.createHash('sha1').update(password).digest('hex').toUpperCase();
  const response = await fetch(`https://api.pwnedpasswords.com/range/${digest.slice(0, 5)}`, { headers: { 'User-Agent': 'SecureFlow-password-policy' } });
  if (!response.ok) throw new Error('HIBP_UNAVAILABLE');
  const suffix = digest.slice(5);
  return (await response.text()).split('\n').some(line => line.split(':')[0]?.trim() === suffix);
}
// Helmet provides baseline browser security headers for every response.
app.use(helmet());
app.use(express.json({ limit: '1mb' }));
// Serve the browser UI from the same origin and prevent stale authentication JavaScript from being cached.
app.use(express.static('public', { setHeaders: (res, filePath) => { if (filePath.endsWith('.html') || filePath.endsWith('.js')) res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate'); } }));
// Enforce same-origin or explicit CSRF proof on state-changing application routes.
app.use((req, res, next) => {
  const requestId = req.header('x-request-id') || crypto.randomUUID();
  res.setHeader('x-request-id', requestId);
  if (['POST','PATCH','PUT','DELETE'].includes(req.method) && req.path.startsWith('/api/v1/')) {
    const origin = req.header('origin');
    const configuredOrigin = new URL(config.BETTER_AUTH_URL).origin;
    const csrf = req.header('x-csrf-token');
    if ((origin && origin !== configuredOrigin) || (!origin && !csrf)) return res.status(403).json({ error: { code: 'CSRF_BLOCKED', message: 'CSRF protection failed' }, meta: { requestId } });
  }
  next();
});
app.use('/api/v1', api);

// Liveness also checks PostgreSQL because the API is not useful without its database.
app.get('/health', async (_req, res) => {
  try { await query('SELECT 1'); res.json({ status: 'ok', database: 'ok' }); }
  catch { res.status(503).json({ status: 'unavailable' }); }
});

// Delegate all authentication routes to Better Auth; SecureFlow does not duplicate them.
app.all('/api/auth/{*splat}', async (req, res) => {
  // Registration requires CAPTCHA in production; the UI uses the explicit local token only in development.
  if (req.path.endsWith('/sign-up/email')) {
    // Validate confirmation on the server too; browser checks alone are not trusted.
    if (typeof req.body?.password !== 'string' || req.body.password !== req.body?.confirmPassword) return res.status(422).json({ error: { code: 'PASSWORD_MISMATCH', message: 'Passwords do not match' } });
    const captchaValid = await verifyCaptcha(req.body?.captchaToken || req.header('x-captcha-token'), req.ip ?? undefined);
    if (!captchaValid) return res.status(422).json({ error: { code: 'CAPTCHA_REQUIRED', message: 'CAPTCHA verification failed' } });
    try {
      if (await isBreachedPassword(String(req.body.password))) return res.status(422).json({ error: { code: 'PASSWORD_BREACHED', message: 'Choose a password that has not appeared in a known breach' } });
    } catch {
      if (process.env.NODE_ENV === 'production') return res.status(503).json({ error: { code: 'PASSWORD_CHECK_UNAVAILABLE', message: 'Password security check is temporarily unavailable' } });
    }
    delete req.body.confirmPassword;
  }
  // Protect the login endpoint before Better Auth performs password work.
  if (req.path.endsWith('/sign-in/email') && isRateLimited(`${String(req.body?.email ?? '').toLowerCase()}:${req.ip ?? ''}`)) return res.status(429).json({ error: { code: 'LOGIN_THROTTLED', message: 'Too many attempts; try again later' } });
  const headers = new Headers();
  for (const [key, value] of Object.entries(req.headers)) if (value) headers.set(key, Array.isArray(value) ? value.join(', ') : value);
  const response = await auth.handler(new Request(`${config.BETTER_AUTH_URL}${req.originalUrl}`, { method: req.method, headers, body: ['GET', 'HEAD'].includes(req.method) ? undefined : JSON.stringify(req.body) }));
  // Record only outcome metadata; password and token contents never enter logs or alerts.
  if (req.path.endsWith('/sign-in/email')) {
    const email = String(req.body?.email ?? '');
    if (response.status >= 400) await recordLoginFailure(email, req.ip ?? 'unknown');
    else await recordLoginSuccess(email, req.ip ?? 'unknown');
  }
  res.status(response.status);
  response.headers.forEach((value, key) => res.setHeader(key, value));
  res.send(Buffer.from(await response.arrayBuffer()));
});

// Convert parser and unexpected middleware failures into generic JSON; stack traces stay in server logs only.
app.use((error: unknown, req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error('request_failed', { path: req.path, method: req.method, error: error instanceof Error ? error.message : 'unknown' });
  if (res.headersSent) return;
  res.status(400).json({ error: { code: 'INVALID_REQUEST', message: 'The request could not be processed' } });
});

app.listen(config.PORT, () => console.log(`SecureFlow listening on ${config.PORT}`));

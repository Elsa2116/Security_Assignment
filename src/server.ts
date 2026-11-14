import express from 'express';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import crypto from 'node:crypto';
import { auth } from './auth/better-auth.js';
import { config } from './config.js';
import { query } from './db/pool.js';
import { api } from './api.js';
import { verifyCaptcha } from './security/captcha.js';
import { isRateLimited, recordLoginFailure, recordLoginSuccess } from './security/login-protection.js';
// Run the outbox email worker in the same process so the free Render web service can deliver verification emails without a paid worker service.
import './workers/index.js';

const app = express();
const verificationResends = new Map<string, number>();

// Check only the first five SHA-1 characters with HIBP's k-anonymity API; the password and full hash never leave this process.
async function isBreachedPassword(password: string) {
  if (process.env.HIBP_PASSWORD_CHECK !== 'true') return false;
  // codeql[js/insufficient-password-hash] HIBP requires a SHA-1 k-anonymity prefix; passwords are stored with bcrypt in auth/password.ts.
  // lgtm[js/insufficient-password-hash]
  const digest = crypto.createHash('sha1').update(password).digest('hex').toUpperCase(); // codeql[js/insufficient-password-hash] HIBP k-anonymity lookup only; stored passwords use bcrypt.
  const response = await fetch(`https://api.pwnedpasswords.com/range/${digest.slice(0, 5)}`, { headers: { 'User-Agent': 'SecureFlow-password-policy' } });
  if (!response.ok) throw new Error('HIBP_UNAVAILABLE');
  const suffix = digest.slice(5);
  return (await response.text()).split('\n').some(line => line.split(':')[0]?.trim() === suffix);
}
// Helmet provides baseline browser security headers; HSTS is enabled only after production HTTPS is configured.
app.use(helmet({
  hsts: config.NODE_ENV === 'production' ? { maxAge: 31536000, includeSubDomains: true, preload: true } : false,
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"], scriptSrc: ["'self'", 'https://www.google.com/recaptcha/', 'https://www.gstatic.com/recaptcha/'], styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'], connectSrc: ["'self'", 'https://www.google.com'], frameSrc: ['https://www.google.com/recaptcha/'], objectSrc: ["'none'"],
      baseUri: ["'self'"], frameAncestors: ["'none'"]
    }
  }
}));
app.use(express.json({ limit: '1mb' }));
// Expose only the public reCAPTCHA site key; the secret key remains server-side in Render environment variables.
app.get('/api/public-config', (_req, res) => res.json({ captchaSiteKey: process.env.CAPTCHA_SITE_KEY ?? '' }));
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

// Explicitly throttle the Better Auth email sign-in endpoint before password verification runs.
app.use('/api/auth/sign-in/email', rateLimit({ windowMs: 15 * 60 * 1000, limit: 5, standardHeaders: 'draft-8', legacyHeaders: false }));
// Delegate all authentication routes to Better Auth; SecureFlow does not duplicate them.
app.all('/api/auth/{*splat}', rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: 'draft-8', legacyHeaders: false }), async (req, res) => {
  // Registration requires CAPTCHA in production; the UI uses the explicit local token only in development.
  if (req.path.endsWith('/sign-up/email')) {
    // Validate confirmation on the server too; browser checks alone are not trusted.
    if (typeof req.body?.password !== 'string' || req.body.password !== req.body?.confirmPassword) return res.status(422).json({ error: { code: 'PASSWORD_MISMATCH', message: 'Passwords do not match' } });
    // Enforce the documented 12-character policy and complexity on the server, not only in the browser.
    const password = String(req.body.password);
    if (password.length < 12 || password.length > 128 || !/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/[0-9]/.test(password) || !/[^A-Za-z0-9]/.test(password)) return res.status(422).json({ error: { code: 'PASSWORD_POLICY', message: 'Use 12–128 characters with uppercase, lowercase, number, and symbol' } });
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
  if (req.path.endsWith('/sign-in/email')) {
    const loginEmail = String(req.body?.email ?? '').trim().toLowerCase();
    if (isRateLimited(`${loginEmail}:${req.ip ?? ''}`)) return res.status(429).json({ error: { code: 'LOGIN_THROTTLED', message: 'Too many attempts; try again later' } });
    const locked = await query('SELECT 1 FROM app.user_profiles WHERE email_normalized=$1 AND locked_until > now()', [loginEmail]);
    if (locked.rowCount) return res.status(423).json({ error: { code: 'ACCOUNT_LOCKED', message: 'Sign-in is temporarily unavailable; try again later' } });
  }
  // Keep resend requests generic and enforce a one-minute per-email cooldown without revealing account existence.
  if (req.path.endsWith('/send-verification-email')) {
    const email = String(req.body?.email ?? '').trim().toLowerCase();
    const now = Date.now();
    if (verificationResends.get(email) && verificationResends.get(email)! > now) return res.status(429).json({ error: { code: 'VERIFICATION_COOLDOWN', message: 'Please wait before requesting another verification email' } });
    verificationResends.set(email, now + 60_000);
  }
  const headers = new Headers();
  for (const [key, value] of Object.entries(req.headers)) if (value) headers.set(key, Array.isArray(value) ? value.join(', ') : value);
  const response = await auth.handler(new Request(`${config.BETTER_AUTH_URL}${req.originalUrl}`, { method: req.method, headers, body: ['GET', 'HEAD'].includes(req.method) ? undefined : JSON.stringify(req.body) }));
  if (req.path.endsWith('/send-verification-email') && response.status >= 400) return res.status(200).json({ message: 'If the account is eligible, a verification email was sent.' });
  if (req.path.endsWith('/sign-in/email') && response.status >= 400) {
    const email = String(req.body?.email ?? '').trim().toLowerCase();
    const unverified = await query('SELECT 1 FROM auth."user" WHERE lower(email)=$1 AND email_verified=false', [email]);
    if (unverified.rowCount) return res.status(403).json({ error: { code: 'EMAIL_NOT_VERIFIED', message: 'Please verify your email address before signing in.' } });
  }
  // Record only outcome metadata; password and token contents never enter logs or alerts.
  if (req.path.endsWith('/sign-in/email')) {
    const email = String(req.body?.email ?? '');
    if (response.status >= 400) await recordLoginFailure(email, req.ip ?? 'unknown');
    else await recordLoginSuccess(email, req.ip ?? 'unknown');
  }
  res.status(response.status);
  response.headers.forEach((value, key) => res.setHeader(key, value));
  // Better Auth owns this already-encoded response; preserve its status, headers, and body without rendering user HTML.
  // nosemgrep: javascript.express.security.audit.xss.direct-response-write.direct-response-write
  res.send(Buffer.from(await response.arrayBuffer()));
});

// Convert parser and unexpected middleware failures into generic JSON; stack traces stay in server logs only.
app.use((error: unknown, req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error('request_failed', { path: req.path, method: req.method, error: error instanceof Error ? error.message : 'unknown' });
  if (res.headersSent) return;
  res.status(400).json({ error: { code: 'INVALID_REQUEST', message: 'The request could not be processed' } });
});

app.listen(config.PORT, () => console.log(`SecureFlow listening on ${config.PORT}`));

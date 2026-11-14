import type { RequestHandler } from 'express';
import { query, withTransaction } from '../db/pool.js';

const attempts = new Map<string, { count: number; resetAt: number }>();
const MAX_ATTEMPTS = 5;
const WINDOW_MS = 15 * 60 * 1000;

// Apply an explicit request-level limiter to sensitive routes; this complements the database-backed login lockout.
export function routeRateLimit(scope: string, maxAttempts = MAX_ATTEMPTS): RequestHandler {
  return (req, res, next) => {
    const key = `${scope}:${req.ip ?? 'unknown'}`;
    const current = attempts.get(key);
    if (!current || current.resetAt <= Date.now()) attempts.set(key, { count: 1, resetAt: Date.now() + WINDOW_MS });
    else if (++current.count > maxAttempts) return res.status(429).json({ error: { code: 'RATE_LIMITED', message: 'Too many requests; try again later' } });
    next();
  };
}

// Apply a small in-process throttle for local deployments; production should back this with Redis.
export function isRateLimited(key: string) {
  const current = attempts.get(key);
  if (!current || current.resetAt <= Date.now()) return false;
  return current.count >= MAX_ATTEMPTS;
}

// Persist lockout evidence and create a security alert after repeated failures.
export async function recordLoginFailure(email: string, ip: string) {
  const key = `${email.toLowerCase()}:${ip}`;
  const current = attempts.get(key) ?? { count: 0, resetAt: Date.now() + WINDOW_MS };
  current.count += 1;
  attempts.set(key, current);
  if (current.count < MAX_ATTEMPTS) return;
  await withTransaction(async (client) => {
    await client.query(`UPDATE app.user_profiles SET failed_login_count=failed_login_count+1,locked_until=now()+interval '15 minutes' WHERE email_normalized=$1`, [email.toLowerCase()]);
    await client.query(`INSERT INTO app.security_alerts(alert_type,severity,details) VALUES ('LOGIN_LOCKOUT','high',$1)`, [JSON.stringify({ email: email.toLowerCase(), ip })]);
  });
}

// Clear the local throttle after a successful Better Auth login.
export async function recordLoginSuccess(email: string, ip: string) {
  attempts.delete(`${email.toLowerCase()}:${ip}`);
  await query('UPDATE app.user_profiles SET failed_login_count=0,locked_until=NULL WHERE email_normalized=$1', [email.toLowerCase()]);
}

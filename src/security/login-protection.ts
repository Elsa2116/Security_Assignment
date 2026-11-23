import { Redis } from 'ioredis';
import { query, withTransaction } from '../db/pool.js';
import { emitSecurityEvent } from '../observability/siem.js';

const attempts = new Map<string, { count: number; resetAt: number }>();
const MAX_ATTEMPTS = 5;
const WINDOW_MS = 15 * 60 * 1000;
const LOCKOUT_MS = 15 * 60 * 1000;
const redis = process.env.REDIS_URL ? new Redis(process.env.REDIS_URL, { lazyConnect: true, maxRetriesPerRequest: 1 }) : null;

// Use Redis when configured so login throttling is shared by multiple API instances;
// keep the bounded in-process fallback for local development without Redis.
async function redisCommand<T>(work: (client: Redis) => Promise<T>, fallback: T): Promise<T> {
  if (!redis) return fallback;
  try {
    if (redis.status === 'wait') await redis.connect();
    return await work(redis);
  } catch {
    return fallback;
  }
}

// Apply a small in-process throttle for local deployments; production should back this with Redis.
export function isRateLimited(key: string) {
  const current = attempts.get(key);
  if (!current || current.resetAt <= Date.now()) return false;
  return current.count >= MAX_ATTEMPTS;
}

// Check both the local counter and the database lock so every protected sign-in
// request applies the same five-failures/fifteen-minute policy.
export async function isLoginLocked(email: string, ip: string) {
  const key = `${email.toLowerCase()}:${ip}`;
  if (isRateLimited(key)) return true;
  const redisLocked = await redisCommand(async client => (await client.exists(`secureflow:login-lock:${key}`)) === 1, false);
  if (redisLocked) return true;
  const persisted = await query('SELECT 1 FROM app.user_profiles WHERE email_normalized=$1 AND locked_until > now()', [email.toLowerCase()]);
  return Boolean(persisted.rowCount);
}

// Persist lockout evidence and create a security alert after repeated failures.
export async function recordLoginFailure(email: string, ip: string) {
  const key = `${email.toLowerCase()}:${ip}`;
  const current = attempts.get(key) ?? { count: 0, resetAt: Date.now() + WINDOW_MS };
  current.count += 1;
  attempts.set(key, current);
  const distributedCount = await redisCommand(async client => {
    const count = await client.incr(`secureflow:login-failures:${key}`);
    if (count === 1) await client.expire(`secureflow:login-failures:${key}`, Math.ceil(WINDOW_MS / 1000));
    return count;
  }, current.count);
  // Persist every failure for auditability; only the fifth failure activates lockout.
  await withTransaction(async (client) => {
    await client.query(`UPDATE app.user_profiles SET failed_login_count=failed_login_count+1,locked_until=CASE WHEN $2 >= $3 THEN now()+($4 * interval '1 millisecond') ELSE locked_until END WHERE email_normalized=$1`, [email.toLowerCase(), distributedCount, MAX_ATTEMPTS, LOCKOUT_MS]);
    if (distributedCount === MAX_ATTEMPTS) await client.query(`INSERT INTO app.security_alerts(alert_type,severity,details) VALUES ('LOGIN_LOCKOUT','high',$1)`, [JSON.stringify({ email: email.toLowerCase(), ip, durationSeconds: LOCKOUT_MS / 1000 })]);
  });
  if (distributedCount >= MAX_ATTEMPTS) await redisCommand(async client => { await client.set(`secureflow:login-lock:${key}`, '1', 'PX', LOCKOUT_MS); return true; }, false);
  emitSecurityEvent('auth.login_failure', { email: email.toLowerCase(), ip, attempt: distributedCount, locked: distributedCount >= MAX_ATTEMPTS });
}

// Clear the local throttle after a successful Better Auth login.
export async function recordLoginSuccess(email: string, ip: string) {
  const key = `${email.toLowerCase()}:${ip}`;
  attempts.delete(key);
  await redisCommand(async client => { await client.del(`secureflow:login-failures:${key}`, `secureflow:login-lock:${key}`); return true; }, false);
  await query('UPDATE app.user_profiles SET failed_login_count=0,locked_until=NULL WHERE email_normalized=$1', [email.toLowerCase()]);
}

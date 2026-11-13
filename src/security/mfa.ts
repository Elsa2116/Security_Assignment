import crypto from 'node:crypto';
import { authenticator } from 'otplib';
import { config } from '../config.js';
import { query, withTransaction } from '../db/pool.js';

// Derive a local AES key from the configured master secret; raw TOTP seeds never enter logs or audit metadata.
const key = () => crypto.createHash('sha256').update(config.BACKUP_ENCRYPTION_KEY).digest();

// Encrypt the TOTP seed before it is persisted in the application database.
function encrypt(value: string) {
  const iv = crypto.randomBytes(12); const cipher = crypto.createCipheriv('aes-256-gcm', key(), iv); const body = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), body]).toString('base64url');
}

// Decrypt only inside the verification path; callers receive no seed value.
function decrypt(value: string) {
  const raw = Buffer.from(value, 'base64url'); const decipher = crypto.createDecipheriv('aes-256-gcm', key(), raw.subarray(0, 12)); decipher.setAuthTag(raw.subarray(12, 28));
  return Buffer.concat([decipher.update(raw.subarray(28)), decipher.final()]).toString('utf8');
}

// Start enrollment by generating and encrypting a new secret without enabling MFA yet.
export async function beginMfaEnrollment(userId: string) {
  const secret = authenticator.generateSecret();
  await query(`INSERT INTO app.mfa_credentials(user_id,encrypted_secret,enabled_at) VALUES ($1,$2,NULL) ON CONFLICT(user_id) DO UPDATE SET encrypted_secret=EXCLUDED.encrypted_secret,enabled_at=NULL`, [userId, encrypt(secret)]);
  return { issuer: 'SecureFlow', account: userId, otpauthUrl: authenticator.keyuri(userId, 'SecureFlow', secret) };
}

// Confirm the first code, enable MFA, and return recovery codes exactly once.
export async function confirmMfa(userId: string, code: string) {
  const found = await query<{ encrypted_secret: string }>('SELECT encrypted_secret FROM app.mfa_credentials WHERE user_id=$1 AND enabled_at IS NULL', [userId]);
  if (!found.rowCount || !authenticator.verify({ token: code, secret: decrypt(found.rows[0].encrypted_secret) })) return false;
  const codes = Array.from({ length: 10 }, () => crypto.randomBytes(10).toString('hex'));
  await withTransaction(async (client) => {
    await client.query('UPDATE app.mfa_credentials SET enabled_at=now() WHERE user_id=$1', [userId]);
    await client.query('DELETE FROM app.mfa_recovery_codes WHERE user_id=$1', [userId]);
    for (const recoveryCode of codes) await client.query('INSERT INTO app.mfa_recovery_codes(user_id,code_hash) VALUES ($1,$2)', [userId, crypto.createHash('sha256').update(recoveryCode).digest('hex')]);
  });
  return { recoveryCodes: codes };
}

// Verify either the current TOTP or one unused recovery code atomically.
export async function verifyMfa(userId: string, code: string) {
  const found = await query<{ encrypted_secret: string }>('SELECT encrypted_secret FROM app.mfa_credentials WHERE user_id=$1 AND enabled_at IS NOT NULL', [userId]);
  if (found.rowCount && authenticator.verify({ token: code, secret: decrypt(found.rows[0].encrypted_secret) })) return true;
  const hash = crypto.createHash('sha256').update(code).digest('hex');
  const consumed = await withTransaction(async (client) => { const row = await client.query<{ id: string }>('SELECT id FROM app.mfa_recovery_codes WHERE user_id=$1 AND code_hash=$2 AND used_at IS NULL FOR UPDATE', [userId, hash]); if (!row.rowCount) return false; await client.query('UPDATE app.mfa_recovery_codes SET used_at=now() WHERE id=$1', [row.rows[0].id]); return true; });
  return consumed;
}

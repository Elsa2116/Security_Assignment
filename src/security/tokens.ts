import crypto from 'node:crypto';
import { generateKeyPairSync } from 'node:crypto';
import jwt from 'jsonwebtoken';
import { config } from '../config.js';
import { pool, query, withTransaction } from '../db/pool.js';

const generated = generateKeyPairSync('rsa', { modulusLength: 2048 });
const privateKey = process.env.JWT_PRIVATE_KEY || generated.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
const publicKey = process.env.JWT_PUBLIC_KEY || generated.publicKey.export({ type: 'spki', format: 'pem' }).toString();
const issuer = process.env.TOKEN_ISSUER || 'secureflow';
const audience = process.env.TOKEN_AUDIENCE || 'secureflow-api';

// Issue a short-lived asymmetric access token. Roles are informational; authorization still queries PostgreSQL.
export function issueAccessToken(userId: string, roles: string[], sessionId: string) {
  return jwt.sign({ sub: userId, roles, type: 'access', sid: sessionId, jti: crypto.randomUUID() }, privateKey, { algorithm: 'RS256', expiresIn: Math.min(config.ACCESS_TOKEN_TTL_SECONDS, 600), issuer, audience, keyid: process.env.JWT_KEY_ID || 'dev-ephemeral' });
}

// Validate signature, issuer/audience, claims, token revocation, and live session state.
export async function verifyAccessToken(token: string) {
  const payload = jwt.verify(token, publicKey, { algorithms: ['RS256'], issuer, audience }) as jwt.JwtPayload;
  if (!payload.jti || !payload.sid || !payload.sub) throw new Error('invalid_token_claims');
  const revoked = await query('SELECT 1 FROM app.jwt_revocations WHERE jti=$1 AND expires_at>now()', [payload.jti]);
  if (revoked.rowCount) throw new Error('revoked_token');
  const session = await query('SELECT 1 FROM auth.session WHERE id=$1 AND user_id=$2 AND expires_at>now()', [payload.sid, payload.sub]);
  if (!session.rowCount) throw new Error('revoked_session');
  return payload;
}

// Hash opaque refresh secrets before persistence so database disclosure does not reveal usable tokens.
export function hashRefreshToken(token: string) { return crypto.createHash('sha256').update(token).digest('hex'); }

// Create a seven-day refresh-token family and persist only the token hash.
export async function issueRefreshToken(userId: string, sessionId: string) {
  return withTransaction(async (client) => {
    const family = await client.query<{ id: string }>(`INSERT INTO app.refresh_token_families(user_id,session_id,absolute_expires_at) VALUES ($1,$2,now()+interval '7 days') RETURNING id`, [userId, sessionId]);
    const token = crypto.randomBytes(32).toString('base64url');
    await client.query(`INSERT INTO app.refresh_tokens(user_id,token_hash,family_id,expires_at) VALUES ($1,$2,$3,now()+interval '7 days')`, [userId, hashRefreshToken(token), family.rows[0].id]);
    return { token, familyId: family.rows[0].id };
  });
}

// Rotate one refresh token inside one transaction and revoke the family on replay.
export async function rotateRefreshToken(oldToken: string, userId: string) {
  return withTransaction(async (client) => {
    const oldHash = hashRefreshToken(oldToken);
    const found = await client.query<{ id: string; family_id: string; revoked_at: Date | null; used_at: Date | null }>('SELECT id,family_id,revoked_at,used_at FROM app.refresh_tokens WHERE token_hash=$1 AND user_id=$2 FOR UPDATE', [oldHash, userId]);
    if (found.rowCount !== 1) throw new Error('invalid_refresh_token');
    const current = found.rows[0];
    if (current.revoked_at || current.used_at) {
      await client.query("UPDATE app.refresh_token_families SET status='REVOKED',revoked_at=now() WHERE id=$1", [current.family_id]);
      await client.query('UPDATE app.refresh_tokens SET revoked_at=now() WHERE family_id=$1 AND revoked_at IS NULL', [current.family_id]);
      await client.query("INSERT INTO app.security_alerts(alert_type,severity,details) VALUES ('REFRESH_TOKEN_REPLAY','high',$1)", [JSON.stringify({ userId })]);
      await client.query("INSERT INTO app.audit_events(actor_user_id,action,resource_type,outcome,metadata) VALUES ($1,'refresh-token.replay','refresh_token','failure',$2)", [userId, JSON.stringify({ familyId: current.family_id })]);
      throw new Error('refresh_token_replay');
    }
    const next = crypto.randomBytes(32).toString('base64url');
    const inserted = await client.query<{ id: string }>(`INSERT INTO app.refresh_tokens(user_id,token_hash,family_id,expires_at) SELECT user_id,$1,family_id,LEAST(expires_at,now()+interval '7 days') FROM app.refresh_tokens WHERE id=$2 RETURNING id`, [hashRefreshToken(next), current.id]);
    await client.query('UPDATE app.refresh_tokens SET used_at=now(),revoked_at=now(),replaced_by=$1,last_used_at=now() WHERE id=$2', [inserted.rows[0].id, current.id]);
    await client.query("INSERT INTO app.audit_events(actor_user_id,action,resource_type,resource_id,outcome) VALUES ($1,'refresh-token.rotate','refresh_token',$2,'success')", [userId, current.id]);
    return next;
  });
}

// Revoke the Better Auth session so previously issued access tokens fail the live-session check.
export async function revokeSession(userId: string, sessionId: string, reason = 'logout') {
  await withTransaction(async (client) => {
    await client.query('UPDATE auth.session SET revoked_at=now() WHERE id=$1 AND user_id=$2', [sessionId, userId]);
    await client.query("INSERT INTO app.audit_events(actor_user_id,action,resource_type,resource_id,outcome) VALUES ($1,'session.revoke','session',$2,'success')", [userId, sessionId]);
  });
}

export { pool };

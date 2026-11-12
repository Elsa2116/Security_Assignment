import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import { config } from '../config.js';
import { withTransaction } from '../db/pool.js';

export function issueAccessToken(userId: string, roles: string[]) {
  return jwt.sign({ sub: userId, roles, type: 'access' }, config.JWT_ACCESS_SECRET, { expiresIn: config.ACCESS_TOKEN_TTL_SECONDS });
}

export function hashRefreshToken(token: string) { return crypto.createHash('sha256').update(token).digest('hex'); }

export async function rotateRefreshToken(oldToken: string, userId: string) {
  return withTransaction(async (client) => {
    const oldHash = hashRefreshToken(oldToken);
    const found = await client.query<{ id: string; family_id: string }>(
      'SELECT id, family_id FROM app.refresh_tokens WHERE token_hash = $1 AND user_id = $2 AND revoked_at IS NULL AND expires_at > now() FOR UPDATE', [oldHash, userId]);
    if (found.rowCount !== 1) throw new Error('invalid_refresh_token');
    const next = crypto.randomBytes(48).toString('base64url');
    const inserted = await client.query<{ id: string }>(
      `INSERT INTO app.refresh_tokens(user_id, token_hash, family_id, expires_at) VALUES ($1, $2, $3, now() + ($4 * interval '1 second')) RETURNING id`,
      [userId, hashRefreshToken(next), found.rows[0].family_id, config.REFRESH_TOKEN_TTL_SECONDS]);
    await client.query('UPDATE app.refresh_tokens SET revoked_at = now(), replaced_by = $1, last_used_at = now() WHERE id = $2', [inserted.rows[0].id, found.rows[0].id]);
    await client.query('INSERT INTO app.audit_events(actor_user_id, action, resource_type, resource_id, outcome) VALUES ($1, $2, $3, $4, $5)', [userId, 'refresh_token.rotate', 'refresh_token', found.rows[0].id, 'success']);
    return next;
  });
}

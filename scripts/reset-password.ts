import 'dotenv/config';
import bcrypt from 'bcryptjs';
import { pool, withTransaction } from '../src/db/pool.js';

const email = process.argv[2];
const password = process.argv[3];
if (!email || !password || password.length < 12) throw new Error('Usage: reset-password <email> <password>=12+ characters');

// This local operator utility migrates an existing demo account to the current bcrypt format.
// It is intentionally a script rather than an HTTP endpoint so passwords never cross the API.
const passwordHash = await bcrypt.hash(password, 12);
await withTransaction(async (client) => {
  const user = await client.query<{ id: string }>('SELECT id FROM auth."user" WHERE lower(email)=lower($1)', [email]);
  if (!user.rowCount) throw new Error('user_not_found');
  await client.query(`UPDATE auth.account SET password=$1 WHERE user_id=$2 AND provider_id='credential'`, [passwordHash, user.rows[0].id]);
  await client.query('UPDATE app.user_profiles SET failed_login_count=0,locked_until=NULL WHERE user_id=$1', [user.rows[0].id]);
  await client.query(`UPDATE auth.session SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL`, [user.rows[0].id]);
});
console.log(`Password reset for ${email}. Existing sessions were revoked.`);
await pool.end();

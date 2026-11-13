import 'dotenv/config';
import { pool, withTransaction } from '../src/db/pool.js';

const email = process.argv[2];
if (!email) throw new Error('Usage: promote-admin <verified-email>');

// Local bootstrap only: the operator must first verify the account through Better Auth.
// This script grants the ADMIN role and assigns the first seeded organization/department.
await withTransaction(async (client) => {
  const user = await client.query<{ id: string; email_verified: boolean }>('SELECT id,email_verified FROM auth."user" WHERE lower(email)=lower($1)', [email]);
  if (!user.rowCount) throw new Error('user_not_found');
  if (!user.rows[0].email_verified) throw new Error('email_not_verified');
  const directory = await client.query<{ organization_id: string; department_id: string }>(`SELECT o.id AS organization_id,d.id AS department_id FROM app.organizations o JOIN app.departments d ON d.organization_id=o.id WHERE o.status='ACTIVE' ORDER BY o.created_at,d.created_at LIMIT 1`);
  if (!directory.rowCount) throw new Error('seed_organization_missing');
  const role = await client.query<{ id: string }>('SELECT id FROM app.roles WHERE code=\'ADMIN\'');
  if (!role.rowCount) throw new Error('admin_role_missing');
  await client.query(`UPDATE app.user_profiles SET organization_id=$1,department_id=$2,status='ACTIVE',email_verified_at=now(),updated_at=now() WHERE user_id=$3`, [directory.rows[0].organization_id, directory.rows[0].department_id, user.rows[0].id]);
  await client.query('INSERT INTO app.user_roles(user_id,role_id,assigned_by) VALUES ($1,$2,$1) ON CONFLICT (user_id,role_id) DO UPDATE SET revoked_at=NULL', [user.rows[0].id, role.rows[0].id]);
});
console.log(`Admin access granted to ${email}.`);
await pool.end();

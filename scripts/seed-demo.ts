import 'dotenv/config';
import { pool, withTransaction } from '../src/db/pool.js';

if (process.env.SEED_DEMO_ENABLED !== 'true' && process.env.NODE_ENV === 'production') throw new Error('Demo seed is disabled in production');
await withTransaction(async (client) => {
  const org = await client.query<{ id: string }>(`INSERT INTO app.organizations(name,slug) VALUES ('SecureFlow Demo Organization','secureflow-demo') ON CONFLICT(slug) DO UPDATE SET name=EXCLUDED.name RETURNING id`);
  await client.query(`INSERT INTO app.departments(organization_id,name) VALUES ($1,'Operations'),($1,'Engineering'),($1,'Security') ON CONFLICT(organization_id,name) DO NOTHING`, [org.rows[0].id]);
  await client.query(`INSERT INTO app.role_permissions(role_id,permission_id) SELECT r.id,p.id FROM app.roles r CROSS JOIN app.permissions p WHERE r.code='ADMIN' ON CONFLICT DO NOTHING`);
});
console.log('Seeded safe organization, departments, roles, and permissions. No demo passwords or tokens were created.');
await pool.end();

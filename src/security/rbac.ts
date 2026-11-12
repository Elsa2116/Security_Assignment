import type { PoolClient } from 'pg';
import { query, withTransaction } from '../db/pool.js';

export async function hasPermission(userId: string, permission: string) {
  const result = await query<{ allowed: boolean }>(
    `SELECT EXISTS (SELECT 1 FROM app.user_roles ur JOIN app.role_permissions rp ON rp.role_id = ur.role_id JOIN app.permissions p ON p.id = rp.permission_id WHERE ur.user_id = $1 AND p.name = $2) AS allowed`, [userId, permission]);
  return result.rows[0]?.allowed === true;
}

export function changeRole(actorUserId: string, targetUserId: string, roleName: string) {
  return withTransaction(async (client: PoolClient) => {
    const role = await client.query<{ id: string }>('SELECT id FROM app.roles WHERE name = $1', [roleName]);
    if (role.rowCount !== 1) throw new Error('role_not_found');
    await client.query('INSERT INTO app.user_roles(user_id, role_id, assigned_by) VALUES ($1, $2, $3) ON CONFLICT (user_id, role_id) DO NOTHING', [targetUserId, role.rows[0].id, actorUserId]);
    await client.query('INSERT INTO app.audit_events(actor_user_id, action, resource_type, resource_id, outcome, metadata) VALUES ($1, $2, $3, $4, $5, $6)', [actorUserId, 'role.assign', 'user', targetUserId, 'success', JSON.stringify({ role: roleName })]);
  });
}

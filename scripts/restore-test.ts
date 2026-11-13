import { pool, query, withTransaction } from '../src/db/pool.js';
const row = await query<{ id: string }>(`SELECT id FROM app.backup_records WHERE status='COMPLETED' ORDER BY created_at DESC LIMIT 1`);
if (!row.rowCount) throw new Error('no_completed_backup');
const started = Date.now();
await withTransaction(async (client) => {
  await client.query(`INSERT INTO app.restore_tests(backup_record_id,started_at,finished_at,integrity_result,measured_rto_ms,status) VALUES ($1,now(),now(),'NOT_RUN',NULL,'BLOCKED_REQUIRES_ISOLATED_DATABASE')`, [row.rows[0].id]);
});
console.error(`Restore test requires an isolated PostgreSQL target; recorded as blocked after ${Date.now() - started}ms.`);
await pool.end();
process.exitCode = 2;

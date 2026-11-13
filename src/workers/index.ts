import 'dotenv/config';
import { pool, query } from '../db/pool.js';

console.log(JSON.stringify({ event: 'worker.startup', service: 'secureflow-worker', at: new Date().toISOString() }));
const processOutbox = async () => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const rows = await client.query<{ id: string; event_type: string; payload: unknown }>(`SELECT id,event_type,payload FROM app.outbox_events WHERE status='PENDING' AND next_attempt_at<=now() ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 25`);
    for (const row of rows.rows) {
      await client.query(`UPDATE app.outbox_events SET status='DELIVERED',attempt_count=attempt_count+1 WHERE id=$1`, [row.id]);
    }
    await client.query('COMMIT');
  } catch { await client.query('ROLLBACK'); }
  finally { client.release(); }
};
setInterval(() => void processOutbox(), 5000);
await query('SELECT 1');
process.on('SIGTERM', async () => { console.log(JSON.stringify({ event: 'worker.shutdown' })); await pool.end(); process.exit(0); });

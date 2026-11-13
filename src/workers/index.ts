import 'dotenv/config';
import { pool, query } from '../db/pool.js';
import { deliverEmail } from './mailer.js';

console.log(JSON.stringify({ event: 'worker.startup', service: 'secureflow-worker', at: new Date().toISOString() }));

// Claim pending outbox events with SKIP LOCKED so multiple workers do not deliver the same event.
const processOutbox = async () => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const rows = await client.query<{ id: string; event_type: string; payload: { email?: string; url?: string } }>(`SELECT id,event_type,payload FROM app.outbox_events WHERE status='PENDING' AND next_attempt_at<=now() ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 25`);
    for (const row of rows.rows) {
      try {
        if (row.event_type === 'EMAIL_VERIFICATION' || row.event_type === 'PASSWORD_RESET') await deliverEmail(row.event_type, row.payload);
        await client.query(`UPDATE app.outbox_events SET status='DELIVERED',attempt_count=attempt_count+1 WHERE id=$1`, [row.id]);
      } catch {
        // Retry later with bounded exponential backoff; failed delivery remains observable in the outbox.
        await client.query(`UPDATE app.outbox_events SET status='FAILED',attempt_count=attempt_count+1,next_attempt_at=now()+(LEAST(attempt_count+1,6) * interval '1 minute') WHERE id=$1`, [row.id]);
      }
    }
    await client.query('COMMIT');
  } catch { await client.query('ROLLBACK'); }
  finally { client.release(); }
};

// Poll the outbox; production can replace this interval with a Redis-backed queue consumer.
setInterval(() => void processOutbox(), 5000);
await query('SELECT 1');
process.on('SIGTERM', async () => { console.log(JSON.stringify({ event: 'worker.shutdown' })); await pool.end(); process.exit(0); });

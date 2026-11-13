import { pool, query } from '../src/db/pool.js';
import { verifyEncryptedBackup } from '../src/services/backup.js';
const row = await query<{ storage_key: string; checksum: string }>(`SELECT storage_key,checksum FROM app.backup_records WHERE kind='FULL' AND status='COMPLETED' ORDER BY created_at DESC LIMIT 1`);
if (!row.rowCount) throw new Error('no_completed_backup');
try { console.log(JSON.stringify(await verifyEncryptedBackup(row.rows[0].storage_key, row.rows[0].checksum), null, 2)); }
finally { await pool.end(); }

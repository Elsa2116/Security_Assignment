import { createEncryptedFullBackup, pool } from '../src/services/backup.js';
try { console.log(JSON.stringify(await createEncryptedFullBackup(), null, 2)); } finally { await pool.end(); }

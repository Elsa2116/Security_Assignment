import { verifyAuditChain } from '../src/security/audit-chain.js';
import { pool } from '../src/db/pool.js';
const result = await verifyAuditChain();
console.log(JSON.stringify(result, null, 2));
await pool.end();
if (!result.valid) process.exitCode = 1;

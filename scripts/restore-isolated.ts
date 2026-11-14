import crypto from 'node:crypto';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { config } from '../src/config.js';

const execFileAsync = promisify(execFile);
const backupFile = process.env.BACKUP_FILE;
const restoreUrl = process.env.RESTORE_DATABASE_URL;

if (!backupFile || !restoreUrl) throw new Error('Set BACKUP_FILE and RESTORE_DATABASE_URL');
if (restoreUrl === config.DATABASE_URL) throw new Error('Refusing to restore over the application database');
if (process.env.ALLOW_ISOLATED_RESTORE !== 'true') throw new Error('Set ALLOW_ISOLATED_RESTORE=true for an explicit isolated restore');

// Decrypt one encrypted backup into a temporary file and restore only into a separately supplied database URL.
const payload = await readFile(path.resolve(backupFile));
if (payload.subarray(0, 6).toString() !== 'SFBAK1') throw new Error('backup_format_invalid');
const derivedKey = crypto.createHash('sha256').update(config.BACKUP_ENCRYPTION_KEY).digest();
const decipher = crypto.createDecipheriv('aes-256-gcm', derivedKey, payload.subarray(6, 18), { authTagLength: 16 });
decipher.setAuthTag(payload.subarray(18, 34));
const dump = Buffer.concat([decipher.update(payload.subarray(34)), decipher.final()]);
const temporaryDirectory = await mkdtemp(path.join(os.tmpdir(), 'secureflow-restore-'));
const dumpFile = path.join(temporaryDirectory, 'restore.dump');
try {
  await writeFile(dumpFile, dump, { mode: 0o600 });
  await execFileAsync('pg_restore', ['--clean', '--if-exists', '--no-owner', '--dbname', restoreUrl, dumpFile], { maxBuffer: 10 * 1024 * 1024 });
  console.log(JSON.stringify({ restored: true, bytes: dump.byteLength, target: new URL(restoreUrl).host }));
} finally {
  await rm(temporaryDirectory, { recursive: true, force: true });
}

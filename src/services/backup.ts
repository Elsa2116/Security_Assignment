import crypto from 'node:crypto';
import { execFile } from 'node:child_process';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';
import { PutObjectCommand, S3Client } from '@aws-sdk/client-s3';
import { config } from '../config.js';
import { pool, withTransaction } from '../db/pool.js';

const execFileAsync = promisify(execFile);
const backupDir = path.resolve(process.env.BACKUP_DIR ?? './backups');
// Derive the encryption key locally; production should replace this with a KMS envelope key.
function key() { return crypto.createHash('sha256').update(config.BACKUP_ENCRYPTION_KEY).digest(); }

// Upload only already-encrypted backup bytes to configured S3-compatible storage; local-only mode remains the default.
async function uploadOffsite(storageKey: string, payload: Buffer) {
  const endpoint = process.env.OBJECT_STORAGE_ENDPOINT_URL;
  const accessKey = process.env.OBJECT_STORAGE_ACCESS_KEY;
  const secretKey = process.env.OBJECT_STORAGE_SECRET_KEY;
  const bucket = process.env.OBJECT_STORAGE_BUCKET;
  if (!endpoint || !accessKey || !secretKey || !bucket) return { uploaded: false, immutable: false };
  const retentionDays = Math.max(1, Number(process.env.OBJECT_STORAGE_RETENTION_DAYS ?? 30));
  const client = new S3Client({ endpoint, region: process.env.OBJECT_STORAGE_REGION ?? 'us-east-1', forcePathStyle: true, credentials: { accessKeyId: accessKey, secretAccessKey: secretKey } });
  const retainUntil = new Date(Date.now() + retentionDays * 86400000);
  await client.send(new PutObjectCommand({
    Bucket: bucket, Key: storageKey, Body: payload, ContentType: 'application/octet-stream',
    ServerSideEncryption: 'AES256', ObjectLockMode: 'COMPLIANCE', ObjectLockRetainUntilDate: retainUntil
  }));
  return { uploaded: true, immutable: true, retainUntil: retainUntil.toISOString() };
}

// Produce an encrypted pg_dump artifact, checksum it, and persist its manifest/audit record.
export async function createEncryptedFullBackup() {
  await mkdir(backupDir, { recursive: true });
  const started = new Date();
  // Request binary stdout explicitly; converting a custom-format dump through UTF-8 would corrupt it.
  const { stdout } = await execFileAsync('pg_dump', ['--format=custom', '--no-owner', config.DATABASE_URL], { maxBuffer: 50 * 1024 * 1024, encoding: 'buffer' });
  const plaintext = Buffer.isBuffer(stdout) ? stdout : Buffer.from(stdout);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key(), iv);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const payload = Buffer.concat([Buffer.from('SFBAK1'), iv, cipher.getAuthTag(), encrypted]);
  const checksum = crypto.createHash('sha256').update(payload).digest('hex');
  const storageKey = `full-${started.toISOString().replaceAll(':','')}-${checksum.slice(0,12)}.dump.enc`;
  await writeFile(path.join(backupDir, storageKey), payload, { flag: 'wx', mode: 0o600 });
  const offsite = await uploadOffsite(storageKey, payload);
  const finished = new Date();
  await withTransaction(async (client) => {
    await client.query(`INSERT INTO app.backup_records(kind,storage_key,checksum,encryption_key_id,started_at,finished_at,status,retention_until) VALUES ('FULL',$1,$2,$3,$4,$5,'COMPLETED',now()+interval '30 days')`, [storageKey, checksum, 'local-dev-derived-key', started, finished]);
    await client.query(`INSERT INTO app.audit_events(action,resource_type,outcome,metadata) VALUES ('backup.full','backup','success',$1)`, [JSON.stringify({ storageKey, checksum, offsite })]);
  });
  return { storageKey, checksum, bytes: payload.byteLength, offsite };
}

// Verify both the artifact checksum and AES-GCM authentication tag before accepting a backup.
export async function verifyEncryptedBackup(storageKey: string, expectedChecksum: string) {
  const payload = await readFile(path.join(backupDir, storageKey));
  const checksum = crypto.createHash('sha256').update(payload).digest('hex');
  if (checksum !== expectedChecksum) throw new Error('backup_checksum_mismatch');
  if (payload.subarray(0, 6).toString() !== 'SFBAK1') throw new Error('backup_format_invalid');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key(), payload.subarray(6, 18), { authTagLength: 16 });
  decipher.setAuthTag(payload.subarray(18, 34));
  decipher.update(payload.subarray(34)); decipher.final();
  return { valid: true, checksum, bytes: payload.byteLength };
}

export { pool };

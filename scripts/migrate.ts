import 'dotenv/config';
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { pool } from '../src/db/pool.js';

const migrationsDir = path.resolve(process.cwd(), 'migrations');
const client = await pool.connect();
try {
  await client.query('BEGIN');
  await client.query('CREATE SCHEMA IF NOT EXISTS app');
  await client.query('CREATE TABLE IF NOT EXISTS app.schema_migrations (version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())');
  const applied = new Set((await client.query<{ version: string }>('SELECT version FROM app.schema_migrations')).rows.map((r) => r.version));
  const files = (await readdir(migrationsDir)).filter((f) => f.endsWith('.sql')).sort();
  for (const file of files) {
    if (applied.has(file)) continue;
    await client.query(await readFile(path.join(migrationsDir, file), 'utf8'));
    await client.query('INSERT INTO app.schema_migrations(version) VALUES ($1)', [file]);
  }
  await client.query('COMMIT');
} catch (error) {
  await client.query('ROLLBACK');
  throw error;
} finally {
  client.release();
  await pool.end();
}

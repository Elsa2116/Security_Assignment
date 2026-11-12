import { Pool, type PoolClient, type QueryResultRow } from 'pg';
import { config } from '../config.js';

export const pool = new Pool({ connectionString: config.DATABASE_URL, max: 20, idleTimeoutMillis: 30_000 });

export async function query<T extends QueryResultRow>(text: string, values: unknown[] = []) {
  return pool.query<T>(text, values);
}

export async function withTransaction<T>(work: (client: PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await work(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

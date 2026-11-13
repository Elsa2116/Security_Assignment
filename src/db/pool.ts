import { Pool, type PoolClient, type QueryResultRow } from 'pg';
import { config } from '../config.js';

// The shared application pool is used for all raw SQL queries and is bounded to
// prevent the API from exhausting PostgreSQL connections under load.
export const pool = new Pool({ connectionString: config.DATABASE_URL, max: 20, idleTimeoutMillis: 30_000 });

/** Execute a parameterized read/write query outside an explicit transaction. */
export async function query<T extends QueryResultRow>(text: string, values: unknown[] = []) {
  return pool.query<T>(text, values);
}

/**
 * Run a unit of work on one checked-out client. Keeping BEGIN/COMMIT/ROLLBACK
 * here prevents callers from accidentally mixing pooled connections mid-flow.
 */
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

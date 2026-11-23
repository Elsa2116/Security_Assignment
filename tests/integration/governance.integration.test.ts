import { afterAll, describe, expect, it } from 'vitest';
import { Pool } from 'pg';

// Run this suite only against an explicitly supplied PostgreSQL test database; it never fabricates governance data.
const databaseUrl = process.env.TEST_DATABASE_URL;
const suite = databaseUrl ? describe : describe.skip;
const pool = databaseUrl ? new Pool({ connectionString: databaseUrl }) : undefined;

suite('SecureFlow governance migration', () => {
  it('contains organization ownership and decision tables in PostgreSQL', async () => {
    const result = await pool!.query<{ table_name: string; column_name: string }>(
      `SELECT table_name, column_name
       FROM information_schema.columns
       WHERE table_schema = 'app'
         AND ((table_name IN ('security_incidents','risks','policy_documents','security_changes','awareness_campaigns') AND column_name = 'organization_id')
           OR table_name IN ('access_reviews','access_review_items'))
       ORDER BY table_name, column_name`
    );
    const values = result.rows.map((row) => `${row.table_name}.${row.column_name}`);
    expect(values).toEqual(expect.arrayContaining([
      'security_incidents.organization_id',
      'risks.organization_id',
      'policy_documents.organization_id',
      'security_changes.organization_id',
      'awareness_campaigns.organization_id',
      'access_reviews.id',
      'access_review_items.id'
    ]));
  });

  afterAll(async () => {
    await pool?.end();
  });
});

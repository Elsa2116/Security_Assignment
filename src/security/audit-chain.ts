import crypto from 'node:crypto';
import type { PoolClient } from 'pg';

type AuditInput = { actorId?: string; action: string; resourceType: string; resourceId?: string; outcome: 'success' | 'failure'; ipAddress?: string; userAgent?: string; correlationId?: string; metadata?: Record<string, unknown> };

export async function appendAudit(client: PoolClient, event: AuditInput) {
  const previous = await client.query<{ entry_hash: string | null }>('SELECT entry_hash FROM app.audit_events ORDER BY sequence DESC NULLS LAST LIMIT 1');
  const previousHash = previous.rows[0]?.entry_hash ?? '';
  const canonical = JSON.stringify({ ...event, metadata: event.metadata ?? {}, previousHash });
  const entryHash = crypto.createHash('sha256').update(previousHash + canonical).digest('hex');
  await client.query(
    `INSERT INTO app.audit_events(actor_user_id,action,resource_type,resource_id,outcome,ip_address,user_agent,correlation_id,previous_hash,entry_hash,metadata)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
    [event.actorId ?? null, event.action, event.resourceType, event.resourceId ?? null, event.outcome, event.ipAddress ?? null, event.userAgent ?? null, event.correlationId ?? null, previousHash, entryHash, JSON.stringify(event.metadata ?? {})]
  );
  return entryHash;
}

export async function verifyAuditChain() {
  const { query } = await import('../db/pool.js');
  const rows = await query<{ sequence: string; entry_hash: string; previous_hash: string; actor_user_id: string | null; action: string; resource_type: string; resource_id: string | null; outcome: string; metadata: Record<string, unknown> }>('SELECT sequence,entry_hash,previous_hash,actor_user_id,action,resource_type,resource_id,outcome,metadata FROM app.audit_events ORDER BY sequence');
  let previousHash = '';
  for (const row of rows.rows) {
    if (row.previous_hash !== previousHash) return { valid: false, sequence: row.sequence };
    const canonical = JSON.stringify({ actorId: row.actor_user_id, action: row.action, resourceType: row.resource_type, resourceId: row.resource_id ?? undefined, outcome: row.outcome, metadata: row.metadata ?? {}, previousHash });
    const expected = crypto.createHash('sha256').update(previousHash + canonical).digest('hex');
    if (expected !== row.entry_hash) return { valid: false, sequence: row.sequence };
    previousHash = row.entry_hash;
  }
  return { valid: true, count: rows.rowCount ?? 0, lastHash: previousHash || null };
}

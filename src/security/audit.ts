import { withTransaction } from '../db/pool.js';

export function recordAuditEvent(event: { actorUserId?: string; action: string; resourceType: string; resourceId?: string; outcome: 'success' | 'failure'; ipAddress?: string; userAgent?: string; metadata?: Record<string, unknown> }) {
  return withTransaction(async (client) => {
    await client.query('INSERT INTO app.audit_events(actor_user_id, action, resource_type, resource_id, outcome, ip_address, user_agent, metadata) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)', [event.actorUserId ?? null, event.action, event.resourceType, event.resourceId ?? null, event.outcome, event.ipAddress ?? null, event.userAgent ?? null, JSON.stringify(event.metadata ?? {})]);
  });
}

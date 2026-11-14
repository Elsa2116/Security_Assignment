import crypto from 'node:crypto';
import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import { query, withTransaction } from './db/pool.js';
import { appendAudit, verifyAuditChain } from './security/audit-chain.js';
import { AuthenticatedRequest, failure, requireAuth, requirePermission, requestContext, result } from './security/http.js';
import { beginMfaEnrollment, confirmMfa, verifyMfa } from './security/mfa.js';
import { revokeSession } from './security/tokens.js';

const uuid = z.string().uuid();
const requestSchema = z.object({ type: z.enum(['LEAVE','EQUIPMENT','SERVICE']), title: z.string().trim().min(1).max(160), description: z.string().max(4000).default(''), payload: z.record(z.string(), z.unknown()) });
const roleRequestSchema = z.object({ targetUserId: uuid, roleCode: z.string().regex(/^[A-Z_]+$/), operation: z.enum(['GRANT','REVOKE']), reason: z.string().trim().min(10).max(2000) });

export const api = Router();
api.use(requestContext);

// Public operational endpoints allow Docker health checks without exposing application data.
api.get('/health/live', (_req, res) => result(res, undefined, { status: 'ok' }));
api.get('/health/ready', async (req: AuthenticatedRequest, res) => {
  try { await query('SELECT 1'); return result(res, req.requestId, { status: 'ready', database: 'ok' }); }
  catch { return failure(res, req.requestId, 'NOT_READY', 'Dependency unavailable', 503); }
});

api.get('/me', requireAuth, async (req: AuthenticatedRequest, res) => {
  const r = await query(`SELECT up.user_id AS "userId", up.name, up.email_normalized AS email, up.status, up.organization_id AS "organizationId", o.name AS "organizationName", up.department_id AS "departmentId", d.name AS "departmentName",
    COALESCE(json_agg(DISTINCT ro.code) FILTER (WHERE ro.code IS NOT NULL), '[]') roles FROM app.user_profiles up LEFT JOIN app.organizations o ON o.id=up.organization_id LEFT JOIN app.departments d ON d.id=up.department_id LEFT JOIN app.user_roles ur ON ur.user_id=up.user_id AND ur.revoked_at IS NULL LEFT JOIN app.roles ro ON ro.id=ur.role_id WHERE up.user_id=$1 GROUP BY up.user_id,o.name,d.name`, [req.user!.id]);
  return result(res, req.requestId, r.rows[0] ?? { userId: req.user!.id });
});

// Employee request list is always owner-scoped and uses an allowlisted status filter.
api.get('/requests', requireAuth, async (req: AuthenticatedRequest, res) => {
  const limit = Math.min(Number(req.query.limit ?? 20) || 20, 100);
  const status = typeof req.query.status === 'string' ? req.query.status : null;
  const r = await query(`SELECT id,type,title,description,payload_json AS payload,status,version,created_at AS "createdAt",updated_at AS "updatedAt"
    FROM app.requests WHERE owner_id=$1 AND ($2::text IS NULL OR status=$2) ORDER BY created_at DESC LIMIT $3`, [req.user!.id, status, limit]);
  return result(res, req.requestId, r.rows);
});

// Create a request with idempotency, profile/department lookup, history, and audit in one transaction.
api.post('/requests', requireAuth, async (req: AuthenticatedRequest, res) => {
  const parsed = requestSchema.safeParse(req.body);
  if (!parsed.success) return failure(res, req.requestId, 'VALIDATION_ERROR', 'Invalid request', 422, parsed.error.flatten().fieldErrors as Record<string, string>);
  const idempotency = req.header('idempotency-key');
  if (!idempotency) return failure(res, req.requestId, 'IDEMPOTENCY_REQUIRED', 'Idempotency-Key is required', 400);
  const requestHash = crypto.createHash('sha256').update(JSON.stringify(parsed.data)).digest('hex');
  try {
    const created = await withTransaction(async (client) => {
      const existing = await client.query<{ response_ref: string | null; request_hash: string }>('SELECT response_ref,request_hash FROM app.idempotency_keys WHERE user_id=$1 AND key=$2 AND route=$3 AND expires_at>now()', [req.user!.id, idempotency, 'POST /requests']);
      if (existing.rowCount) {
        if (existing.rows[0].request_hash !== requestHash) throw new Error('IDEMPOTENCY_CONFLICT');
        return client.query('SELECT id,status,version FROM app.requests WHERE id=$1', [existing.rows[0].response_ref]);
      }
      const profile = await client.query<{ organization_id: string; department_id: string; manager_user_id: string | null }>(`SELECT up.organization_id,up.department_id,COALESCE(d.manager_user_id,(SELECT admin_profile.user_id FROM app.user_profiles admin_profile JOIN app.user_roles admin_role ON admin_role.user_id=admin_profile.user_id AND admin_role.revoked_at IS NULL JOIN app.roles admin_role_definition ON admin_role_definition.id=admin_role.role_id WHERE admin_profile.organization_id=up.organization_id AND admin_profile.status='ACTIVE' AND admin_role_definition.code='ADMIN' LIMIT 1)) AS manager_user_id FROM app.user_profiles up JOIN app.departments d ON d.id=up.department_id WHERE up.user_id=$1 AND up.status='ACTIVE'`, [req.user!.id]);
      if (profile.rowCount !== 1 || !profile.rows[0].manager_user_id) throw new Error('PROFILE_NOT_ADMITTED');
      const inserted = await client.query<{ id: string; status: string; version: number }>(`INSERT INTO app.requests(organization_id,department_id,owner_id,assigned_manager_id,type,title,description,payload_json) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id,status,version`, [profile.rows[0].organization_id, profile.rows[0].department_id, req.user!.id, profile.rows[0].manager_user_id, parsed.data.type, parsed.data.title, parsed.data.description, JSON.stringify(parsed.data.payload)]);
      await client.query('INSERT INTO app.request_history(request_id,actor_id,to_status,changed_fields) VALUES ($1,$2,$3,$4)', [inserted.rows[0].id, req.user!.id, 'PENDING', JSON.stringify(parsed.data)]);
      await client.query('INSERT INTO app.idempotency_keys(user_id,key,route,request_hash,response_ref,expires_at) VALUES ($1,$2,$3,$4,$5,now()+interval \'24 hours\')', [req.user!.id, idempotency, 'POST /requests', requestHash, inserted.rows[0].id]);
      await appendAudit(client, { actorId: req.user!.id, action: 'request.create', resourceType: 'request', resourceId: inserted.rows[0].id, outcome: 'success', correlationId: req.requestId, metadata: { type: parsed.data.type } });
      return { rows: [inserted.rows[0]] };
    });
    return result(res, req.requestId, created.rows[0], 201);
  } catch (error) {
    if (error instanceof Error && error.message === 'IDEMPOTENCY_CONFLICT') return failure(res, req.requestId, 'IDEMPOTENCY_CONFLICT', 'The same idempotency key was used with different data', 409);
    if (error instanceof Error && error.message === 'PROFILE_NOT_ADMITTED') return failure(res, req.requestId, 'NOT_ADMITTED', 'The account is not admitted to an organization', 403);
    return failure(res, req.requestId, 'REQUEST_CREATE_FAILED', 'Could not create request', 409);
  }
});

// Return a request only to its owner or assigned manager, together with immutable history.
api.get('/requests/:id', requireAuth, async (req: AuthenticatedRequest, res) => {
  const r = await query(`SELECT r.id,r.type,r.title,r.description,r.payload_json AS payload,r.status,r.version,r.owner_id AS "ownerId",r.department_id AS "departmentId",r.assigned_manager_id AS "assignedManagerId",r.created_at AS "createdAt",r.updated_at AS "updatedAt"
    FROM app.requests r WHERE r.id=$1 AND (r.owner_id=$2 OR r.assigned_manager_id=$2)`, [req.params.id, req.user!.id]);
  if (!r.rowCount) return failure(res, req.requestId, 'NOT_FOUND', 'Request not found', 404);
  const history = await query('SELECT actor_id AS "actorId",from_status AS "fromStatus",to_status AS "toStatus",changed_fields AS "changedFields",created_at AS "createdAt" FROM app.request_history WHERE request_id=$1 ORDER BY created_at', [req.params.id]);
  return result(res, req.requestId, { ...r.rows[0], history: history.rows });
});

// Update only pending requests owned by the caller using optimistic version checking.
api.patch('/requests/:id', requireAuth, async (req: AuthenticatedRequest, res) => {
  const parsed = z.object({ expectedVersion: z.number().int().positive(), title: z.string().trim().min(1).max(160).optional(), description: z.string().max(4000).optional(), payload: z.record(z.string(), z.unknown()).optional() }).safeParse(req.body);
  if (!parsed.success) return failure(res, req.requestId, 'VALIDATION_ERROR', 'Invalid request update', 422);
  const updated = await withTransaction(async (client) => {
    const current = await client.query<{ status: string; version: number; title: string; description: string; payload_json: unknown }>('SELECT status,version,title,description,payload_json FROM app.requests WHERE id=$1 AND owner_id=$2 FOR UPDATE', [req.params.id, req.user!.id]);
    if (!current.rowCount) throw new Error('NOT_FOUND');
    if (current.rows[0].status !== 'PENDING' || current.rows[0].version !== parsed.data.expectedVersion) throw new Error('CONFLICT');
    const next = await client.query('UPDATE app.requests SET title=COALESCE($1,title),description=COALESCE($2,description),payload_json=COALESCE($3,payload_json),version=version+1,updated_at=now() WHERE id=$4 RETURNING id,status,version', [parsed.data.title ?? null, parsed.data.description ?? null, parsed.data.payload ? JSON.stringify(parsed.data.payload) : null, req.params.id]);
    await client.query('INSERT INTO app.request_history(request_id,actor_id,from_status,to_status,changed_fields) VALUES ($1,$2,$3,$3,$4)', [req.params.id, req.user!.id, 'PENDING', JSON.stringify(parsed.data)]);
    await appendAudit(client, { actorId: req.user!.id, action: 'request.update', resourceType: 'request', resourceId: String(req.params.id), outcome: 'success', correlationId: String(req.requestId) });
    return next.rows[0];
  }).catch((error) => { throw error; });
  return result(res, req.requestId, updated);
});

// Cancel only a caller-owned pending request and record the state transition atomically.
api.post('/requests/:id/cancel', requireAuth, async (req: AuthenticatedRequest, res) => {
  try {
    const cancelled = await withTransaction(async (client) => {
      const row = await client.query<{ version: number }>(`SELECT version FROM app.requests WHERE id=$1 AND owner_id=$2 AND status='PENDING' FOR UPDATE`, [req.params.id, req.user!.id]);
      if (!row.rowCount) throw new Error('NOT_FOUND_OR_NOT_PENDING');
      const next = await client.query(`UPDATE app.requests SET status='CANCELLED',version=version+1,updated_at=now() WHERE id=$1 AND version=$2 RETURNING id,status,version`, [req.params.id, row.rows[0].version]);
      await client.query('INSERT INTO app.request_history(request_id,actor_id,from_status,to_status,changed_fields) VALUES ($1,$2,$3,$4,$5)', [req.params.id, req.user!.id, 'PENDING', 'CANCELLED', JSON.stringify({ reason: req.body?.reason ?? '' })]);
      await appendAudit(client, { actorId: req.user!.id, action: 'request.cancel', resourceType: 'request', resourceId: String(req.params.id), outcome: 'success', correlationId: String(req.requestId) });
      return next.rows[0];
    });
    return result(res, req.requestId, cancelled);
  } catch { return failure(res, req.requestId, 'NOT_FOUND_OR_NOT_PENDING', 'Request cannot be cancelled', 409); }
});

// Manager queue is restricted to requests assigned to the authenticated manager.
api.get('/approvals', requireAuth, async (req: AuthenticatedRequest, res) => {
  const r = await query(`SELECT id,type,title,description,status,version,owner_id AS "ownerId",department_id AS "departmentId",created_at AS "createdAt" FROM app.requests WHERE assigned_manager_id=$1 AND status='PENDING' ORDER BY created_at`, [req.user!.id]);
  return result(res, req.requestId, r.rows);
});

// Admin overview data is organization-scoped and only exposes counts plus actionable queue items.
api.get('/admin/overview', requireAuth, async (req: AuthenticatedRequest, res) => {
  if (!(await requirePermission(req.user!.id, 'requests:read_all'))) return failure(res, req.requestId, 'FORBIDDEN', 'Admin access required', 403);
  const profile = await query<{ organization_id: string | null }>('SELECT organization_id FROM app.user_profiles WHERE user_id=$1', [req.user!.id]);
  if (!profile.rows[0]?.organization_id) return failure(res, req.requestId, 'NO_ORGANIZATION', 'Admin is not assigned to an organization', 409);
  const organizationId = profile.rows[0].organization_id;
  const [counts, queue] = await Promise.all([
    query(`SELECT count(*) FILTER (WHERE status='PENDING')::int AS "pendingRequests", count(*) FILTER (WHERE status='APPROVED')::int AS "approvedRequests", count(*) FILTER (WHERE status='REJECTED')::int AS "rejectedRequests", count(*)::int AS "totalRequests" FROM app.requests WHERE organization_id=$1`, [organizationId]),
    query(`SELECT r.id,r.type,r.title,r.description,r.status,r.version,r.created_at AS "createdAt",up.name AS "requesterName",up.email_normalized AS "requesterEmail",d.name AS "departmentName" FROM app.requests r JOIN app.user_profiles up ON up.user_id=r.owner_id LEFT JOIN app.departments d ON d.id=r.department_id WHERE r.organization_id=$1 AND r.status='PENDING' ORDER BY r.created_at ASC LIMIT 25`, [organizationId])
  ]);
  return result(res, req.requestId, { ...counts.rows[0], pending: queue.rows });
});

// Admins use this queue to manage verified users who are waiting for organization admission.
api.get('/admin/members', requireAuth, async (req: AuthenticatedRequest, res) => {
  if (!(await requirePermission(req.user!.id, 'members:read'))) return failure(res, req.requestId, 'FORBIDDEN', 'Member administration required', 403);
  const rows = await query(`SELECT up.user_id AS "userId",up.name,up.email_normalized AS email,up.status,up.organization_id AS "organizationId",up.department_id AS "departmentId",up.created_at AS "createdAt",au.email_verified AS "emailVerified" FROM app.user_profiles up JOIN auth."user" au ON au.id=up.user_id ORDER BY CASE WHEN up.status='PENDING_ADMISSION' THEN 0 ELSE 1 END,up.created_at DESC LIMIT 100`);
  return result(res, req.requestId, rows.rows);
});

// Admission options are read-only metadata used by the admin assignment form.
api.get('/admin/directory', requireAuth, async (req: AuthenticatedRequest, res) => {
  if (!(await requirePermission(req.user!.id, 'members:read'))) return failure(res, req.requestId, 'FORBIDDEN', 'Directory access required', 403);
  const organizations = await query('SELECT id,name,slug FROM app.organizations WHERE status=\'ACTIVE\' ORDER BY name');
  const departments = await query('SELECT id,organization_id AS "organizationId",name,manager_user_id AS "managerUserId" FROM app.departments ORDER BY name');
  return result(res, req.requestId, { organizations: organizations.rows, departments: departments.rows });
});

// Admit a verified user and assign organization/department in one auditable transaction.
api.post('/admin/members/:userId/admit', requireAuth, async (req: AuthenticatedRequest, res) => {
  if (!(await requirePermission(req.user!.id, 'members:admit'))) return failure(res, req.requestId, 'FORBIDDEN', 'Member admission permission required', 403);
  const body = z.object({ organizationId: uuid, departmentId: uuid }).safeParse(req.body);
  if (!body.success) return failure(res, req.requestId, 'VALIDATION_ERROR', 'Organization and department are required', 422);
  try {
    const admitted = await withTransaction(async (client) => {
      const verified = await client.query<{ email_verified: boolean }>('SELECT email_verified FROM auth."user" WHERE id=$1', [req.params.userId]);
      if (verified.rows[0]?.email_verified !== true) throw new Error('EMAIL_NOT_VERIFIED');
      const department = await client.query('SELECT id FROM app.departments WHERE id=$1 AND organization_id=$2', [body.data.departmentId, body.data.organizationId]);
      if (!department.rowCount) throw new Error('DEPARTMENT_INVALID');
      // Departments without a configured manager use the organization admin as the approval owner.
      await client.query('UPDATE app.departments SET manager_user_id=COALESCE(manager_user_id,$1),updated_at=now() WHERE id=$2', [req.user!.id, body.data.departmentId]);
      const profile = await client.query(`UPDATE app.user_profiles SET organization_id=$1,department_id=$2,status='ACTIVE',email_verified_at=now(),updated_at=now() WHERE user_id=$3 AND status='PENDING_ADMISSION' RETURNING user_id AS "userId",name,email_normalized AS email,status,organization_id AS "organizationId",department_id AS "departmentId"`, [body.data.organizationId, body.data.departmentId, req.params.userId]);
      if (!profile.rowCount) throw new Error('MEMBER_NOT_PENDING');
      const role = await client.query<{ id: string }>('SELECT id FROM app.roles WHERE code=\'USER\' LIMIT 1');
      if (role.rowCount) await client.query('INSERT INTO app.user_roles(user_id,role_id,assigned_by) VALUES ($1,$2,$3) ON CONFLICT (user_id,role_id) DO UPDATE SET revoked_at=NULL', [req.params.userId, role.rows[0].id, req.user!.id]);
      await client.query('INSERT INTO app.notifications(user_id,type,title,body) VALUES ($1,\'MEMBER_ADMITTED\',\'Organization access approved\',\'Your SecureFlow account is now active.\')', [req.params.userId]);
      await appendAudit(client, { actorId: req.user!.id, action: 'member.admit', resourceType: 'user', resourceId: String(req.params.userId), outcome: 'success', correlationId: req.requestId, metadata: { organizationId: body.data.organizationId, departmentId: body.data.departmentId } });
      return profile.rows[0];
    });
    return result(res, req.requestId, admitted);
  } catch (error) {
    const code = error instanceof Error ? error.message : '';
    return failure(res, req.requestId, code === 'EMAIL_NOT_VERIFIED' ? 'EMAIL_NOT_VERIFIED' : 'ADMISSION_FAILED', code === 'EMAIL_NOT_VERIFIED' ? 'The user must verify their email first' : 'The user could not be admitted', 409);
  }
});

// Admin approval queue includes requester and department context for review screens.
api.get('/admin/requests', requireAuth, async (req: AuthenticatedRequest, res) => {
  if (!(await requirePermission(req.user!.id, 'requests:read_all'))) return failure(res, req.requestId, 'FORBIDDEN', 'Admin request access required', 403);
  const profile = await query<{ organization_id: string | null }>('SELECT organization_id FROM app.user_profiles WHERE user_id=$1', [req.user!.id]);
  const rows = await query(`SELECT r.id,r.type,r.title,r.description,r.payload_json AS payload,r.status,r.version,r.owner_id AS "ownerId",up.name AS "requesterName",up.email_normalized AS "requesterEmail",d.name AS "departmentName",r.created_at AS "createdAt" FROM app.requests r JOIN app.user_profiles up ON up.user_id=r.owner_id LEFT JOIN app.departments d ON d.id=r.department_id WHERE r.organization_id=$1 ORDER BY r.created_at DESC LIMIT 100`, [profile.rows[0]?.organization_id ?? null]);
  return result(res, req.requestId, rows.rows);
});

// Shared approval implementation prevents self-approval and makes the final decision single-writer.
async function decideRequest(req: AuthenticatedRequest, res: any, decision: 'APPROVED'|'REJECTED') {
  const schema = z.object({ expectedVersion: z.number().int().positive(), comment: z.string().max(2000).default(''), reason: z.string().trim().min(1).max(2000).optional() });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success || (decision === 'REJECTED' && !parsed.data.reason)) return failure(res, req.requestId, 'VALIDATION_ERROR', 'A rejection reason is required', 422);
  const key = req.header('idempotency-key');
  if (!key) return failure(res, req.requestId, 'IDEMPOTENCY_REQUIRED', 'Idempotency-Key is required', 400);
  try {
    const updated = await withTransaction(async (client) => {
      const found = await client.query<{ id: string; owner_id: string; assigned_manager_id: string; status: string; version: number }>('SELECT id,owner_id,assigned_manager_id,status,version FROM app.requests WHERE id=$1 FOR UPDATE', [req.params.id]);
      if (found.rowCount !== 1) throw new Error('NOT_FOUND');
      const row = found.rows[0];
      const globalApproval = await requirePermission(req.user!.id, 'requests:approve_global');
      if ((row.assigned_manager_id !== req.user!.id && !globalApproval) || row.owner_id === req.user!.id) throw new Error('FORBIDDEN');
      if (row.status !== 'PENDING' || row.version !== parsed.data.expectedVersion) throw new Error('CONFLICT');
      const next = await client.query<{ id: string; status: string; version: number }>('UPDATE app.requests SET status=$1,version=version+1,updated_at=now() WHERE id=$2 AND status=\'PENDING\' AND version=$3 RETURNING id,status,version', [decision, req.params.id, parsed.data.expectedVersion]);
      if (!next.rowCount) throw new Error('CONFLICT');
      await client.query('INSERT INTO app.request_decisions(request_id,reviewer_id,decision,reason) VALUES ($1,$2,$3,$4)', [req.params.id, req.user!.id, decision, parsed.data.reason ?? parsed.data.comment]);
      await client.query('INSERT INTO app.request_history(request_id,actor_id,from_status,to_status,changed_fields) VALUES ($1,$2,$3,$4,$5)', [req.params.id, req.user!.id, 'PENDING', decision, JSON.stringify({ comment: parsed.data.comment, reason: parsed.data.reason })]);
      await client.query('INSERT INTO app.notifications(user_id,type,title,body) SELECT owner_id,$1,$2,$3 FROM app.requests WHERE id=$4', ['REQUEST_DECISION', `Request ${decision.toLowerCase()}`, `Your request has been ${decision.toLowerCase()}.`, req.params.id]);
      await client.query('INSERT INTO app.outbox_events(event_type,payload) VALUES ($1,$2)', ['REQUEST_DECISION', JSON.stringify({ requestId: req.params.id, decision })]);
      await appendAudit(client, { actorId: req.user!.id, action: `request.${decision.toLowerCase()}`, resourceType: 'request', resourceId: String(req.params.id), outcome: 'success', correlationId: String(req.requestId) });
      return next.rows[0];
    });
    return result(res, req.requestId, updated);
  } catch (error) {
    const code = error instanceof Error ? error.message : '';
    return failure(res, req.requestId, code === 'FORBIDDEN' ? 'FORBIDDEN' : code === 'NOT_FOUND' ? 'NOT_FOUND' : 'STATE_CONFLICT', code === 'FORBIDDEN' ? 'You cannot approve this request' : 'Request is no longer actionable', code === 'FORBIDDEN' ? 403 : code === 'NOT_FOUND' ? 404 : 409);
  }
}
api.post('/requests/:id/approve', requireAuth, (req, res) => decideRequest(req as AuthenticatedRequest, res, 'APPROVED'));
api.post('/requests/:id/reject', requireAuth, (req, res) => decideRequest(req as AuthenticatedRequest, res, 'REJECTED'));

// Submit a privileged role change; granting/revoking is deferred to independent review.
api.post('/access/role-change-requests', requireAuth, async (req: AuthenticatedRequest, res) => {
  const parsed = roleRequestSchema.safeParse(req.body);
  if (!parsed.success) return failure(res, req.requestId, 'VALIDATION_ERROR', 'Invalid role change request', 422);
  try {
    const created = await withTransaction(async (client) => {
      const role = await client.query<{ id: string }>('SELECT id FROM app.roles WHERE code=$1', [parsed.data.roleCode]);
      if (!role.rowCount) throw new Error('ROLE_NOT_FOUND');
      const inserted = await client.query('INSERT INTO app.role_change_requests(target_user_id,requested_by,role_id,operation,reason) VALUES ($1,$2,$3,$4,$5) RETURNING id,status,version,created_at AS "createdAt"', [parsed.data.targetUserId, req.user!.id, role.rows[0].id, parsed.data.operation, parsed.data.reason]);
      await appendAudit(client, { actorId: req.user!.id, action: 'role-change.request', resourceType: 'role_change_request', resourceId: inserted.rows[0].id, outcome: 'success', correlationId: req.requestId, metadata: { roleCode: parsed.data.roleCode, operation: parsed.data.operation } });
      return inserted.rows[0];
    });
    return result(res, req.requestId, created, 201);
  } catch { return failure(res, req.requestId, 'ROLE_REQUEST_FAILED', 'Could not create role change request', 409); }
});

// Reviewers see the queue; ordinary users see only requests they submitted or target them.
api.get('/access/role-change-requests', requireAuth, async (req: AuthenticatedRequest, res) => {
  const review = await requirePermission(req.user!.id, 'roles:approve');
  const r = await query(`SELECT rr.id,rr.target_user_id AS "targetUserId",rr.requested_by AS "requestedBy",ro.code AS "roleCode",rr.operation,rr.reason,rr.status,rr.version,rr.created_at AS "createdAt"
    FROM app.role_change_requests rr JOIN app.roles ro ON ro.id=rr.role_id WHERE ($1 OR rr.requested_by=$2 OR rr.target_user_id=$2) ORDER BY rr.created_at DESC`, [review, req.user!.id]);
  return result(res, req.requestId, r.rows);
});

// Apply an independent role decision and invalidate the target's sessions when approved.
async function decideRoleChange(req: AuthenticatedRequest, res: any, decision: 'APPROVED'|'REJECTED') {
  const body = z.object({ comment: z.string().trim().min(decision === 'REJECTED' ? 1 : 0).max(2000).default('') }).safeParse(req.body);
  if (!body.success) return failure(res, req.requestId, 'VALIDATION_ERROR', 'Comment is required', 422);
  if (!(await requirePermission(req.user!.id, 'roles:approve'))) return failure(res, req.requestId, 'FORBIDDEN', 'Role approval permission required', 403);
  try {
    const final = await withTransaction(async (client) => {
      const found = await client.query<{ target_user_id: string; requested_by: string; role_id: string; operation: 'GRANT'|'REVOKE'; status: string }>('SELECT target_user_id,requested_by,role_id,operation,status FROM app.role_change_requests WHERE id=$1 FOR UPDATE', [req.params.id]);
      if (!found.rowCount) throw new Error('NOT_FOUND');
      const item = found.rows[0];
      if (item.requested_by === req.user!.id || item.target_user_id === req.user!.id || item.status !== 'PENDING') throw new Error('FORBIDDEN');
      await client.query('INSERT INTO app.role_change_decisions(role_change_request_id,reviewer_id,decision,comment) VALUES ($1,$2,$3,$4)', [req.params.id, req.user!.id, decision, body.data.comment]);
      const role = await client.query<{ code: string }>('SELECT code FROM app.roles WHERE id=$1', [item.role_id]);
      if (decision === 'APPROVED' && role.rows[0]?.code === 'ADMIN') {
        const count = await client.query<{ count: string }>('SELECT count(*) FROM app.role_change_decisions WHERE role_change_request_id=$1 AND decision=\'APPROVED\'', [req.params.id]);
        if (Number(count.rows[0].count) < 2) return { status: 'PENDING', approvals: Number(count.rows[0].count) };
      }
      await client.query('UPDATE app.role_change_requests SET status=$1,version=version+1,updated_at=now() WHERE id=$2', [decision, req.params.id]);
      if (decision === 'APPROVED') {
        if (item.operation === 'GRANT') await client.query('INSERT INTO app.user_roles(user_id,role_id,assigned_by,grant_request_id) VALUES ($1,$2,$3,$4) ON CONFLICT (user_id,role_id) DO UPDATE SET revoked_at=NULL,assigned_by=EXCLUDED.assigned_by', [item.target_user_id, item.role_id, req.user!.id, req.params.id]);
        else await client.query('UPDATE app.user_roles SET revoked_at=now() WHERE user_id=$1 AND role_id=$2', [item.target_user_id, item.role_id]);
        await client.query('UPDATE auth.session SET revoked_at=now() WHERE user_id=$1', [item.target_user_id]).catch(() => undefined);
      }
      await appendAudit(client, { actorId: req.user!.id, action: `role-change.${decision.toLowerCase()}`, resourceType: 'role_change_request', resourceId: String(req.params.id), outcome: 'success', correlationId: String(req.requestId) });
      return { status: decision, roleCode: role.rows[0]?.code };
    });
    return result(res, req.requestId, final);
  } catch { return failure(res, req.requestId, 'ROLE_CHANGE_CONFLICT', 'Role change cannot be completed', 409); }
}
api.post('/admin/role-change-requests/:id/approve', requireAuth, (req,res) => decideRoleChange(req as AuthenticatedRequest,res,'APPROVED'));
api.post('/admin/role-change-requests/:id/reject', requireAuth, (req,res) => decideRoleChange(req as AuthenticatedRequest,res,'REJECTED'));

// MFA routes keep the TOTP seed server-side and expose recovery codes only at confirmation time.
api.get('/auth/mfa/status', requireAuth, async (req: AuthenticatedRequest, res) => {
  // Only return enrollment metadata; encrypted TOTP seeds and recovery-code hashes never leave the server.
  const r = await query(`SELECT (enabled_at IS NOT NULL) AS enabled, (SELECT count(*)::int FROM app.mfa_recovery_codes WHERE user_id=$1 AND used_at IS NULL) AS "recoveryCodesRemaining" FROM app.mfa_credentials WHERE user_id=$1`, [req.user!.id]);
  return result(res, req.requestId, r.rows[0] ?? { enabled: false, recoveryCodesRemaining: 0 });
});
api.post('/auth/mfa/enroll', requireAuth, async (req: AuthenticatedRequest, res) => result(res, req.requestId, await beginMfaEnrollment(req.user!.id)));
api.post('/auth/mfa/confirm', requireAuth, async (req: AuthenticatedRequest, res) => {
  const code = z.string().regex(/^\d{6}$/).safeParse(req.body?.code);
  if (!code.success) return failure(res, req.requestId, 'VALIDATION_ERROR', 'A six digit TOTP code is required', 422);
  const confirmed = await confirmMfa(req.user!.id, code.data);
  if (!confirmed) return failure(res, req.requestId, 'MFA_INVALID', 'Invalid MFA code', 401);
  return result(res, req.requestId, confirmed);
});
// Limit MFA guesses independently from password-login throttling.
api.post('/auth/mfa/challenge', rateLimit({ windowMs: 15 * 60 * 1000, limit: 5, standardHeaders: 'draft-8', legacyHeaders: false }), requireAuth, async (req: AuthenticatedRequest, res) => {
  const code = z.string().min(6).max(20).safeParse(req.body?.code);
  if (!code.success || !(await verifyMfa(req.user!.id, code.data))) return failure(res, req.requestId, 'MFA_INVALID', 'Invalid MFA code', 401);
  await query('UPDATE auth.session SET mfa_verified_at=now(),updated_at=now() WHERE id=$1 AND user_id=$2', [req.session?.id ?? '', req.user!.id]);
  return result(res, req.requestId, { mfaVerified: true });
});
// Session metadata is safe to display because it excludes session tokens and refresh secrets.
api.get('/auth/sessions', requireAuth, async (req: AuthenticatedRequest, res) => {
  const sessions = await query('SELECT id,expires_at AS "expiresAt",ip_address AS "ipAddress",user_agent AS "userAgent",created_at AS "createdAt",updated_at AS "updatedAt" FROM auth.session WHERE user_id=$1 AND revoked_at IS NULL AND expires_at>now() ORDER BY created_at DESC', [req.user!.id]);
  return result(res, req.requestId, sessions.rows);
});
// Revoke one owned session or all sessions for logout-all/password-change behavior.
api.delete('/auth/sessions/:id', requireAuth, async (req: AuthenticatedRequest, res) => { await revokeSession(req.user!.id, String(req.params.id)); return res.status(204).send(); });
api.post('/auth/sessions/revoke-all', requireAuth, async (req: AuthenticatedRequest, res) => { await query('UPDATE auth.session SET revoked_at=now() WHERE user_id=$1', [req.user!.id]); return result(res, req.requestId, { revoked: true }); });

// Audit reads and integrity checks are protected by separate fresh permissions.
api.get('/admin/audit', requireAuth, async (req: AuthenticatedRequest, res) => {
  if (!(await requirePermission(req.user!.id, 'audit:read'))) return failure(res, req.requestId, 'FORBIDDEN', 'Audit access required', 403);
  const r = await query('SELECT sequence,actor_user_id AS "actorId",action,resource_type AS "resourceType",resource_id AS "resourceId",outcome,created_at AS "occurredAt",correlation_id AS "correlationId",entry_hash AS "entryHash" FROM app.audit_events ORDER BY sequence DESC LIMIT 100');
  return result(res, req.requestId, r.rows);
});
// Limit repeated audit-chain verification requests because they can be CPU intensive.
api.get('/admin/audit/integrity', rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: 'draft-8', legacyHeaders: false }), requireAuth, async (req: AuthenticatedRequest, res) => {
  if (!(await requirePermission(req.user!.id, 'audit:verify'))) return failure(res, req.requestId, 'FORBIDDEN', 'Audit verification access required', 403);
  return result(res, req.requestId, await verifyAuditChain());
});
// Security alert routes provide restricted evidence and acknowledgement operations.
api.get('/admin/alerts', requireAuth, async (req: AuthenticatedRequest, res) => {
  if (!(await requirePermission(req.user!.id, 'alerts:read'))) return failure(res, req.requestId, 'FORBIDDEN', 'Alert access required', 403);
  const r = await query('SELECT id,alert_type AS rule,severity,details,acknowledged_at AS "acknowledgedAt",created_at AS "createdAt" FROM app.security_alerts ORDER BY created_at DESC LIMIT 100');
  return result(res, req.requestId, r.rows);
});
api.patch('/admin/alerts/:id', requireAuth, async (req: AuthenticatedRequest, res) => {
  if (!(await requirePermission(req.user!.id, 'alerts:manage'))) return failure(res, req.requestId, 'FORBIDDEN', 'Alert management required', 403);
  const action = z.enum(['ACKNOWLEDGE','ESCALATE']).safeParse(req.body?.action);
  if (!action.success) return failure(res, req.requestId, 'VALIDATION_ERROR', 'Unknown alert action', 422);
  const next = await withTransaction(async (client) => { const r = await client.query('UPDATE app.security_alerts SET acknowledged_at=CASE WHEN $1=\'ACKNOWLEDGE\' THEN now() ELSE acknowledged_at END WHERE id=$2 RETURNING id,alert_type AS rule,severity,acknowledged_at AS "acknowledgedAt"', [action.data, req.params.id]); await appendAudit(client, { actorId: req.user!.id, action: `alert.${action.data.toLowerCase()}`, resourceType: 'security_alert', resourceId: String(req.params.id), outcome: r.rowCount ? 'success' : 'failure', correlationId: String(req.requestId) }); return r.rows[0]; });
  if (!next) return failure(res, req.requestId, 'NOT_FOUND', 'Alert not found', 404); return result(res, req.requestId, next);
});
api.get('/admin/incidents', requireAuth, async (req: AuthenticatedRequest, res) => { if (!(await requirePermission(req.user!.id, 'incidents:manage'))) return failure(res, req.requestId, 'FORBIDDEN', 'Incident access required', 403); const r = await query('SELECT id,alert_id AS "alertId",owner_id AS "ownerId",severity,status,summary,postmortem,created_at AS "createdAt",updated_at AS "updatedAt" FROM app.security_incidents ORDER BY created_at DESC'); return result(res, req.requestId, r.rows); });
api.post('/admin/incidents', requireAuth, async (req: AuthenticatedRequest, res) => { if (!(await requirePermission(req.user!.id, 'incidents:manage'))) return failure(res, req.requestId, 'FORBIDDEN', 'Incident management required', 403); const body = z.object({ severity: z.string().min(1), summary: z.string().trim().min(1).max(2000), alertId: uuid.optional() }).safeParse(req.body); if (!body.success) return failure(res, req.requestId, 'VALIDATION_ERROR', 'Invalid incident', 422); const incident = await withTransaction(async (client) => { const r = await client.query('INSERT INTO app.security_incidents(alert_id,owner_id,severity,summary) VALUES ($1,$2,$3,$4) RETURNING id,status', [body.data.alertId ?? null, req.user!.id, body.data.severity, body.data.summary]); await client.query('INSERT INTO app.incident_events(incident_id,actor_id,action,note) VALUES ($1,$2,\'CREATED\',$3)', [r.rows[0].id, req.user!.id, body.data.summary]); await appendAudit(client, { actorId: req.user!.id, action: 'incident.create', resourceType: 'security_incident', resourceId: r.rows[0].id, outcome: 'success', correlationId: String(req.requestId) }); return r.rows[0]; }); return result(res, req.requestId, incident, 201); });
api.patch('/admin/incidents/:id', requireAuth, async (req: AuthenticatedRequest, res) => { if (!(await requirePermission(req.user!.id, 'incidents:manage'))) return failure(res, req.requestId, 'FORBIDDEN', 'Incident management required', 403); const body = z.object({ status: z.enum(['TRIAGED','CONTAINED','ERADICATED','RECOVERED','CLOSED']), note: z.string().max(2000).default('') }).safeParse(req.body); if (!body.success) return failure(res, req.requestId, 'VALIDATION_ERROR', 'Invalid incident transition', 422); const incident = await withTransaction(async (client) => { const r = await client.query('UPDATE app.security_incidents SET status=$1,postmortem=CASE WHEN $1=\'CLOSED\' THEN $2 ELSE postmortem END,updated_at=now() WHERE id=$3 RETURNING id,status', [body.data.status, body.data.note, req.params.id]); if (!r.rowCount) throw new Error('NOT_FOUND'); await client.query('INSERT INTO app.incident_events(incident_id,actor_id,action,note) VALUES ($1,$2,$3,$4)', [req.params.id, req.user!.id, body.data.status, body.data.note]); await appendAudit(client, { actorId: req.user!.id, action: 'incident.transition', resourceType: 'security_incident', resourceId: String(req.params.id), outcome: 'success', correlationId: String(req.requestId), metadata: { status: body.data.status } }); return r.rows[0]; }); return result(res, req.requestId, incident); });
// Access reviews and awareness assignments are organization-scoped and auditable governance workflows.
api.get('/admin/access-reviews', requireAuth, async (req: AuthenticatedRequest, res) => { if (!(await requirePermission(req.user!.id, 'audit:read'))) return failure(res, req.requestId, 'FORBIDDEN', 'Access review permission required', 403); const r = await query(`SELECT ar.id,ar.period_start AS "periodStart",ar.period_end AS "periodEnd",ar.status,count(ari.id)::int AS "itemCount",count(ari.id) FILTER (WHERE ari.decision='PENDING')::int AS "pendingCount" FROM app.access_reviews ar LEFT JOIN app.access_review_items ari ON ari.review_id=ar.id WHERE ar.organization_id=(SELECT organization_id FROM app.user_profiles WHERE user_id=$1) GROUP BY ar.id ORDER BY ar.created_at DESC`, [req.user!.id]); return result(res, req.requestId, r.rows); });
api.post('/admin/access-reviews', requireAuth, async (req: AuthenticatedRequest, res) => { if (!(await requirePermission(req.user!.id, 'audit:read'))) return failure(res, req.requestId, 'FORBIDDEN', 'Access review permission required', 403); const body = z.object({ periodStart: z.string().date(), periodEnd: z.string().date() }).safeParse(req.body); if (!body.success) return failure(res, req.requestId, 'VALIDATION_ERROR', 'Invalid access review period', 422); const review = await withTransaction(async client => { const created = await client.query(`INSERT INTO app.access_reviews(organization_id,reviewer_id,period_start,period_end) SELECT organization_id,$1,$2,$3 FROM app.user_profiles WHERE user_id=$1 RETURNING id,status`, [req.user!.id, body.data.periodStart, body.data.periodEnd]); if (!created.rowCount) throw new Error('NO_ORGANIZATION'); await client.query(`INSERT INTO app.access_review_items(review_id,user_id,role_id) SELECT $1,ur.user_id,ur.role_id FROM app.user_roles ur JOIN app.user_profiles up ON up.user_id=ur.user_id WHERE up.organization_id=(SELECT organization_id FROM app.user_profiles WHERE user_id=$2) AND ur.revoked_at IS NULL`, [created.rows[0].id, req.user!.id]); await appendAudit(client, { actorId: req.user!.id, action: 'access-review.create', resourceType: 'access_review', resourceId: created.rows[0].id, outcome: 'success', correlationId: req.requestId }); return created.rows[0]; }); return result(res, req.requestId, review, 201); });
api.get('/training', requireAuth, async (req: AuthenticatedRequest, res) => { const r = await query(`SELECT c.id,c.title,c.content,c.due_at AS "dueAt",a.completed_at AS "completedAt" FROM app.awareness_campaigns c JOIN app.awareness_assignments a ON a.campaign_id=c.id WHERE a.user_id=$1 AND c.status='ACTIVE' ORDER BY c.due_at NULLS LAST`, [req.user!.id]); return result(res, req.requestId, r.rows); });
api.post('/training/:id/complete', requireAuth, async (req: AuthenticatedRequest, res) => { const completed = await withTransaction(async client => { const r = await client.query('UPDATE app.awareness_assignments SET completed_at=COALESCE(completed_at,now()) WHERE campaign_id=$1 AND user_id=$2 RETURNING campaign_id AS "campaignId",completed_at AS "completedAt"', [req.params.id, req.user!.id]); if (!r.rowCount) throw new Error('NOT_FOUND'); await appendAudit(client, { actorId: req.user!.id, action: 'awareness.complete', resourceType: 'awareness_campaign', resourceId: String(req.params.id), outcome: 'success', correlationId: req.requestId }); return r.rows[0]; }); return result(res, req.requestId, completed); });
api.post('/admin/training', requireAuth, async (req: AuthenticatedRequest, res) => { if (!(await requirePermission(req.user!.id, 'policy:manage'))) return failure(res, req.requestId, 'FORBIDDEN', 'Training management required', 403); const body = z.object({ title: z.string().trim().min(1).max(240), content: z.string().trim().min(20).max(10000), dueAt: z.string().datetime().optional() }).safeParse(req.body); if (!body.success) return failure(res, req.requestId, 'VALIDATION_ERROR', 'Invalid training campaign', 422); const r = await withTransaction(async client => { const campaign = await client.query('INSERT INTO app.awareness_campaigns(title,content,due_at,created_by) VALUES ($1,$2,$3,$4) RETURNING id,title,due_at AS "dueAt",status', [body.data.title,body.data.content,body.data.dueAt ?? null,req.user!.id]); await client.query(`INSERT INTO app.awareness_assignments(campaign_id,user_id) SELECT $1,user_id FROM app.user_profiles WHERE organization_id=(SELECT organization_id FROM app.user_profiles WHERE user_id=$2) AND status='ACTIVE'`, [campaign.rows[0].id,req.user!.id]); await appendAudit(client, { actorId: req.user!.id, action: 'awareness.create', resourceType: 'awareness_campaign', resourceId: campaign.rows[0].id, outcome: 'success', correlationId: req.requestId }); return campaign.rows[0]; }); return result(res, req.requestId, r, 201); });
// Governance resources are managed with raw SQL and protected by their dedicated admin permissions.
api.get('/admin/risks', requireAuth, async (req: AuthenticatedRequest, res) => { if (!(await requirePermission(req.user!.id, 'risk:manage'))) return failure(res, req.requestId, 'FORBIDDEN', 'Risk management required', 403); const r = await query('SELECT id,title,likelihood,impact,likelihood*impact AS score,owner_id AS "ownerId",mitigation,status,next_review_at AS "nextReviewAt" FROM app.risks ORDER BY likelihood*impact DESC,created_at DESC'); return result(res, req.requestId, r.rows); });
api.post('/admin/risks', requireAuth, async (req: AuthenticatedRequest, res) => { if (!(await requirePermission(req.user!.id, 'risk:manage'))) return failure(res, req.requestId, 'FORBIDDEN', 'Risk management required', 403); const body = z.object({ title: z.string().trim().min(1).max(240), likelihood: z.number().int().min(1).max(5), impact: z.number().int().min(1).max(5), mitigation: z.string().max(4000).default(''), nextReviewAt: z.string().date().optional() }).safeParse(req.body); if (!body.success) return failure(res, req.requestId, 'VALIDATION_ERROR', 'Invalid risk', 422); const r = await withTransaction(async client => { const created = await client.query('INSERT INTO app.risks(title,likelihood,impact,owner_id,mitigation,next_review_at) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id,title,likelihood,impact,mitigation,status', [body.data.title,body.data.likelihood,body.data.impact,req.user!.id,body.data.mitigation,body.data.nextReviewAt ?? null]); await appendAudit(client, { actorId: req.user!.id, action: 'risk.create', resourceType: 'risk', resourceId: created.rows[0].id, outcome: 'success', correlationId: req.requestId }); return created.rows[0]; }); return result(res, req.requestId, r, 201); });
api.get('/admin/policies', requireAuth, async (req: AuthenticatedRequest, res) => { if (!(await requirePermission(req.user!.id, 'policy:manage'))) return failure(res, req.requestId, 'FORBIDDEN', 'Policy management required', 403); const r = await query('SELECT id,type,version,content,approved_by AS "approvedBy",effective_at AS "effectiveAt",created_at AS "createdAt" FROM app.policy_documents ORDER BY created_at DESC'); return result(res, req.requestId, r.rows); });
api.post('/admin/policies', requireAuth, async (req: AuthenticatedRequest, res) => { if (!(await requirePermission(req.user!.id, 'policy:manage'))) return failure(res, req.requestId, 'FORBIDDEN', 'Policy management required', 403); const body = z.object({ type: z.string().trim().min(1).max(120), version: z.string().trim().min(1).max(40), content: z.string().trim().min(20).max(20000) }).safeParse(req.body); if (!body.success) return failure(res, req.requestId, 'VALIDATION_ERROR', 'Invalid policy document', 422); const r = await withTransaction(async client => { const created = await client.query('INSERT INTO app.policy_documents(type,version,content,approved_by,effective_at) VALUES ($1,$2,$3,$4,now()) RETURNING id,type,version,effective_at AS "effectiveAt"', [body.data.type,body.data.version,body.data.content,req.user!.id]); await appendAudit(client, { actorId: req.user!.id, action: 'policy.publish', resourceType: 'policy_document', resourceId: created.rows[0].id, outcome: 'success', correlationId: req.requestId }); return created.rows[0]; }); return result(res, req.requestId, r, 201); });
api.get('/admin/security-changes', requireAuth, async (req: AuthenticatedRequest, res) => { if (!(await requirePermission(req.user!.id, 'change:approve'))) return failure(res, req.requestId, 'FORBIDDEN', 'Change approval required', 403); const r = await query('SELECT id,requested_by AS "requestedBy",reviewed_by AS "reviewedBy",type,before_json AS "before",after_json AS "after",status,reason,created_at AS "createdAt" FROM app.security_changes ORDER BY created_at DESC'); return result(res, req.requestId, r.rows); });
api.post('/admin/security-changes', requireAuth, async (req: AuthenticatedRequest, res) => { if (!(await requirePermission(req.user!.id, 'change:approve'))) return failure(res, req.requestId, 'FORBIDDEN', 'Change approval required', 403); const body = z.object({ type: z.string().trim().min(1).max(120), reason: z.string().trim().min(10).max(2000), before: z.record(z.string(),z.unknown()).default({}), after: z.record(z.string(),z.unknown()).default({}) }).safeParse(req.body); if (!body.success) return failure(res, req.requestId, 'VALIDATION_ERROR', 'Invalid security change', 422); const r = await withTransaction(async client => { const created = await client.query('INSERT INTO app.security_changes(requested_by,type,before_json,after_json,reason) VALUES ($1,$2,$3,$4,$5) RETURNING id,status,created_at AS "createdAt"', [req.user!.id,body.data.type,JSON.stringify(body.data.before),JSON.stringify(body.data.after),body.data.reason]); await appendAudit(client, { actorId: req.user!.id, action: 'security-change.create', resourceType: 'security_change', resourceId: created.rows[0].id, outcome: 'success', correlationId: req.requestId }); return created.rows[0]; }); return result(res, req.requestId, r, 201); });
api.get('/notifications', requireAuth, async (req: AuthenticatedRequest, res) => {
  const r = await query('SELECT id,type,title,body,status,read_at AS "readAt",created_at AS "createdAt" FROM app.notifications WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100', [req.user!.id]);
  return result(res, req.requestId, r.rows);
});
// Notifications are always filtered by user ID so one user cannot mark another user's message read.
api.patch('/notifications/:id/read', requireAuth, async (req: AuthenticatedRequest, res) => {
  await query('UPDATE app.notifications SET status=\'READ\',read_at=now() WHERE id=$1 AND user_id=$2', [req.params.id, req.user!.id]);
  return result(res, req.requestId, { id: req.params.id, status: 'READ' });
});


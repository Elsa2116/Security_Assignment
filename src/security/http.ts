import crypto from 'node:crypto';
import type { NextFunction, Request, Response } from 'express';
import { fromNodeHeaders } from 'better-auth/node';
import { auth } from '../auth/better-auth.js';
import { query } from '../db/pool.js';

export type AuthenticatedRequest = Request & { user?: { id: string; email?: string; name?: string }; session?: unknown; requestId?: string };

export function requestContext(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  req.requestId = req.header('x-request-id') || crypto.randomUUID();
  res.setHeader('x-request-id', req.requestId);
  next();
}

export async function requireAuth(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  try {
    const session = await auth.api.getSession({ headers: fromNodeHeaders(req.headers), query: { disableCookieCache: true } });
    if (!session) return res.status(401).json({ error: { code: 'UNAUTHENTICATED', message: 'Authentication required' }, meta: { requestId: req.requestId } });
    req.user = { id: session.user.id, email: session.user.email, name: session.user.name };
    req.session = session.session;
    return next();
  } catch {
    return res.status(401).json({ error: { code: 'UNAUTHENTICATED', message: 'Authentication required' }, meta: { requestId: req.requestId } });
  }
}

export function result(res: Response, requestId: string | undefined, data: unknown, status = 200, meta: Record<string, unknown> = {}) {
  return res.status(status).json({ data, meta: { requestId, ...meta } });
}

export function failure(res: Response, requestId: string | undefined, code: string, message: string, status: number, fieldErrors: Record<string, string> = {}) {
  return res.status(status).json({ error: { code, message, fieldErrors }, meta: { requestId } });
}

export async function requirePermission(userId: string, permission: string) {
  const found = await query<{ allowed: boolean }>(`SELECT EXISTS (
    SELECT 1 FROM app.user_roles ur JOIN app.role_permissions rp ON rp.role_id = ur.role_id JOIN app.permissions p ON p.id = rp.permission_id
    WHERE ur.user_id = $1 AND p.name = $2 AND (ur.expires_at IS NULL OR ur.expires_at > now()) AND ur.revoked_at IS NULL
  ) allowed`, [userId, permission]);
  return found.rows[0]?.allowed === true;
}

# SecureFlow architecture

SecureFlow uses an Express TypeScript API, PostgreSQL 16, Redis, Mailpit, MinIO, and a separate worker. Better Auth owns credential/session lifecycle through its official PostgreSQL `pg.Pool` integration. Application-specific persistence is raw parameterized SQL through `pg.Pool`; every multi-write workflow checks out one client and uses explicit `BEGIN`, `COMMIT`, and `ROLLBACK`.

The `app` schema contains organization, department, profile, requests, approvals, role workflows, notifications/outbox, security evidence, backup manifests, and governance data. The `auth` schema contains Better Auth core tables. Audit events are append-only and hash chained; ordinary application endpoints do not update or delete them.

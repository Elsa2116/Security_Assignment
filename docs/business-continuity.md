# SecureFlow business continuity

## Local baseline targets

- Recovery point objective: 24 hours until WAL archiving is configured.
- Recovery time objective: 4 hours for an isolated PostgreSQL restore.
- Critical dependencies: PostgreSQL, API, Better Auth session data, Redis, and backup storage.

## Recovery procedure

1. Declare the incident and record the start time.
2. Preserve the latest verified encrypted backup.
3. Provision an isolated PostgreSQL target.
4. Restore and verify users, requests, audit events, and migrations.
5. Validate API health and authentication before switching traffic.
6. Record measured RPO/RTO and complete a post-incident review.

Production requires off-site immutable storage, tested WAL recovery, and a documented failover owner.

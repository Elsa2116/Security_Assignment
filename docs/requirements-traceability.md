# SecureFlow requirement traceability

| Contract requirement | Implementation | Test/evidence | Status |
|---|---|---|---|
| PostgreSQL + `pg.Pool` + parameterized SQL | `src/db/pool.ts`, `migrations/` | Docker build and live readiness | PASS |
| Better Auth official PostgreSQL integration | `src/auth/better-auth.ts` | Live signup against PostgreSQL | PASS |
| Bcrypt password hashing | `src/auth/password.ts` | Better Auth custom password hook, work factor 12 | PASS |
| Registration CAPTCHA | `src/security/captcha.ts`, `src/server.ts` | Local development bypass; production secret required | PARTIAL |
| Lockout and login throttling | `src/security/login-protection.ts`, `src/server.ts` | Code path implemented; distributed Redis evidence pending | PARTIAL |
| Atomic request approval | `src/api.ts` `decideRequest`, `withTransaction` | Integration test/demo users required | PARTIAL |
| Role-change separation of duties | `src/api.ts` `decideRoleChange` | Integration test/demo users required | PARTIAL |
| Refresh rotation and replay alerts | `src/security/tokens.ts` | Security test required | PARTIAL |
| MFA/TOTP and recovery codes | `src/security/mfa.ts` | Better Auth challenge integration required | PARTIAL |
| Append-only hash-chain audit | `src/security/audit-chain.ts`, SQL trigger | `scripts/verify-audit-chain.ts` | PARTIAL |
| Encrypted full backup | `src/services/backup.ts` | `npm run backup:full`, external `pg_dump` required | BLOCKED |
| Supporting services | `docker-compose.yml` | `docker compose ps` | PASS |
| Full UI route inventory | Contract section 8 | No Next.js UI yet | BLOCKED |
| Security scans and DAST | `.github/workflows/` pending | Not run | BLOCKED |

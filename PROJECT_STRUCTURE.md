# SecureFlow Project Structure

## Scope

This document records the current structure of SecureFlow and a safe professional target structure. The organization request explicitly prohibits changing source code, imports, configuration, routes, database behavior, dependencies, or runtime behavior. Therefore, no existing application files were moved.

## Current technology layout

- Backend: TypeScript, Node.js, Express, Better Auth, `pg.Pool`, raw parameterized PostgreSQL SQL.
- Frontend: same-origin static HTML, CSS, and browser JavaScript served by Express from `public/`.
- Database: PostgreSQL migrations in `migrations/`; Docker initialization files in `docker/postgres/init/`.
- Background processing: worker entry point in `src/workers/` and Mailpit/SMTP integration.
- Tests: Vitest configuration and tests under `tests/`.
- Operations: Docker Compose, backup scripts, security documentation, and OpenAPI documentation.

## Complete current project tree

```text
SecureFlow/
├── .env                         # Local secrets; ignored by Git
├── .env.example                 # Environment variable template
├── .gitignore
├── Dockerfile
├── docker-compose.yml
├── package.json
├── package-lock.json
├── tsconfig.json
├── vitest.config.ts
├── vitest.integration.config.ts
├── auth.ts                      # Better Auth CLI configuration entry point
├── README.md
├── PROJECT_STRUCTURE.md
├── public/                      # Static browser application served by Express
│   ├── index.html
│   └── app.js
├── src/                         # TypeScript backend and worker source
│   ├── api.ts                   # Application API routes and handlers
│   ├── server.ts                # Express server, static hosting, auth boundary
│   ├── config.ts                # Runtime configuration
│   ├── auth/
│   │   ├── better-auth.ts       # Better Auth PostgreSQL integration
│   │   └── password.ts          # bcrypt password configuration/hooks
│   ├── db/
│   │   └── pool.ts              # PostgreSQL pool and transaction helpers
│   ├── security/
│   │   ├── audit.ts
│   │   ├── audit-chain.ts
│   │   ├── captcha.ts
│   │   ├── http.ts
│   │   ├── login-protection.ts
│   │   ├── mfa.ts
│   │   ├── rbac.ts
│   │   └── tokens.ts
│   ├── services/
│   │   └── backup.ts
│   └── workers/
│       ├── index.ts
│       └── mailer.ts
├── migrations/                  # Versioned PostgreSQL migrations
│   ├── 001_app_core.sql
│   ├── 002_security_constraints.sql
│   ├── 003_migrations_table.sql
│   ├── 004_secureflow_contract.sql
│   ├── 005_better_auth_core.sql
│   ├── 006_contract_roles.sql
│   ├── 007_admin_workflows.sql
│   ├── 008_mfa_session_enforcement.sql
│   └── 009_governance_workflows.sql
├── docker/
│   └── postgres/
│       └── init/
│           └── 001-schemas.sql
├── scripts/                     # Operational, migration, seed, and verification scripts
│   ├── backup-full.ts
│   ├── defense-check.ts
│   ├── migrate.ts
│   ├── promote-admin.ts
│   ├── reset-password.ts
│   ├── restore-test.ts
│   ├── seed-demo.ts
│   ├── verify-audit-chain.ts
│   └── verify-backup.ts
├── tests/
│   └── health.test.ts
├── openapi/
│   └── secureflow.openapi.yaml
└── docs/
    ├── architecture.md
    ├── admin-workflow.md
    ├── business-continuity.md
    ├── implementation-status.md
    ├── incident-response.md
    ├── operations-runbook.md
    ├── password-recovery.md
    └── requirements-traceability.md
```

Generated or local-only directories such as `node_modules/`, `dist/`, `.git/`, and the local `.env` are intentionally excluded from the application tree above.

## Recommended professional target structure

The following structure is recommended for a future controlled refactor. It is not applied in this task because it would require import, route, Docker, TypeScript, and migration-path changes.

```text
SecureFlow/
├── frontend/
│   ├── public/
│   │   └── index.html
│   ├── src/
│   │   ├── app/
│   │   ├── components/
│   │   ├── features/
│   │   ├── services/
│   │   ├── styles/
│   │   └── app.js
│   └── tests/
├── backend/
│   ├── src/
│   │   ├── auth/
│   │   ├── config/
│   │   ├── db/
│   │   ├── routes/
│   │   ├── security/
│   │   ├── services/
│   │   └── workers/
│   ├── tests/
│   └── scripts/
├── database/
│   ├── migrations/
│   └── init/
├── docs/
├── openapi/
├── Dockerfile
├── docker-compose.yml
└── workspace configuration files
```

## Existing-file mapping

| Current location | Future location | Reason it was not moved now |
|---|---|---|
| `public/index.html`, `public/app.js` | `frontend/public/`, `frontend/src/` | `src/server.ts` serves the literal `public` directory; moving requires a server-path change. |
| `src/**` | `backend/src/**` | `package.json`, `tsconfig.json`, Docker commands, and internal relative imports depend on `src`. |
| `scripts/**` | `backend/scripts/**` | Scripts import `../src/**`, use the root `migrations` path, and are called directly by npm and Docker. |
| `migrations/**` | `database/migrations/**` | `scripts/migrate.ts` resolves the root `migrations` directory. |
| `docker/postgres/init/**` | `database/init/**` | Docker Compose currently mounts the literal path. |
| `auth.ts` | `backend/auth.ts` | Dockerfile copies the root file and Better Auth CLI configuration expects the current location. |
| `tests/**` | `backend/tests/**` and `frontend/tests/**` | Test locations and future test split require configuration updates. |
| `docs/**`, `openapi/**` | unchanged | Already appropriately separated from runtime code. |

## Safely moved files

None. Moving any existing runtime file would require changing code or configuration, which the task explicitly forbids.

## Files that require a planned migration

The following should only be moved in a dedicated refactor branch with tests and explicit approval:

1. `public/` requires an Express static-root update and frontend build/test conventions.
2. `src/` requires TypeScript root and output changes plus import updates.
3. `scripts/` requires npm script, Docker command, and relative import updates.
4. `migrations/` requires migration discovery and Docker path updates.
5. `tests/` requires Vitest include/path updates.
6. `auth.ts` requires Docker and Better Auth CLI path updates.

## Validation performed

- Inspected all tracked project files and directories.
- Inspected TypeScript, npm, Docker, server static-file, script, and migration path references.
- Confirmed the current structure is internally consistent with those references.
- No existing source file was rewritten or deleted.
- No dependency was installed or removed.
- No database migration, deployment, commit, or push was performed for this structure-only task.

## Future maintainability recommendations

- Perform the target move in a separate branch with a complete import/path migration.
- Add frontend and backend test directories only when real tests are introduced.
- Keep migrations append-only and versioned.
- Keep operational scripts separate from application runtime modules.
- Keep generated `dist/`, dependency, backup, and secret files out of Git.
- Run build, typecheck, integration tests, Docker Compose health checks, and migration checks after every structural move.

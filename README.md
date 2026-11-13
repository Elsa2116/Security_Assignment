# SecureFlow

SecureFlow is scaffolded as a TypeScript Node API with PostgreSQL in Docker.

Code comments follow a maintenance convention: module comments explain ownership, function comments explain security invariants and transaction boundaries, and migration comments explain schema intent. New security-sensitive code should document what it protects and why.

## Database rules

- Application queries use `pg.Pool` and parameterized SQL only.
- Transactions use one checked-out `PoolClient` and explicit `BEGIN`/`COMMIT`/`ROLLBACK`.
- Better Auth uses its official PostgreSQL integration with a `pg.Pool`; it owns supported authentication behavior.
- Application tables live under `app`; Better Auth tables live under `auth` and are generated/managed by the Better Auth CLI.
- No Prisma, Drizzle, Sequelize, TypeORM, or other ORM is used by the application.

## Run

```sh
copy .env.example .env
npm install
docker compose up -d postgres
npm run db:migrate
npm run db:auth:migrate
npm run dev
```

The API health endpoint is `GET /health`; Better Auth routes are under `/api/auth/*`.

## Next implementation slices

The scaffold includes the database foundation, role assignment, refresh-token rotation, audit event transactions, and Better Auth wiring. Contract-specific route handlers, MFA policy enforcement, approval workflows, encrypted backup jobs, alert delivery, and end-to-end security tests should be added in the next slices against the complete contract text.

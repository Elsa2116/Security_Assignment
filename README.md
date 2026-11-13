# SecureFlow

SecureFlow is scaffolded as a TypeScript Node API with PostgreSQL in Docker.

Code comments follow a maintenance convention: module comments explain ownership, function comments explain security invariants and transaction boundaries, and migration comments explain schema intent. New security-sensitive code should document what it protects and why.

## Database rules

- Application queries use `pg.Pool` and parameterized SQL only.
- Transactions use one checked-out `PoolClient` and explicit `BEGIN`/`COMMIT`/`ROLLBACK`.
- Better Auth uses its official PostgreSQL integration with a `pg.Pool`; it owns supported authentication behavior.
- Application tables live under `app`; Better Auth tables live under `auth` and are generated/managed by the Better Auth CLI.
- No Prisma, Drizzle, Sequelize, TypeORM, or other ORM is used by the application.

## Run locally

```sh
docker compose up -d --build
```

Open `http://localhost:3000`. Mailpit is available at `http://localhost:8025` for verification and password-reset messages.

The API health endpoint is `GET /health`; Better Auth routes are under `/api/auth/*`.

## Local workflow

1. Register an employee account and verify the email in Mailpit.
2. Sign in with the organization administrator account (`admin@example.test` in the seeded local database).
3. Open `http://localhost:3000/?view=admin` and admit the verified employee into an organization and department.
4. Sign out, sign in as the employee, and open `http://localhost:3000/?view=new-request`.
5. Submit a request, then sign in as the administrator and approve or reject it from the admin console.
6. The employee can review the decision at `http://localhost:3000/?view=requests`.
7. Use Settings to enroll TOTP MFA, save the one-time recovery codes, and revoke active sessions.

## Manual production steps

- Replace development secrets in `.env` with generated values of at least 32 characters.
- Configure SMTP credentials and a production CAPTCHA provider.
- Put the API behind HTTPS/TLS and configure secure cookie behavior for the production domain.
- Configure an external immutable backup target and run both backup verification and an isolated restore drill.
- Run the security scans and browser tests in CI before deployment.


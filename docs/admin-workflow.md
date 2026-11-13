# SecureFlow admin workflow

SecureFlow now supports the complete local demonstration flow:

1. An employee registers and verifies their email in Mailpit.
2. An organization administrator admits the verified employee and assigns an organization and department.
3. The employee signs in and submits a request.
4. The administrator opens `Admin console`, reviews the centralized queue, and approves or rejects the request.
5. Every admission and request decision is written to the audit chain and the employee receives an in-app notification.

## Create a local administrator

Register a second account through the browser and verify it in Mailpit at `http://localhost:8025`. Then run:

```powershell
docker compose exec api node dist/scripts/promote-admin.js "admin@example.test"
```

The script is local bootstrap tooling only. It requires the account to be email-verified, assigns the first seeded organization and department, and grants the `ADMIN` role.

## Admin console

The admin console uses these protected raw-SQL API routes:

- `GET /api/v1/admin/overview` — organization metrics and pending requests
- `GET /api/v1/admin/members` — admission queue
- `GET /api/v1/admin/directory` — organization and department choices
- `POST /api/v1/admin/members/:userId/admit` — transactional admission
- `GET /api/v1/admin/requests` — organization request history
- `POST /api/v1/requests/:id/approve` — approve with optimistic versioning and idempotency
- `POST /api/v1/requests/:id/reject` — reject with a required reason

Admin approval is organization-scoped, prevents self-approval, records request history and audit entries, and creates a notification for the employee.

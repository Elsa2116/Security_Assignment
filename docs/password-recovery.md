# Local password recovery

Use this only for local/demo accounts whose password hash predates the current bcrypt configuration. It is not exposed as an HTTP endpoint and does not print the password.

```powershell
docker compose build api
docker compose up -d api
docker compose exec api node dist/scripts/reset-password.js "your-email@example.com" "NewPasswordAtLeast12!"
```

The script updates the Better Auth credential hash to bcrypt, clears the local lockout counters, and revokes existing sessions. Production password recovery must use the Better Auth email reset flow with configured SMTP.

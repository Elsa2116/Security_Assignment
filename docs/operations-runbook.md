# Operations runbook

## Start

```powershell
docker compose up -d
docker compose ps
Invoke-WebRequest http://localhost:3000/health
```

Ports: API `3000`, PostgreSQL host `5433`, Redis `6379`, Mailpit SMTP/UI `1025/8025`, MinIO API/console `9010/9011`.

## Logs

```powershell
docker compose logs -f api worker postgres
```

## Stop

```powershell
docker compose down
```

Do not delete the database volume in a shared or evidence environment. Production secrets, TLS, object-lock storage, and restore targets must be configured outside source control.

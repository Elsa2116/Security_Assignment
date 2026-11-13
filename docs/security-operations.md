# SecureFlow Security Operations Checklist

## Required production configuration

- HTTPS with a valid certificate and `BETTER_AUTH_URL` set to the HTTPS origin.
- HSTS enabled only after HTTPS has been verified.
- Production CAPTCHA site and secret keys.
- Verified SMTP sender/domain and authenticated SMTP key.
- Secrets stored in a managed secret store, not source control or Docker Compose files.
- `HIBP_PASSWORD_CHECK=true`.

## Monitoring

Forward application stdout, reverse-proxy logs, PostgreSQL security events, backup events, and audit integrity failures to the organization SIEM. Alert on repeated login failures, MFA failures, role changes, audit-chain failures, backup failures, and unusual administrative activity.

## Backup and recovery targets

The local baseline is RPO 24 hours and RTO 4 hours for an isolated restore. Production owners must confirm these targets, configure scheduled encrypted backups, keep an off-site immutable copy, and record a restore drill at least quarterly.

## Release gate

Before release, run build/typecheck, dependency audit, Semgrep, CodeQL, Playwright, ZAP, load testing, and an authorized penetration test. Record findings, owners, fixes, and retest evidence.

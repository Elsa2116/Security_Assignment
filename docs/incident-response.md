# SecureFlow incident response

## Roles

- Incident owner: security administrator assigned in the incident record.
- Decision authority: organization administrator for containment and recovery.
- Evidence owner: auditor responsible for preserving audit-chain and backup evidence.

## Procedure

1. Detect and record the alert or report.
2. Triage severity, affected users, and affected services.
3. Contain by revoking sessions, disabling accounts, or isolating infrastructure.
4. Eradicate the cause and rotate exposed credentials.
5. Recover from a verified backup and monitor for recurrence.
6. Close only after a postmortem, evidence review, and owner approval.

All state changes must be recorded through the incident API and append-only audit log.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS app.organizations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text NOT NULL, slug text NOT NULL UNIQUE,
  status text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','SUSPENDED')), created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS app.departments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL REFERENCES app.organizations(id), name text NOT NULL,
  manager_user_id text, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(), UNIQUE(organization_id,name)
);
CREATE TABLE IF NOT EXISTS app.user_profiles (
  user_id text PRIMARY KEY, organization_id uuid REFERENCES app.organizations(id), department_id uuid REFERENCES app.departments(id),
  name text NOT NULL DEFAULT '', email_normalized text, status text NOT NULL DEFAULT 'PENDING_ADMISSION' CHECK (status IN ('PENDING_ADMISSION','ACTIVE','SUSPENDED','DELETED')),
  email_verified_at timestamptz, locked_until timestamptz, failed_login_count integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS user_profiles_org_email ON app.user_profiles(organization_id,email_normalized) WHERE email_normalized IS NOT NULL AND status <> 'DELETED';

ALTER TABLE app.roles ADD COLUMN IF NOT EXISTS code text;
ALTER TABLE app.roles ADD COLUMN IF NOT EXISTS is_privileged boolean NOT NULL DEFAULT false;
UPDATE app.roles SET code = upper(replace(name,' ','_')) WHERE code IS NULL;
ALTER TABLE app.roles ALTER COLUMN code SET NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS roles_code_key ON app.roles(code);
ALTER TABLE app.permissions ADD COLUMN IF NOT EXISTS resource text;
ALTER TABLE app.permissions ADD COLUMN IF NOT EXISTS action text;
ALTER TABLE app.permissions ADD COLUMN IF NOT EXISTS scope text NOT NULL DEFAULT 'ADMIN';
UPDATE app.permissions SET resource = split_part(name,':',1), action = split_part(name,':',2) WHERE resource IS NULL;
ALTER TABLE app.permissions ALTER COLUMN resource SET NOT NULL;
ALTER TABLE app.permissions ALTER COLUMN action SET NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS permissions_resource_action_scope_key ON app.permissions(resource,action,scope);

CREATE TABLE IF NOT EXISTS app.role_change_requests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), target_user_id text NOT NULL, requested_by text NOT NULL, role_id uuid NOT NULL REFERENCES app.roles(id),
  operation text NOT NULL CHECK (operation IN ('GRANT','REVOKE')), reason text NOT NULL, status text NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING','APPROVED','REJECTED','CANCELLED')),
  version integer NOT NULL DEFAULT 1, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE app.user_roles ADD COLUMN IF NOT EXISTS grant_request_id uuid REFERENCES app.role_change_requests(id);
ALTER TABLE app.user_roles ADD COLUMN IF NOT EXISTS expires_at timestamptz;
ALTER TABLE app.user_roles ADD COLUMN IF NOT EXISTS revoked_at timestamptz;
CREATE TABLE IF NOT EXISTS app.role_change_decisions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), role_change_request_id uuid NOT NULL REFERENCES app.role_change_requests(id), reviewer_id text NOT NULL,
  decision text NOT NULL CHECK (decision IN ('APPROVED','REJECTED')), comment text, decided_at timestamptz NOT NULL DEFAULT now(), UNIQUE(role_change_request_id,reviewer_id)
);
CREATE TABLE IF NOT EXISTS app.requests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL REFERENCES app.organizations(id), department_id uuid NOT NULL REFERENCES app.departments(id),
  owner_id text NOT NULL, assigned_manager_id text NOT NULL, type text NOT NULL CHECK (type IN ('LEAVE','EQUIPMENT','SERVICE')), title text NOT NULL,
  description text NOT NULL DEFAULT '', payload_json jsonb NOT NULL DEFAULT '{}', status text NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING','APPROVED','REJECTED','CANCELLED')),
  version integer NOT NULL DEFAULT 1, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS requests_owner_created ON app.requests(owner_id,created_at DESC);
CREATE INDEX IF NOT EXISTS requests_manager_status ON app.requests(assigned_manager_id,status,created_at DESC);
CREATE TABLE IF NOT EXISTS app.request_decisions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), request_id uuid NOT NULL REFERENCES app.requests(id), reviewer_id text NOT NULL,
  decision text NOT NULL CHECK (decision IN ('APPROVED','REJECTED')), reason text, decided_at timestamptz NOT NULL DEFAULT now(), UNIQUE(request_id)
);
CREATE TABLE IF NOT EXISTS app.request_history (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), request_id uuid NOT NULL REFERENCES app.requests(id), actor_id text NOT NULL, from_status text, to_status text NOT NULL,
  changed_fields jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS app.notifications (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id text NOT NULL, type text NOT NULL, title text NOT NULL, body text NOT NULL,
  status text NOT NULL DEFAULT 'UNREAD' CHECK (status IN ('UNREAD','READ')), read_at timestamptz, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS app.outbox_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), event_type text NOT NULL, payload jsonb NOT NULL, status text NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING','PROCESSING','DELIVERED','FAILED')),
  attempt_count integer NOT NULL DEFAULT 0, next_attempt_at timestamptz NOT NULL DEFAULT now(), created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS app.refresh_token_families (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id text NOT NULL, session_id text, status text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','REVOKED')),
  absolute_expires_at timestamptz NOT NULL, revoked_at timestamptz, created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE app.refresh_tokens ADD COLUMN IF NOT EXISTS family_id uuid;
ALTER TABLE app.refresh_tokens ADD COLUMN IF NOT EXISTS used_at timestamptz;
CREATE INDEX IF NOT EXISTS refresh_token_family_idx ON app.refresh_tokens(family_id);
CREATE TABLE IF NOT EXISTS app.jwt_revocations (
  jti text PRIMARY KEY, session_id text, expires_at timestamptz NOT NULL, reason text NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS app.mfa_credentials (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id text NOT NULL UNIQUE, encrypted_secret text NOT NULL, enabled_at timestamptz,
  last_used_step bigint, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS app.mfa_recovery_codes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id text NOT NULL, code_hash text NOT NULL, used_at timestamptz, created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE app.audit_events ADD COLUMN IF NOT EXISTS sequence bigint;
ALTER TABLE app.audit_events ADD COLUMN IF NOT EXISTS correlation_id text;
ALTER TABLE app.audit_events ADD COLUMN IF NOT EXISTS previous_hash text;
ALTER TABLE app.audit_events ADD COLUMN IF NOT EXISTS entry_hash text;
CREATE SEQUENCE IF NOT EXISTS app.audit_sequence;
ALTER TABLE app.audit_events ALTER COLUMN sequence SET DEFAULT nextval('app.audit_sequence');
CREATE UNIQUE INDEX IF NOT EXISTS audit_events_sequence_key ON app.audit_events(sequence);
CREATE TABLE IF NOT EXISTS app.audit_checkpoints (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), last_sequence bigint NOT NULL, chain_hash text NOT NULL, external_storage_key text,
  verified_at timestamptz, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS app.security_incidents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), alert_id uuid REFERENCES app.security_alerts(id), owner_id text, severity text NOT NULL,
  status text NOT NULL DEFAULT 'TRIAGED' CHECK (status IN ('TRIAGED','CONTAINED','ERADICATED','RECOVERED','CLOSED')), summary text NOT NULL, postmortem text,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS app.incident_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), incident_id uuid NOT NULL REFERENCES app.security_incidents(id), actor_id text NOT NULL, action text NOT NULL,
  note text NOT NULL DEFAULT '', occurred_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS app.backup_records (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), kind text NOT NULL CHECK (kind IN ('FULL','WAL','INCREMENTAL')), storage_key text NOT NULL,
  checksum text NOT NULL, encryption_key_id text NOT NULL, started_at timestamptz NOT NULL, finished_at timestamptz, status text NOT NULL,
  retention_until timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS app.restore_tests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), backup_record_id uuid NOT NULL REFERENCES app.backup_records(id), started_at timestamptz NOT NULL,
  finished_at timestamptz, integrity_result text NOT NULL, measured_rto_ms bigint, status text NOT NULL
);
CREATE TABLE IF NOT EXISTS app.risks (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), title text NOT NULL, likelihood integer NOT NULL CHECK (likelihood BETWEEN 1 AND 5), impact integer NOT NULL CHECK (impact BETWEEN 1 AND 5),
  owner_id text, mitigation text NOT NULL DEFAULT '', status text NOT NULL DEFAULT 'OPEN', next_review_at timestamptz, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS app.policy_documents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), type text NOT NULL, version text NOT NULL, content text NOT NULL, approved_by text, effective_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(type,version)
);
CREATE TABLE IF NOT EXISTS app.policy_acknowledgements (
  policy_id uuid NOT NULL REFERENCES app.policy_documents(id), user_id text NOT NULL, acknowledged_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(policy_id,user_id)
);
CREATE TABLE IF NOT EXISTS app.security_changes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), requested_by text NOT NULL, reviewed_by text, type text NOT NULL, before_json jsonb NOT NULL DEFAULT '{}', after_json jsonb NOT NULL DEFAULT '{}',
  status text NOT NULL DEFAULT 'PENDING', reason text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS app.idempotency_keys (
  user_id text NOT NULL, key text NOT NULL, route text NOT NULL, request_hash text NOT NULL, response_ref text, expires_at timestamptz NOT NULL,
  PRIMARY KEY(user_id,key,route)
);

INSERT INTO app.permissions(name,resource,action,scope,description) VALUES
 ('requests:create','requests','create','OWN','Create own requests'), ('requests:read','requests','read','OWN','Read own requests'),
 ('requests:approve','requests','approve','DEPARTMENT','Approve assigned department requests'), ('roles:approve','roles','approve','ADMIN','Approve role changes'),
 ('audit:read','audit','read','ADMIN','Read audit evidence'), ('audit:verify','audit','verify','ADMIN','Verify audit chain'), ('alerts:read','alerts','read','ADMIN','Read alerts'),
 ('alerts:manage','alerts','manage','ADMIN','Manage alerts'), ('incidents:manage','incidents','manage','ADMIN','Manage incidents'), ('backup:read','backup','read','ADMIN','Read backup metadata'),
 ('backup:execute','backup','execute','ADMIN','Run backups'), ('backup:test','backup','test','ADMIN','Run restore tests'), ('risk:manage','risk','manage','ADMIN','Manage risks'),
 ('policy:manage','policy','manage','ADMIN','Manage policies'), ('change:approve','change','approve','ADMIN','Approve security changes')
ON CONFLICT (name) DO NOTHING;

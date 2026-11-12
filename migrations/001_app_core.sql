CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS app.roles (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL UNIQUE,
  description text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS app.permissions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL UNIQUE,
  description text
);

CREATE TABLE IF NOT EXISTS app.role_permissions (
  role_id uuid NOT NULL REFERENCES app.roles(id) ON DELETE CASCADE,
  permission_id uuid NOT NULL REFERENCES app.permissions(id) ON DELETE CASCADE,
  PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE IF NOT EXISTS app.user_roles (
  user_id text NOT NULL,
  role_id uuid NOT NULL REFERENCES app.roles(id) ON DELETE CASCADE,
  assigned_by text,
  assigned_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, role_id)
);

CREATE TABLE IF NOT EXISTS app.refresh_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id text NOT NULL,
  token_hash text NOT NULL UNIQUE,
  family_id uuid NOT NULL,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  replaced_by uuid REFERENCES app.refresh_tokens(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz
);

CREATE TABLE IF NOT EXISTS app.audit_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_user_id text,
  action text NOT NULL,
  resource_type text NOT NULL,
  resource_id text,
  outcome text NOT NULL CHECK (outcome IN ('success', 'failure')),
  ip_address inet,
  user_agent text,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS app.security_alerts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id text,
  alert_type text NOT NULL,
  severity text NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
  details jsonb NOT NULL DEFAULT '{}'::jsonb,
  acknowledged_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON app.user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON app.refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family_id ON app.refresh_tokens(family_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_actor_created ON app.audit_events(actor_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_alerts_user_created ON app.security_alerts(user_id, created_at DESC);

INSERT INTO app.roles(name, description) VALUES
  ('admin', 'Full platform administration'),
  ('security_admin', 'Security and identity administration'),
  ('auditor', 'Read-only audit access'),
  ('user', 'Standard SecureFlow user')
ON CONFLICT (name) DO NOTHING;

CREATE OR REPLACE FUNCTION app.set_updated_at() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;

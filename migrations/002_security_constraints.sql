-- Add immutable audit protection and supporting indexes after the base tables exist.
ALTER TABLE app.refresh_tokens
  ADD CONSTRAINT refresh_tokens_expiry_check CHECK (expires_at > created_at);

CREATE INDEX IF NOT EXISTS idx_audit_events_action ON app.audit_events(action);
CREATE INDEX IF NOT EXISTS idx_audit_events_created_at ON app.audit_events(created_at DESC);

CREATE OR REPLACE FUNCTION app.prevent_audit_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit_events are append-only';
END;
$$;

DROP TRIGGER IF EXISTS audit_events_immutable ON app.audit_events;
CREATE TRIGGER audit_events_immutable
BEFORE UPDATE OR DELETE ON app.audit_events
FOR EACH ROW EXECUTE FUNCTION app.prevent_audit_mutation();

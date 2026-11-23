-- Scope governance records to an organization and support auditable decisions.
ALTER TABLE app.security_incidents ADD COLUMN IF NOT EXISTS organization_id uuid REFERENCES app.organizations(id);
ALTER TABLE app.risks ADD COLUMN IF NOT EXISTS organization_id uuid REFERENCES app.organizations(id);
ALTER TABLE app.policy_documents ADD COLUMN IF NOT EXISTS organization_id uuid REFERENCES app.organizations(id);
ALTER TABLE app.security_changes ADD COLUMN IF NOT EXISTS organization_id uuid REFERENCES app.organizations(id);
ALTER TABLE app.awareness_campaigns ADD COLUMN IF NOT EXISTS organization_id uuid REFERENCES app.organizations(id);

-- Backfill ownership from the existing application profile records.
UPDATE app.security_incidents si SET organization_id = up.organization_id
FROM app.user_profiles up WHERE si.organization_id IS NULL AND si.owner_id = up.user_id;
UPDATE app.risks r SET organization_id = up.organization_id
FROM app.user_profiles up WHERE r.organization_id IS NULL AND r.owner_id = up.user_id;
UPDATE app.policy_documents p SET organization_id = up.organization_id
FROM app.user_profiles up WHERE p.organization_id IS NULL AND p.approved_by = up.user_id;
UPDATE app.security_changes sc SET organization_id = up.organization_id
FROM app.user_profiles up WHERE sc.organization_id IS NULL AND sc.requested_by = up.user_id;
UPDATE app.awareness_campaigns ac SET organization_id = up.organization_id
FROM app.user_profiles up WHERE ac.organization_id IS NULL AND ac.created_by = up.user_id;

CREATE INDEX IF NOT EXISTS security_incidents_org_idx ON app.security_incidents(organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS risks_org_idx ON app.risks(organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS policy_documents_org_idx ON app.policy_documents(organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS security_changes_org_idx ON app.security_changes(organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS awareness_campaigns_org_idx ON app.awareness_campaigns(organization_id, created_at DESC);

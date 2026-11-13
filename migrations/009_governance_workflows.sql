-- Quarterly access reviews and security-awareness assignments required by the governance requirements.
CREATE TABLE IF NOT EXISTS app.access_reviews (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL REFERENCES app.organizations(id), reviewer_id text NOT NULL,
  period_start date NOT NULL, period_end date NOT NULL, status text NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN','COMPLETED','CANCELLED')),
  created_at timestamptz NOT NULL DEFAULT now(), completed_at timestamptz
);
CREATE TABLE IF NOT EXISTS app.access_review_items (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), review_id uuid NOT NULL REFERENCES app.access_reviews(id) ON DELETE CASCADE, user_id text NOT NULL,
  role_id uuid NOT NULL REFERENCES app.roles(id), decision text NOT NULL DEFAULT 'PENDING' CHECK (decision IN ('PENDING','KEEP','REVOKE','INVESTIGATE')),
  reason text NOT NULL DEFAULT '', decided_by text, decided_at timestamptz, UNIQUE(review_id,user_id,role_id)
);
CREATE TABLE IF NOT EXISTS app.awareness_campaigns (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), title text NOT NULL, content text NOT NULL, due_at timestamptz, created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(), status text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','CLOSED'))
);
CREATE TABLE IF NOT EXISTS app.awareness_assignments (
  campaign_id uuid NOT NULL REFERENCES app.awareness_campaigns(id) ON DELETE CASCADE, user_id text NOT NULL,
  completed_at timestamptz, assigned_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(campaign_id,user_id)
);
CREATE INDEX IF NOT EXISTS access_review_org_status_idx ON app.access_reviews(organization_id,status);
CREATE INDEX IF NOT EXISTS awareness_assignment_user_idx ON app.awareness_assignments(user_id,completed_at);

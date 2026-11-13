-- Admin workflow permissions and indexes for organization admission and centralized approvals.
-- Keep these permissions separate from department-scoped manager approval.
INSERT INTO app.permissions(name,resource,action,scope,description) VALUES
 ('members:read','members','read','ADMIN','View organization members and admission queue'),
 ('members:admit','members','admit','ADMIN','Admit a verified user into an organization'),
 ('requests:read_all','requests','read_all','ADMIN','View organization request queue'),
 ('requests:approve_global','requests','approve_global','ADMIN','Approve or reject any organization request')
ON CONFLICT (name) DO NOTHING;

-- The ADMIN role receives the organization-wide capabilities used by the admin console.
INSERT INTO app.role_permissions(role_id,permission_id)
SELECT r.id,p.id FROM app.roles r CROSS JOIN app.permissions p
WHERE r.code='ADMIN' AND p.name IN ('members:read','members:admit','requests:read_all','requests:approve_global','roles:approve','audit:read','audit:verify','alerts:read','alerts:manage','incidents:manage','backup:read','backup:execute','backup:test','risk:manage','policy:manage','change:approve')
ON CONFLICT DO NOTHING;

CREATE INDEX IF NOT EXISTS user_profiles_admission_queue_idx ON app.user_profiles(status,created_at DESC);
CREATE INDEX IF NOT EXISTS requests_org_status_created_idx ON app.requests(organization_id,status,created_at DESC);

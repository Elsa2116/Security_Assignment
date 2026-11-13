-- Add the operational roles required by the assignment's approval and separation-of-duties demonstrations.
INSERT INTO app.roles(code,name,description,is_privileged) VALUES
  ('MANAGER','manager','Department request approver',false),
  ('SECURITY_REVIEWER','security reviewer','Independent privileged-access reviewer',true)
ON CONFLICT (code) DO NOTHING;

-- Managers may approve department requests; security reviewers may approve role changes.
INSERT INTO app.role_permissions(role_id,permission_id)
SELECT r.id,p.id FROM app.roles r CROSS JOIN app.permissions p
WHERE (r.code='MANAGER' AND p.name IN ('requests:create','requests:read','requests:approve'))
   OR (r.code='SECURITY_REVIEWER' AND p.name IN ('roles:approve','audit:read','audit:verify','alerts:read','alerts:manage','incidents:manage'))
ON CONFLICT DO NOTHING;

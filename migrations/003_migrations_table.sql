-- Records each successfully applied SQL file so startup migrations are repeatable.
CREATE TABLE IF NOT EXISTS app.schema_migrations (
  version text PRIMARY KEY,
  applied_at timestamptz NOT NULL DEFAULT now()
);

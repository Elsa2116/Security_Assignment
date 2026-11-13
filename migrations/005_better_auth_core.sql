-- Better Auth's official PostgreSQL adapter owns these tables at runtime.
-- Column mappings are declared in src/auth/better-auth.ts; this migration only provisions them.
CREATE TABLE IF NOT EXISTS auth."user" (
  id text PRIMARY KEY,
  name text NOT NULL,
  email text NOT NULL UNIQUE,
  email_verified boolean NOT NULL DEFAULT false,
  image text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS auth.session (
  id text PRIMARY KEY,
  user_id text NOT NULL REFERENCES auth."user"(id) ON DELETE CASCADE,
  token text NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL,
  ip_address text,
  user_agent text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz
);
CREATE INDEX IF NOT EXISTS auth_session_user_idx ON auth.session(user_id);
CREATE TABLE IF NOT EXISTS auth.account (
  id text PRIMARY KEY,
  user_id text NOT NULL REFERENCES auth."user"(id) ON DELETE CASCADE,
  account_id text NOT NULL,
  provider_id text NOT NULL,
  access_token text,
  refresh_token text,
  access_token_expires_at timestamptz,
  refresh_token_expires_at timestamptz,
  scope text,
  id_token text,
  password text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(provider_id,account_id)
);
CREATE INDEX IF NOT EXISTS auth_account_user_idx ON auth.account(user_id);
CREATE TABLE IF NOT EXISTS auth.verification (
  id text PRIMARY KEY,
  identifier text NOT NULL,
  value text NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS auth_verification_identifier_idx ON auth.verification(identifier);

-- Store MFA completion on the Better Auth session so a password-only login cannot reach application data.
ALTER TABLE auth.session ADD COLUMN IF NOT EXISTS mfa_verified_at timestamptz;
CREATE INDEX IF NOT EXISTS auth_session_mfa_idx ON auth.session(user_id,mfa_verified_at);

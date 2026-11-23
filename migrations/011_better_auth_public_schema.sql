-- Better Auth's PostgreSQL adapter uses the default public schema unless a
-- schema option is explicitly configured. Keep the supported adapter and raw
-- application queries on the same tables.
CREATE TABLE IF NOT EXISTS public."user" (
  id text PRIMARY KEY,
  name text NOT NULL,
  email text NOT NULL UNIQUE,
  email_verified boolean NOT NULL DEFAULT false,
  image text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.session (
  id text PRIMARY KEY,
  user_id text NOT NULL REFERENCES public."user"(id) ON DELETE CASCADE,
  token text NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL,
  ip_address text,
  user_agent text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  mfa_verified_at timestamptz
);
CREATE INDEX IF NOT EXISTS public_session_user_idx ON public.session(user_id);
CREATE INDEX IF NOT EXISTS public_session_mfa_idx ON public.session(user_id,mfa_verified_at);

CREATE TABLE IF NOT EXISTS public.account (
  id text PRIMARY KEY,
  user_id text NOT NULL REFERENCES public."user"(id) ON DELETE CASCADE,
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
CREATE INDEX IF NOT EXISTS public_account_user_idx ON public.account(user_id);

CREATE TABLE IF NOT EXISTS public.verification (
  id text PRIMARY KEY,
  identifier text NOT NULL,
  value text NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS public_verification_identifier_idx ON public.verification(identifier);

-- Preserve existing local/legacy auth data when the old schema is present.
DO $$
BEGIN
  IF to_regclass('auth."user"') IS NOT NULL THEN
    INSERT INTO public."user" (id,name,email,email_verified,image,created_at,updated_at)
    SELECT id,name,email,email_verified,image,created_at,updated_at
    FROM auth."user" ON CONFLICT (id) DO NOTHING;
  END IF;
  IF to_regclass('auth.session') IS NOT NULL THEN
    INSERT INTO public.session (id,user_id,token,expires_at,ip_address,user_agent,created_at,updated_at,revoked_at)
    SELECT id,user_id,token,expires_at,ip_address,user_agent,created_at,updated_at,revoked_at
    FROM auth.session ON CONFLICT (id) DO NOTHING;
  END IF;
  IF to_regclass('auth.account') IS NOT NULL THEN
    INSERT INTO public.account (id,user_id,account_id,provider_id,access_token,refresh_token,access_token_expires_at,refresh_token_expires_at,scope,id_token,password,created_at,updated_at)
    SELECT id,user_id,account_id,provider_id,access_token,refresh_token,access_token_expires_at,refresh_token_expires_at,scope,id_token,password,created_at,updated_at
    FROM auth.account ON CONFLICT (id) DO NOTHING;
  END IF;
  IF to_regclass('auth.verification') IS NOT NULL THEN
    INSERT INTO public.verification (id,identifier,value,expires_at,created_at,updated_at)
    SELECT id,identifier,value,expires_at,created_at,updated_at
    FROM auth.verification ON CONFLICT (id) DO NOTHING;
  END IF;
END $$;

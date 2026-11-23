import 'dotenv/config';
import { z } from 'zod';

// Validate configuration once at startup so missing secrets or database settings
// fail fast instead of causing an unsafe, partially configured server.
const parsedConfig = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().default(3000),
  DATABASE_URL: z.string().url().or(z.string().startsWith('postgres://')),
  JWT_ACCESS_SECRET: z.string().min(32),
  BETTER_AUTH_SECRET: z.string().min(32),
  BETTER_AUTH_URL: z.string().url(),
  ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().default(900),
  REFRESH_TOKEN_TTL_SECONDS: z.coerce.number().default(2592000),
  BACKUP_ENCRYPTION_KEY: z.string().min(32),
  REDIS_URL: z.string().url().optional(),
  SIEM_INGEST_URL: z.string().url().optional(),
  SIEM_INGEST_TOKEN: z.string().min(16).optional(),
  LOG_RETENTION_DAYS: z.coerce.number().int().positive().default(365),
  SMTP_HOST: z.string().optional(),
  SMTP_PORT: z.coerce.number().int().positive().optional(),
  SMTP_USER: z.string().optional(),
  SMTP_PASSWORD: z.string().optional(),
  EMAIL_FROM: z.string().optional(),
  SMTP_USE_TLS: z.enum(['true', 'false']).default('true'),
  CAPTCHA_SECRET_KEY: z.string().optional(),
  CAPTCHA_SITE_KEY: z.string().optional(),
  HIBP_PASSWORD_CHECK: z.enum(['true', 'false']).default('false')
}).superRefine((value, context) => {
  // Production must use HTTPS so Better Auth can issue secure session cookies.
  if (value.NODE_ENV === 'production' && !value.BETTER_AUTH_URL.startsWith('https://')) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['BETTER_AUTH_URL'], message: 'Production BETTER_AUTH_URL must use https://' });
  }
  // Production email must use transport encryption and password screening must stay enabled.
  if (value.NODE_ENV === 'production' && value.SMTP_USE_TLS !== 'true') {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['SMTP_USE_TLS'], message: 'Production SMTP_USE_TLS must be true' });
  }
  // Production registration and password-reset mail must use an explicitly configured provider.
  if (value.NODE_ENV === 'production') {
    for (const key of ['SMTP_HOST', 'SMTP_USER', 'SMTP_PASSWORD', 'EMAIL_FROM'] as const) {
      if (!value[key]?.trim()) context.addIssue({ code: z.ZodIssueCode.custom, path: [key], message: `Production ${key} is required` });
    }
    if (!value.SMTP_PORT) context.addIssue({ code: z.ZodIssueCode.custom, path: ['SMTP_PORT'], message: 'Production SMTP_PORT is required' });
    if (!value.CAPTCHA_SECRET_KEY?.trim() || !value.CAPTCHA_SITE_KEY?.trim()) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ['CAPTCHA'], message: 'Production CAPTCHA_SITE_KEY and CAPTCHA_SECRET_KEY are required' });
    }
  }
  if (value.NODE_ENV === 'production' && value.HIBP_PASSWORD_CHECK !== 'true') {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['HIBP_PASSWORD_CHECK'], message: 'Production HIBP_PASSWORD_CHECK must be true' });
  }
});

export const config = parsedConfig.parse(process.env);

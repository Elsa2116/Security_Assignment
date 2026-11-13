import 'dotenv/config';
import { z } from 'zod';

// Validate configuration once at startup so missing secrets or database settings
// fail fast instead of causing an unsafe, partially configured server.
export const config = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().default(3000),
  DATABASE_URL: z.string().url().or(z.string().startsWith('postgres://')),
  JWT_ACCESS_SECRET: z.string().min(32),
  BETTER_AUTH_SECRET: z.string().min(32),
  BETTER_AUTH_URL: z.string().url(),
  ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().default(900),
  REFRESH_TOKEN_TTL_SECONDS: z.coerce.number().default(2592000),
  BACKUP_ENCRYPTION_KEY: z.string().min(32)
}).parse(process.env);

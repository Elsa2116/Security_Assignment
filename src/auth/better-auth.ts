import { betterAuth } from 'better-auth';
import { Pool } from 'pg';
import { config } from '../config.js';

// Better Auth owns supported authentication operations. Application data access remains raw SQL.
export const authPool = new Pool({ connectionString: config.DATABASE_URL, max: 10, options: '-c search_path=auth' });
export const auth = betterAuth({
  secret: config.BETTER_AUTH_SECRET,
  baseURL: config.BETTER_AUTH_URL,
  database: authPool,
  emailAndPassword: { enabled: true },
  advanced: { database: { joins: true } }
});

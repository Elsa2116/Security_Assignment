import { betterAuth } from 'better-auth';
import { Pool } from 'pg';
import { config } from '../config.js';
import { query } from '../db/pool.js';
import { hashPassword, verifyPassword } from './password.js';

// Better Auth owns supported authentication operations. Application data access remains raw SQL.
// The auth pool uses the auth schema so Better Auth's tables cannot collide with app tables.
export const authPool = new Pool({ connectionString: config.DATABASE_URL, max: 10, options: '-c search_path=auth' });

// This configuration keeps credential lifecycle, sessions, and verification in Better Auth,
// while the post-create hook creates SecureFlow's organization/profile record.
export const auth = betterAuth({
  secret: config.BETTER_AUTH_SECRET,
  baseURL: config.BETTER_AUTH_URL,
  database: authPool,
  user: { fields: { emailVerified: 'email_verified', createdAt: 'created_at', updatedAt: 'updated_at' } },
  session: { fields: { userId: 'user_id', expiresAt: 'expires_at', ipAddress: 'ip_address', userAgent: 'user_agent', createdAt: 'created_at', updatedAt: 'updated_at' } },
  account: { fields: { userId: 'user_id', accountId: 'account_id', providerId: 'provider_id', accessToken: 'access_token', refreshToken: 'refresh_token', accessTokenExpiresAt: 'access_token_expires_at', refreshTokenExpiresAt: 'refresh_token_expires_at', idToken: 'id_token', createdAt: 'created_at', updatedAt: 'updated_at' } },
  verification: { fields: { expiresAt: 'expires_at', createdAt: 'created_at', updatedAt: 'updated_at' } },
  emailAndPassword: {
    enabled: true,
    requireEmailVerification: true,
    minPasswordLength: 12,
    maxPasswordLength: 128,
    password: { hash: hashPassword, verify: verifyPassword },
    revokeSessionsOnPasswordReset: true,
    sendResetPassword: async ({ user, url }: { user: { id: string; email: string }; url: string }) => {
      await query('INSERT INTO app.outbox_events(event_type,payload) VALUES ($1,$2)', ['PASSWORD_RESET', JSON.stringify({ userId: user.id, email: user.email, url })]);
    }
  },
  emailVerification: {
    sendVerificationEmail: async ({ user, url }: { user: { id: string; email: string }; url: string }) => {
      await query('INSERT INTO app.outbox_events(event_type,payload) VALUES ($1,$2)', ['EMAIL_VERIFICATION', JSON.stringify({ userId: user.id, email: user.email, url })]);
    }
  },
  databaseHooks: {
    user: {
      create: {
        after: async (user: { id: string; name: string; email: string }) => {
          await query(`INSERT INTO app.user_profiles(user_id,name,email_normalized,status,email_verified_at) VALUES ($1,$2,lower($3),'PENDING_ADMISSION',NULL) ON CONFLICT(user_id) DO NOTHING`, [user.id, user.name, user.email]);
        }
      }
    }
  },
  advanced: { database: { joins: true } }
});

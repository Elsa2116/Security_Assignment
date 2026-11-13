import { config } from '../src/config.js';
const checks = {
  // Defense mode must never be enabled against a production environment.
  nonProduction: config.NODE_ENV !== 'production',
  databaseConfigured: config.DATABASE_URL.startsWith('postgres'),
  secretsConfigured: !config.JWT_ACCESS_SECRET.includes('replace-with') && !config.BETTER_AUTH_SECRET.includes('replace-with'),
  tokenTtlWithinTenMinutes: config.ACCESS_TOKEN_TTL_SECONDS <= 600
};
console.log(JSON.stringify(checks, null, 2));
if (Object.values(checks).some((value) => !value)) process.exitCode = 1;

import bcrypt from 'bcryptjs';

// Keep the bcrypt work factor explicit so password cost is reviewable and reproducible.
const SALT_ROUNDS = 12;

// Better Auth calls this function during signup and password changes; plaintext is never persisted.
export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, SALT_ROUNDS);
}

// Better Auth calls this function during login and reset verification.
export function verifyPassword(input: { hash: string; password: string }) {
  return bcrypt.compare(input.password, input.hash);
}

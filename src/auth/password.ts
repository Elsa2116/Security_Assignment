import argon2 from 'argon2';

// Argon2id parameters are intentionally explicit so password cost is reviewable and reproducible.
const options = {
  type: 2 as const,
  memoryCost: 65_536,
  timeCost: 3,
  parallelism: 4,
  raw: false
};

// Better Auth calls this function during signup and password changes; plaintext is never persisted.
export async function hashPassword(password: string): Promise<string> {
  return String(await argon2.hash(password, options));
}

// Better Auth calls this function during login and reset verification.
export function verifyPassword(input: { hash: string; password: string }) {
  return argon2.verify(input.hash, input.password);
}

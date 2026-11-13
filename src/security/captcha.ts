import { config } from '../config.js';

// Verify reCAPTCHA server-side when configured; local development explicitly uses a documented bypass.
export async function verifyCaptcha(token: string | undefined, remoteIp?: string) {
  const secret = process.env.CAPTCHA_SECRET_KEY;
  if (!secret) return config.NODE_ENV === 'development' && token === 'local-development-captcha';
  if (!token) return false;
  const body = new URLSearchParams({ secret, response: token });
  if (remoteIp) body.set('remoteip', remoteIp);
  const response = await fetch('https://www.google.com/recaptcha/api/siteverify', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body });
  const result = await response.json() as { success?: boolean; score?: number };
  return result.success === true && (result.score === undefined || result.score >= 0.5);
}

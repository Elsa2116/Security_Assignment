import dns from 'node:dns';
import nodemailer from 'nodemailer';

// Prefer IPv4 for local Docker environments whose IPv6 route can fail before SMTP negotiation.
dns.setDefaultResultOrder('ipv4first');

// Mailpit is used locally; production must provide an authenticated TLS SMTP provider.
const transport = nodemailer.createTransport({
  host: process.env.SMTP_HOST ?? 'mailpit',
  port: Number(process.env.SMTP_PORT ?? 1025),
  // SMTP providers use implicit TLS on 465 and STARTTLS on 587; Mailpit remains local plain SMTP.
  secure: Number(process.env.SMTP_PORT ?? 1025) === 465,
  requireTLS: Number(process.env.SMTP_PORT ?? 1025) === 587,
  auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASSWORD ?? '' } : undefined
});

// Deliver only known outbox email types and keep sensitive values out of logs.
export async function deliverEmail(eventType: string, payload: { email?: string; url?: string }) {
  if (!payload.email || !payload.url) throw new Error('email_payload_incomplete');
  const isReset = eventType === 'PASSWORD_RESET';
  const title = isReset ? 'Reset your SecureFlow password' : 'Verify your SecureFlow email';
  const escapedUrl = payload.url.replaceAll('&', '&amp;').replaceAll('"', '&quot;');
  await transport.sendMail({
    from: process.env.EMAIL_FROM ?? 'SecureFlow <no-reply@secureflow.local>',
    to: payload.email,
    subject: title,
    text: isReset ? `Reset your password using this link: ${payload.url}` : `Verify your SecureFlow email using this link: ${payload.url}`,
    html: `<div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;color:#172033"><h1 style="color:#1d5bd7">SecureFlow</h1><h2>${isReset ? 'Reset your password' : 'Welcome to SecureFlow'}</h2><p>${isReset ? 'Use the button below to choose a new password.' : 'Thanks for registering. Verify your email address to activate your SecureFlow account.'}</p><p><a href="${escapedUrl}" style="display:inline-block;background:#1d5bd7;color:#fff;padding:13px 20px;border-radius:8px;text-decoration:none;font-weight:700">${isReset ? 'Reset Password' : 'Verify Email Address'}</a></p><p style="color:#64748b;font-size:13px">${isReset ? 'If you did not request this, you can ignore this email.' : 'This verification link expires after 15 minutes and can only be used once.'}</p></div>`
  });
}

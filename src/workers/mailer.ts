import nodemailer from 'nodemailer';

// Mailpit is used locally; production must provide an authenticated TLS SMTP provider.
const transport = nodemailer.createTransport({
  host: process.env.SMTP_HOST ?? 'mailpit',
  port: Number(process.env.SMTP_PORT ?? 1025),
  secure: false,
  auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASSWORD ?? '' } : undefined
});

// Deliver only known outbox email types and keep sensitive values out of logs.
export async function deliverEmail(eventType: string, payload: { email?: string; url?: string }) {
  if (!payload.email || !payload.url) throw new Error('email_payload_incomplete');
  const isReset = eventType === 'PASSWORD_RESET';
  await transport.sendMail({
    from: process.env.EMAIL_FROM ?? 'SecureFlow <no-reply@secureflow.local>',
    to: payload.email,
    subject: isReset ? 'Reset your SecureFlow password' : 'Verify your SecureFlow email',
    text: isReset ? `Reset your password using this link: ${payload.url}` : `Verify your SecureFlow email using this link: ${payload.url}`
  });
}

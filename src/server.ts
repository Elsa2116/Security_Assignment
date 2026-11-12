import express from 'express';
import helmet from 'helmet';
import { auth } from './auth/better-auth.js';
import { config } from './config.js';
import { query } from './db/pool.js';

const app = express();
app.use(helmet());
app.use(express.json({ limit: '1mb' }));

app.get('/health', async (_req, res) => {
  try { await query('SELECT 1'); res.json({ status: 'ok', database: 'ok' }); }
  catch { res.status(503).json({ status: 'unavailable' }); }
});

app.all('/api/auth/{*splat}', async (req, res) => {
  const headers = new Headers();
  for (const [key, value] of Object.entries(req.headers)) if (value) headers.set(key, Array.isArray(value) ? value.join(', ') : value);
  const response = await auth.handler(new Request(`${config.BETTER_AUTH_URL}${req.originalUrl}`, { method: req.method, headers, body: ['GET', 'HEAD'].includes(req.method) ? undefined : JSON.stringify(req.body) }));
  res.status(response.status);
  response.headers.forEach((value, key) => res.setHeader(key, value));
  res.send(Buffer.from(await response.arrayBuffer()));
});

app.listen(config.PORT, () => console.log(`SecureFlow listening on ${config.PORT}`));

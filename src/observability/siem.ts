import { config } from '../config.js';

// Forward structured security events to an optional HTTPS SIEM collector while
// preserving local JSON logs when no external collector is configured.
export function emitSecurityEvent(event: string, details: Record<string, unknown> = {}) {
  const payload = { event, at: new Date().toISOString(), service: 'secureflow-api', ...details };
  console.log(JSON.stringify(payload));
  if (!config.SIEM_INGEST_URL) return;
  void fetch(config.SIEM_INGEST_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(config.SIEM_INGEST_TOKEN ? { authorization: `Bearer ${config.SIEM_INGEST_TOKEN}` } : {}) },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(3000)
  }).catch(() => {
    // SIEM outages must not make authentication or approval workflows fail.
  });
}

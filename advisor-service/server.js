// Advisor service (plan.md Phase 10). One POST endpoint:
// signed incident -> raw to Spaces, incident to Postgres, incident+trend
// (never raw) to the DO-hosted Gemma model -> narration back to the device.
// Auth runs before any write or model call: an unauthenticated endpoint
// would be DB pollution + GenAI cost abuse.

const http = require('node:http');
const crypto = require('node:crypto');

const MAX_BODY = 1 << 20;
const MAX_SKEW_MS = 5 * 60 * 1000;
const HEX64 = /^[0-9a-f]{64}$/;

// Ed25519 SPKI DER = fixed 12-byte prefix + 32-byte raw key.
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

// Pure, testable: returns the parsed body or throws with a 401 reason.
// ponytail: replays inside the skew window re-run the model call (DB insert is idempotent); add a seen-sig set if cost matters.
function authenticate(headers, raw, allowed, now = Date.now()) {
  const pubkey = String(headers['x-tcell-pubkey'] || '').toLowerCase();
  const sig = String(headers['x-tcell-sig'] || '');
  if (!HEX64.test(pubkey) || !allowed.has(pubkey)) throw new Error('unknown device');
  const key = crypto.createPublicKey({ key: Buffer.concat([SPKI_PREFIX, Buffer.from(pubkey, 'hex')]), format: 'der', type: 'spki' });
  if (!/^[0-9a-f]{128}$/i.test(sig) || !crypto.verify(null, raw, key, Buffer.from(sig, 'hex'))) throw new Error('bad signature');
  const body = JSON.parse(raw);
  if (!(Math.abs(now - body.sent_ms) <= MAX_SKEW_MS)) throw new Error('stale request');
  const i = body.incident || {};
  if (!HEX64.test(i.threat_id) || !Array.isArray(i.actions) || !Array.isArray(i.attack_ids)) throw new Error('bad incident');
  return { pubkey, body };
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) {
        reject(new Error('too large'));
        req.destroy();
      } else chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

async function narrate(incident, trend) {
  const res = await fetch(process.env.INFERENCE_URL || 'https://inference.do-ai.run/v1/chat/completions', {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${process.env.MODEL_KEY}` },
    body: JSON.stringify({
      model: process.env.MODEL || 'gemma-4-31B-it',
      max_tokens: 300,
      messages: [
        {
          role: 'system',
          content:
            'You are the T-cell endpoint-defense advisor. In 2-3 plain sentences for a non-technical user, explain what was stopped (from the actions and ATT&CK ids) and whether the device trend looks better or worse. Use only the data given; do not invent details.',
        },
        { role: 'user', content: JSON.stringify({ incident, trend_last_7_days: trend }) },
      ],
    }),
    signal: AbortSignal.timeout(20000),
  });
  if (!res.ok) throw new Error(`model ${res.status}`);
  return (await res.json()).choices[0].message.content;
}

function start() {
  const { Pool } = require('pg');
  const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');

  const allowed = new Set((process.env.ALLOWED_PUBKEYS || '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean));
  // sslmode in the URL would override the ssl object below (pg merges the parsed URL last).
  const dbUrl = new URL(process.env.DATABASE_URL);
  dbUrl.searchParams.delete('sslmode');
  const db = new Pool({ connectionString: dbUrl.toString(), ssl: { ca: process.env.CA_CERT }, max: 3 });
  const s3 = new S3Client({
    endpoint: 'https://nyc3.digitaloceanspaces.com',
    region: 'us-east-1',
    credentials: { accessKeyId: process.env.SPACES_KEY, secretAccessKey: process.env.SPACES_SECRET },
  });

  async function handleIncident(req, res) {
    let auth;
    try {
      auth = authenticate(req.headers, await readBody(req), allowed);
    } catch (e) {
      return send(res, 401, { error: e.message });
    }
    const { pubkey, body } = auth;
    const i = body.incident;
    const tsNs = BigInt(i.ts_ns);

    await s3.send(
      new PutObjectCommand({
        Bucket: 'tcell-telemetry-raw',
        Key: `${pubkey}/${i.threat_id}-${tsNs}.json`,
        Body: JSON.stringify(body.raw ?? []),
        ContentType: 'application/json',
      }),
    );
    await db.query(
      `INSERT INTO incidents (threat_id, device_pubkey, ts, score, actions, attack_ids, latency_ns)
       VALUES ($1, $2, to_timestamp($3::numeric / 1e9), $4, $5, $6, $7)
       ON CONFLICT DO NOTHING`,
      [i.threat_id, pubkey, tsNs.toString(), i.score, i.actions, i.attack_ids, i.latency_ns ?? null],
    );
    const { rows: trend } = await db.query(
      `SELECT day, incidents, max_score, avg_score FROM device_risk_daily
       WHERE device_pubkey = $1 AND day >= now() - interval '7 days' ORDER BY day`,
      [pubkey],
    );

    let narration = null;
    try {
      narration = await narrate(i, trend);
    } catch (e) {
      console.error('narration failed:', e.message);
    }
    send(res, 200, { narration, trend });
  }

  http
    .createServer((req, res) => {
      if (req.method === 'GET' && req.url === '/healthz') return send(res, 200, { ok: true });
      if (req.method === 'POST' && req.url === '/v1/incident') {
        return handleIncident(req, res).catch((e) => {
          console.error(e);
          send(res, 500, { error: 'internal' });
        });
      }
      send(res, 404, { error: 'not found' });
    })
    .listen(Number(process.env.PORT) || 8080, () => console.log(`advisor listening on ${process.env.PORT || 8080}, ${allowed.size} allowed device(s)`));
}

function send(res, status, obj) {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(obj));
}

if (require.main === module) start();
module.exports = { authenticate };

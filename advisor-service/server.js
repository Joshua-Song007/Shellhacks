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
  // ponytail: ALLOWED_PUBKEYS=* opens it to any device for the download-to-launch demo; signature still proves key possession, but anyone can mint a key, so remove after the demo.
  if (!HEX64.test(pubkey) || !(allowed.has('*') || allowed.has(pubkey))) throw new Error('unknown device');
  const key = crypto.createPublicKey({ key: Buffer.concat([SPKI_PREFIX, Buffer.from(pubkey, 'hex')]), format: 'der', type: 'spki' });
  if (!/^[0-9a-f]{128}$/i.test(sig) || !crypto.verify(null, raw, key, Buffer.from(sig, 'hex'))) throw new Error('bad signature');
  const body = JSON.parse(raw);
  if (!(Math.abs(now - body.sent_ms) <= MAX_SKEW_MS)) throw new Error('stale request');
  return { pubkey, body };
}

function validIncident(i) {
  return !!i && HEX64.test(i.threat_id) && Array.isArray(i.actions) && Array.isArray(i.attack_ids);
}

// Gemma is asked for JSON but is free text; take the first {...} and keep only
// the expected shape, else fall back to the whole reply as the headline.
function parseReview(text) {
  try {
    const o = JSON.parse(text.slice(text.indexOf('{'), text.lastIndexOf('}') + 1));
    if (typeof o.headline === 'string') return { headline: o.headline, tips: (Array.isArray(o.tips) ? o.tips : []).filter((t) => typeof t === 'string').slice(0, 3) };
  } catch {}
  return { headline: text.trim(), tips: [] };
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

async function chat(system, user, maxTokens) {
  const res = await fetch(process.env.INFERENCE_URL || 'https://inference.do-ai.run/v1/chat/completions', {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${process.env.MODEL_KEY}` },
    body: JSON.stringify({
      model: process.env.MODEL || 'gemma-4-31B-it',
      max_tokens: maxTokens,
      messages: [
        { role: 'system', content: system },
        { role: 'user', content: JSON.stringify(user) },
      ],
    }),
    signal: AbortSignal.timeout(20000),
  });
  if (!res.ok) throw new Error(`model ${res.status}`);
  return (await res.json()).choices[0].message.content;
}

const narrate = (incident, trend) =>
  chat(
    'You are the T-cell endpoint-defense advisor. In 2-3 plain sentences for a non-technical user, explain what was stopped (from the actions and ATT&CK ids) and whether the device trend looks better or worse. Use only the data given; do not invent details.',
    { incident, trend_last_7_days: trend },
    300,
  );

const REVIEW_PROMPT =
  'You are the T-cell endpoint-defense advisor giving a weekly review to a non-technical user. From the week summary (Stage-1 actions stopped, ATT&CK ids, daily trend, and last week\'s count for comparison), spot tendencies that put the user at risk and give practical habits to lower it. ' +
  'ExecFromTempOrCache = a program ran from a temp/cache/download folder (often an opened attachment or download); RecoverySnapshotTamper = something tried to delete backups; RapidFileModBurst = mass file changes, typical of ransomware. ' +
  'Reply with JSON only: {"headline": "<one short sentence, max 12 words>", "tips": ["<up to 3 short, specific habits, max 20 words each>"]}. Use only the data given; do not invent details.';

const QUIET_REVIEW = { headline: 'A quiet week. Nothing tried to get in.', tips: ['Keep installing updates when your computer asks.'] };

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
    if (!validIncident(i)) return send(res, 400, { error: 'bad incident' });
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

  // Weekly review: this device's own last 7 days, aggregated here (derived
  // incident rows only, never raw) -> Gemma. The device caches it for a week.
  async function handleReview(req, res) {
    let auth;
    try {
      auth = authenticate(req.headers, await readBody(req), allowed);
    } catch (e) {
      return send(res, 401, { error: e.message });
    }
    const { pubkey } = auth;
    const week = `device_pubkey = $1 AND ts >= now() - interval '7 days'`;
    const [{ rows: [counts] }, { rows: actions }, { rows: attackIds }, { rows: trend }] = await Promise.all([
      db.query(
        `SELECT count(*) FILTER (WHERE ts >= now() - interval '7 days')::int AS incidents,
                count(*) FILTER (WHERE ts < now() - interval '7 days')::int AS incidents_prior_week,
                max(score) FILTER (WHERE ts >= now() - interval '7 days') AS max_score
         FROM incidents WHERE device_pubkey = $1 AND ts >= now() - interval '14 days'`,
        [pubkey],
      ),
      db.query(`SELECT a AS action, count(*)::int AS n FROM incidents, unnest(actions) a WHERE ${week} GROUP BY a ORDER BY n DESC`, [pubkey]),
      db.query(`SELECT a AS attack_id, count(*)::int AS n FROM incidents, unnest(attack_ids) a WHERE ${week} GROUP BY a ORDER BY n DESC`, [pubkey]),
      db.query(`SELECT day, incidents, max_score, avg_score FROM device_risk_daily WHERE ${week.replace('ts', 'day')} ORDER BY day`, [pubkey]),
    ]);
    const summary = { ...counts, actions, attack_ids: attackIds, trend };

    // ponytail: a zero-incident week skips the model call (nothing to find a trend in).
    let review = QUIET_REVIEW;
    if (counts.incidents) {
      try {
        review = parseReview(await chat(REVIEW_PROMPT, summary, 400));
      } catch (e) {
        console.error('review failed:', e.message);
        review = null;
      }
    }
    send(res, 200, { summary, review });
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
      if (req.method === 'POST' && req.url === '/v1/review') {
        return handleReview(req, res).catch((e) => {
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
module.exports = { authenticate, parseReview, validIncident };

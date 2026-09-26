const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const { authenticate } = require('./server.js');

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const pubHex = publicKey.export({ format: 'der', type: 'spki' }).subarray(12).toString('hex');
const allowed = new Set([pubHex]);
const incident = { threat_id: 'a'.repeat(64), ts_ns: 1, score: 110, actions: ['ExecFromTempOrCache'], attack_ids: ['T1204'] };

function signed(body, key = privateKey) {
  const raw = Buffer.from(JSON.stringify(body));
  return { raw, headers: { 'x-tcell-pubkey': pubHex, 'x-tcell-sig': crypto.sign(null, raw, key).toString('hex') } };
}

test('accepts a fresh, signed request from an allowed device', () => {
  const { raw, headers } = signed({ sent_ms: Date.now(), incident });
  assert.strictEqual(authenticate(headers, raw, allowed).pubkey, pubHex);
});

test('rejects a bad signature', () => {
  const { raw, headers } = signed({ sent_ms: Date.now(), incident }, crypto.generateKeyPairSync('ed25519').privateKey);
  assert.throws(() => authenticate(headers, raw, allowed), /bad signature/);
});

test('rejects a tampered body', () => {
  const { headers } = signed({ sent_ms: Date.now(), incident });
  const raw = Buffer.from(JSON.stringify({ sent_ms: Date.now(), incident: { ...incident, score: 0 } }));
  assert.throws(() => authenticate(headers, raw, allowed), /bad signature/);
});

test('rejects an unknown device', () => {
  const { raw, headers } = signed({ sent_ms: Date.now(), incident });
  assert.throws(() => authenticate(headers, raw, new Set()), /unknown device/);
});

test('rejects a stale request', () => {
  const { raw, headers } = signed({ sent_ms: Date.now() - 10 * 60 * 1000, incident });
  assert.throws(() => authenticate(headers, raw, allowed), /stale/);
});

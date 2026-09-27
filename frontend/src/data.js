// The one place the UI gets data from. Everything below `simulate()` is fake;
// to link the backend, replace simulate() with code that mutates `state` and
// calls emit() with the same event names:
//   'devices'  state.devices changed (status/heartbeat)
//   'genes'    state.genes changed (a cure was learned)
//   'genome-clear' state.genes reset to empty (local cure history cleared, not a learn)
//   'block'    detail = block, also pushed to state.blocks (and state.contributions if mine)
//   'mesh'     detail = { from, to: [ids] } a cure hint travelled the lymph network
//   'incident' detail = { device, phase: 'watching'|'isolated'|'cured'|'clear', threat }
//   'stats'    state.stats / state.lineages refreshed
//   'log'      detail = { t, src: 'tes'|'scout'|'soldier'|'ledger'|'mesh', level: 'info'|'warn'|'alert'|'ok', msg }
//   'threat'   state.incident changed (lineage tree, allele search, time-to-immunity marks, suppression)
//   'advice'   detail = { threat_id, narration } the advisor explained an incident (live only)
//   'pair'     detail = { phase: 'paired', device } a device redeemed this device's pairing code | { phase: 'error', error: 'Expired'|'NonceMismatch' } | { phase: 'expired' }

export const feed = new EventTarget();
const emit = (type, detail) => feed.dispatchEvent(new CustomEvent(type, { detail }));

const hex = (n) => Array.from(crypto.getRandomValues(new Uint8Array(n)), (b) => b.toString(16).padStart(2, '0')).join('');
const pick = (a) => a[(Math.random() * a.length) | 0];
const rand = (a, b) => a + Math.random() * (b - a);
const HOUR = 3_600_000;

export const state = {
  self: 'this-device',
  source: null, // 'live' | 'simulated', set once at the bottom of this file
  devices: [
    { id: 'this-device', name: 'This device', kind: 'laptop' },
    { id: 'kitchen', name: 'Kitchen iMac', kind: 'desktop' },
    { id: 'studio', name: 'Studio device mini', kind: 'mini' },
    { id: 'work', name: 'Work MacBook', kind: 'laptop' },
    { id: 'den', name: 'Den iMac', kind: 'desktop' },
  ].map((d) => ({ ...d, status: 'clean', heartbeat: Date.now(), pubkey: hex(32) })),
  genes: [], // local immune memory: { threat, gene, name, from, time, bytes }
  blocks: [], // recent global chain activity, newest last
  contributions: [], // blocks this device wrote
  stats: { cpu: 3, mem: 41, eps: 0, dropped: 0, rejected: 0, source: 'eslogger', gaps: 0, lag: 0.4, slot: 318_442_000 + ((Math.random() * 9000) | 0), globalGenes: 0, globalDevices: 0 },
  history: { cpu: [], mem: [], eps: [] },
  lineages: [], // { pid, exe, score, actions[] }
  incident: null,
  stoppedThisWeek: 3,
};

// Plain-language names for the threat families the Scout can recognise.
export const THREATS = [
  { name: 'File-scrambling ransomware', actions: ['ExecFromTempOrCache', 'RapidFileModBurst', 'RecoverySnapshotTamper'], exe: '/private/var/folders/x1/T/invoice_viewer', parent: '/Applications/Safari.app/Contents/MacOS/Safari' },
  { name: 'Backup-wiping ransomware', actions: ['ExecFromTempOrCache', 'RecoverySnapshotTamper', 'RapidFileModBurst'], exe: '/tmp/.cache/updater', parent: '/bin/zsh' },
  // Scout counts each action once per lineage, so every threat needs all three to reach 100.
  { name: 'Fake installer encrypting files', actions: ['ExecFromTempOrCache', 'RapidFileModBurst', 'RecoverySnapshotTamper'], exe: '/Users/Shared/Library/Caches/setup_helper', parent: '/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder' },
];
export const WEIGHT = { ExecFromTempOrCache: 20, RecoverySnapshotTamper: 50, RapidFileModBurst: 40 };
export const ACT_LABEL = { ExecFromTempOrCache: 'Ran from a temp folder', RecoverySnapshotTamper: 'Deleted backups', RapidFileModBurst: 'Mass file rewrite' };
export const ATTACK = { ExecFromTempOrCache: 'T1204', RecoverySnapshotTamper: 'T1490', RapidFileModBurst: 'T1486' };

// Mirrors crates/soldier/src/allele_search.rs: same 5 alleles in bit order, same costs and coverage.
export const ALLELES = [
  { name: 'QuarantineDroppedFiles', label: 'Quarantine files', cost: 5, stops: ['ExecFromTempOrCache'] },
  { name: 'BlockSockets', label: 'Block sockets', cost: 15, stops: [] },
  { name: 'SigStop', label: 'SIGSTOP', cost: 25, stops: ['ExecFromTempOrCache', 'RapidFileModBurst'] },
  { name: 'RevertTouchedFiles', label: 'Revert files', cost: 45, stops: ['RecoverySnapshotTamper', 'RapidFileModBurst'] },
  { name: 'KillChildTree', label: 'Kill child tree', cost: 150, stops: ['ExecFromTempOrCache', 'RecoverySnapshotTamper', 'RapidFileModBurst'] },
];
// ponytail: no benign trace in the sim, so the collision penalty is always 0.
export function evaluate(mask, actions) {
  const on = ALLELES.filter((_, i) => mask & (1 << i));
  const stopped = new Set(on.flatMap((a) => a.stops));
  const containment = actions.filter((a) => stopped.has(a)).reduce((n, a) => n + WEIGHT[a], 0);
  const cost = on.reduce((n, a) => n + a.cost, 0);
  return { containment, cost, fitness: containment - cost, size: on.length };
}

// TES v1 (DATA-1) event. ts_ns is a digit string (too big for a JS number); unquote it when printing.
let seq = 9_400_000 + ((Math.random() * 90_000) | 0);
function tes(proc, kind, data) {
  const ts = BigInt(Date.now()) * 1_000_000n + BigInt((Math.random() * 1e6) | 0);
  return { v: 1, seq: seq++, ts_ns: String(ts), recv_ns: String(ts + BigInt(250_000 + ((Math.random() * 500_000) | 0))), proc: { ...proc, platform: false }, event: { kind, data } };
}

const device = (id) => state.devices.find((d) => d.id === id);
const log = (src, level, msg) => emit('log', { t: Date.now(), src, level, msg });

function pushBlock(b) {
  if (b.slot === undefined) state.stats.slot += 18 + ((Math.random() * 70) | 0);
  else state.stats.slot = Math.max(state.stats.slot, b.slot); // live mode: a real slot number, don't fake-increment
  const block = { slot: state.stats.slot, sig: hex(32), time: Date.now(), mine: false, ...b };
  state.blocks.push(block);
  if (state.blocks.length > 60) state.blocks.shift();
  if (block.mine) state.contributions.unshift(block);
  emit('block', block);
  return block;
}

function setStatus(id, status) {
  device(id).status = status;
  emit('devices', state.devices);
  if (id === state.self && state.source === 'live') window.tcell.sendMeshCommand({ cmd: 'status', status }); // every own change reaches paired peers, not just isolate/cure
}

// meshd's pubkeys are libp2p protobuf-encoded: every Ed25519 key starts with the same 08011220 header, so names/ids come from the key after it.
const keyTail = (pubkey) => pubkey.slice(8);
const peerDevice = (pubkey) => ({ id: `dev-${keyTail(pubkey).slice(0, 8)}`, name: `Device ${keyTail(pubkey).slice(0, 6)}`, kind: 'laptop', status: 'clean', heartbeat: Date.now(), pubkey });

const wait = (ms) => new Promise((r) => setTimeout(r, ms));

async function incident() {
  const d = Math.random() < 0.4 ? device(state.self) : pick(state.devices.filter((x) => x.id !== state.self));
  const threat = pick(THREATS);
  const pid = 4000 + ((Math.random() * 60000) | 0);
  const ppid = 300 + ((Math.random() * 3000) | 0);
  const pidver = (Math.random() * 90) | 0;
  const lineage = { pid, exe: threat.exe, score: 0, actions: [] };
  const threatId = hex(32);
  state.lineages.unshift(lineage);
  const childTes = tes({ pid, pidver, ppid, exe: threat.parent }, 'exec', { target: threat.exe, args: [threat.exe], new_pidver: pidver + 1 });
  const inc = {
    device: d.id, threat: threat.name, actions: threat.actions, threatId, t0: Date.now(), marks: {}, score: 0,
    tree: {
      parent: { pid: ppid, exe: threat.parent, tes: tes({ pid: ppid, pidver: 2, ppid: 1, exe: threat.parent }, 'fork', { child_pid: pid, child_pidver: pidver }) },
      child: { pid, exe: threat.exe, tes: childTes },
      acts: [],
    },
    search: null, gene: null, done: false,
  };
  state.incident = inc;
  const changed = () => emit('threat', inc);

  setStatus(d.id, 'watching');
  emit('incident', { device: d.id, phase: 'watching', threat: threat.name });
  log('tes', 'info', `exec pid=${pid} pidver=${pidver} exe=${threat.exe}`);
  changed();

  const ACT_TES = {
    ExecFromTempOrCache: () => childTes,
    RecoverySnapshotTamper: () => tes({ pid: pid + 1, pidver: 1, ppid: pid, exe: threat.exe }, 'exec', { target: '/usr/bin/tmutil', args: ['tmutil', 'deletelocalsnapshots', '/'], new_pidver: 2 }),
    RapidFileModBurst: () => tes({ pid, pidver: pidver + 1, ppid, exe: threat.exe }, 'rename', { from: '/Users/me/Documents/taxes_2025.pdf', to: '/Users/me/Documents/taxes_2025.pdf.locked' }),
  };
  for (const a of threat.actions) {
    await wait(rand(1100, 1900));
    lineage.score += WEIGHT[a];
    lineage.actions.push(a);
    inc.score = lineage.score;
    inc.tree.acts.push({ action: a, weight: WEIGHT[a], attack: ATTACK[a], tes: ACT_TES[a]() });
    log('scout', lineage.score >= 100 ? 'alert' : 'warn', `${d.name}: lineage ${pid} +${WEIGHT[a]} ${a} (${ATTACK[a]}) score=${lineage.score}/100`);
    changed();
  }

  setStatus(d.id, 'isolated');
  inc.marks.detect = Date.now();
  emit('incident', { device: d.id, phase: 'isolated', threat: threat.name });
  log('scout', 'alert', `SIGSTOP lineage root ${pid}; wake {Threat_ID=${threatId.slice(0, 16)}…, pid=${pid}, schema=1}`);
  pushBlock({ kind: 'submit_threat', threat: threatId, confidence: 1, mine: d.id === state.self, by: d.id, name: threat.name });
  log('ledger', 'info', `submit_threat ${threatId.slice(0, 12)}… confirmed`);
  changed();

  await wait(700);
  log('soldier', 'info', `soldier woke; wasmi sandbox ready (imports=0); searching ${1 << ALLELES.length} allele combinations`);
  inc.search = { tested: 0, fitness: [], best: 0 };
  for (let m = 0; m < 1 << ALLELES.length; m++) {
    const e = evaluate(m, threat.actions);
    const b = evaluate(inc.search.best, threat.actions);
    inc.search.fitness.push(e.fitness);
    inc.search.tested = m + 1;
    if (m === 0 || e.fitness > b.fitness || (e.fitness === b.fitness && e.size < b.size)) {
      inc.search.best = m;
      const names = ALLELES.filter((_, i) => m & (1 << i)).map((x) => x.name).join(', ') || 'none';
      log('soldier', 'info', `candidate ${m + 1}/32 {${names}} fitness ${e.fitness >= 0 ? '+' : ''}${e.fitness} (containment ${e.containment}, cost ${e.cost}) new best`);
    }
    changed();
    await wait(70);
  }
  const gene = hex(32);
  const bytes = 380 + ((Math.random() * 420) | 0);
  inc.gene = gene;
  inc.marks.gene = Date.now();
  log('soldier', 'ok', `gene compiled ${bytes}B, gene_hash=${gene.slice(0, 16)}…`);
  changed();

  await wait(600);
  inc.marks.regress = Date.now();
  log('soldier', 'ok', 'stage-3 regression: 0 of 12 whitelisted apps affected; applied; apoptosis');
  changed();

  await wait(500);
  for (let s = 1; s <= 3; s++) {
    await wait(300);
    log('ledger', 'info', `PoI signature ${s}/3 collected`);
  }
  pushBlock({ kind: 'commit_gene', threat: threatId, gene, signers: 3 + ((Math.random() * 3) | 0), mine: d.id === state.self, by: d.id, name: threat.name });
  inc.marks.commit = Date.now();
  log('ledger', 'ok', `commit_gene ${gene.slice(0, 12)}… finalized (3-of-5 PoI)`);

  state.genes.push({ threat: threatId, gene, name: threat.name, from: d.id, time: Date.now(), bytes });
  emit('genes', state.genes);
  setStatus(d.id, 'cured');
  state.stoppedThisWeek++;
  lineage.score = 0;
  inc.marks.immune = Date.now();
  emit('incident', { device: d.id, phase: 'cured', threat: threat.name });
  changed();

  const others = state.devices.filter((x) => x.id !== d.id).map((x) => x.id);
  emit('mesh', { from: d.id, to: others });
  for (const id of others) log('mesh', 'ok', `${device(id).name}: cure hint verified (sig ok, quorum 2/2, epigenetic=active)`);

  await wait(6000);
  state.lineages = state.lineages.filter((l) => l !== lineage);
  setStatus(d.id, 'clean');
  inc.done = true; // kept on state.incident so Advanced can still show the last response
  emit('incident', { device: d.id, phase: 'clear' });
  changed();
}

// suppress_gene (FR-L-7): 3-of-5 PoI, then every node flips Epigenetic_Status and stops running the gene.
export async function suppress() {
  return state.source === 'live' ? liveSuppress() : simSuppress();
}

async function simSuppress() {
  const inc = state.incident;
  if (!inc?.marks.commit || inc.suppress) return;
  inc.suppress = { sigs: 0 };
  const changed = () => emit('threat', inc);
  log('ledger', 'warn', `suppress_gene ${inc.gene.slice(0, 12)}… requested by ${device(state.self).name}: cure flagged as breaking a whitelisted app`);
  changed();
  for (let s = 1; s <= 3; s++) {
    await wait(350);
    inc.suppress.sigs = s;
    log('ledger', 'info', `PoI signature ${s}/3 collected`);
    changed();
  }
  pushBlock({ kind: 'suppress_gene', threat: inc.threatId, gene: inc.gene, mine: true, by: state.self, name: inc.threat });
  const g = state.genes.find((x) => x.gene === inc.gene);
  if (g) g.suppressed = true;
  inc.suppress.done = Date.now();
  log('ledger', 'ok', `suppress_gene ${inc.gene.slice(0, 12)}… finalized; Epigenetic_Status=suppressed`);
  const others = state.devices.filter((x) => x.id !== state.self).map((x) => x.id);
  emit('mesh', { from: state.self, to: others });
  for (const id of others) log('mesh', 'ok', `${device(id).name}: epigenetic=suppressed, gene ${inc.gene.slice(0, 8)}… halted`);
  changed();
}

// Real suppress_gene: calls backend.cjs -> crates/ledger-client's `suppress`
// example (LedgerClient::suppress_gene) via IPC. No fake sig countdown --
// the 3-of-5 PoI signing happens inside that one call, so `sigs` only ever
// shows 0 (requested) or 3 (confirmed), never a live per-signer count (no
// wire mechanism reports partial progress, same documented gap as
// commit_gene's own confirmation path). No fake mesh-broadcast log lines
// either -- meshd has no real "suppression" broadcast wired yet.
async function liveSuppress() {
  const inc = state.incident;
  if (!inc?.marks.commit || inc.suppress) return;
  inc.suppress = { sigs: 0 };
  const changed = () => emit('threat', inc);
  log('ledger', 'warn', `suppress_gene ${inc.gene.slice(0, 12)}… requested by ${device(state.self).name}: cure flagged as breaking a whitelisted app`);
  changed();
  try {
    const result = await window.tcell.suppressGene(inc.threatId);
    inc.suppress.sigs = 3;
    pushBlock({ kind: 'suppress_gene', threat: inc.threatId, gene: inc.gene, sig: result.signature, mine: true, by: state.self, name: inc.threat });
    const g = state.genes.find((x) => x.gene === inc.gene);
    if (g) g.suppressed = true;
    inc.suppress.done = Date.now();
    log('ledger', 'ok', `suppress_gene ${result.signature.slice(0, 12)}… confirmed; Epigenetic_Status=suppressed`);
  } catch (e) {
    inc.suppress = null;
    log('ledger', 'warn', `suppress_gene failed: ${e.message}`);
  }
  changed();
}

// ---------- Pairing (FR-M-1) + revocation (FR-M-7), mirroring crates/mesh identity.rs / revocation.rs ----------
// identity.rs: PairingCode = { nonce: 16 random bytes, issuer: this device's pubkey, expires_at: now + 5 min }.
// The new device gets the nonce out of band (the QR), presents it back, and Roster::redeem checks expiry, then the
// nonce (constant-time), then records the key; redeeming an already-paired key is a no-op.
// ponytail: simulated; the Electron app has no bridge to crates/mesh yet, so a fake device redeems 3.5-6s in.
export const PAIR_TTL = 5 * 60_000;
const NEW_DEVICES = [
  { name: 'Guest MacBook Air', kind: 'laptop' },
  { name: 'Office iMac', kind: 'desktop' },
  { name: 'Garage device mini', kind: 'mini' },
  { name: 'Living room iMac', kind: 'desktop' },
];
const self = () => device(state.self);
export const revoked = new Set(); // revocation.rs: a CRL of pubkeys, separate from the roster

let pairing = null;
function simStartPairing() {
  simCancelPairing();
  const code = { nonce: hex(16), issuer: self().pubkey, expires: Date.now() + PAIR_TTL };
  // ponytail: QR payload format is ours, identity.rs only defines the nonce + issuer it must carry.
  code.uri = `tcell://pair?issuer=${code.issuer}&nonce=${code.nonce}`;
  const p = (pairing = { code });
  log('mesh', 'info', `PairingCode issued, nonce ${code.nonce.slice(0, 8)}…, expires in 5 min`);
  const left = NEW_DEVICES.filter((n) => !state.devices.some((d) => d.name === n.name));
  p.timer = setTimeout(() => {
    if (pairing !== p || !left.length) return;
    const n = pick(left);
    redeem({ ...n, id: `dev-${hex(3)}`, pubkey: hex(32) }, code.nonce);
  }, rand(3500, 6000));
  p.expiry = setTimeout(() => pairing === p && (simCancelPairing(), emit('pair', { phase: 'expired' })), PAIR_TTL + 50);
  return Promise.resolve(code);
}
function simCancelPairing() {
  if (!pairing) return;
  clearTimeout(pairing.timer);
  clearTimeout(pairing.expiry);
  pairing = null;
}
// Roster::redeem, same order of checks. Errors mirror identity.rs's PairingError.
function redeem(dev, presentedNonce) {
  const code = pairing?.code;
  if (!code || Date.now() > code.expires) return emit('pair', { phase: 'error', error: 'Expired' });
  if (presentedNonce !== code.nonce) {
    log('mesh', 'warn', `${dev.name} presented a wrong nonce; refused (NonceMismatch)`);
    return emit('pair', { phase: 'error', error: 'NonceMismatch' });
  }
  simCancelPairing(); // one-time: the code is spent
  if (state.devices.some((d) => d.pubkey === dev.pubkey)) return; // already paired: no-op, no duplicate
  revoked.delete(dev.pubkey); // re-attestation = a fresh pairing
  state.devices.push({ ...dev, status: 'clean', heartbeat: Date.now() });
  log('mesh', 'ok', `${dev.name} redeemed the pairing code; pubkey ${dev.pubkey.slice(0, 12)}… added to the household roster`);
  emit('pair', { phase: 'paired', device: dev });
  emit('devices', state.devices);
  setTimeout(() => emit('mesh', { from: state.self, to: [dev.id] }), 1200); // hand the new node the current immune memory, once it has slid into place
}

// RevocationList::revoke: the key stays known but every cure hint it signs is rejected from now on.
function simRevoke(id) {
  const d = device(id);
  if (!d || id === state.self) return;
  if (state.incident && !state.incident.done && state.incident.device === id) return; // mid-response: let it finish first
  revoked.add(d.pubkey);
  state.devices = state.devices.filter((x) => x !== d);
  log('mesh', 'warn', `${d.name} revoked; pubkey ${d.pubkey.slice(0, 12)}… added to the revocation list`);
  emit('devices', state.devices);
}

// ---------- Live translator (Phase 9 item 11): real pairing over crates/mesh's meshd, via window.tcell (preload.cjs) ----------
let pendingPairResolve = null;
function liveStartPairing() {
  pendingPairResolve = null;
  const p = new Promise((resolve) => (pendingPairResolve = resolve));
  window.tcell.sendMeshCommand({ cmd: 'pair_start' });
  return p;
}
function liveCancelPairing() {
  // meshd has no real cancel stdin command; this only stops listening for
  // this pairing's resolution client-side. The issued code still lives
  // (and can still be redeemed) until its own 5 min server-side expiry.
  // Documented gap, no revisit scheduled.
  pendingPairResolve = null;
}
export function joinByUri(uri) {
  if (state.source !== 'live') return; // no real peer to join against in simulated mode
  window.tcell.sendMeshCommand({ cmd: 'pair_join', uri });
}
function liveRevoke(id) {
  const d = device(id);
  if (!d || id === state.self) return;
  window.tcell.sendMeshCommand({ cmd: 'revoke', pubkey: d.pubkey });
  // Not optimistic-local: state.devices is only mutated once the real
  // `revoked` mesh record confirms it (see dispatch['mesh'] below).
}

export function startPairing() {
  return state.source === 'live' ? liveStartPairing() : simStartPairing();
}
export function cancelPairing() {
  return state.source === 'live' ? liveCancelPairing() : simCancelPairing();
}
export function revoke(id) {
  return state.source === 'live' ? liveRevoke(id) : simRevoke(id);
}

let nextIncident;
const runIncident = () => incident().then(() => (nextIncident = setTimeout(runIncident, rand(9000, 16000))));
// Demo control: start an incident now instead of waiting for the next random one.
// Weekly review from the advisor (advisor-service /v1/review): { at, summary, review: { headline, tips[] } },
// null when no advisor is configured, { error } when unreachable. Live mode caches it for a week in backend.cjs.
export async function getReview(force = false) {
  if (state.source === 'live') {
    try {
      return (await window.tcell.getReview?.(force)) ?? null;
    } catch (e) {
      return { error: e.message }; // IPC failed (e.g. main process predates the handler): say so, never hang
    }
  }
  // ponytail: canned review in the browser sim, there is no model to ask.
  await new Promise((r) => setTimeout(r, force ? 1400 : 300));
  return {
    at: Date.now() - (force ? 0 : 2 * 24 * HOUR),
    summary: { incidents: state.stoppedThisWeek, incidents_prior_week: 1 },
    review: {
      headline: 'Most threats this week started from downloaded files.',
      tips: ['Open attachments only from people you were expecting them from.', 'Clear out your Downloads folder once a week.', 'Keep Time Machine on; something tried to delete your backups.'],
    },
  };
}

export function inject() {
  if (state.source === 'live') return window.tcell.runTestThreat(); // fire-and-forget scripts/test_threat.sh; Scout (already running) is what observes it
  if (state.incident && !state.incident.done) return;
  clearTimeout(nextIncident);
  runIncident();
}

// Dismisses the finished incident from the panel so main.js's "Run test
// threat"/"Clear test" toggle can offer a fresh run again. Only ever
// resets the DISPLAY pointer, not any underlying result -- in live mode the
// real detection/cure/ledger activity already happened for real regardless
// (liveIncidents keeps the entry, a repeat test_threat.sh run starts a new
// one anyway since its root_exe is a fresh mktemp path each time); in sim
// mode the incident object is simply dropped.
export function clearIncident() {
  state.incident = null;
  emit('threat', null);
}

// Wipes this device's local cure history (the "Immune memory" helix), demo-visible proof
// that local memory is disposable: Soldier's own FR-L-7 check (main.rs) always re-fetches
// the Genome Registry from the chain at wake time regardless of anything in this dashboard,
// so a real recurring threat is still inherited from the network with nothing lost here.
// A distinct event, not 'genes' (documented above as "a cure was learned", append-only) --
// main.js's existing 'genes' listener unconditionally does state.genes.at(-1).gene, which
// would throw on an empty array.
export function clearLocalGenome() {
  state.genes = [];
  emit('genome-clear');
}

// ---------- Live translator (Phase 9 item 11): scout/soldier/mesh/ledger NDJSON -> the SAME feed contract above ----------
// window.tcell (preload.cjs) only exists under Electron; a plain browser
// (`npm run web`) has no bridge, so state.source stays 'simulated' and
// everything above this line keeps running completely unchanged.
const pendingLedger = new Map(); // signature -> { kind, threatId, gene, name, mine }
const liveIncidents = new Map(); // keyed by root_exe (the only key both scout progress AND detection records carry)

// Real System-panel stats tracking: eps/lag are derived from data Scout
// already emits (no new wire mechanism); cpu/mem arrive via the 'hoststats'
// channel (backend.cjs's ps poller, Phase 9 item 9 addendum).
let lastAccepted = null;
let lastAcceptedAt = null;
let lastLagMs = null;
function pushHistory() {
  for (const k of ['cpu', 'mem', 'eps']) {
    state.history[k].push(state.stats[k]);
    if (state.history[k].length > 60) state.history[k].shift();
  }
}

const schemaLabel = (schema) => schema.map((a) => ACT_LABEL[a] ?? a).join(', ');
const deviceByPubkey = (pubkey) => state.devices.find((d) => d.pubkey === pubkey);

// simulate()'s own cure completion (line ~204) shows 'cured' for exactly this
// long before settling back to 'clean' -- the live path never had an
// equivalent revert, so a real cure left the device stuck on "Fixed"
// indefinitely. Guarded on the CURRENT status still being 'cured' at fire
// time (not unconditional) so a newer detection/status change that landed
// in between (e.g. another repeat run's own isolated -> cured cycle) is
// never clobbered by a stale timer from an earlier one.
const CURED_REVERT_MS = 6000;
function scheduleCuredRevert(id) {
  setTimeout(() => {
    const d = device(id);
    if (d && d.status === 'cured') {
      setStatus(id, 'clean');
      emit('incident', { device: id, phase: 'clear' });
    }
  }, CURED_REVERT_MS);
}

// Real bug caught live: under a live eslogger Scout, ordinary macOS background
// daemons (Spotlight's corespotlightd, cfprefsd, corecaptured, ScreenTimeAgent
// -- all legitimate system processes, none malicious) routinely trip a
// partial, never-convicted RapidFileModBurst score on their own, completely
// unrelated to any test. Every one of them is a NEW lineage's first progress
// event, and 'watching' had NO revert of its own (unlike 'cured', above) --
// so the device status pill got set to 'watching' and then simply never
// reset, and since a new benign lineage trips this every few seconds to
// minutes on a live system, the device showed permanently yellow instead of
// "Safe" almost the entire time. Debounced (not a single fire-once timer
// like scheduleCuredRevert): every progress event of ANY lineage refreshes
// this same timer, so an actively-accumulating lineage (still short of full
// conviction) keeps the status pinned on 'watching' the whole time it's
// producing new actions, and only reverts to 'clean' after a real quiet
// period. Guarded on the status still being 'watching' at fire time, so it's
// a no-op once a real detection has since escalated to 'isolated' or a cure
// has already moved it to 'cured'.
const WATCHING_REVERT_MS = 5000;
let watchingRevertTimer = null;
function scheduleWatchingRevert(id) {
  clearTimeout(watchingRevertTimer);
  watchingRevertTimer = setTimeout(() => {
    const d = device(id);
    if (d && d.status === 'watching') {
      setStatus(id, 'clean');
      emit('incident', { device: id, phase: 'clear' });
      // Real bug: this revert only ever touched the device-status pill --
      // the Threat response PANEL (state.incident) is a completely separate
      // pointer, so it kept showing whatever partial lineage was last
      // displayed forever, with no dismiss button either (the "Clear test"
      // toggle only appears once marks.detect/immune/done fires, none of
      // which a merely-watched, never-convicted lineage ever reaches) --
      // "Safe" on the pill, "tracking a threat" in the panel, permanently.
      // Only auto-clear a lineage that never escalated to a real conviction
      // (marks.detect) -- a genuinely convicted incident (test or real) still
      // requires the explicit "Clear test" dismiss, unchanged.
      if (state.incident && !state.incident.marks.detect) {
        state.incident = null;
        emit('threat', null);
      }
    }
  }, WATCHING_REVERT_MS);
}

function liveIncidentFor(rootExe) {
  let inc = liveIncidents.get(rootExe);
  if (!inc) {
    inc = { key: rootExe, device: state.self, threat: null, actions: [], threatId: null, t0: Date.now(), lastSeen: Date.now(), marks: {}, score: 0, tree: { parent: null, child: null, acts: [] }, search: null, gene: null, done: false };
    liveIncidents.set(rootExe, inc);
  }
  // Scout watches the WHOLE system, not just the deliberate test lineage --
  // an unrelated real detection (e.g. a heavy dev-tool/build process crossing
  // Stage-1 thresholds on its own) can start scoring at any moment, including
  // mid-test, and used to unconditionally hijack the display pointer away from
  // a test the user was actively watching, making it look like "the test
  // threat" itself had changed into something else. `inc` (this lineage's own
  // tracked object) is always updated normally by the caller regardless --
  // only the DISPLAY pointer is deferred, so the unrelated lineage's real
  // detect/cure/ledger activity still proceeds correctly in the background.
  const cur = state.incident;
  const curFinished = !cur || cur.done || !!cur.marks.immune;
  if (cur === inc || curFinished) state.incident = inc;
  return inc;
}

// Advanced-view-only visibility into background Scout activity: lineages
// currently accumulating a partial (never-convicted) score, separate from
// the single Threat response panel above (state.incident only ever shows
// ONE incident at a time, per the conflation fix above -- background noise
// like corespotlightd/BiomeAgent no longer has to hijack it to be seen at
// all). Uses a longer window than scheduleWatchingRevert (see below), so a
// lineage stays listed after the status pill itself reverts to 'clean'.
// Sim mode has no liveIncidents, so this is always empty there.
// Human-in-the-loop: the list keeps a lineage for WATCH_LIST_MS (not the
// pill's 5s) so a person has time to look and decide. A paused lineage never
// drops off -- even after a cure is requested -- since this list is the only
// place to resume it.
const WATCH_LIST_MS = 60_000;
export function watchingLineages() {
  const now = Date.now();
  return [...liveIncidents.values()]
    .filter((inc) => inc.paused || (!inc.marks.detect && !inc.dismissed && now - inc.lastSeen < WATCH_LIST_MS))
    .sort((a, b) => b.lastSeen - a.lastSeen)
    .map((inc) => ({ key: inc.key, exe: inc.tree.child?.exe ?? 'unknown', score: inc.score, threat: inc.threat, acts: inc.tree.acts, pids: lineageTargets(inc).map((t) => t.pid), lastSeen: inc.lastSeen, paused: !!inc.paused, escalated: !!inc.escalated }));
}

// Only the pids Scout credited an action to are known (no full ancestry).
function lineageTargets(inc) {
  const seen = new Map();
  for (const a of inc.tree.acts) if (a.tes?.proc?.pid) seen.set(a.tes.proc.pid, { pid: a.tes.proc.pid, exe: a.tes.proc.exe });
  return [...seen.values()];
}

async function signalLineage(inc, sig) {
  const results = await window.tcell.signalLineage(lineageTargets(inc), sig);
  for (const r of results.filter((r) => !r.ok)) log('scout', 'warn', `${sig} pid ${r.pid}: ${r.reason}`);
  return results;
}

// Returns the per-pid results so the caller can show why a pid was skipped.
export async function pauseLineage(key) {
  const inc = liveIncidents.get(key);
  if (!inc || inc.paused) return [];
  const results = await signalLineage(inc, 'SIGSTOP');
  inc.pausedPids = results.filter((r) => r.ok).map((r) => r.pid);
  if (inc.pausedPids.length) {
    inc.paused = true;
    setStatus(state.self, 'isolated');
    emit('incident', { device: state.self, phase: 'isolated', threat: inc.threat });
    log('scout', 'alert', `paused by you: ${inc.key} (pid ${inc.pausedPids.join(', ')})`);
  }
  emit('threat', state.incident);
  return results;
}

export async function resumeLineage(key) {
  const inc = liveIncidents.get(key);
  if (!inc?.paused) return [];
  const results = await window.tcell.signalLineage(lineageTargets(inc).filter((t) => inc.pausedPids.includes(t.pid)), 'SIGCONT');
  inc.paused = false;
  inc.dismissed = !inc.escalated; // resumed = judged fine; don't keep nagging
  log('scout', 'info', `resumed by you: ${inc.key}`);
  if (![...liveIncidents.values()].some((i) => i.paused)) {
    setStatus(state.self, 'watching');
    scheduleWatchingRevert(state.self);
  }
  emit('threat', state.incident);
  return results;
}

// Stands in for Scout's 100-pt conviction: same WakeSignal through the same
// relay, so the rest (Soldier evolve/inherit, ledger, panel) is the normal path.
export async function escalateLineage(key) {
  const inc = liveIncidents.get(key);
  if (!inc?.paused || inc.escalated) return;
  inc.threatId = await window.tcell.escalate(inc.actions, inc.pausedPids[0]);
  inc.escalated = true;
  inc.marks.detect = Date.now();
  state.incident = inc; // the person asked for this one, so it takes the panel
  log('scout', 'alert', `escalated by you: ${inc.key}; wake {Threat_ID=${inc.threatId.slice(0, 16)}…, schema=${inc.actions.length}}`);
  emit('threat', inc);
}

export function dismissLineage(key) {
  const inc = liveIncidents.get(key);
  if (!inc || inc.paused) return;
  inc.dismissed = true;
  emit('threat', state.incident);
}

function onScout(payload) {
  if (payload.type === 'progress') {
    const p = payload.progress;
    const inc = liveIncidentFor(p.root_exe);
    const changed = () => emit('threat', inc);
    if (!inc.tree.child) {
      inc.tree.child = { pid: p.event.proc.pid, exe: p.root_exe };
      // Scout only reports SCORED actions, not full ancestry -- the OS
      // parent's own exe is genuinely unknown from this telemetry alone.
      inc.tree.parent = { pid: p.event.proc.ppid, exe: 'unknown parent process' };
      setStatus(state.self, 'watching');
      emit('incident', { device: state.self, phase: 'watching', threat: schemaLabel([p.action]) });
    }
    inc.score = p.score;
    inc.lastSeen = Date.now();
    inc.dismissed = false; // new behaviour since "Looks fine" -- worth another look
    inc.actions = [...inc.actions, p.action];
    inc.tree.acts.push({ action: p.action, weight: WEIGHT[p.action], attack: p.attack_id, tes: p.event });
    inc.threat = schemaLabel(inc.actions);
    log('scout', inc.score >= 100 ? 'alert' : 'warn', `lineage ${p.root_exe} +${WEIGHT[p.action]} ${p.action} (${p.attack_id}) score=${inc.score}/100`);
    if (typeof p.event?.recv_ns === 'number' && typeof p.event?.ts_ns === 'number') {
      lastLagMs = Math.max(0, (p.event.recv_ns - p.event.ts_ns) / 1e6); // real pipeline lag (NFR-1), ms precision only -- u64 ns round-trips JSON as a float64, sub-us error here doesn't matter
    }
    scheduleWatchingRevert(state.self);
    changed();
    return;
  }
  if (payload.type === 'detection') {
    const d = payload.detection;
    const inc = liveIncidentFor(d.root_exe);
    const changed = () => emit('threat', inc);
    inc.threatId = d.wake.threat_id;
    inc.threat = inc.threat ?? schemaLabel(d.wake.schema);
    inc.marks.detect = Date.now();
    setStatus(state.self, 'isolated');
    emit('incident', { device: state.self, phase: 'isolated', threat: inc.threat });
    log('scout', 'alert', `SIGSTOP lineage root ${d.wake.pid}; wake {Threat_ID=${d.wake.threat_id.slice(0, 16)}…, pid=${d.wake.pid}, schema=${d.wake.schema.length}}`);
    changed();
    return;
  }
  if (payload.type === 'stats') {
    if (payload.pipeline) {
      state.stats.rejected = payload.pipeline.rejected;
      // Real loss: the reader's full-buffer drops (eslogger) or FSEvents overflow batches (libproc); the record's key names the source.
      state.stats.dropped = payload.reader?.dropped ?? payload.libproc?.fs_dropped_batches ?? 0;
      state.stats.source = payload.libproc ? 'libproc' : 'eslogger';
      state.stats.gaps = payload.pipeline.seq_gap_events;
      const now = Date.now();
      if (lastAccepted !== null) {
        const dtSeconds = (now - lastAcceptedAt) / 1000;
        if (dtSeconds > 0) state.stats.eps = Math.max(0, Math.round((payload.pipeline.accepted - lastAccepted) / dtSeconds));
      } // first stats tick has no prior sample to diff against -- baselines silently, matches source_beacon.rs's own "first snapshot never raises findings" convention
      lastAccepted = payload.pipeline.accepted;
      lastAcceptedAt = now;
      if (lastLagMs !== null) state.stats.lag = +lastLagMs.toFixed(2);
      pushHistory();
    }
    emit('stats', state.stats);
  }
}

function onHostStats(payload) {
  state.stats.cpu = payload.cpu;
  state.stats.mem = payload.mem;
  pushHistory();
  emit('stats', state.stats);
}

function onSoldier(payload) {
  if (payload.type !== 'cure') return;
  // threat_id is deterministic (scoring.rs FR-D-9): a repeat run of the same
  // synthetic trigger reuses the SAME threat_id on a brand-new root_exe-keyed
  // liveIncidents entry, so a plain scan-for-match lands on the oldest entry
  // sharing that id, not the one actually on screen -- prefer state.incident
  // whenever it's already the right target.
  const inc = state.incident?.threatId === payload.threat_id ? state.incident : ([...liveIncidents.values()].find((i) => i.threatId === payload.threat_id) ?? state.incident);
  if (!inc) return;
  const changed = () => emit('threat', inc);

  if (payload.source === 'suppressed') {
    log('soldier', 'warn', `gene for ${payload.threat_id.slice(0, 12)}… is suppressed (Epigenetic_Status); refusing`);
    inc.done = true;
    setStatus(state.self, 'clean');
    emit('incident', { device: state.self, phase: 'clear' });
    changed();
    return;
  }

  if (payload.source === 'inherited') {
    inc.gene = payload.gene_hash;
    inc.inheritedGene = true; // no local search ran; main.js's Cure search panel checks this
    log('soldier', 'ok', `gene inherited from network, gene_hash=${payload.gene_hash.slice(0, 16)}…`);
    // Inherited means a cure for this exact threat_id is already committed
    // and suppressed-checked on chain elsewhere (FR-L-7) -- there is no
    // fresh commit_gene call for this run, so no ledger signature will ever
    // arrive to resolve "On chain"/"Home immune" the normal way. Both are
    // already true the instant this device adopts the existing cure.
    inc.marks.commit = Date.now();
    inc.marks.immune = Date.now();
    // Real gap: `setStatus(..., 'cured')` otherwise only ever fires from
    // onLedger's commit_gene confirmation (below) -- but Inherit never
    // calls commit_gene (that's the point), so that confirmation was never
    // going to arrive here. Without this, the device stayed on whatever
    // status detection last set ('isolated') forever, even though the
    // incident timeline itself already showed every step, including
    // "Home immune", as done. state.genes is left untouched here (unlike
    // onLedger's commit_gene branch) -- this device didn't just add a new
    // chain entry, the gene got here via an earlier commit_gene or a
    // 'genome' record ingest, both of which already populate it.
    state.stoppedThisWeek++;
    setStatus(state.self, 'cured');
    scheduleCuredRevert(state.self);
    emit('incident', { device: state.self, phase: 'cured', threat: inc.threat });
  } else {
    // evolved: replay the EXISTING local search purely for the step-by-step
    // UI animation (real mirror of allele_search.rs, same fitness fn over
    // the REAL detected actions) -- the ending is always forced to the
    // REAL result below, since a real --benign-trace collision this client
    // can't see would make the local replay's own winner diverge.
    log('soldier', 'info', `soldier woke; wasmi sandbox ready (imports=0); searching ${1 << ALLELES.length} allele combinations`);
    inc.search = { tested: 0, fitness: [], best: 0 };
    for (let m = 0; m < 1 << ALLELES.length; m++) {
      const e = evaluate(m, inc.actions);
      const b = evaluate(inc.search.best, inc.actions);
      inc.search.fitness.push(e.fitness);
      inc.search.tested = m + 1;
      if (m === 0 || e.fitness > b.fitness || (e.fitness === b.fitness && e.size < b.size)) inc.search.best = m;
      changed();
    }
    const localNames = ALLELES.filter((_, i) => inc.search.best & (1 << i)).map((a) => a.name).sort().join();
    const realNames = [...payload.sequence].sort().join();
    if (localNames !== realNames) log('soldier', 'warn', "local allele replay diverged from Soldier's real winning sequence (a real benign-trace collision this client can't see) -- showing the real result");
    inc.gene = payload.gene_hash;
    log('soldier', 'ok', `gene compiled, gene_hash=${payload.gene_hash.slice(0, 16)}…`);
  }
  inc.marks.gene = Date.now();
  changed();

  inc.marks.regress = Date.now();
  log('soldier', payload.applied ? 'ok' : 'warn', payload.applied ? 'stage-3 regression passed; applied; apoptosis' : 'gene failed sandbox instantiation');
  changed();

  const name = schemaLabel(payload.schema);
  if (payload.ledger.submit_sig) pendingLedger.set(payload.ledger.submit_sig, { kind: 'submit_threat', threatId: payload.threat_id, name, mine: true });
  for (const sig of payload.ledger.commit_sigs) pendingLedger.set(sig, { kind: 'commit_gene', threatId: payload.threat_id, gene: payload.gene_hash, name, mine: true });
  for (const err of payload.ledger.errors) log('ledger', 'warn', err);
}

function onLedger(payload) {
  if (payload.type === 'signature') {
    const t = (payload.block_time ?? Date.now() / 1000) * 1000;
    const known = pendingLedger.get(payload.signature);
    if (!known) {
      // feed.rs doesn't decode instruction data, so an unrecognized
      // signature (someone else's, or ours before this session started
      // tracking it) can't be classified -- an honest, unclassified kind,
      // documented gap, no revisit scheduled.
      pushBlock({ kind: 'activity', mine: false, sig: payload.signature, slot: payload.slot, time: t });
      return;
    }
    pendingLedger.delete(payload.signature);
    pushBlock({ kind: known.kind, threat: known.threatId, gene: known.gene, sig: payload.signature, mine: true, by: state.self, name: known.name, slot: payload.slot, time: t });
    log('ledger', 'ok', `${known.kind} ${payload.signature.slice(0, 12)}… confirmed`);
    if (known.kind !== 'commit_gene') return;
    // Same stale-entry hazard as onSoldier above: prefer state.incident when it's already the right target.
    const inc = state.incident?.threatId === known.threatId ? state.incident : [...liveIncidents.values()].find((i) => i.threatId === known.threatId);
    state.genes.push({ threat: known.threatId, gene: known.gene, name: known.name, from: state.self, time: Date.now(), bytes: undefined });
    emit('genes', state.genes);
    setStatus(state.self, 'cured');
    scheduleCuredRevert(state.self);
    state.stoppedThisWeek++;
    if (inc) {
      inc.marks.commit = Date.now();
      inc.marks.immune = Date.now(); // gene already applied locally by this point (Soldier applies before this ledger confirmation ever arrives); the network-durable half of "Home immune" just landed
      emit('threat', inc);
    }
    emit('incident', { device: state.self, phase: 'cured', threat: known.name });
    return;
  }
  if (payload.type === 'genome') {
    const g = state.genes.find((x) => x.gene === payload.gene_hash);
    if (g) {
      g.bytes = payload.bytes;
      if (payload.epigenetic_status && !g.suppressed) {
        g.suppressed = true;
        log('ledger', 'warn', `${g.name}: gene ${payload.gene_hash.slice(0, 8)}… suppressed network-wide (Epigenetic_Status)`);
      }
    } else {
      state.genes.push({ threat: payload.threat_id, gene: payload.gene_hash, name: 'Learned from network', from: 'network', time: Date.now(), bytes: payload.bytes, suppressed: payload.epigenetic_status });
      state.stats.globalGenes++; // best-effort: genes learned since this app started, not a true network-wide total (feed.rs's diff-only design has no way to report that) -- documented gap
      emit('genes', state.genes);
      // A ledger row too. The genome account carries no tx signature or slot, so those stay blank rather than invented.
      pushBlock({ kind: 'commit_gene', threat: payload.threat_id, gene: payload.gene_hash, name: 'Learned from network', slot: null, sig: undefined });
    }
    return;
  }
  if (payload.type === 'network_stats') {
    // Real network-wide totals from chain accounts (feed.rs network_stats).
    state.stats.globalGenes = payload.cures;
    state.stats.globalDevices = payload.devices;
    emit('stats', state.stats);
    return;
  }
  if (payload.type === 'error') log('ledger', 'warn', payload.message);
}

function onMesh(payload) {
  if (payload.type === 'pair_code') {
    const nonce = new URL(payload.uri).searchParams.get('nonce') ?? '';
    log('mesh', 'info', `PairingCode issued, nonce ${nonce.slice(0, 8)}…, expires in 5 min`);
    pendingPairResolve?.({ uri: payload.uri, nonce, expires: Date.now() + payload.expires_ms });
    return;
  }
  if (payload.type === 'paired') {
    if (deviceByPubkey(payload.pubkey)) return; // already known, no duplicate
    const dev = peerDevice(payload.pubkey);
    state.devices.push(dev);
    window.tcell.sendMeshCommand({ cmd: 'status', status: device(state.self).status }); // a new peer only hears changes from now on, so tell it where we stand
    log('mesh', 'ok', `${dev.name} paired; pubkey ${payload.pubkey.slice(0, 12)}… added to the household roster`);
    emit('pair', { phase: 'paired', device: dev });
    emit('devices', state.devices);
    return;
  }
  if (payload.type === 'peer') {
    let d = deviceByPubkey(payload.pubkey);
    if (!d) {
      d = peerDevice(payload.pubkey); // meshd's own name is the shared key header, so it's ignored
      state.devices.push(d);
      window.tcell.sendMeshCommand({ cmd: 'status', status: device(state.self).status }); // first sighting (e.g. restored from state): sync once; later peer records don't echo back
    }
    d.status = payload.status ?? d.status;
    d.heartbeat = Date.now();
    emit('devices', state.devices);
    return;
  }
  if (payload.type === 'revoked') {
    const d = deviceByPubkey(payload.pubkey);
    if (!d) return;
    revoked.add(d.pubkey);
    state.devices = state.devices.filter((x) => x !== d);
    log('mesh', 'warn', `${d.name} revoked; pubkey ${d.pubkey.slice(0, 12)}… added to the revocation list`);
    emit('devices', state.devices);
    return;
  }
  if (payload.type === 'pair_error') emit('pair', { phase: 'error', error: payload.error });
  log('mesh', payload.type === 'pair_error' ? 'warn' : 'info', JSON.stringify(payload)); // listening/pair_error/hint
}

// backend.cjs names errors after its child processes; the terminal filters by pipeline stage.
const ERR_SRC = { meshd: 'mesh', feed: 'ledger' };

function real() {
  state.devices = state.devices.filter((d) => d.id === state.self); // the other 4 were fictional; only real paired peers join from here
  // cpu/mem get overwritten within ~1s by the first real hoststats poll, but
  // lag only updates once a real Stage-1 action is actually scored -- on an
  // idle system that may never happen, and leaving the fabricated sim default
  // (0.4) in place would keep showing fake data under the Live badge (AC-7).
  state.stats.cpu = 0;
  state.stats.mem = 0;
  state.stats.lag = 0;
  state.stats.source = '—'; // filled from Scout's first real stats record, not the sim's default
  state.stats.globalGenes = 0; // seedHistory()'s fake totals; the ledger feed's first network_stats record fills the real ones
  state.stats.globalDevices = 0;
  window.tcell.onEvent(({ channel, payload }) => {
    if (channel === 'scout') onScout(payload);
    else if (channel === 'soldier') onSoldier(payload);
    else if (channel === 'mesh') onMesh(payload);
    else if (channel === 'ledger') onLedger(payload);
    else if (channel === 'hoststats') onHostStats(payload);
    else if (channel === 'wake') log('scout', 'info', `wake queued for threat ${payload.threat_id.slice(0, 12)}…`);
    else if (channel === 'error') log(ERR_SRC[payload.source] ?? payload.source ?? 'tes', 'warn', payload.message);
    else if (channel === 'advisor' && payload.narration) emit('advice', payload);
  });
}

// Past history (fake, both modes) so the views aren't empty on first open; live data lands after it.
// Seeded, so the main and genome windows (each with its own copy of this module) invent the same past cures.
function seedHistory() {
  let s = 0x7ce11;
  const r = () => ((s = (s + 0x6d2b79f5) | 0), (((s ^ (s >>> 15)) * (s | 1)) >>> 0) / 2 ** 32); // ponytail: tiny inline PRNG, only has to agree with itself
  const shex = (n) => Array.from({ length: n }, () => ((r() * 256) | 0).toString(16).padStart(2, '0')).join('');
  for (let i = 0; i < 14; i++) {
    const t = THREATS[(r() * THREATS.length) | 0];
    state.genes.push({ threat: shex(32), gene: shex(32), name: t.name, from: i % 5 === 0 ? state.self : 'network', time: Date.now() - (14 - i) * 9 * HOUR, bytes: 380 + ((r() * 420) | 0) });
  }
  // Each past cure left two blocks on the chain: the threat report, then the cure. The ones this device found are its contributions.
  const slotAt = (t) => state.stats.slot - Math.round(((Date.now() - t) / HOUR) * 333); // same pace as genome.js's slotAt
  for (const g of state.genes) {
    const mine = g.from === state.self;
    for (const [kind, dt] of [['submit_threat', 0.1 * HOUR], ['commit_gene', 0]]) {
      const time = g.time - dt;
      const b = { slot: slotAt(time), kind, threat: g.threat, gene: kind === 'commit_gene' ? g.gene : undefined, signers: kind === 'commit_gene' ? 4 : undefined, sig: shex(32), time, mine, by: mine ? state.self : 'network', name: g.name };
      state.blocks.push(b);
      if (mine) state.contributions.unshift(b);
    }
  }
  state.stats.globalGenes = 1_800 + ((Math.random() * 300) | 0);
  state.stats.globalDevices = 23_000 + ((Math.random() * 4000) | 0);
}

function simulate() {
  // Global chain chatter from other networks
  (function chatter() {
    setTimeout(() => {
      const kind = Math.random() < 0.55 ? 'submit_threat' : 'commit_gene';
      pushBlock({ kind, threat: hex(32), gene: kind === 'commit_gene' ? hex(32) : undefined, signers: kind === 'commit_gene' ? 3 + ((Math.random() * 3) | 0) : undefined, confidence: 1 + ((Math.random() * 6) | 0) });
      if (kind === 'commit_gene') state.stats.globalGenes++;
      chatter();
    }, rand(2500, 5000));
  })();

  // Background telemetry noise
  const EXES = ['/usr/bin/git', '/Applications/Safari.app/Contents/MacOS/Safari', '/usr/sbin/cfprefsd', '/bin/zsh', '/usr/libexec/xpcproxy', '/Applications/Slack.app/Contents/MacOS/Slack'];
  (function noise() {
    setTimeout(() => {
      const pid = 300 + ((Math.random() * 9000) | 0);
      const kind = pick(['exec', 'fork', 'open', 'open', 'create', 'exit']);
      const exe = pick(EXES);
      const tail = kind === 'open' ? ` path=/Users/me/Documents/${hex(3)}.txt write=${Math.random() < 0.3}` : kind === 'fork' ? ` child=${pid + 1}` : '';
      log('tes', 'info', `${kind} pid=${pid} exe=${exe}${tail}`);
      noise();
    }, rand(250, 900));
  })();

  // System stats + heartbeats
  const busy = () => (state.incident && !state.incident.done ? 1 : 0);
  setInterval(() => {
    const s = state.stats;
    s.cpu = Math.max(1, Math.min(95, s.cpu * 0.7 + (2 + Math.random() * 3 + busy() * 18) * 0.3));
    s.mem = Math.max(30, Math.min(90, s.mem + rand(-0.6, 0.6) + busy() * 0.3));
    s.eps = Math.round(180 + Math.random() * 120 + busy() * 900);
    s.lag = +(0.3 + Math.random() * 0.4 + busy() * 1.2).toFixed(2);
    if (busy() && Math.random() < 0.15) s.dropped++;
    if (Math.random() < 0.02) s.rejected++;
    for (const k of ['cpu', 'mem', 'eps']) {
      state.history[k].push(s[k]);
      if (state.history[k].length > 60) state.history[k].shift();
    }
    for (const d of state.devices) if (Math.random() < 0.8) d.heartbeat = Date.now();
    emit('stats', s);
  }, 1000);

  nextIncident = setTimeout(runIncident, rand(9000, 16000));
}

seedHistory();
if (window.tcell?.onEvent) {
  state.source = 'live';
  real();
} else {
  state.source = 'simulated';
  simulate();
}

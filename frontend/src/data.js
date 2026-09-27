// The one place the UI gets data from. Everything below `simulate()` is fake;
// to link the backend, replace simulate() with code that mutates `state` and
// calls emit() with the same event names:
//   'devices'  state.devices changed (status/heartbeat)
//   'genes'    state.genes changed (a cure was learned)
//   'block'    detail = block, also pushed to state.blocks (and state.contributions if mine)
//   'mesh'     detail = { from, to: [ids] } a cure hint travelled the lymph network
//   'incident' detail = { device, phase: 'watching'|'isolated'|'cured'|'clear', threat }
//   'stats'    state.stats / state.lineages refreshed
//   'log'      detail = { t, src: 'tes'|'scout'|'soldier'|'ledger'|'mesh', level: 'info'|'warn'|'alert'|'ok', msg }
//   'threat'   state.incident changed (lineage tree, allele search, time-to-immunity marks, suppression)
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
  stats: { cpu: 3, mem: 41, eps: 0, dropped: 0, gaps: 0, lag: 0.4, slot: 318_442_000 + ((Math.random() * 9000) | 0), globalGenes: 0, globalDevices: 0 },
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
}

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
export function inject() {
  if (state.source === 'live') return window.tcell.runTestThreat(); // fire-and-forget scripts/test_threat.sh; Scout (already running) is what observes it
  if (state.incident && !state.incident.done) return;
  clearTimeout(nextIncident);
  runIncident();
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

function liveIncidentFor(rootExe) {
  let inc = liveIncidents.get(rootExe);
  if (!inc) {
    inc = { device: state.self, threat: null, actions: [], threatId: null, t0: Date.now(), marks: {}, score: 0, tree: { parent: null, child: null, acts: [] }, search: null, gene: null, done: false };
    liveIncidents.set(rootExe, inc);
  }
  state.incident = inc;
  return inc;
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
    inc.actions = [...inc.actions, p.action];
    inc.tree.acts.push({ action: p.action, weight: WEIGHT[p.action], attack: p.attack_id, tes: p.event });
    inc.threat = schemaLabel(inc.actions);
    log('scout', inc.score >= 100 ? 'alert' : 'warn', `lineage ${p.root_exe} +${WEIGHT[p.action]} ${p.action} (${p.attack_id}) score=${inc.score}/100`);
    if (typeof p.event?.recv_ns === 'number' && typeof p.event?.ts_ns === 'number') {
      lastLagMs = Math.max(0, (p.event.recv_ns - p.event.ts_ns) / 1e6); // real pipeline lag (NFR-1), ms precision only -- u64 ns round-trips JSON as a float64, sub-us error here doesn't matter
    }
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
    window.tcell.sendMeshCommand({ cmd: 'status', status: 'isolated' });
    changed();
    return;
  }
  if (payload.type === 'stats') {
    if (payload.pipeline) {
      state.stats.dropped = payload.pipeline.rejected;
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
  const inc = [...liveIncidents.values()].find((i) => i.threatId === payload.threat_id) ?? state.incident;
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
    log('soldier', 'ok', `gene inherited from network, gene_hash=${payload.gene_hash.slice(0, 16)}…`);
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
    const inc = [...liveIncidents.values()].find((i) => i.threatId === known.threatId);
    state.genes.push({ threat: known.threatId, gene: known.gene, name: known.name, from: state.self, time: Date.now(), bytes: undefined });
    emit('genes', state.genes);
    setStatus(state.self, 'cured');
    state.stoppedThisWeek++;
    if (inc) {
      inc.marks.commit = Date.now();
      emit('threat', inc);
    }
    emit('incident', { device: state.self, phase: 'cured', threat: known.name });
    window.tcell.sendMeshCommand({ cmd: 'status', status: 'cured' });
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
    }
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
    const dev = { id: `dev-${payload.pubkey.slice(0, 8)}`, name: `Device ${payload.pubkey.slice(0, 6)}`, kind: 'laptop', status: 'clean', heartbeat: Date.now(), pubkey: payload.pubkey };
    state.devices.push(dev);
    log('mesh', 'ok', `${dev.name} paired; pubkey ${payload.pubkey.slice(0, 12)}… added to the household roster`);
    emit('pair', { phase: 'paired', device: dev });
    emit('devices', state.devices);
    return;
  }
  if (payload.type === 'peer') {
    let d = deviceByPubkey(payload.pubkey);
    if (!d) {
      d = { id: `dev-${payload.pubkey.slice(0, 8)}`, name: payload.name ?? `Device ${payload.pubkey.slice(0, 6)}`, kind: 'laptop', status: 'clean', heartbeat: Date.now(), pubkey: payload.pubkey };
      state.devices.push(d);
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
  log('mesh', payload.type === 'pair_error' ? 'warn' : 'info', JSON.stringify(payload)); // listening/pair_error/hint
}

function real() {
  state.devices = state.devices.filter((d) => d.id === state.self); // the other 4 were fictional; only real paired peers join from here
  // cpu/mem get overwritten within ~1s by the first real hoststats poll, but
  // lag only updates once a real Stage-1 action is actually scored -- on an
  // idle system that may never happen, and leaving the fabricated sim default
  // (0.4) in place would keep showing fake data under the Live badge (AC-7).
  state.stats.cpu = 0;
  state.stats.mem = 0;
  state.stats.lag = 0;
  window.tcell.onEvent(({ channel, payload }) => {
    if (channel === 'scout') onScout(payload);
    else if (channel === 'soldier') onSoldier(payload);
    else if (channel === 'mesh') onMesh(payload);
    else if (channel === 'ledger') onLedger(payload);
    else if (channel === 'hoststats') onHostStats(payload);
    else if (channel === 'wake') log('scout', 'info', `wake queued for threat ${payload.threat_id.slice(0, 12)}…`);
    else if (channel === 'error') log(payload.source ?? 'tes', 'warn', payload.message);
  });
}

function simulate() {
  // History so the views aren't empty on first open
  for (let i = 0; i < 14; i++) {
    const t = pick(THREATS);
    state.genes.push({ threat: hex(32), gene: hex(32), name: t.name, from: i % 5 === 0 ? state.self : 'network', time: Date.now() - (14 - i) * 9 * HOUR, bytes: 380 + ((Math.random() * 420) | 0) });
  }
  for (const [kind, ago, back] of [['submit_threat', 50, 400_310], ['commit_gene', 49.9, 400_000]]) {
    const b = { slot: state.stats.slot - back, kind, threat: hex(32), gene: kind === 'commit_gene' ? hex(32) : undefined, signers: 4, sig: hex(32), time: Date.now() - ago * HOUR, mine: true, by: state.self, name: THREATS[0].name };
    state.contributions.unshift(b);
  }
  state.stats.globalGenes = 1_800 + ((Math.random() * 300) | 0);
  state.stats.globalDevices = 23_000 + ((Math.random() * 4000) | 0);

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
    for (const k of ['cpu', 'mem', 'eps']) {
      state.history[k].push(s[k]);
      if (state.history[k].length > 60) state.history[k].shift();
    }
    for (const d of state.devices) if (Math.random() < 0.8) d.heartbeat = Date.now();
    emit('stats', s);
  }, 1000);

  nextIncident = setTimeout(runIncident, rand(9000, 16000));
}

if (window.tcell?.onEvent) {
  state.source = 'live';
  real();
} else {
  state.source = 'simulated';
  simulate();
}

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

export const feed = new EventTarget();
const emit = (type, detail) => feed.dispatchEvent(new CustomEvent(type, { detail }));

const hex = (n) => Array.from(crypto.getRandomValues(new Uint8Array(n)), (b) => b.toString(16).padStart(2, '0')).join('');
const pick = (a) => a[(Math.random() * a.length) | 0];
const rand = (a, b) => a + Math.random() * (b - a);
const HOUR = 3_600_000;

export const state = {
  self: 'this-mac',
  devices: [
    { id: 'this-mac', name: 'This Mac', kind: 'laptop' },
    { id: 'kitchen', name: 'Kitchen iMac', kind: 'desktop' },
    { id: 'studio', name: 'Studio Mac mini', kind: 'mini' },
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
  { name: 'File-scrambling ransomware', actions: ['ExecFromTempOrCache', 'RapidFileModBurst', 'RecoverySnapshotTamper'], exe: '/private/var/folders/x1/T/invoice_viewer' },
  { name: 'Backup-wiping ransomware', actions: ['ExecFromTempOrCache', 'RecoverySnapshotTamper', 'RapidFileModBurst'], exe: '/tmp/.cache/updater' },
  { name: 'Fake installer encrypting files', actions: ['ExecFromTempOrCache', 'RapidFileModBurst', 'RapidFileModBurst'], exe: '/Users/Shared/Library/Caches/setup_helper' },
];
const WEIGHT = { ExecFromTempOrCache: 20, RecoverySnapshotTamper: 50, RapidFileModBurst: 40 };
const ATTACK = { ExecFromTempOrCache: 'T1204', RecoverySnapshotTamper: 'T1490', RapidFileModBurst: 'T1486' };

const device = (id) => state.devices.find((d) => d.id === id);
const log = (src, level, msg) => emit('log', { t: Date.now(), src, level, msg });

function pushBlock(b) {
  state.stats.slot += 18 + ((Math.random() * 70) | 0);
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
  const lineage = { pid, exe: threat.exe, score: 0, actions: [] };
  const threatId = hex(32);
  state.lineages.unshift(lineage);
  state.incident = { device: d.id, threat: threat.name };

  setStatus(d.id, 'watching');
  emit('incident', { device: d.id, phase: 'watching', threat: threat.name });
  log('tes', 'info', `exec pid=${pid} pidver=${(Math.random() * 90) | 0} exe=${threat.exe}`);

  for (const a of threat.actions) {
    await wait(rand(1100, 1900));
    lineage.score += WEIGHT[a];
    lineage.actions.push(a);
    log('scout', lineage.score >= 100 ? 'alert' : 'warn', `${d.name}: lineage ${pid} +${WEIGHT[a]} ${a} (${ATTACK[a]}) score=${lineage.score}/100`);
  }

  setStatus(d.id, 'isolated');
  emit('incident', { device: d.id, phase: 'isolated', threat: threat.name });
  log('scout', 'alert', `SIGSTOP lineage root ${pid}; wake {Threat_ID=${threatId.slice(0, 16)}…, pid=${pid}, schema=1}`);
  pushBlock({ kind: 'submit_threat', threat: threatId, confidence: 1, mine: d.id === state.self, by: d.id });
  log('ledger', 'info', `submit_threat ${threatId.slice(0, 12)}… confirmed`);

  await wait(700);
  log('soldier', 'info', 'soldier woke; wasmi sandbox ready (imports=0)');
  let fit = rand(0.2, 0.4);
  for (let g = 1; g <= 5; g++) {
    await wait(rand(450, 800));
    fit = Math.min(0.99, fit + rand(0.08, 0.2));
    log('soldier', 'info', `gen ${g}: best fitness ${fit.toFixed(2)} [containment ${(fit + 0.01).toFixed(2)}, host stability ${(0.9 + Math.random() * 0.09).toFixed(2)}]`);
  }
  const gene = hex(32);
  const bytes = 380 + ((Math.random() * 420) | 0);
  log('soldier', 'ok', `gene compiled ${bytes}B, gene_hash=${gene.slice(0, 16)}…; applied; apoptosis`);

  await wait(800);
  for (let s = 1; s <= 3; s++) {
    await wait(300);
    log('ledger', 'info', `PoI signature ${s}/3 collected`);
  }
  pushBlock({ kind: 'commit_gene', threat: threatId, gene, signers: 3 + ((Math.random() * 3) | 0), mine: d.id === state.self, by: d.id, name: threat.name });
  log('ledger', 'ok', `commit_gene ${gene.slice(0, 12)}… finalized (3-of-5 PoI)`);

  state.genes.push({ threat: threatId, gene, name: threat.name, from: d.id, time: Date.now(), bytes });
  emit('genes', state.genes);
  setStatus(d.id, 'cured');
  state.stoppedThisWeek++;
  lineage.score = 0;
  emit('incident', { device: d.id, phase: 'cured', threat: threat.name });

  const others = state.devices.filter((x) => x.id !== d.id).map((x) => x.id);
  emit('mesh', { from: d.id, to: others });
  for (const id of others) log('mesh', 'ok', `${device(id).name}: cure hint verified (sig ok, quorum 2/2, epigenetic=active)`);

  await wait(6000);
  state.lineages = state.lineages.filter((l) => l !== lineage);
  setStatus(d.id, 'clean');
  state.incident = null;
  emit('incident', { device: d.id, phase: 'clear' });
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
  const busy = () => (state.incident ? 1 : 0);
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

  (function incidents() {
    setTimeout(() => incident().then(incidents), rand(9000, 16000));
  })();
}

simulate();

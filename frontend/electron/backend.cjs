// Phase 9 item 9: process supervisor + NDJSON bridge + wake relay.
//
// Plain Node (child_process/net/readline/fs/path/os) only, no new npm
// deps, no Electron coupling -- this module is spawn-and-parse glue, same
// shape architecture.md already documents ("frontend -> process/NDJSON
// only, no Rust linkage"). NOT wired into main.cjs/preload.cjs here --
// that's item 10 (a separate, not-yet-built file); this module only
// exports `startBackend()`.
//
// Precondition: `cargo build --workspace --examples` must have already
// run (this spawns the resulting target/debug/{scout,soldier,meshd} bins
// and target/debug/examples/feed; a packaged .app instead passes its
// bundled Contents/Resources paths in via main.cjs). A missing binary emits an `'error'`
// event rather than throwing, so a partially-built workspace doesn't take
// the whole Electron app down.
//
// Wake relay shape (mirrors soldier's own module doc in main.rs almost
// verbatim -- that doc already names this file as the supervisor):
// Soldier binds `--wake-socket PATH` itself and is the server; Scout is
// the client that connects once, writes one WakeSignal JSON line, and
// drops (crates/soldier/src/trigger.rs). Soldier self-terminates after
// exactly one wake+cure cycle, so nothing is listening on that path most
// of the time. This module is the thing that actually always listens: it
// binds the CANONICAL wake socket itself (the address given to
// `scout --wake-socket`), FIFO-queues each incoming WakeSignal, and for
// each one spawns a fresh Soldier on its own ephemeral socket, waits for
// Soldier's own real readiness line on stderr ("dormant, waiting on" --
// unmodified, already emitted by soldier/src/main.rs), then connects to
// THAT socket as the client and delivers the buffered wake -- so a wake
// arriving during any respawn gap is queued, never dropped.

const { spawn, execFile } = require('node:child_process');
const net = require('node:net');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const readline = require('node:readline');
const { EventEmitter } = require('node:events');

const ROOT = path.resolve(__dirname, '..', '..');
const TCELL_HOME = path.join(os.homedir(), '.tcell');
const RESPAWN_DELAY_MS = 500;
const SOLDIER_READY_TIMEOUT_MS = 5000;
const HOST_STATS_INTERVAL_MS = 5000; // matches scout's own --stats-every default (main.rs); same lightweight-periodic-poll pattern already used by source_beacon.rs's lsof lane (FR-D-11)

function defaultConfig() {
  fs.mkdirSync(TCELL_HOME, { recursive: true });
  return {
    scoutBin: path.join(ROOT, 'target/debug/scout'),
    soldierBin: path.join(ROOT, 'target/debug/soldier'),
    meshdBin: path.join(ROOT, 'target/debug/meshd'),
    feedBin: path.join(ROOT, 'target/debug/examples/feed'),
    suppressBin: path.join(ROOT, 'target/debug/examples/suppress'),
    testThreatScript: path.join(ROOT, 'scripts/test_threat.sh'),
    scoutMode: process.env.TCELL_SCOUT_MODE || 'eslogger', // attempt full (root) detection by default, spawnScout falls back to --libproc (NFR-3, no-root) on a declined/failed prompt; TCELL_SCOUT_MODE=libproc opts out of the prompt entirely
    rpcUrl: process.env.TCELL_RPC_URL || null, // null -> each bin's own devnet default
    poiKeys: [1, 2, 3, 4, 5].map((n) => path.join(ROOT, `crates/ledger-program/keys/poi-${n}.json`)),
    trace: path.join(ROOT, 'crates/soldier/traces/demo_ransomware.ndjson'),
    benignTrace: path.join(ROOT, 'crates/soldier/traces/benign_apps.ndjson'),
    meshIdentity: path.join(TCELL_HOME, 'mesh_identity.key'),
    meshState: path.join(TCELL_HOME, 'mesh_state.json'),
    meshPort: process.env.TCELL_MESH_PORT ? Number(process.env.TCELL_MESH_PORT) : 0,
    wakeSocketPath: path.join(os.tmpdir(), 'tcell-wake.sock'),
    advisorUrl: process.env.TCELL_ADVISOR_URL ?? 'https://advisor-kr3vx.ondigitalocean.app', // null -> advisor relay off
  };
}

// Phase 10 advisor relay: on each Scout detection, POST the incident plus
// its raw progress/detection records to advisor-service, signed with this
// device's mesh identity key. Fails open -- any error is just an 'error'
// event, the detection/cure path never waits on it.
const ADVISOR_TIMEOUT_MS = 30000;
const MAX_BUFFERED_PROGRESS = 64;
const REVIEW_MAX_AGE_MS = 7 * 24 * 3600 * 1000; // weekly review cadence

function makeAdvisorRelay(events, cfg) {
  const progressByRoot = new Map();

  // libp2p protobuf Ed25519 keypair (identity.rs): last 64 bytes = seed || public.
  function loadKey() {
    const b = fs.readFileSync(cfg.meshIdentity);
    const seed = b.subarray(b.length - 64, b.length - 32);
    const pub = b.subarray(b.length - 32);
    const key = crypto.createPrivateKey({ key: { kty: 'OKP', crv: 'Ed25519', d: seed.toString('base64url'), x: pub.toString('base64url') }, format: 'jwk' });
    return { key, pubHex: pub.toString('hex') };
  }

  async function signedPost(route, payload) {
    const body = Buffer.from(JSON.stringify({ sent_ms: Date.now(), ...payload }));
    const { key, pubHex } = loadKey();
    const res = await fetch(new URL(route, cfg.advisorUrl), {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-tcell-pubkey': pubHex, 'x-tcell-sig': crypto.sign(null, body, key).toString('hex') },
      body,
      signal: AbortSignal.timeout(ADVISOR_TIMEOUT_MS),
    });
    if (!res.ok) throw new Error(`advisor HTTP ${res.status}`);
    return res.json();
  }

  async function post(record) {
    const d = record.detection;
    const raw = [...(progressByRoot.get(d.root_exe) || []), record];
    progressByRoot.delete(d.root_exe);
    const incident = {
      threat_id: d.wake.threat_id,
      ts_ns: d.trigger_ts_ns,
      score: d.score,
      actions: d.wake.schema,
      attack_ids: d.attack_ids,
      latency_ns: d.latency_ns,
    };
    const { narration, trend } = await signedPost('/v1/incident', { incident, raw });
    events.emit('advisor', { threat_id: incident.threat_id, narration, trend });
  }

  // Demo history: fake past incidents (3 this week, matching the hero's "Stopped this week", 2 the week before)
  // so the review has a trend to read. Sent once per key per week, straight to the advisor, never shown as live events.
  const seededAt = path.join(TCELL_HOME, 'advisor_seeded.json');
  const DAY_NS = 86_400n * 1_000_000_000n;
  async function seedPast() {
    const { pubHex } = loadKey();
    try {
      const m = JSON.parse(fs.readFileSync(seededAt, 'utf8'));
      if (m.pub === pubHex && Date.now() - m.at < REVIEW_MAX_AGE_MS) return;
    } catch {}
    const now = BigInt(Date.now()) * 1_000_000n;
    const ATTACK = { ExecFromTempOrCache: 'T1204', RapidFileModBurst: 'T1486', RecoverySnapshotTamper: 'T1490' };
    const orders = [ // each conviction needs all three Stage-1 actions (scoring.rs); only the order varies
      ['ExecFromTempOrCache', 'RapidFileModBurst', 'RecoverySnapshotTamper'],
      ['ExecFromTempOrCache', 'RecoverySnapshotTamper', 'RapidFileModBurst'],
    ];
    const days = [0.6, 2.3, 4.8, 8.5, 11.2]; // days ago
    const results = await Promise.allSettled(days.map((d, k) => {
      const actions = orders[k % 2];
      const incident = {
        threat_id: crypto.randomBytes(32).toString('hex'),
        ts_ns: (now - (DAY_NS * BigInt(Math.round(d * 1000))) / 1000n).toString(),
        score: 110,
        actions,
        attack_ids: actions.map((a) => ATTACK[a]),
        latency_ns: 2_000_000 + crypto.randomInt(7_000_000),
      };
      return signedPost('/v1/incident', { incident, raw: [] });
    }));
    if (results.some((r) => r.status === 'fulfilled')) {
      fs.writeFileSync(seededAt, JSON.stringify({ pub: pubHex, at: Date.now() }));
      fs.rmSync(reviewCache, { force: true }); // a review cached before the history existed is stale
    }
  }

  // Weekly review, cached on disk so it runs once a week, not per launch.
  // null = advisor off; { error } = unreachable (the UI says so, never blocks).
  const reviewCache = path.join(TCELL_HOME, 'advisor_review.json');
  async function getReview(force = false) {
    if (!cfg.advisorUrl) return null;
    await seedPast().catch((e) => events.emit('error', { source: 'advisor', message: `seed: ${e.message}` }));
    if (!force) {
      try {
        const cached = JSON.parse(fs.readFileSync(reviewCache, 'utf8'));
        if (Date.now() - cached.at < REVIEW_MAX_AGE_MS) return cached;
      } catch {}
    }
    try {
      const { summary, review } = await signedPost('/v1/review', {});
      if (!review) return { error: 'model unavailable' };
      const out = { at: Date.now(), summary, review };
      fs.writeFileSync(reviewCache, JSON.stringify(out));
      return out;
    } catch (e) {
      events.emit('error', { source: 'advisor', message: e.message });
      return { error: e.message };
    }
  }

  // Plain-language explanation of one genome block, cached per gene for the session (one model call per block).
  // null = advisor off; { error } = unreachable or model down (the genome window falls back to its own text).
  const explained = new Map();
  async function explainBlock({ gene, ...block }) {
    if (!cfg.advisorUrl) return null;
    if (explained.has(gene)) return explained.get(gene);
    try {
      const { summary } = await signedPost('/v1/explain', { block });
      if (!summary) return { error: 'model unavailable' };
      explained.set(gene, { summary });
      return { summary };
    } catch (e) {
      events.emit('error', { source: 'advisor', message: e.message });
      return { error: e.message };
    }
  }

  function onScout(record) {
    if (!cfg.advisorUrl) return;
    if (record.type === 'progress') {
      const root = record.progress.root_exe;
      const list = progressByRoot.get(root) || [];
      if (list.length < MAX_BUFFERED_PROGRESS) list.push(record);
      progressByRoot.set(root, list);
    } else if (record.type === 'detection') {
      post(record).catch((e) => events.emit('error', { source: 'advisor', message: e.message }));
    }
  }

  return { onScout, getReview, explainBlock };
}

function tryParseJson(line) {
  try {
    return JSON.parse(line);
  } catch {
    return null;
  }
}

// Generic spawn+NDJSON-bridge with auto-restart. `onLine` gets the raw
// stdout line (parsing is the caller's job, since every source here
// already speaks NDJSON but the record shapes differ per source).
function spawnLineReader(events, name, cmd, args, { onLine, restart, stdin, env, onExit } = {}) {
  let stopped = false;
  let child = null;

  function launch() {
    if (!fs.existsSync(cmd)) {
      events.emit('error', { source: name, message: `binary not found: ${cmd} (run cargo build --workspace --examples first)` });
      onExit?.();
      return;
    }
    child = spawn(cmd, args, { stdio: [stdin ? 'pipe' : 'ignore', 'pipe', 'pipe'], env: env ?? process.env });
    readline.createInterface({ input: child.stdout }).on('line', (line) => onLine && onLine(line));
    readline.createInterface({ input: child.stderr }).on('line', (line) => console.error(`[${name}] ${line}`));
    child.on('exit', (code, signal) => {
      if (stopped) return;
      events.emit('error', { source: name, message: `exited (code=${code}, signal=${signal})` });
      if (restart) setTimeout(launch, RESPAWN_DELAY_MS);
      onExit?.();
    });
  }

  launch();
  return {
    get child() {
      return child;
    },
    stop() {
      stopped = true;
      if (child) child.kill();
    },
  };
}

// One-shot spawn+capture, for a binary that runs once and prints a single
// NDJSON result line -- distinct from spawnLineReader (built for long-lived
// daemons with auto-restart, wrong shape for a request/response call).
function runOnce(cmd, args) {
  return new Promise((resolve, reject) => {
    if (!fs.existsSync(cmd)) return reject(new Error(`binary not found: ${cmd} (run cargo build --workspace --examples first)`));
    const child = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    child.stdout.on('data', (d) => {
      out += d;
    });
    readline.createInterface({ input: child.stderr }).on('line', (line) => console.error(`[${path.basename(cmd)}] ${line}`));
    child.on('exit', () => {
      const line = out.trim().split('\n').filter(Boolean).pop();
      const record = line && tryParseJson(line);
      if (record && record.type !== 'error') resolve(record);
      else reject(new Error(record?.message || `no parseable output (last line: ${JSON.stringify(line)})`));
    });
    child.on('error', reject);
  });
}

// Human-in-the-loop (Scout watch list): pause/resume a watched lineage's
// known pids. Only the pids Scout credited an action to are known (progress
// records carry the actor, not full ancestry). Before signalling, each pid's
// live exe must still match the one Scout saw -- a recycled pid is skipped,
// never signalled. Own-uid processes are signalled directly; root daemons
// (eslogger mode) fall back to `sudo -n kill`, same best-effort as Scout.
const SYSTEM_PID_FLOOR = 100; // matches scoring.rs's floor
function signalPids(targets, sig, protectedPids) {
  if (sig !== 'SIGSTOP' && sig !== 'SIGCONT') return Promise.reject(new Error(`unsupported signal ${sig}`));
  const liveExe = (pid) => new Promise((r) => execFile('ps', ['-p', String(pid), '-o', 'comm='], (err, out) => r(err ? null : out.trim())));
  const sudoKill = (pid) => new Promise((r) => execFile('/usr/bin/sudo', ['-n', '/bin/kill', `-${sig.slice(3)}`, String(pid)], (err) => r(!err)));
  return Promise.all(
    targets.map(async ({ pid, exe }) => {
      if (!Number.isInteger(pid) || pid < SYSTEM_PID_FLOOR || protectedPids.includes(pid)) return { pid, ok: false, reason: 'protected process' };
      const now = await liveExe(pid);
      if (!now) return { pid, ok: false, reason: 'already exited' };
      if (now !== exe) return { pid, ok: false, reason: 'pid now belongs to a different program' };
      try {
        process.kill(pid, sig);
        return { pid, ok: true };
      } catch (e) {
        if (e.code === 'EPERM' && (await sudoKill(pid))) return { pid, ok: true };
        return { pid, ok: false, reason: e.code === 'EPERM' ? 'not permitted (owned by another user; needs cached sudo)' : e.message };
      }
    }),
  );
}

// scoring.rs threat_id(): SHA-256 over the ordered action codes.
const ACTION_CODE = { ExecFromTempOrCache: 1, RecoverySnapshotTamper: 2, RapidFileModBurst: 3 };
function threatIdHex(schema) {
  return crypto.createHash('sha256').update(Buffer.from(schema.map((a) => ACTION_CODE[a]))).digest('hex');
}

function scoutArgs(cfg) {
  const base = cfg.scoutMode === 'eslogger' ? ['--eslogger'] : ['--libproc'];
  return [...base, '--wake-socket', cfg.wakeSocketPath];
}

// sudo execve's this, so it can't live inside app.asar (a virtual archive); packaged builds unpack it (package.json build.asarUnpack).
const ASKPASS_HELPER = path.join(__dirname, 'askpass.applescript').replace(`app.asar${path.sep}`, `app.asar.unpacked${path.sep}`);

function scoutSpawn(cfg) {
  if (cfg.scoutMode === 'eslogger') {
    // -A (askpass): sudo invokes SUDO_ASKPASS -- a real GUI password prompt
    // (askpass.applescript's "display dialog ... with hidden answer") --
    // instead of trying to read a password from a TTY, since there is none
    // here (Electron spawns with stdio ['ignore','pipe','pipe']). A
    // cancelled/failed prompt makes sudo itself fail fast with no stdout
    // ever produced; spawnScout (below) treats that as "declined" and falls
    // back to --libproc rather than retrying the same prompt in a loop.
    return { cmd: '/usr/bin/sudo', args: ['-A', cfg.scoutBin, ...scoutArgs(cfg)], env: { ...process.env, SUDO_ASKPASS: ASKPASS_HELPER } };
  }
  return { cmd: cfg.scoutBin, args: scoutArgs(cfg) };
}

// Wraps scoutSpawn/spawnLineReader with the elevation-decline fallback: in
// 'eslogger' mode, attempt the real (privileged) path first every launch; if
// the elevated attempt exits WITHOUT ever having produced a single stdout
// line (declined password prompt, wrong password exhausting sudo's own
// retries, or eslogger otherwise unavailable even as root -- e.g. missing
// Full Disk Access, a SEPARATE macOS TCC grant this prompt cannot itself
// satisfy, see plan.md), fall back once to plain --libproc (NFR-3, no root)
// instead of re-showing the same prompt forever. If it DID produce output
// (a real elevated session that later crashes for an unrelated reason), the
// normal restart:true retry re-attempts the SAME elevated path -- sudo's own
// timestamp cache usually avoids re-prompting for a quick respawn.
// cfg.scoutMode !== 'eslogger' (an explicit TCELL_SCOUT_MODE=libproc opt-out)
// skips all of this and behaves exactly as before, no prompt at all.
function spawnScout(events, cfg, onLine) {
  if (cfg.scoutMode !== 'eslogger') return spawnLineReader(events, 'scout', cfg.scoutBin, scoutArgs(cfg), { restart: true, onLine });

  let current = null;

  function launchElevated() {
    let sawLine = false;
    const scoutCmd = scoutSpawn(cfg);
    current = spawnLineReader(events, 'scout', scoutCmd.cmd, scoutCmd.args, {
      restart: false, // this wrapper owns the retry/fallback decision, not spawnLineReader's own loop
      env: scoutCmd.env,
      onLine: (line) => {
        sawLine = true;
        onLine(line);
      },
      onExit: () => {
        if (sawLine) setTimeout(launchElevated, RESPAWN_DELAY_MS);
        else {
          events.emit('error', { source: 'scout', message: 'administrator access declined or unavailable; continuing with reduced (no-root) detection' });
          current = spawnLineReader(events, 'scout', cfg.scoutBin, scoutArgs({ ...cfg, scoutMode: 'libproc' }), { restart: true, onLine });
        }
      },
    });
  }

  launchElevated();
  return {
    get child() {
      return current.child;
    },
    stop() {
      current.stop();
    },
  };
}

// FIFO relay: Scout connects once per wake, writes one WakeSignal JSON
// line, drops. Each queued wake gets its own fresh Soldier on its own
// ephemeral socket, delivered serially (one cure at a time, matching
// "one wake per Soldier").
class WakeRelay {
  constructor(events, cfg) {
    this.events = events;
    this.cfg = cfg;
    this.queue = [];
    this.draining = false;
    this.soldierCounter = 0;
    this.server = null;
  }

  start() {
    try {
      fs.unlinkSync(this.cfg.wakeSocketPath);
    } catch {
      // no stale socket, fine
    }
    this.server = net.createServer((socket) => {
      readline.createInterface({ input: socket }).on('line', (line) => {
        const wake = tryParseJson(line);
        if (wake && typeof wake.threat_id === 'string') this.enqueue(wake);
      });
    });
    this.server.listen(this.cfg.wakeSocketPath);
  }

  enqueue(wake) {
    this.queue.push(wake);
    this.events.emit('wake', wake);
    this._drain();
  }

  stop() {
    if (this.server) this.server.close();
    try {
      fs.unlinkSync(this.cfg.wakeSocketPath);
    } catch {
      // already gone, fine
    }
  }

  async _drain() {
    if (this.draining) return;
    this.draining = true;
    while (this.queue.length > 0) {
      const wake = this.queue.shift();
      await this._deliverToFreshSoldier(wake);
    }
    this.draining = false;
  }

  _deliverToFreshSoldier(wake) {
    const cfg = this.cfg;
    const ephemeral = path.join(os.tmpdir(), `tcell-soldier-${this.soldierCounter++}.sock`);
    try {
      fs.unlinkSync(ephemeral);
    } catch {
      // no stale socket, fine
    }

    return new Promise((resolve) => {
      if (!fs.existsSync(cfg.soldierBin)) {
        this.events.emit('error', { source: 'soldier', message: `binary not found: ${cfg.soldierBin}` });
        return resolve();
      }
      const args = ['--wake-socket', ephemeral, '--trace', cfg.trace, '--benign-trace', cfg.benignTrace];
      for (const k of cfg.poiKeys) args.push('--poi-key', k);
      if (cfg.rpcUrl) args.push('--rpc', cfg.rpcUrl);

      const child = spawn(cfg.soldierBin, args, { stdio: ['ignore', 'pipe', 'pipe'] });
      let ready = false;
      let settled = false;
      const timeout = setTimeout(() => {
        if (ready || settled) return;
        this.events.emit('error', { source: 'soldier', message: `never became ready for threat ${wake.threat_id}, skipping delivery` });
      }, SOLDIER_READY_TIMEOUT_MS);

      readline.createInterface({ input: child.stdout }).on('line', (line) => {
        const record = tryParseJson(line);
        if (record) this.events.emit('soldier', record);
      });
      readline.createInterface({ input: child.stderr }).on('line', (line) => {
        console.error(`[soldier] ${line}`);
        if (!ready && line.includes('dormant, waiting on')) {
          ready = true;
          clearTimeout(timeout);
          const client = net.connect(ephemeral, () => {
            client.end(`${JSON.stringify(wake)}\n`);
          });
          client.on('error', (e) => this.events.emit('error', { source: 'soldier', message: `wake delivery failed: ${e.message}` }));
        }
      });
      child.on('exit', () => {
        settled = true;
        clearTimeout(timeout);
        try {
          fs.unlinkSync(ephemeral);
        } catch {
          // already gone, fine
        }
        resolve();
      });
    });
  }
}

// Real host-resource cost of the T-cell agent itself (NFR-2's "idle Scout
// CPU cost shall be negligible" is exactly what this surfaces). No source
// anywhere reports its own cpu/mem, so this polls `ps` for the PIDs already
// spawned above -- soldier is deliberately excluded: it's short-lived and
// self-terminates after exactly one wake+cure cycle, so it's rarely alive
// at poll time and isn't part of the agent's steady-state footprint.
function startHostStatsPoller(events, getPids) {
  function poll() {
    const pids = getPids();
    if (pids.length === 0) return;
    execFile('ps', ['-o', 'pid=,%cpu=,%mem=', '-p', pids.join(',')], (err, stdout) => {
      if (err) return; // a pid exited mid-poll, or ps unavailable -- skip this tick, not fatal
      let cpu = 0;
      let mem = 0;
      for (const line of stdout.trim().split('\n')) {
        const parts = line.trim().split(/\s+/);
        if (parts.length < 3) continue;
        cpu += parseFloat(parts[1]) || 0;
        mem += parseFloat(parts[2]) || 0;
      }
      events.emit('hoststats', { type: 'hoststats', cpu, mem, procs: pids.length });
    });
  }

  poll();
  const timer = setInterval(poll, HOST_STATS_INTERVAL_MS);
  return { stop: () => clearInterval(timer) };
}

function startBackend(overrides = {}) {
  const cfg = { ...defaultConfig(), ...overrides };
  const events = new EventEmitter();
  // Node's EventEmitter throws (crashing this process) if an 'error' event
  // fires with zero listeners attached -- a real risk here, since a few
  // launch()-time checks below (spawnLineReader) can emit 'error'
  // synchronously, before main.cjs (the caller) has gotten `events` back
  // from startBackend() and attached its own forwarding listener. This
  // permanent no-op listener makes 'error' behave like every other channel
  // here (an event to forward, never a thing that can crash the app);
  // main.cjs's real listener still receives it too, EventEmitter fans out
  // to every listener, not just the first one registered.
  events.on('error', () => {});

  const advisor = makeAdvisorRelay(events, cfg);
  const scout = spawnScout(events, cfg, (line) => {
    const record = tryParseJson(line);
    if (record) {
      events.emit('scout', record);
      advisor.onScout(record);
    }
  });

  const meshdArgs = ['--identity', cfg.meshIdentity, '--state', cfg.meshState, '--port', String(cfg.meshPort), '--benign-trace', cfg.benignTrace];
  if (cfg.rpcUrl) meshdArgs.push('--rpc', cfg.rpcUrl);
  const meshd = spawnLineReader(events, 'meshd', cfg.meshdBin, meshdArgs, {
    restart: true,
    stdin: true,
    onLine: (line) => {
      const record = tryParseJson(line);
      if (record) events.emit('mesh', record);
    },
  });

  const feedArgs = cfg.rpcUrl ? ['--rpc', cfg.rpcUrl] : [];
  const feed = spawnLineReader(events, 'feed', cfg.feedBin, feedArgs, {
    restart: true,
    onLine: (line) => {
      const record = tryParseJson(line);
      if (record) events.emit('ledger', record);
    },
  });

  const relay = new WakeRelay(events, cfg);
  relay.start();

  const hostStats = startHostStatsPoller(events, () =>
    [scout.child?.pid, meshd.child?.pid, feed.child?.pid].filter((p) => typeof p === 'number'),
  );

  return {
    events,
    sendMeshCommand(cmd) {
      if (meshd.child && meshd.child.stdin.writable) {
        meshd.child.stdin.write(`${JSON.stringify(cmd)}\n`);
      }
    },
    getReview: advisor.getReview,
    explainBlock: advisor.explainBlock,
    runTestThreat() {
      // Deliberately NOT `spawn('sh', [cfg.testThreatScript], ...)`: a shell
      // observed with a positional (script-path) arg fails lineage.rs's
      // is_boundary() interactive-shell check, same as electron's own
      // process and the `sh -c` wrapper npm run dev uses -- none of them are
      // boundaries, so Scout's fork/exec rollup merges the trigger into the
      // SAME lineage as vite/meshd/feed/every Electron helper process, and
      // suspend_all() SIGSTOPs every live member of a convicted lineage, not
      // just the trigger -- i.e. the whole app freezes a few seconds in.
      // A bare shell with NO positional args (fed the script path over
      // stdin instead) IS classified as interactive by that same check, so
      // it becomes a fresh lineage boundary and isolates the conviction to
      // just itself + its own children.
      const sh = spawn('sh', [], { stdio: ['pipe', 'ignore', 'ignore'] });
      sh.stdin.end(`${cfg.testThreatScript}\n`);
    },
    signalLineage(targets, sig) {
      const own = [process.pid, process.ppid, scout.child?.pid, meshd.child?.pid, feed.child?.pid].filter(Boolean);
      return signalPids(targets, sig, own);
    },
    // A person's escalation stands in for Scout's 100-pt conviction: the same
    // WakeSignal shape goes through the same relay to a fresh Soldier.
    escalate(schema, pid) {
      if (!Array.isArray(schema) || !schema.length || !schema.every((a) => a in ACTION_CODE)) throw new Error('bad schema');
      const wake = { threat_id: threatIdHex(schema), pid, schema };
      relay.enqueue(wake);
      return wake.threat_id;
    },
    suppressGene(threatIdHex) {
      const args = [threatIdHex, ...(cfg.rpcUrl ? [cfg.rpcUrl] : [])];
      return runOnce(cfg.suppressBin, args);
    },
    stop() {
      scout.stop();
      meshd.stop();
      feed.stop();
      relay.stop();
      hostStats.stop();
    },
  };
}

module.exports = { startBackend };

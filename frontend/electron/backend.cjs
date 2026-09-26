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
// and target/debug/examples/feed). A missing binary emits an `'error'`
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

const { spawn } = require('node:child_process');
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

function defaultConfig() {
  fs.mkdirSync(TCELL_HOME, { recursive: true });
  return {
    scoutBin: path.join(ROOT, 'target/debug/scout'),
    soldierBin: path.join(ROOT, 'target/debug/soldier'),
    meshdBin: path.join(ROOT, 'target/debug/meshd'),
    feedBin: path.join(ROOT, 'target/debug/examples/feed'),
    testThreatScript: path.join(ROOT, 'scripts/test_threat.sh'),
    scoutMode: process.env.TCELL_SCOUT_MODE || 'libproc', // NFR-3: no-root default
    rpcUrl: process.env.TCELL_RPC_URL || null, // null -> each bin's own devnet default
    poiKeys: [1, 2, 3, 4, 5].map((n) => path.join(ROOT, `crates/ledger-program/keys/poi-${n}.json`)),
    trace: path.join(ROOT, 'crates/soldier/traces/demo_ransomware.ndjson'),
    benignTrace: path.join(ROOT, 'crates/soldier/traces/benign_apps.ndjson'),
    meshIdentity: path.join(TCELL_HOME, 'mesh_identity.key'),
    meshState: path.join(TCELL_HOME, 'mesh_state.json'),
    meshPort: process.env.TCELL_MESH_PORT ? Number(process.env.TCELL_MESH_PORT) : 0,
    wakeSocketPath: path.join(os.tmpdir(), 'tcell-wake.sock'),
    advisorUrl: process.env.TCELL_ADVISOR_URL || null, // null -> advisor relay off
  };
}

// Phase 10 advisor relay: on each Scout detection, POST the incident plus
// its raw progress/detection records to advisor-service, signed with this
// device's mesh identity key. Fails open -- any error is just an 'error'
// event, the detection/cure path never waits on it.
const ADVISOR_TIMEOUT_MS = 30000;
const MAX_BUFFERED_PROGRESS = 64;

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
    const body = Buffer.from(JSON.stringify({ sent_ms: Date.now(), incident, raw }));
    const { key, pubHex } = loadKey();
    const res = await fetch(new URL('/v1/incident', cfg.advisorUrl), {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-tcell-pubkey': pubHex, 'x-tcell-sig': crypto.sign(null, body, key).toString('hex') },
      body,
      signal: AbortSignal.timeout(ADVISOR_TIMEOUT_MS),
    });
    if (!res.ok) throw new Error(`advisor HTTP ${res.status}`);
    const { narration, trend } = await res.json();
    events.emit('advisor', { threat_id: incident.threat_id, narration, trend });
  }

  return function onScout(record) {
    if (!cfg.advisorUrl) return;
    if (record.type === 'progress') {
      const root = record.progress.root_exe;
      const list = progressByRoot.get(root) || [];
      if (list.length < MAX_BUFFERED_PROGRESS) list.push(record);
      progressByRoot.set(root, list);
    } else if (record.type === 'detection') {
      post(record).catch((e) => events.emit('error', { source: 'advisor', message: e.message }));
    }
  };
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
function spawnLineReader(events, name, cmd, args, { onLine, restart, stdin } = {}) {
  let stopped = false;
  let child = null;

  function launch() {
    if (!fs.existsSync(cmd)) {
      events.emit('error', { source: name, message: `binary not found: ${cmd} (run cargo build --workspace --examples first)` });
      return;
    }
    child = spawn(cmd, args, { stdio: [stdin ? 'pipe' : 'ignore', 'pipe', 'pipe'] });
    readline.createInterface({ input: child.stdout }).on('line', (line) => onLine && onLine(line));
    readline.createInterface({ input: child.stderr }).on('line', (line) => console.error(`[${name}] ${line}`));
    child.on('exit', (code, signal) => {
      if (stopped) return;
      events.emit('error', { source: name, message: `exited (code=${code}, signal=${signal})` });
      if (restart) setTimeout(launch, RESPAWN_DELAY_MS);
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

function scoutArgs(cfg) {
  const base = cfg.scoutMode === 'eslogger' ? ['--eslogger'] : ['--libproc'];
  return [...base, '--wake-socket', cfg.wakeSocketPath];
}

function scoutSpawn(cfg) {
  if (cfg.scoutMode === 'eslogger') {
    // Best-effort: requires an already-cached sudo timestamp (`sudo -v` run
    // beforehand by the operator). No interactive-sudo UX is attempted
    // here -- deliberate simplification, see plan.md.
    return { cmd: 'sudo', args: ['-n', cfg.scoutBin, ...scoutArgs(cfg)] };
  }
  return { cmd: cfg.scoutBin, args: scoutArgs(cfg) };
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
        if (wake && typeof wake.threat_id === 'string') {
          this.queue.push(wake);
          this.events.emit('wake', wake);
          this._drain();
        }
      });
    });
    this.server.listen(this.cfg.wakeSocketPath);
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

function startBackend(overrides = {}) {
  const cfg = { ...defaultConfig(), ...overrides };
  const events = new EventEmitter();

  const advisor = makeAdvisorRelay(events, cfg);
  const scoutCmd = scoutSpawn(cfg);
  const scout = spawnLineReader(events, 'scout', scoutCmd.cmd, scoutCmd.args, {
    restart: true,
    onLine: (line) => {
      const record = tryParseJson(line);
      if (record) {
        events.emit('scout', record);
        advisor(record);
      }
    },
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

  return {
    events,
    sendMeshCommand(cmd) {
      if (meshd.child && meshd.child.stdin.writable) {
        meshd.child.stdin.write(`${JSON.stringify(cmd)}\n`);
      }
    },
    runTestThreat() {
      spawn('sh', [cfg.testThreatScript], { stdio: 'ignore' });
    },
    stop() {
      scout.stop();
      meshd.stop();
      feed.stop();
      relay.stop();
    },
  };
}

module.exports = { startBackend };

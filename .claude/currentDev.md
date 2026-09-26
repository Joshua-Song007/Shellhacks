## Status: Staged — backend ↔ frontend integration (Phase 9)

### Global
- Electron main = supervisor + bridge; data.js = translator → existing `state` + `emit()` events (header contract unchanged)
- `simulate()` only when `window.tcell?.live` absent (`npm run web`)
- Env (Electron main only): `TCELL_RPC` default `https://api.devnet.solana.com`; `TCELL_DRY_RUN=1` → scout `--dry-run`; `TCELL_MESH_PORT` default 4101
- Devnet only (FR-L-5/CON-2); no local validator in runtime path
- Devnet program `27v76nMPKQg5akQHBsPHnhPt8K7kSf3s8GZjRzUnvBuq` = old build: reads ok; commit/suppress fail until `HeAub…W6b3` runs `anchor upgrade` (Soldier fail-open, UI logs ledger errors)

### 0. Docs first
- overview.md FR-U-1: "Tauri + React + Vite" → "Electron + vanilla JS + Vite" (user-approved)
- architecture.md module tree: `dashboard/ App.tsx…` → `frontend/ electron/{main,preload,backend}.cjs, src/{data,main,mesh,helix,genome}.js`
- architecture.md dashboard edges = process/NDJSON: scout stdout, soldier stdout, meshd stdout, ledger-client `feed` example stdout
- architecture.md: Scout I/O adds `progress`; new edge mesh -> soldier (Stage-3, user-approved); wake path Scout → backend.cjs relay → Soldier
- plan.md: add Phase 9 checklist = items 1–12

### 1. crates/scout/src/pipeline.rs
- `pub struct Progress { lineage: LineageId, root_exe, score, action: Action, attack_id, event: TesEvent }` (Serialize)
- `process_with`: `before = scorer.score(lineage)`; after `observe_with`, if score > before push one Progress per credited action; actions = unique subset of weights summing to `score - before` (20/40/50 subsets all distinct)
- `pub fn drain_progress(&mut self) -> Vec<Progress>` (mem::take)
- Test: 3-action trace → 3 Progress, cumulative scores (e.g. 20/70/110); one exec crediting 2 actions → 2 Progress

### 2. crates/scout/src/main.rs
- `run` + `run_libproc` loops: after each `feed_*`, write `{"type":"progress",…}` per drained Progress, before any `detection`

### 3. crates/soldier/src/main.rs
- `cure["schema"]` = wake.schema names
- Module doc: replace "A supervisor relaunching Soldier for the next threat is out of scope." with "Relaunch is handled by an external supervisor (frontend/electron/backend.cjs), which respawns a fresh Soldier after each exit. Wake signals are buffered by the supervisor, so a wake arriving during the respawn gap is delivered to the next Soldier, not lost." (user-approved)

### 3b. crates/soldier/src/regression.rs (new)
- `pub fn check(gene: &[u8], benign: &ReplayTarget) -> bool`: `Sandbox::instantiate` → read `allele_bitmask` global → decode via `allele_search::ALL` bit order → pass iff no allele `neutralizes()` ∩ `benign_actions()`
- Tests: clean passes; colliding allele fails; malformed wasm fails

### 4. crates/soldier/traces/demo_ransomware.ndjson (new, FR-R-4)
- exec from `/private/var/folders/...`; ≥64 rename/unlink within 1s; exec `tmutil deletelocalsnapshots`
- Must pass `scout --tes-file … --dry-run`: 3 progress + 1 detection, 0 rejects

### 4b. crates/soldier/traces/benign_apps.ndjson (new)
- Normal activity (editor saves, git, browser cache writes); no Stage-1 crossing
- Used as `--benign-trace` by every Soldier + meshd Stage-3

### 5. crates/mesh/src/identity.rs
- `pub fn admit(&mut self, code: &PairingCode, presented_nonce: &[u8;16], presenter: PublicKey) -> Result<(), PairingError>`: expiry → constant-time nonce → record `presenter` (no-op if present)
- Tests: happy / expired / mismatch / idempotent

### 6. crates/mesh/src/bin/meshd.rs (new)
- Args: `--identity PATH --state PATH --port N --rpc URL --benign-trace PATH`
- mesh Cargo.toml: libp2p features + `request-response`, `json`; dep `soldier` (path)
- Swarm: transport.rs `build_swarm`/`listen_on`/`dial`; behaviour = `ping` + `request_response::json`
- Wire req: `Pair{nonce_hex}` | `Hint(CureHint)` (DATA-3 exact) | `Status{status}`; resp `Ok` | `Err(String)`
- stdin cmds: `pair_start` → emit `{type:"pair_code", uri:"tcell://pair?addr=<ip:port>&peer=<peer_id>&nonce=<hex>", expires_ms}` | `pair_join{uri}` → dial + `Pair`, on Ok record issuer | `broadcast{threat_id, gene_hash}` → `CureHint::sign` → all paired | `status{status}` → all paired | `revoke{pubkey}` → `RevocationList::revoke` + drop conn
- Inbound `Pair`: `Roster::admit`, presenter = Noise-authenticated peer key; code spent on success
- Inbound `Hint`: gene = `fetch_genome_registry(threat_id).gene_seq`; require sha256 == hint.gene_hash; Stage3Regression = `soldier::regression::check`; → `verify::evaluate`; Accept → `gene_compile::apply`; `RejectNoQuorum` → `confirm_via_chain` → true: `mark_verified` + re-evaluate / false: `rollback`; epigenetic from last registry read
- stdout: `peer{pubkey,name,addr,status,heartbeat_ms}`, `paired{pubkey,addr}`, `pair_error{error}`, `hint{from,threat_id,gene_hash,decision}`, `revoked{pubkey}`
- Persist roster + revocations + peer addrs → `--state` JSON (0600); redial on start
- Multi-thread tokio runtime
- Test (tests/pairing.rs pattern): 2 meshd subprocesses → both `paired`; broadcast → receiver emits `hint` w/ sig ok

### 7b. crates/ledger-client (client.rs + examples/feed.rs)
- `recent_signatures(until: Option<Signature>)` → (sig, slot, block_time, kind, threat_id): `get_signatures_for_address_with_config` + `get_transaction` logs `Instruction: SubmitThreat|CommitGene|SuppressGene`, threat_id = ix data [8..40]; confirmed commitment
- `all_genomes()` → `get_program_accounts` + GenomeRegistry discriminator filter
- examples/feed.rs: every 2s `{type:"block",slot,sig,time,kind,threat}`; every 10s `{type:"genome",genes:[{threat,gene,bytes,suppressed}]}`
- Test: `#[ignore]` devnet read

### 8. scripts/test_threat.sh + scripts/test_threat.c (new; benign synthetic, CON-7 divergence approved)
- Build fresh into `/tmp/tcell-test/`: `trigger` + no-op stub `tmutil` (exit 0)
- `trigger`: 80× create+rename+unlink own files in `/tmp/tcell-test/work/` <1s → execv `/tmp/tcell-test/tmutil deletelocalsnapshots`; real /usr/bin/tmutil never runs
- Launch: `launchctl submit -l tcell.test -- …` (parent launchd → own lineage)
- Cleanup after cure: `launchctl remove tcell.test`, kill stub, `rm -rf /tmp/tcell-test`

### 9. frontend/electron/backend.cjs (new)
- scout: `sudo -n target/debug/scout --wake-socket $TMP/tcell-wake.sock --stats-every 1 [--dry-run]`; sudo fail → `scout --libproc --wake-socket …`; emit `{type:"source",source}`
- wake relay: listen `$TMP/tcell-wake.sock`; FIFO queue; one wake per Soldier → `$TMP/tcell-soldier.sock` (connect-retry until bound)
- soldier: `target/debug/soldier --wake-socket $TMP/tcell-soldier.sock --trace crates/soldier/traces/demo_ransomware.ndjson --benign-trace crates/soldier/traces/benign_apps.ndjson --poi-key crates/ledger-program/keys/poi-{1,2,3}.json --rpc $TCELL_RPC`; respawn on every exit
- meshd: `target/debug/meshd --identity ~/.tcell/identity.key --state ~/.tcell/peers.json --port $TCELL_MESH_PORT --rpc $TCELL_RPC --benign-trace crates/soldier/traces/benign_apps.ndjson`
- feed: `target/debug/examples/feed $TCELL_RPC`
- stdout lines → JSON.parse → `broadcast({src,…rec})`; stderr → `{type:"log",src,msg}`
- `{type:"sys",cpu,mem}` every 1s (os.loadavg / os.freemem)
- Glue: `cure` → meshd `broadcast{threat_id,gene_hash}` + `status{cured}`; `detection` → `status{isolated}`; first `progress` per lineage → `status{watching}`
- Keep last 60 blocks + last genome for `snapshot`
- Cmds: `suppress(hex)` → `target/debug/examples/suppress <hex> $TCELL_RPC`; `testThreat()` → scripts/test_threat.sh; `mesh(cmd)` → meshd stdin
- Missing binary → one `log warn` "run cargo build --workspace"
- `stop()` on quit; `sudo -n kill` for scout

### 10. frontend/electron/main.cjs + preload.cjs
- main: `backend.start(rec → all windows webContents.send('backend', rec))`; `ipcMain.handle('snapshot')`; `ipcMain.on('cmd')`
- preload: `live: true`, `onRecord(cb)`, `snapshot()`, `cmd(name, arg)`; keep `openGenome`

### 11. frontend/src/data.js
- `window.tcell?.live ? live() : simulate()`
- `live()`: devices = [self] (pubkey from meshd); no fake history; globalGenes = genome count; globalDevices = paired + 1
- `progress` → upsert lineage; open/extend incident (tree.child from event.proc; acts push {action,weight,attack,tes}); first → `watching`; `log scout warn`; emit `threat`
- `detection` → `marks.detect`, threatId, latency log; `isolated`; `log scout alert`
- `cure` → gene, `marks.gene/immune`; `marks.regress` + "Stage-3: benign-collision penalty applied" (penalty, not a gate — AC-7 wording); `inc.search` = replay `evaluate()` over 32 masks for `schema`; commit_sigs → `marks.commit`; genes push; `cured`; `suppressed` → log warn; ledger errors → log warn
- `stats` → eps = Δaccepted/Δt, dropped = reader.dropped, gaps = pipeline.seq_gap_events; `sys` → cpu/mem
- `block` → `pushBlock` (mine = own sigs); `genome` → genes/globalGenes
- `peer`/`paired`/`revoked` → devices upsert/remove; `hint` Accept → `mesh{from,to:[self]}` + log ok; reject → log warn w/ decision
- `pair_code` → resolve `startPairing()`; `pair_error` → `pair{error}`; `log` → passthrough
- `inject()` → cmd testThreat; `suppress()` → cmd suppress; `startPairing()` async via pair_start; `revoke(id)` → mesh revoke
- Threat label: schema → nearest THREATS entry else "Unknown ransomware-like behaviour"
- `stoppedThisWeek` = cure count this session

### 12. frontend/src/main.js + index.html
- Pairing dialog: "Join a device" paste field → mesh `pair_join{uri}`
- Await `startPairing()`
- Advanced: detection source badge from `source`

### 13. Docs after code
- plan.md Phase 9 ticks + parentheticals: CON-7 synthetic trigger; AC-6 2-device K=2 → chain confirm; wake relay via backend.cjs; stoppedThisWeek not persisted; AC-3 needs real ART atomic separately
- architecture.md: meshd, regression.rs, ledger-client feed internals
- branchDep.md: libp2p `request-response`, `json`; mesh → soldier path dep

### Build order
- 0 → 1 → 2 → 4 → 4b → 3 → 3b → 5 → 6 → 7b → 8 → 9 → 10 → 11 → 12 → 13

### Verification
- `cargo test --workspace`
- `scout --tes-file crates/soldier/traces/demo_ransomware.ndjson --dry-run` → 3 progress, 1 detection, 0 rejects
- `sudo -v`; `cargo build --workspace`; `cd frontend && npm run dev` → source=eslogger, eps > 0, devnet history in feed
- Run test threat → 20/60/110 tree, SIGSTOP, cure evolved
- Two test threats back-to-back → both cured (relay)
- Pre-upgrade: commit/suppress → ledger errors logged; post-upgrade: commit block, rerun → inherited, suppress → rerun refused
- 2nd meshd (other port/machine): pair via URI → both listed; cure on A → B `hint` Accept after chain confirm
- `npm run web` → sim works

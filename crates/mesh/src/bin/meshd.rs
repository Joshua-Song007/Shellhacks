//! Mesh daemon (Phase 9 item 6): the real process behind crates/mesh's
//! pairing/message/verify/revocation modules -- one per lymph node,
//! stdin/stdout JSON-driven so frontend/electron/backend.cjs can supervise
//! it the same way it supervises Scout/Soldier.
//!
//! Wire protocol note (FR-M-1/FR-M-2): `Event::Message` only ever hands a
//! `PeerId`, never the peer's `PublicKey` -- and a PeerId cannot be
//! reversed into a PublicKey (it's a one-way multihash). So both pairing
//! directions carry the requester's/responder's own protobuf-encoded
//! pubkey in-band and verify `pubkey.to_peer_id() == observed_peer_id`
//! before trusting it -- the only way to bind "this authenticated
//! connection" to "this specific PublicKey". Only one pairing operation
//! (one issued code, one outstanding join) is tracked at a time --
//! simplification, matches this file's single-pending-code model.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use futures::StreamExt;
use ledger_client::LedgerClient;
use libp2p::identity::{Keypair, PeerId, PublicKey};
use libp2p::multiaddr::Protocol;
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::swarm::{NetworkBehaviour, Swarm, SwarmEvent};
use libp2p::{Multiaddr, StreamProtocol, ping};
use mesh::identity::{Identity, PairingCode, Roster};
use mesh::message::CureHint;
use mesh::revocation::RevocationList;
use mesh::transport::{build_swarm, dial, listen_on};
use mesh::verify::{self, CorroborationTracker, Decision, Stage3Regression, VerifiedHashCache};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use solana_commitment_config::CommitmentConfig;
use soldier::replay_target::ReplayTarget;
use tokio::io::{AsyncBufReadExt, BufReader};

const PROTOCOL: &str = "/tcell/pair/1";

// ---------- CLI ----------

const USAGE: &str = "usage: meshd --identity PATH --state PATH --port N [--rpc URL] --benign-trace PATH";

struct Args {
    identity: PathBuf,
    state: PathBuf,
    port: u16,
    rpc: Option<String>,
    benign_trace: PathBuf,
}

fn parse_args() -> Result<Args, String> {
    let mut identity = None;
    let mut state = None;
    let mut port = None;
    let mut rpc = None;
    let mut benign_trace = None;
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--identity" => identity = Some(PathBuf::from(value()?)),
            "--state" => state = Some(PathBuf::from(value()?)),
            "--port" => port = Some(value()?.parse::<u16>().map_err(|_| "--port needs an integer".to_string())?),
            "--rpc" => rpc = Some(value()?),
            "--benign-trace" => benign_trace = Some(PathBuf::from(value()?)),
            "-h" | "--help" => return Err(String::new()),
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    Ok(Args {
        identity: identity.ok_or("--identity is required")?,
        state: state.ok_or("--state is required")?,
        port: port.ok_or("--port is required")?,
        rpc,
        benign_trace: benign_trace.ok_or("--benign-trace is required")?,
    })
}

// ---------- Wire protocol ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
enum WireRequest {
    Pair { nonce_hex: String, pubkey: Vec<u8> },
    Hint(CureHint),
    Status { status: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum WireResponse {
    Ok { pubkey: Vec<u8> },
    Err(String),
}

#[derive(NetworkBehaviour)]
struct MeshBehaviour {
    ping: ping::Behaviour,
    rr: request_response::json::Behaviour<WireRequest, WireResponse>,
}

fn build_behaviour(_key: &Keypair) -> MeshBehaviour {
    MeshBehaviour {
        ping: ping::Behaviour::new(ping::Config::new()),
        rr: request_response::json::Behaviour::new(
            [(StreamProtocol::new(PROTOCOL), ProtocolSupport::Full)],
            request_response::Config::default(),
        ),
    }
}

// ---------- stdin commands ----------

#[derive(Debug, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
enum StdinCmd {
    PairStart,
    PairJoin { uri: String },
    Broadcast { threat_id: String, gene_hash: String },
    Status { status: String },
    Revoke { pubkey: String },
}

// ---------- persisted state ----------

#[derive(Debug, Default, Serialize, Deserialize)]
struct PersistedState {
    roster: Vec<String>,
    revoked: Vec<String>,
    peers: Vec<PersistedPeer>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedPeer {
    pubkey: String,
    addr: String,
}

// ---------- hex helpers (mirrors soldier/main.rs's own local `unhex`) ----------

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

fn unhex32(s: &str) -> Option<[u8; 32]> {
    hex_decode(s)?.try_into().ok()
}

fn pubkey_hex(key: &PublicKey) -> String {
    hex_encode(&key.encode_protobuf())
}

// ---------- Stage-3 regression adapter ----------

struct Stage3Adapter {
    benign: ReplayTarget,
}

impl Stage3Regression for Stage3Adapter {
    fn check(&self, gene_bytes: &[u8]) -> bool {
        soldier::regression::check(gene_bytes, &self.benign)
    }
}

// ---------- pairing URI ----------

fn build_pair_uri(addr: &str, peer: PeerId, nonce_hex: &str) -> String {
    format!("tcell://pair?addr={addr}&peer={peer}&nonce={nonce_hex}")
}

/// Returns `(addr, nonce_hex)`; `peer` is carried for display only -- it is
/// never used for trust (see module doc).
fn parse_pair_uri(uri: &str) -> Option<(String, String)> {
    let query = uri.split_once('?')?.1;
    let mut addr = None;
    let mut nonce = None;
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=')?;
        match k {
            "addr" => addr = Some(v.to_string()),
            "nonce" => nonce = Some(v.to_string()),
            _ => {}
        }
    }
    Some((addr?, nonce?))
}

fn addr_to_ip_port(addr: &Multiaddr) -> Option<String> {
    let mut ip = None;
    let mut port = None;
    for proto in addr.iter() {
        match proto {
            Protocol::Ip4(a) => ip = Some(a.to_string()),
            Protocol::Ip6(a) => ip = Some(a.to_string()),
            Protocol::Tcp(p) => port = Some(p),
            _ => {}
        }
    }
    Some(format!("{}:{}", ip?, port?))
}

fn is_loopback(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| matches!(p, Protocol::Ip4(a) if a.is_loopback()) || matches!(p, Protocol::Ip6(a) if a.is_loopback()))
}

// ---------- runtime state ----------

struct MeshState {
    roster: Roster,
    revocations: RevocationList,
    cache: VerifiedHashCache,
    corroboration: CorroborationTracker,
    pending_code: Option<PairingCode>,
    pending_join_nonce: Option<String>,
    pending_pair_requests: std::collections::HashSet<request_response::OutboundRequestId>,
    listen_addrs: Vec<Multiaddr>,
    peer_id_of: HashMap<PublicKey, PeerId>,
    pubkey_of: HashMap<PeerId, PublicKey>,
    addr_of: HashMap<PublicKey, String>,
    status_of: HashMap<PublicKey, String>,
    heartbeat_ms_of: HashMap<PublicKey, u64>,
    next_seq: u64,
}

impl MeshState {
    fn new() -> Self {
        Self {
            roster: Roster::new(),
            revocations: RevocationList::new(),
            cache: VerifiedHashCache::new(),
            corroboration: CorroborationTracker::new(),
            pending_code: None,
            pending_join_nonce: None,
            pending_pair_requests: Default::default(),
            listen_addrs: Vec::new(),
            peer_id_of: HashMap::new(),
            pubkey_of: HashMap::new(),
            addr_of: HashMap::new(),
            status_of: HashMap::new(),
            heartbeat_ms_of: HashMap::new(),
            next_seq: 0,
        }
    }

    fn load(path: &Path) -> Self {
        let mut state = Self::new();
        if let Ok(bytes) = std::fs::read(path)
            && let Ok(persisted) = serde_json::from_slice::<PersistedState>(&bytes)
        {
            for hex in &persisted.roster {
                if let Some(key) = hex_decode(hex).and_then(|b| PublicKey::try_decode_protobuf(&b).ok()) {
                    state.roster.add_trusted(key);
                }
            }
            for hex in &persisted.revoked {
                if let Some(key) = hex_decode(hex).and_then(|b| PublicKey::try_decode_protobuf(&b).ok()) {
                    state.revocations.revoke(key);
                }
            }
            for peer in &persisted.peers {
                if let Some(key) = hex_decode(&peer.pubkey).and_then(|b| PublicKey::try_decode_protobuf(&b).ok()) {
                    state.addr_of.insert(key, peer.addr.clone());
                }
            }
        }
        state
    }

    /// Revoked keys aren't separately tracked for round-tripping (`RevocationList`
    /// exposes no iterator by design -- see revocation.rs); persisted as empty and
    /// re-learned via `revoke` stdin commands, which are themselves persisted here.
    fn persist(&self, path: &Path) {
        let persisted = PersistedState {
            roster: self.roster.paired().iter().map(pubkey_hex).collect(),
            revoked: Vec::new(),
            peers: self.addr_of.iter().map(|(k, v)| PersistedPeer { pubkey: pubkey_hex(k), addr: v.clone() }).collect(),
        };
        if let Ok(bytes) = serde_json::to_vec_pretty(&persisted) {
            let _ = std::fs::write(path, bytes);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
            }
        }
    }
}

fn emit(record: serde_json::Value) {
    println!("{record}");
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            if !e.is_empty() {
                eprintln!("meshd: {e}");
            }
            eprintln!("{USAGE}");
            std::process::exit(2);
        }
    };

    let identity = Identity::load_or_generate(&args.identity).expect("load/generate identity");
    let mut state = MeshState::load(&args.state);
    let benign = ReplayTarget::from_traces(
        std::io::empty(),
        std::io::BufReader::new(std::fs::File::open(&args.benign_trace).expect("open benign trace")),
    )
    .expect("parse benign trace");
    let stage3 = Stage3Adapter { benign };
    let ledger = Arc::new(match &args.rpc {
        Some(url) => LedgerClient::new(url, CommitmentConfig::confirmed()),
        None => LedgerClient::devnet(CommitmentConfig::confirmed()),
    });

    let mut swarm = build_swarm(&identity, build_behaviour);
    listen_on(&mut swarm, args.port).expect("listen");

    // Redial every persisted peer address (best-effort; a peer that's
    // offline right now just fails to dial and we move on).
    for addr_str in state.addr_of.values().cloned().collect::<Vec<_>>() {
        if let Ok(addr) = addr_str.parse::<Multiaddr>() {
            let _ = swarm.dial(addr);
        }
    }

    let mut stdin_lines = BufReader::new(tokio::io::stdin()).lines();

    loop {
        tokio::select! {
            event = swarm.select_next_some() => {
                handle_swarm_event(event, &mut swarm, &mut state, &identity, &ledger, &stage3, &args.state).await;
            }
            line = stdin_lines.next_line() => {
                match line {
                    Ok(Some(line)) => handle_stdin_line(&line, &mut swarm, &mut state, &identity, &args.state),
                    Ok(None) => break, // stdin closed
                    Err(e) => eprintln!("meshd: stdin read error: {e}"),
                }
            }
        }
    }
}

async fn handle_swarm_event(
    event: SwarmEvent<MeshBehaviourEvent>,
    swarm: &mut Swarm<MeshBehaviour>,
    state: &mut MeshState,
    identity: &Identity,
    ledger: &Arc<LedgerClient>,
    stage3: &Stage3Adapter,
    state_path: &Path,
) {
    match event {
        SwarmEvent::NewListenAddr { address, .. } => {
            // Explicit stdout marker: a supervisor/test spawning this
            // process races the swarm's async bind otherwise (dial/pair_start
            // issued before any address is known) -- same reason
            // pairing_probe.rs prints "LISTENING".
            emit(json!({"type": "listening", "addr": address.to_string()}));
            state.listen_addrs.push(address);
        }
        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
            if let Some(nonce_hex) = state.pending_join_nonce.take() {
                let request = WireRequest::Pair { nonce_hex, pubkey: identity.public().encode_protobuf() };
                let request_id = swarm.behaviour_mut().rr.send_request(&peer_id, request);
                state.pending_pair_requests.insert(request_id);
            }
        }
        SwarmEvent::Behaviour(MeshBehaviourEvent::Ping(ping::Event { peer, result: Ok(rtt), .. })) => {
            if let Some(key) = state.pubkey_of.get(&peer).cloned() {
                state.heartbeat_ms_of.insert(key.clone(), rtt.as_millis() as u64);
                emit_peer_record(state, &key);
            }
        }
        SwarmEvent::Behaviour(MeshBehaviourEvent::Rr(request_response::Event::Message { peer, message })) => match message {
            request_response::Message::Request { request, channel, .. } => {
                let response = handle_wire_request(peer, request, state, identity, ledger, stage3).await;
                let _ = swarm.behaviour_mut().rr.send_response(channel, response);
            }
            request_response::Message::Response { request_id, response } => {
                if state.pending_pair_requests.remove(&request_id) {
                    handle_pair_response(peer, response, state, state_path);
                }
                // Hint/Status responses need no further action beyond the
                // request already having been sent -- fire-and-forget.
            }
        },
        _ => {}
    }
}

async fn handle_wire_request(
    peer: PeerId,
    request: WireRequest,
    state: &mut MeshState,
    identity: &Identity,
    ledger: &Arc<LedgerClient>,
    stage3: &Stage3Adapter,
) -> WireResponse {
    match request {
        WireRequest::Pair { nonce_hex, pubkey } => handle_inbound_pair(peer, &nonce_hex, &pubkey, state, identity),
        WireRequest::Hint(hint) => {
            handle_inbound_hint(hint, state, ledger, stage3).await;
            WireResponse::Ok { pubkey: identity.public().encode_protobuf() }
        }
        WireRequest::Status { status } => {
            if let Some(key) = state.pubkey_of.get(&peer).cloned() {
                state.status_of.insert(key.clone(), status);
                emit_peer_record(state, &key);
            }
            WireResponse::Ok { pubkey: identity.public().encode_protobuf() }
        }
    }
}

fn handle_inbound_pair(peer: PeerId, nonce_hex: &str, presenter_pubkey_bytes: &[u8], state: &mut MeshState, identity: &Identity) -> WireResponse {
    let Some(presenter) = PublicKey::try_decode_protobuf(presenter_pubkey_bytes).ok().filter(|k| k.to_peer_id() == peer) else {
        emit(json!({"type": "pair_error", "error": "pubkey mismatch"}));
        return WireResponse::Err("pubkey mismatch".into());
    };
    let Some(nonce) = hex_decode(nonce_hex).and_then(|b| <[u8; 16]>::try_from(b).ok()) else {
        emit(json!({"type": "pair_error", "error": "malformed nonce"}));
        return WireResponse::Err("malformed nonce".into());
    };
    let Some(code) = state.pending_code.take() else {
        emit(json!({"type": "pair_error", "error": "no pairing code outstanding"}));
        return WireResponse::Err("no pairing code outstanding".into());
    };
    match state.roster.admit(&code, &nonce, presenter.clone()) {
        Ok(()) => {
            record_paired_peer(state, peer, presenter.clone());
            emit(json!({"type": "paired", "pubkey": pubkey_hex(&presenter), "addr": peer.to_string()}));
            WireResponse::Ok { pubkey: identity.public().encode_protobuf() }
        }
        Err(e) => {
            state.pending_code = Some(code); // not spent, put it back
            emit(json!({"type": "pair_error", "error": format!("{e:?}")}));
            WireResponse::Err(format!("{e:?}"))
        }
    }
}

fn handle_pair_response(peer: PeerId, response: WireResponse, state: &mut MeshState, state_path: &Path) {
    match response {
        WireResponse::Ok { pubkey } => {
            let Some(issuer) = PublicKey::try_decode_protobuf(&pubkey).ok().filter(|k| k.to_peer_id() == peer) else {
                emit(json!({"type": "pair_error", "error": "issuer pubkey mismatch"}));
                return;
            };
            state.roster.add_trusted(issuer.clone());
            record_paired_peer(state, peer, issuer.clone());
            state.persist(state_path);
            emit(json!({"type": "paired", "pubkey": pubkey_hex(&issuer), "addr": peer.to_string()}));
        }
        WireResponse::Err(reason) => {
            emit(json!({"type": "pair_error", "error": reason}));
        }
    }
}

fn record_paired_peer(state: &mut MeshState, peer: PeerId, key: PublicKey) {
    state.peer_id_of.insert(key.clone(), peer);
    state.pubkey_of.insert(peer, key.clone());
    state.addr_of.insert(key, peer.to_string());
}

async fn handle_inbound_hint(hint: CureHint, state: &mut MeshState, ledger: &Arc<LedgerClient>, stage3: &Stage3Adapter) {
    let from = hint.sender_public_key().map(|k| pubkey_hex(&k)).unwrap_or_default();
    let threat_id_hex = hex_encode(&hint.threat_id);
    let gene_hash_hex = hex_encode(&hint.gene_hash);

    // Fail closed (unlike Soldier's own fail-open): a mesh peer's claim
    // alone is not yet corroborated, so an unreadable/absent registry is a
    // reject, not a locally-evolved fallback.
    let genome = match ledger.fetch_genome_registry(hint.threat_id) {
        Ok(Some(g)) => g,
        Ok(None) | Err(_) => {
            emit(json!({"type": "hint", "from": from, "threat_id": threat_id_hex, "gene_hash": gene_hash_hex, "decision": "RejectUnknownGenome"}));
            return;
        }
    };
    if Sha256::digest(&genome.gene_seq)[..] != hint.gene_hash {
        emit(json!({"type": "hint", "from": from, "threat_id": threat_id_hex, "gene_hash": gene_hash_hex, "decision": "RejectHashMismatch"}));
        return;
    }

    let mut decision = verify::evaluate(
        &hint,
        &state.roster,
        &state.revocations,
        &mut state.corroboration,
        &state.cache,
        &genome.gene_seq,
        stage3,
        genome.epigenetic_status,
    );

    if decision == Decision::RejectNoQuorum {
        match verify::confirm_via_chain(Arc::clone(ledger), hint.threat_id, hint.gene_hash).await {
            Ok(true) => {
                state.cache.mark_verified(hint.gene_hash);
                decision = verify::evaluate(
                    &hint,
                    &state.roster,
                    &state.revocations,
                    &mut state.corroboration,
                    &state.cache,
                    &genome.gene_seq,
                    stage3,
                    genome.epigenetic_status,
                );
            }
            Ok(false) => state.cache.rollback(hint.gene_hash),
            Err(_) => {}
        }
    }

    if decision == Decision::Accept {
        let _ = soldier::gene_compile::apply(&genome.gene_seq);
    }
    emit(json!({"type": "hint", "from": from, "threat_id": threat_id_hex, "gene_hash": gene_hash_hex, "decision": format!("{decision:?}")}));
}

fn emit_peer_record(state: &MeshState, key: &PublicKey) {
    let hex = pubkey_hex(key);
    emit(json!({
        "type": "peer",
        "pubkey": hex,
        "name": format!("device-{}", &hex[..8.min(hex.len())]),
        "addr": state.addr_of.get(key).cloned().unwrap_or_default(),
        "status": state.status_of.get(key).cloned().unwrap_or_else(|| "clean".to_string()),
        "heartbeat_ms": state.heartbeat_ms_of.get(key).copied().unwrap_or(0),
    }));
}

fn handle_stdin_line(line: &str, swarm: &mut Swarm<MeshBehaviour>, state: &mut MeshState, identity: &Identity, state_path: &Path) {
    let cmd: StdinCmd = match serde_json::from_str(line) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("meshd: malformed stdin command: {e}");
            return;
        }
    };
    match cmd {
        StdinCmd::PairStart => cmd_pair_start(swarm, state, identity),
        StdinCmd::PairJoin { uri } => cmd_pair_join(&uri, swarm, state),
        StdinCmd::Broadcast { threat_id, gene_hash } => cmd_broadcast(&threat_id, &gene_hash, swarm, state, identity),
        StdinCmd::Status { status } => cmd_status(&status, swarm, state),
        StdinCmd::Revoke { pubkey } => cmd_revoke(&pubkey, swarm, state, state_path),
    }
}

fn cmd_pair_start(swarm: &mut Swarm<MeshBehaviour>, state: &mut MeshState, identity: &Identity) {
    let code = PairingCode::generate(identity);
    let nonce_hex = hex_encode(&code.nonce());
    let addr = state
        .listen_addrs
        .iter()
        .find(|a| !is_loopback(a))
        .or_else(|| state.listen_addrs.first())
        .and_then(addr_to_ip_port)
        .unwrap_or_else(|| "127.0.0.1:0".to_string());
    let uri = build_pair_uri(&addr, *swarm.local_peer_id(), &nonce_hex);
    emit(json!({"type": "pair_code", "uri": uri, "expires_ms": 300_000}));
    state.pending_code = Some(code);
}

fn cmd_pair_join(uri: &str, swarm: &mut Swarm<MeshBehaviour>, state: &mut MeshState) {
    let Some((addr, nonce_hex)) = parse_pair_uri(uri) else {
        emit(json!({"type": "pair_error", "error": "malformed uri"}));
        return;
    };
    let Some((ip_str, port_str)) = addr.rsplit_once(':') else {
        emit(json!({"type": "pair_error", "error": "malformed addr"}));
        return;
    };
    let (Ok(ip), Ok(port)) = (ip_str.parse(), port_str.parse()) else {
        emit(json!({"type": "pair_error", "error": "malformed addr"}));
        return;
    };
    if dial(swarm, ip, port).is_err() {
        emit(json!({"type": "pair_error", "error": "dial failed"}));
        return;
    }
    state.pending_join_nonce = Some(nonce_hex);
}

fn cmd_broadcast(threat_id_hex: &str, gene_hash_hex: &str, swarm: &mut Swarm<MeshBehaviour>, state: &mut MeshState, identity: &Identity) {
    let (Some(threat_id), Some(gene_hash)) = (unhex32(threat_id_hex), unhex32(gene_hash_hex)) else {
        eprintln!("meshd: broadcast: malformed threat_id/gene_hash hex");
        return;
    };
    let hint = CureHint::sign(identity, threat_id, gene_hash, state.next_seq);
    state.next_seq += 1;
    for peer in state.peer_id_of.values().copied().collect::<Vec<_>>() {
        swarm.behaviour_mut().rr.send_request(&peer, WireRequest::Hint(hint.clone()));
    }
}

fn cmd_status(status: &str, swarm: &mut Swarm<MeshBehaviour>, state: &mut MeshState) {
    for peer in state.peer_id_of.values().copied().collect::<Vec<_>>() {
        swarm.behaviour_mut().rr.send_request(&peer, WireRequest::Status { status: status.to_string() });
    }
}

fn cmd_revoke(pubkey_hex_str: &str, swarm: &mut Swarm<MeshBehaviour>, state: &mut MeshState, state_path: &Path) {
    let Some(key) = hex_decode(pubkey_hex_str).and_then(|b| PublicKey::try_decode_protobuf(&b).ok()) else {
        eprintln!("meshd: revoke: malformed pubkey hex");
        return;
    };
    state.revocations.revoke(key.clone());
    if let Some(peer) = state.peer_id_of.get(&key).copied() {
        let _ = swarm.disconnect_peer_id(peer);
    }
    state.persist(state_path);
    emit(json!({"type": "revoked", "pubkey": pubkey_hex(&key)}));
}

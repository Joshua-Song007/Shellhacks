//! FR-M-3/4: libp2p transport -- TCP + Noise (forward secrecy via
//! ephemeral per-connection Noise session keys) + Yamux multiplexing. No
//! mDNS dependency; manual IP dialing is the reliable pairing path
//! (validated by SPIKE-2, plan.md Phase 0). This file owns ONLY "how two
//! peers connect securely" -- not "what they say" (that's message.rs, a
//! later checklist item, not part of this stage), so it's generic over
//! the NetworkBehaviour.

use std::io;
use std::net::IpAddr;
use std::time::Duration;

use libp2p::identity::Keypair;
use libp2p::swarm::{DialError, NetworkBehaviour, Swarm};
use libp2p::{noise, tcp, yamux, Multiaddr, SwarmBuilder, TransportError};

use crate::identity::Identity;

/// Connection idle timeout. Mesh pairing connections are meant to stay
/// open for a real device-pairing session, not close the moment they go
/// briefly quiet -- matches SPIKE-2's own config (plan.md Phase 0).
const IDLE_CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);

/// Builds a Swarm using `identity`'s persistent keypair (not a fresh
/// ephemeral one) so PeerId is stable across restarts and matches what
/// message.rs will sign with (FR-M-2). `behaviour` is handed the same
/// keypair in case the application protocol needs it (e.g. to sign).
pub fn build_swarm<B: NetworkBehaviour>(identity: &Identity, behaviour: impl FnOnce(&Keypair) -> B) -> Swarm<B> {
    SwarmBuilder::with_existing_identity(identity.keypair().clone())
        .with_tokio()
        .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)
        .expect("tcp+noise+yamux transport")
        .with_behaviour(|key| behaviour(key))
        .expect("behaviour construction")
        .with_swarm_config(|c| c.with_idle_connection_timeout(IDLE_CONNECTION_TIMEOUT))
        .build()
}

/// FR-M-4: binds a TCP listener on all interfaces at `port`. No mDNS.
pub fn listen_on<B: NetworkBehaviour>(swarm: &mut Swarm<B>, port: u16) -> Result<(), TransportError<io::Error>> {
    let addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{port}").parse().expect("valid multiaddr");
    swarm.listen_on(addr).map(|_| ())
}

/// FR-M-4: manual pairing by IP -- the reliable path (a controlled hotspot
/// is the demo network; mDNS discovery is never used, per FR-M-4).
pub fn dial<B: NetworkBehaviour>(swarm: &mut Swarm<B>, ip: IpAddr, port: u16) -> Result<(), DialError> {
    let proto = match ip {
        IpAddr::V4(_) => "ip4",
        IpAddr::V6(_) => "ip6",
    };
    let addr: Multiaddr = format!("/{proto}/{ip}/tcp/{port}").parse().expect("valid multiaddr");
    swarm.dial(addr)
}

// The pairing regression test lives in tests/pairing.rs, not here: it
// spawns src/bin/pairing_probe.rs as two real subprocesses (see that
// file's doc comment for why), and `CARGO_BIN_EXE_*` is only available to
// integration tests under tests/, not a lib's own #[cfg(test)] modules.

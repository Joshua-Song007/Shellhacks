//! Real bin target (not an example) so `CARGO_BIN_EXE_pairing_probe` is
//! available to transport.rs's test, per Cargo's documented mechanism.
//! Two roles, one per invocation, meant to be run as two SEPARATE
//! processes -- confirmed during Phase 6's apply that running two swarms
//! in-process hits a libp2p quirk during multistream-select negotiation
//! that does not occur across real processes (how mesh is actually used,
//! one process per device). This mirrors SPIKE-2's own two-process shape.
//!
//! Usage: pairing_probe listen <port> <identity-path> | dial <port> <identity-path>

use futures::StreamExt;
use libp2p::{ping, swarm::SwarmEvent};
use mesh::identity::Identity;
use mesh::transport::{build_swarm, dial, listen_on};

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let role = args.get(1).map(String::as_str);
    let port: u16 = args.get(2).expect("usage: listen|dial <port> <identity-path>").parse().expect("port");
    let identity_path = args.get(3).expect("usage: listen|dial <port> <identity-path>");

    let identity = Identity::load_or_generate(std::path::Path::new(identity_path)).expect("identity");
    println!("peer_id={}", identity.peer_id());
    let mut swarm = build_swarm(&identity, |_| ping::Behaviour::new(ping::Config::new()));

    match role {
        Some("listen") => listen_on(&mut swarm, port).expect("listen"),
        Some("dial") => dial(&mut swarm, "127.0.0.1".parse().unwrap(), port).expect("dial"),
        _ => panic!("usage: listen|dial <port> <identity-path>"),
    }

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { .. } => println!("LISTENING"),
            SwarmEvent::ConnectionEstablished { peer_id, .. } => println!("paired_with={peer_id}"),
            SwarmEvent::Behaviour(ping::Event { result: Ok(_), .. }) => {
                println!("PASS");
                return;
            }
            _ => {}
        }
    }
}

//! SPIKE-2 (§12): confirms two peers can pair via libp2p over manual IP
//! (FR-M-4's reliable path) using a Noise-encrypted transport (FR-M-3), no
//! mDNS (FR-M-4). No second physical device/hotspot is available in this
//! dev environment, so "two devices" is simulated as two OS processes on
//! loopback at different ports/PeerIds -- this still genuinely exercises
//! Noise handshake + manual-IP dialing, just not the venue-network part.
//!
//! Usage:
//!   spike2_libp2p_pair listen <port>
//!   spike2_libp2p_pair dial <ip> <port>

use std::time::Duration;

use futures::StreamExt;
use libp2p::{noise, ping, swarm::SwarmEvent, tcp, yamux, Multiaddr, SwarmBuilder};

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)
        .expect("tcp+noise+yamux transport")
        .with_behaviour(|_key| ping::Behaviour::new(ping::Config::new()))
        .expect("ping behaviour")
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(30)))
        .build();

    println!("spike2: local peer id = {}", swarm.local_peer_id());

    match args.get(1).map(String::as_str) {
        Some("listen") => {
            let port: u16 = args.get(2).map(|s| s.parse().expect("port")).unwrap_or(4001);
            let addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{port}").parse().unwrap();
            swarm.listen_on(addr).expect("listen");
            loop {
                match swarm.select_next_some().await {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        println!("spike2: listening on {address}");
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        println!("spike2: PAIRED (noise-authenticated connection) with {peer_id}");
                    }
                    SwarmEvent::Behaviour(ping::Event { peer, result: Ok(rtt), .. }) => {
                        println!("spike2: ping ok from {peer}, rtt={rtt:?}");
                        println!("spike2: PASS");
                        return;
                    }
                    other => println!("spike2: event {other:?}"),
                }
            }
        }
        Some("dial") => {
            let ip = args.get(2).expect("usage: dial <ip> <port>");
            let port = args.get(3).expect("usage: dial <ip> <port>");
            let addr: Multiaddr = format!("/ip4/{ip}/tcp/{port}").parse().unwrap();
            println!("spike2: dialing {addr} (manual IP, no mDNS)");
            swarm.dial(addr).expect("dial");
            loop {
                match swarm.select_next_some().await {
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        println!("spike2: PAIRED (noise-authenticated connection) with {peer_id}");
                    }
                    SwarmEvent::Behaviour(ping::Event { peer, result: Ok(rtt), .. }) => {
                        println!("spike2: ping ok to {peer}, rtt={rtt:?}");
                        println!("spike2: PASS");
                        return;
                    }
                    SwarmEvent::OutgoingConnectionError { error, .. } => {
                        println!("spike2: FAIL, dial error: {error}");
                        return;
                    }
                    other => println!("spike2: event {other:?}"),
                }
            }
        }
        _ => eprintln!("usage: spike2_libp2p_pair listen <port> | dial <ip> <port>"),
    }
}

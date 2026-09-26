//! Promotes SPIKE-2's exact pairing scenario (plan.md Phase 0) into a
//! permanent regression test, tied to real `Identity`s this time rather
//! than a fresh ephemeral one per run -- proves identity.rs and
//! transport.rs compose correctly, not just individually. Spawns two real
//! OS processes (src/bin/pairing_probe.rs), not two swarms in one
//! process: confirmed during Phase 6's apply that two swarms sharing a
//! process hit a libp2p multistream-select quirk on the accepting side
//! that a real two-process run (matching actual mesh deployment, one
//! process per device) does not.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

#[test]
fn two_real_identities_pair_over_manual_ip_with_noise() {
    let probe = env!("CARGO_BIN_EXE_pairing_probe");
    let dir = tempfile::tempdir().unwrap();
    let listener_key = dir.path().join("listener.key");
    let dialer_key = dir.path().join("dialer.key");
    let port = pick_free_port();

    let mut listener = Command::new(probe)
        .args(["listen", &port.to_string(), listener_key.to_str().unwrap()])
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn listener");
    let mut listener_lines = BufReader::new(listener.stdout.take().unwrap()).lines();
    let mut listener_out: Vec<String> = Vec::new();
    loop {
        let line = listener_lines.next().expect("listener stdout closed before LISTENING").expect("read listener stdout");
        let is_listening = line == "LISTENING";
        listener_out.push(line);
        if is_listening {
            break; // dial only once the listener has actually bound
        }
    }

    let mut dialer = Command::new(probe)
        .args(["dial", &port.to_string(), dialer_key.to_str().unwrap()])
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn dialer");

    let dialer_out = read_lines_until_pass(dialer.stdout.take().unwrap());
    listener_out.extend(read_remaining_lines_until_pass(listener_lines));

    dialer.wait().expect("dialer exits");
    listener.wait().expect("listener exits");

    assert!(dialer_out.iter().any(|l| l == "PASS"), "dialer never reported PASS: {dialer_out:?}");
    assert!(listener_out.iter().any(|l| l == "PASS"), "listener never reported PASS: {listener_out:?}");

    let dialer_peer_id = dialer_out.iter().find_map(|l| l.strip_prefix("peer_id=")).unwrap();
    let listener_peer_id = listener_out.iter().find_map(|l| l.strip_prefix("peer_id=")).unwrap();
    let dialer_saw = dialer_out.iter().find_map(|l| l.strip_prefix("paired_with=")).unwrap();
    let listener_saw = listener_out.iter().find_map(|l| l.strip_prefix("paired_with=")).unwrap();

    assert_eq!(dialer_saw, listener_peer_id, "dialer must see the listener's persisted identity");
    assert_eq!(listener_saw, dialer_peer_id, "listener must see the dialer's persisted identity");
}

fn pick_free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn read_lines_until_pass(stdout: std::process::ChildStdout) -> Vec<String> {
    read_remaining_lines_until_pass(BufReader::new(stdout).lines())
}

fn read_remaining_lines_until_pass(lines: std::io::Lines<BufReader<std::process::ChildStdout>>) -> Vec<String> {
    let mut out = Vec::new();
    for line in lines {
        let line = line.expect("read probe stdout");
        let done = line == "PASS";
        out.push(line);
        if done {
            break;
        }
    }
    out
}

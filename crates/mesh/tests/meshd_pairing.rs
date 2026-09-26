//! Promotes the pairing half of Phase 9 item 6 into a permanent regression
//! test, mirroring tests/pairing.rs's exact two-subprocess pattern (real OS
//! processes, not two swarms in one process -- same libp2p same-process
//! quirk applies here too). Exercises the real `pair_start`/`pair_join`
//! stdin/stdout JSON protocol, not a shortcut.
//!
//! The `broadcast -> hint accepted` path is NOT covered here: it needs a
//! real devnet-committed gene (a live Soldier run) to reach `Accept` for
//! real -- noted as a manual/end-to-end check once more of Phase 9 exists,
//! same precedent as this project's other "needs a live stack" gaps.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

#[test]
fn two_meshd_instances_pair_over_a_real_pair_code_uri() {
    let meshd = env!("CARGO_BIN_EXE_meshd");
    let dir = tempfile::tempdir().unwrap();
    let benign_trace = concat!(env!("CARGO_MANIFEST_DIR"), "/../soldier/traces/benign_apps.ndjson");

    let mut a = spawn_meshd(meshd, &dir, "a", benign_trace);
    let mut b = spawn_meshd(meshd, &dir, "b", benign_trace);

    let mut a_out = BufReader::new(a.stdout.take().unwrap()).lines();
    let mut b_out = BufReader::new(b.stdout.take().unwrap()).lines();

    wait_for(&mut a_out, "listening");
    wait_for(&mut b_out, "listening");

    let mut a_in = a.stdin.take().unwrap();
    let mut b_in = b.stdin.take().unwrap();

    writeln!(a_in, r#"{{"cmd":"pair_start"}}"#).unwrap();
    let pair_code = wait_for(&mut a_out, "pair_code");
    let uri = pair_code["uri"].as_str().expect("pair_code carries a uri").to_string();

    writeln!(b_in, r#"{{"cmd":"pair_join","uri":"{uri}"}}"#).unwrap();

    let a_paired = wait_for(&mut a_out, "paired");
    let b_paired = wait_for(&mut b_out, "paired");

    assert!(a_paired["pubkey"].is_string(), "A's paired record carries B's pubkey: {a_paired}");
    assert!(b_paired["pubkey"].is_string(), "B's paired record carries A's pubkey: {b_paired}");
    assert_ne!(a_paired["pubkey"], b_paired["pubkey"], "each side records the OTHER device's key, not its own");

    drop(a_in);
    drop(b_in);
    let _ = a.wait();
    let _ = b.wait();
}

fn spawn_meshd(meshd: &str, dir: &tempfile::TempDir, name: &str, benign_trace: &str) -> std::process::Child {
    let identity = dir.path().join(format!("{name}.key"));
    let state = dir.path().join(format!("{name}.json"));
    let port = pick_free_port();
    Command::new(meshd)
        .args([
            "--identity",
            identity.to_str().unwrap(),
            "--state",
            state.to_str().unwrap(),
            "--port",
            &port.to_string(),
            "--benign-trace",
            benign_trace,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn meshd")
}

fn pick_free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// Reads lines until one parses as JSON with `"type": type_name`, returning
/// that record. Ignores any other JSON lines in between (e.g. multiple
/// `listening` records for loopback + a real interface, per SPIKE-2's own
/// finding that a listener observes more than one address).
fn wait_for(lines: &mut std::io::Lines<BufReader<std::process::ChildStdout>>, type_name: &str) -> serde_json::Value {
    loop {
        let line = lines.next().expect("stdout closed before the expected record").expect("read stdout");
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) else { continue };
        if value["type"] == type_name {
            return value;
        }
    }
}

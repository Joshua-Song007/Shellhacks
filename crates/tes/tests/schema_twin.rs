//! The JSON Schema twin and the Rust boundary must agree on every fixture.

use serde_json::Value;
use tes::Validator;

const SCHEMA: &str = include_str!("../schema/tes_v1.schema.json");

fn line(proc_extra: &str, event: &str) -> String {
    format!(
        r#"{{"v":1,"seq":1,"ts_ns":1700000000000000000,"recv_ns":1700000000000500000,"proc":{{"pid":501,"pidver":3,"ppid":1,"exe":"/usr/bin/true","platform":true{proc_extra}}},"event":{event}}}"#
    )
}

const EXIT: &str = r#"{"kind":"exit","data":{"status":0}}"#;

fn fixtures() -> Vec<(&'static str, String, bool)> {
    vec![
        ("exec", line("", r#"{"kind":"exec","data":{"target":"/tmp/a","args":["/tmp/a"],"new_pidver":4}}"#), true),
        ("exec without new_pidver", line("", r#"{"kind":"exec","data":{"target":"/tmp/a","args":["/tmp/a"]}}"#), false),
        ("fork", line("", r#"{"kind":"fork","data":{"child_pid":502,"child_pidver":1}}"#), true),
        ("exit", line("", EXIT), true),
        ("open", line("", r#"{"kind":"open","data":{"path":"/a","write":false}}"#), true),
        ("create", line("", r#"{"kind":"create","data":{"path":"/a"}}"#), true),
        ("rename", line("", r#"{"kind":"rename","data":{"from":"/a","to":"/b"}}"#), true),
        ("unlink", line("", r#"{"kind":"unlink","data":{"path":"/a"}}"#), true),
        ("signing ids", line(r#","signing_id":"com.apple.true","team_id":"ABCDE12345""#, EXIT), true),
        ("null signing id", line(r#","signing_id":null"#, EXIT), true),
        ("negative exit status", line("", r#"{"kind":"exit","data":{"status":-9}}"#), true),
        ("unknown top-level", line("", EXIT).replacen('{', r#"{"x":1,"#, 1), false),
        ("unknown proc field", line(r#","x":1"#, EXIT), false),
        ("unknown data field", line("", r#"{"kind":"exit","data":{"status":0,"x":1}}"#), false),
        ("unknown event field", line("", r#"{"kind":"exit","data":{"status":0},"x":1}"#), false),
        ("unknown kind", line("", r#"{"kind":"mmap","data":{}}"#), false),
        ("wrong version", line("", EXIT).replacen(r#""v":1"#, r#""v":2"#, 1), false),
        ("zero pid", line("", EXIT).replacen(r#""pid":501"#, r#""pid":0"#, 1), false),
        ("negative pid", line("", EXIT).replacen(r#""pid":501"#, r#""pid":-1"#, 1), false),
        ("relative exe", line("", EXIT).replacen("/usr/bin/true", "true", 1), false),
        ("relative rename target", line("", r#"{"kind":"rename","data":{"from":"/a","to":"b"}}"#), false),
        ("missing field", line("", EXIT).replacen(r#""ppid":1,"#, "", 1), false),
        ("string seq", line("", EXIT).replacen(r#""seq":1"#, r#""seq":"1""#, 1), false),
        ("kind/data mismatch", line("", r#"{"kind":"exit","data":{"path":"/a"}}"#), false),
    ]
}

#[test]
fn json_schema_twin_agrees_with_rust_boundary() {
    let schema: Value = serde_json::from_str(SCHEMA).unwrap();
    let json_validator = jsonschema::validator_for(&schema).unwrap();

    for (name, l, expected) in fixtures() {
        let rust_ok = Validator::new().check_line(&l).is_ok();
        let instance: Value = serde_json::from_str(&l).unwrap();
        let schema_ok = json_validator.is_valid(&instance);
        assert_eq!(rust_ok, expected, "rust boundary verdict on `{name}`: {l}");
        assert_eq!(schema_ok, expected, "json schema verdict on `{name}`: {l}");
    }
}

//! FR-M-5's Stage-3 regression: does a finished gene's allele sequence
//! collide with a lineage's whitelisted-app behavior? Decodes the
//! `allele_bitmask` global `gene_compile::compile` exports back into a
//! `Vec<Allele>` (bit `i` set iff `ALL[i]` is present -- the inverse of
//! `gene_compile`'s own private `bitmask()`, same documented convention) and
//! reuses each allele's own `neutralizes()` mapping, so this never drifts
//! from `allele_search`'s physics. A gene that instantiates cleanly with no
//! collision passes; a malformed or import-declaring gene fails closed.

use crate::allele_search::{ALL, Allele, ContainmentTarget};
use crate::replay_target::ReplayTarget;
use crate::sandbox::Sandbox;

pub fn check(gene: &[u8], benign: &ReplayTarget) -> bool {
    let Ok((store, instance)) = Sandbox::new().instantiate(gene) else { return false };
    let Some(global) = instance.get_global(&store, "allele_bitmask") else { return false };
    let Some(mask) = global.get(&store).i32() else { return false };
    let sequence: Vec<Allele> = ALL.iter().enumerate().filter(|(i, _)| mask & (1 << i) != 0).map(|(_, a)| *a).collect();
    !sequence.iter().any(|a| a.neutralizes().iter().any(|act| benign.benign_actions().contains(act)))
}

#[cfg(test)]
mod tests {
    use std::io::{self, Cursor};

    use tes::schema::{Event, ExecData, Proc, TesEvent};

    use super::*;
    use crate::gene_compile;

    fn exec_line(target: &str) -> String {
        let ev = TesEvent {
            v: 1,
            seq: 1,
            ts_ns: 1,
            recv_ns: 1,
            proc: Proc { pid: 1, pidver: 1, ppid: 1, exe: "/tmp/p".into(), signing_id: None, team_id: None, platform: false },
            event: Event::Exec(ExecData { target: target.into(), args: vec![target.into()], new_pidver: 2 }),
        };
        ev.to_line()
    }

    /// A benign target whose only whitelisted behavior is an
    /// `ExecFromTempOrCache`-shaped exec (a legitimate helper launched from
    /// a temp dir), so `benign_actions() == [ExecFromTempOrCache]`.
    fn benign_target() -> ReplayTarget {
        let benign_line = exec_line("/tmp/legit-helper");
        ReplayTarget::from_traces(io::empty(), Cursor::new(benign_line.into_bytes())).unwrap()
    }

    #[test]
    fn a_clean_allele_passes() {
        // RevertTouchedFiles neutralizes RecoverySnapshotTamper/RapidFileModBurst,
        // neither of which the benign target exhibits.
        let gene = gene_compile::compile(&[Allele::RevertTouchedFiles]);
        assert!(check(&gene, &benign_target()));
    }

    #[test]
    fn a_colliding_allele_fails() {
        // QuarantineDroppedFiles neutralizes ExecFromTempOrCache, which the
        // benign target's own legit-helper exec also triggers.
        let gene = gene_compile::compile(&[Allele::QuarantineDroppedFiles]);
        assert!(!check(&gene, &benign_target()));
    }

    #[test]
    fn malformed_wasm_fails_closed() {
        assert!(!check(b"not wasm", &benign_target()));
    }

    #[test]
    fn the_empty_sequence_never_collides() {
        let gene = gene_compile::compile(&[]);
        assert!(check(&gene, &benign_target()));
    }
}

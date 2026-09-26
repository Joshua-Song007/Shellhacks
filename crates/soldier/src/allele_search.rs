//! FR-R-3: combinatorial allele search. Scores every candidate allele
//! sequence on containment success AND target-host stability, and returns
//! the sequence with the best net fitness -- not the first sequence that
//! happens to fully contain the threat. Full containment is one point in
//! the search space, not a gate: a cheaper partial-containment sequence
//! can out-fit a costlier full-containment one, and the single most
//! aggressive allele can lose to a smarter combination (see the worked
//! example in the tests below). Without that gradient there is nothing
//! for a "search" to trade off -- it degenerates into enumerate-until-you
//! -hit-100%.
//!
//! The allele -> neutralized-action mapping and every cost number below is
//! invented for this task: overview.md does not specify allele physics,
//! and FR-R-6 (real containment alleles) is MAY-tier and unimplemented, so
//! there is no real data yet to derive costs from. What's modeled is the
//! shape FR-R-4/FR-R-6 call for -- a synthetic-physics baseline where a
//! more aggressive allele stops more behavior but costs more host
//! stability -- not a claim that these specific numbers are measured.

use scout::scoring::Action;

/// FR-R-6's containment primitives, used symbolically here (FR-R-6 itself
/// stays unimplemented/MAY). Declared least- to most-aggressive; `ALL`
/// mirrors that order so subset enumeration is deterministic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Allele {
    QuarantineDroppedFiles,
    BlockSockets,
    SigStop,
    RevertTouchedFiles,
    KillChildTree,
}

pub const ALL: [Allele; 5] = [
    Allele::QuarantineDroppedFiles,
    Allele::BlockSockets,
    Allele::SigStop,
    Allele::RevertTouchedFiles,
    Allele::KillChildTree,
];

/// Flat penalty added per allele in a sequence whose neutralized set
/// overlaps the target's whitelisted behavior (collateral damage).
const BENIGN_COLLISION_PENALTY: u32 = 50;

impl Allele {
    /// Stage-1 actions (scout::scoring::Action) this allele stops if
    /// applied alone. Invented synthetic physics -- see module doc.
    pub fn neutralizes(self) -> &'static [Action] {
        use Action::{ExecFromTempOrCache, RapidFileModBurst, RecoverySnapshotTamper};
        match self {
            Allele::QuarantineDroppedFiles => &[ExecFromTempOrCache],
            Allele::BlockSockets => &[],
            Allele::SigStop => &[ExecFromTempOrCache, RapidFileModBurst],
            Allele::RevertTouchedFiles => &[RecoverySnapshotTamper, RapidFileModBurst],
            Allele::KillChildTree => &[ExecFromTempOrCache, RecoverySnapshotTamper, RapidFileModBurst],
        }
    }

    /// Host-stability cost of applying this allele alone. Invented;
    /// strictly increasing with aggressiveness (surgical -> nuclear), so a
    /// more thorough allele always costs more, never less, than a gentler
    /// one covering a subset of the same ground.
    pub const fn cost(self) -> u32 {
        match self {
            Allele::QuarantineDroppedFiles => 5,
            Allele::BlockSockets => 15,
            Allele::SigStop => 25,
            Allele::RevertTouchedFiles => 45,
            Allele::KillChildTree => 150,
        }
    }
}

/// What the search evaluates a candidate sequence against. Implemented by
/// replay_target.rs (FR-R-4): a replayed TES trace exposing which Stage-1
/// actions occurred, plus whichever whitelisted-app actions must survive.
pub trait ContainmentTarget {
    /// Actions the replayed trace contains; a fully-neutralizing gene
    /// stops all of these.
    fn threat_actions(&self) -> &[Action];
    /// Actions the host's whitelisted behavior legitimately produces; an
    /// allele that neutralizes one of these causes collateral damage.
    fn benign_actions(&self) -> &[Action];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Evaluation {
    /// Sum of `Action::weight()` over `threat_actions` the sequence covers.
    pub containment_value: u32,
    /// Sum of allele costs plus collision penalties.
    pub stability_cost: u32,
    /// `containment_value - stability_cost`; what the search maximizes.
    pub fitness: i64,
}

/// Scores one candidate sequence against `target`. Public so tests (and
/// any future caller comparing specific candidates) don't have to go
/// through `search`'s global optimum to see how a sequence scores.
pub fn evaluate(sequence: &[Allele], target: &dyn ContainmentTarget) -> Evaluation {
    let neutralized: Vec<Action> = sequence.iter().flat_map(|a| a.neutralizes().iter().copied()).collect();
    let containment_value: u32 =
        target.threat_actions().iter().filter(|a| neutralized.contains(a)).copied().map(Action::weight).sum();
    let base_cost: u32 = sequence.iter().map(|a| a.cost()).sum();
    let colliding_alleles = sequence.iter().filter(|a| a.neutralizes().iter().any(|n| target.benign_actions().contains(n))).count();
    let collision_penalty: u32 = u32::try_from(colliding_alleles).unwrap_or(u32::MAX) * BENIGN_COLLISION_PENALTY;
    let stability_cost = base_cost + collision_penalty;
    Evaluation { containment_value, stability_cost, fitness: i64::from(containment_value) - i64::from(stability_cost) }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchResult {
    pub sequence: Vec<Allele>,
    pub evaluation: Evaluation,
}

/// FR-R-3: brute-force search over every subset of `ALL` (including the
/// empty subset -- "apply nothing" is a legitimate winner when no
/// combination nets positive fitness). Picks the max-fitness subset; ties
/// break on fewest alleles, then `ALL`'s canonical order, so the result is
/// deterministic given the same target.
pub fn search(target: &dyn ContainmentTarget) -> SearchResult {
    let mut best: Option<SearchResult> = None;
    for mask in 0u32..(1u32 << ALL.len()) {
        let sequence: Vec<Allele> = (0..ALL.len()).filter(|&i| mask & (1u32 << i) != 0).map(|i| ALL[i]).collect();
        let evaluation = evaluate(&sequence, target);
        let key = (evaluation.fitness, std::cmp::Reverse(sequence.len()));
        let keep = best.as_ref().is_none_or(|b| key > (b.evaluation.fitness, std::cmp::Reverse(b.sequence.len())));
        if keep {
            best = Some(SearchResult { sequence, evaluation });
        }
    }
    best.expect("mask 0 (the empty sequence) always produces a candidate")
}

#[cfg(test)]
mod tests {
    use super::*;

    struct T {
        threat: Vec<Action>,
        benign: Vec<Action>,
    }

    impl ContainmentTarget for T {
        fn threat_actions(&self) -> &[Action] {
            &self.threat
        }
        fn benign_actions(&self) -> &[Action] {
            &self.benign
        }
    }

    fn target(threat: &[Action], benign: &[Action]) -> T {
        T { threat: threat.to_vec(), benign: benign.to_vec() }
    }

    fn full_trajectory() -> T {
        target(&[Action::ExecFromTempOrCache, Action::RecoverySnapshotTamper, Action::RapidFileModBurst], &[])
    }

    #[test]
    fn search_prefers_the_cheap_full_containment_combo_over_the_nuclear_option() {
        let result = search(&full_trajectory());
        assert_eq!(result.sequence, [Allele::QuarantineDroppedFiles, Allele::RevertTouchedFiles]);
        assert_eq!(result.evaluation.containment_value, 110, "covers all three Stage-1 actions");
        assert_eq!(result.evaluation.fitness, 60);
    }

    #[test]
    fn partial_containment_can_beat_a_costlier_full_attempt() {
        let t = full_trajectory();
        let partial = evaluate(&[Allele::RevertTouchedFiles], &t);
        let costlier_full = evaluate(&[Allele::SigStop, Allele::RevertTouchedFiles], &t);
        assert_eq!(partial.fitness, 45, "misses ExecFromTempOrCache but is cheap");
        assert_eq!(costlier_full.fitness, 40, "covers everything but pays for a redundant SigStop");
        assert!(partial.fitness > costlier_full.fitness, "covering less can still fit better once cost is priced in");
    }

    #[test]
    fn the_most_aggressive_allele_alone_is_worse_than_doing_nothing() {
        let t = full_trajectory();
        let nuclear = evaluate(&[Allele::KillChildTree], &t);
        let nothing = evaluate(&[], &t);
        assert_eq!(nuclear.containment_value, 110, "KillChildTree alone covers everything");
        assert_eq!(nuclear.fitness, -40);
        assert_eq!(nothing.fitness, 0);
        assert!(nuclear.fitness < nothing.fitness, "max aggression is not automatically optimal");
    }

    #[test]
    fn a_benign_collision_flips_a_would_be_cost_advantage() {
        let t = target(&[Action::RapidFileModBurst], &[Action::ExecFromTempOrCache]);
        let clean = evaluate(&[Allele::RevertTouchedFiles], &t);
        let colliding = evaluate(&[Allele::SigStop], &t);
        assert_eq!(clean.fitness, -5, "no collateral damage, just pays its own cost");
        assert_eq!(colliding.fitness, -35, "cheaper base cost but collides with the whitelisted Exec behavior");
        assert!(clean.fitness > colliding.fitness, "the nominally cheaper allele loses once collateral damage is priced in");
    }

    #[test]
    fn search_refuses_full_containment_when_every_covering_allele_collides() {
        let t = target(&[Action::ExecFromTempOrCache, Action::RapidFileModBurst], &[Action::ExecFromTempOrCache]);
        let result = search(&t);
        assert!(result.sequence.is_empty(), "every allele that covers the required Exec action also collides with it");
        assert_eq!(result.evaluation.fitness, 0);
    }

    #[test]
    fn search_is_deterministic() {
        let t = target(&[Action::RapidFileModBurst], &[]);
        assert_eq!(search(&t), search(&t));
    }
}

use anchor_lang::{
    prelude::Pubkey,
    solana_program::{instruction::Instruction, system_program},
    AccountDeserialize, InstructionData, ToAccountMetas,
};
use litesvm::LiteSVM;
use solana_keypair::{read_keypair_file, Keypair};
use solana_message::{Message, VersionedMessage};
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;

fn fresh_svm() -> (Pubkey, LiteSVM) {
    let program_id = t_cell::id();
    let mut svm = LiteSVM::new();
    let bytes = include_bytes!(concat!(env!("CARGO_TARGET_TMPDIR"), "/../deploy/t_cell.so"));
    svm.add_program(program_id, bytes).unwrap();
    (program_id, svm)
}

/// Loads one of the 5 real devnet PoI committee keypairs generated under
/// crates/ledger-program/keys/ (gitignored) -- poi.rs hardcodes their
/// pubkeys as POI_COMMITTEE.
fn poi_keypair(n: u8) -> Keypair {
    let path = match n {
        1 => concat!(env!("CARGO_MANIFEST_DIR"), "/../../keys/poi-1.json"),
        2 => concat!(env!("CARGO_MANIFEST_DIR"), "/../../keys/poi-2.json"),
        3 => concat!(env!("CARGO_MANIFEST_DIR"), "/../../keys/poi-3.json"),
        4 => concat!(env!("CARGO_MANIFEST_DIR"), "/../../keys/poi-4.json"),
        5 => concat!(env!("CARGO_MANIFEST_DIR"), "/../../keys/poi-5.json"),
        _ => panic!("only 5 PoI keypairs exist"),
    };
    read_keypair_file(path).expect("poi keypair file present (crates/ledger-program/keys/, gitignored)")
}

/// Dedupes `signers` by pubkey (repeats are expected -- see poi.rs's doc
/// comment on why PoI slots are always-required rather than `Option`, so a
/// caller short on distinct committee members repeats one), and forces a
/// fresh blockhash so two structurally-identical transactions (e.g. the
/// same reporter submitting the same threat_id twice) aren't rejected by
/// litesvm as `AlreadyProcessed` duplicates of each other.
fn send(svm: &mut LiteSVM, signers: &[&Keypair], instruction: Instruction) -> bool {
    let mut unique: Vec<&Keypair> = Vec::with_capacity(signers.len());
    for s in signers {
        if !unique.iter().any(|u| u.pubkey() == s.pubkey()) {
            unique.push(s);
        }
    }
    let payer = unique[0];
    svm.expire_blockhash();
    let blockhash = svm.latest_blockhash();
    let msg = Message::new_with_blockhash(&[instruction], Some(&payer.pubkey()), &blockhash);
    let tx = VersionedTransaction::try_new(VersionedMessage::Legacy(msg), &unique).unwrap();
    svm.send_transaction(tx).is_ok()
}

fn threat_registry_pda(program_id: &Pubkey, threat_id: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(&[t_cell::constants::THREAT_SEED, threat_id.as_ref()], program_id).0
}

fn genome_registry_pda(program_id: &Pubkey, threat_id: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(&[t_cell::constants::GENOME_SEED, threat_id.as_ref()], program_id).0
}

#[test]
fn submit_threat_creates_registry_and_dedupes_by_reporter() {
    let (program_id, mut svm) = fresh_svm();
    let reporter1 = Keypair::new();
    let reporter2 = Keypair::new();
    svm.airdrop(&reporter1.pubkey(), 1_000_000_000).unwrap();
    svm.airdrop(&reporter2.pubkey(), 1_000_000_000).unwrap();

    let threat_id = [7u8; 32];
    let schema_hash = [9u8; 32];
    let threat_registry = threat_registry_pda(&program_id, &threat_id);

    let submit = |reporter: &Keypair| {
        Instruction::new_with_bytes(
            program_id,
            &t_cell::instruction::SubmitThreat { threat_id, behavioral_schema_hash: schema_hash }.data(),
            t_cell::accounts::SubmitThreat {
                reporter: reporter.pubkey(),
                threat_registry,
                system_program: system_program::ID,
            }
            .to_account_metas(None),
        )
    };

    let read_registry = |svm: &LiteSVM| {
        let account = svm.get_account(&threat_registry).unwrap();
        let mut data: &[u8] = &account.data;
        t_cell::state::ThreatRegistry::try_deserialize(&mut data).unwrap()
    };

    assert!(send(&mut svm, &[&reporter1], submit(&reporter1)));
    let registry = read_registry(&svm);
    assert_eq!(registry.threat_id, threat_id);
    assert_eq!(registry.confidence_score, 1);

    assert!(send(&mut svm, &[&reporter2], submit(&reporter2)));
    assert_eq!(read_registry(&svm).confidence_score, 2, "a second, independent reporter corroborates");

    assert!(send(&mut svm, &[&reporter1], submit(&reporter1)));
    assert_eq!(read_registry(&svm).confidence_score, 2, "a repeat report from the same reporter must not double-count");
}

#[test]
fn commit_gene_requires_three_of_five_committee_signers() {
    let (program_id, mut svm) = fresh_svm();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 1_000_000_000).unwrap();

    let threat_id = [3u8; 32];
    let gene_hash = [4u8; 32];
    let genome_registry = genome_registry_pda(&program_id, &threat_id);
    let (a, b, c, d, e) = (poi_keypair(1), poi_keypair(2), poi_keypair(3), poi_keypair(4), poi_keypair(5));

    let instruction = |a: &Keypair, b: &Keypair, c: &Keypair, d: &Keypair, e: &Keypair| {
        Instruction::new_with_bytes(
            program_id,
            &t_cell::instruction::CommitGene { threat_id, gene_hash, chunk: vec![1, 2, 3], is_final_chunk: true }
                .data(),
            t_cell::accounts::CommitGene {
                payer: payer.pubkey(),
                genome_registry,
                system_program: system_program::ID,
                signer_a: a.pubkey(),
                signer_b: b.pubkey(),
                signer_c: c.pubkey(),
                signer_d: d.pubkey(),
                signer_e: e.pubkey(),
            }
            .to_account_metas(None),
        )
    };

    // only 2 distinct committee members (repeats fill the rest) -> rejected
    assert!(
        !send(&mut svm, &[&payer, &a, &b, &a, &a], instruction(&a, &b, &a, &a, &a)),
        "2-of-5 must not pass PoI"
    );

    // 3 distinct committee members -> accepted
    assert!(send(&mut svm, &[&payer, &a, &b, &c, &c], instruction(&a, &b, &c, &c, &c)), "3-of-5 must pass PoI");

    let account = svm.get_account(&genome_registry).unwrap();
    let mut data: &[u8] = &account.data;
    let genome = t_cell::state::GenomeRegistry::try_deserialize(&mut data).unwrap();
    assert_eq!(genome.threat_id, threat_id);
    assert_eq!(genome.gene_hash, gene_hash);
    assert_eq!(genome.gene_seq, vec![1, 2, 3]);
    assert!(!genome.epigenetic_status);

    let _ = d;
    let _ = e;
}

#[test]
fn commit_gene_chunks_append_and_gene_hash_lands_only_on_final_chunk() {
    let (program_id, mut svm) = fresh_svm();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 1_000_000_000).unwrap();

    let threat_id = [5u8; 32];
    let gene_hash = [6u8; 32];
    let genome_registry = genome_registry_pda(&program_id, &threat_id);
    let (a, b, c) = (poi_keypair(1), poi_keypair(2), poi_keypair(3));

    let chunk_ix = |chunk: Vec<u8>, is_final: bool| {
        Instruction::new_with_bytes(
            program_id,
            &t_cell::instruction::CommitGene { threat_id, gene_hash, chunk, is_final_chunk: is_final }.data(),
            t_cell::accounts::CommitGene {
                payer: payer.pubkey(),
                genome_registry,
                system_program: system_program::ID,
                signer_a: a.pubkey(),
                signer_b: b.pubkey(),
                signer_c: c.pubkey(),
                signer_d: c.pubkey(),
                signer_e: c.pubkey(),
            }
            .to_account_metas(None),
        )
    };

    assert!(send(&mut svm, &[&payer, &a, &b, &c], chunk_ix(vec![10, 11], false)));
    let account = svm.get_account(&genome_registry).unwrap();
    let mut data: &[u8] = &account.data;
    let genome = t_cell::state::GenomeRegistry::try_deserialize(&mut data).unwrap();
    assert_eq!(genome.gene_seq, vec![10, 11]);
    assert_eq!(genome.gene_hash, [0u8; 32], "gene_hash is only set once is_final_chunk=true");

    assert!(send(&mut svm, &[&payer, &a, &b, &c], chunk_ix(vec![12, 13], true)));
    let account = svm.get_account(&genome_registry).unwrap();
    let mut data: &[u8] = &account.data;
    let genome = t_cell::state::GenomeRegistry::try_deserialize(&mut data).unwrap();
    assert_eq!(genome.gene_seq, vec![10, 11, 12, 13], "second chunk appends, does not replace");
    assert_eq!(genome.gene_hash, gene_hash);
}

#[test]
fn suppress_gene_requires_poi_and_sets_epigenetic_status() {
    let (program_id, mut svm) = fresh_svm();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 1_000_000_000).unwrap();

    let threat_id = [8u8; 32];
    let gene_hash = [1u8; 32];
    let genome_registry = genome_registry_pda(&program_id, &threat_id);
    let (a, b, c) = (poi_keypair(1), poi_keypair(2), poi_keypair(3));

    let commit_ix = Instruction::new_with_bytes(
        program_id,
        &t_cell::instruction::CommitGene { threat_id, gene_hash, chunk: vec![42], is_final_chunk: true }.data(),
        t_cell::accounts::CommitGene {
            payer: payer.pubkey(),
            genome_registry,
            system_program: system_program::ID,
            signer_a: a.pubkey(),
            signer_b: b.pubkey(),
            signer_c: c.pubkey(),
            signer_d: c.pubkey(),
            signer_e: c.pubkey(),
        }
        .to_account_metas(None),
    );
    assert!(send(&mut svm, &[&payer, &a, &b, &c], commit_ix));

    let suppress_ix = |a: &Keypair, b: &Keypair, c: &Keypair| {
        Instruction::new_with_bytes(
            program_id,
            &t_cell::instruction::SuppressGene { threat_id }.data(),
            t_cell::accounts::SuppressGene {
                genome_registry,
                signer_a: a.pubkey(),
                signer_b: b.pubkey(),
                signer_c: c.pubkey(),
                signer_d: c.pubkey(),
                signer_e: c.pubkey(),
            }
            .to_account_metas(None),
        )
    };

    // only 2 distinct committee members -> rejected, status stays false
    assert!(!send(&mut svm, &[&payer, &a, &b], suppress_ix(&a, &b, &a)));
    let account = svm.get_account(&genome_registry).unwrap();
    let mut data: &[u8] = &account.data;
    assert!(!t_cell::state::GenomeRegistry::try_deserialize(&mut data).unwrap().epigenetic_status);

    // 3 distinct committee members -> accepted
    assert!(send(&mut svm, &[&payer, &a, &b, &c], suppress_ix(&a, &b, &c)));
    let account = svm.get_account(&genome_registry).unwrap();
    let mut data: &[u8] = &account.data;
    assert!(t_cell::state::GenomeRegistry::try_deserialize(&mut data).unwrap().epigenetic_status);
}

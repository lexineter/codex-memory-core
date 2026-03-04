use std::fs;

use codex_core::engine::{Engine, EngineConfig, MutationDecision};
use codex_core::hex::to_hex_lower;
use codex_core::{
    FEATURE_DIVERGENCE_PROOF, FEATURE_DOC_MERKLE_STATE, FEATURE_LIFECYCLE_GOVERNANCE,
    FEATURE_RECURSIVE_PROJECTION, FEATURE_SCORE_COMMITMENT, FEATURE_SNAPSHOT_COMMITMENT,
    FEATURE_SNAPSHOT_DELTA_PROOF,
};

fn cfg() -> EngineConfig {
    EngineConfig {
        default_new_lifecycle_state: 0,
        default_new_representation_mode: 0,
        default_new_compressed_flag: 0,
        quarantine_span_events: 4,
    }
}

fn main() {
    let out_dir = "demo_run";
    let _ = fs::remove_dir_all(out_dir);
    let _ = fs::create_dir_all(out_dir);

    let ledger_path = format!("{out_dir}/ledger.bin");
    let index_path = format!("{out_dir}/index.bin");

    let flags = FEATURE_RECURSIVE_PROJECTION
        | FEATURE_SCORE_COMMITMENT
        | FEATURE_LIFECYCLE_GOVERNANCE
        | FEATURE_SNAPSHOT_COMMITMENT
        | FEATURE_DIVERGENCE_PROOF
        | FEATURE_DOC_MERKLE_STATE
        | FEATURE_SNAPSHOT_DELTA_PROOF;

    let mut engine = Engine::create(&ledger_path, &index_path, None, flags, cfg())
        .expect("demo: engine create must succeed");

    let d0 = engine.insert(b"alpha").expect("demo: insert alpha");
    let d1 = engine.insert(b"beta").expect("demo: insert beta");
    let d2 = engine.insert(b"gamma").expect("demo: insert gamma");

    let query = b"hello";
    let q = engine
        .score_evaluated(query, &[d2.doc_id, d0.doc_id, d1.doc_id])
        .expect("demo: score_evaluated");

    let lifecycle_root = engine
        .lifecycle_mutation(
            q.ordered_doc_ids[0],
            MutationDecision::NoChange,
            q.candidate_commitment,
        )
        .expect("demo: lifecycle_mutation");

    let _ = engine.emit_snapshot().expect("demo: snapshot 1");
    let d3 = engine.insert(b"delta").expect("demo: insert delta");
    let q2 = engine
        .score_evaluated(query, &[d3.doc_id, d0.doc_id, d1.doc_id])
        .expect("demo: score_evaluated 2");
    let _ = engine.emit_snapshot().expect("demo: snapshot 2");

    let delta_root = engine
        .emit_snapshot_delta(lifecycle_root, q2.root_after)
        .expect("demo: snapshot delta");
    let divergence_locator_root = engine
        .emit_divergence_locator()
        .expect("demo: divergence locator");

    let snapshot_root = q2.root_after;
    let doc_merkle_root = engine.current_doc_merkle_root();
    let transcript_hash = engine.export_transcript_hash();

    println!("--- QUERY ---");
    println!("query: \"hello\"");
    println!("top_k: {}", q.ordered_doc_ids.len());
    println!("scores:");
    for (doc_id, score) in q.ordered_doc_ids.iter().zip(q.scores.iter()) {
        println!("  doc_id: {}", to_hex_lower(doc_id));
        println!("  score: {}", score);
    }
    println!(
        "lifecycle_change: root_after={}",
        to_hex_lower(&lifecycle_root)
    );
    println!("snapshot_root: {}", to_hex_lower(&snapshot_root));
    println!("doc_merkle_root: {}", to_hex_lower(&doc_merkle_root));
    println!("delta_root: {}", to_hex_lower(&delta_root));
    println!(
        "divergence_locator_root: {}",
        to_hex_lower(&divergence_locator_root)
    );
    println!("transcript_hash: {}", to_hex_lower(&transcript_hash));
}

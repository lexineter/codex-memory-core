use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use codex_core::engine::{Engine, EngineConfig};
use codex_core::protocol::protocol_hash;
use codex_core::replay::compute_transcript_hash;
use codex_core::{FEATURE_JSON_MIRROR, FEATURE_SNAPSHOT_COMMITMENT};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_temp_path(name: &str, ext: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    p.push(format!(
        "codex_core_determinism_{}_{}_{}.{}",
        std::process::id(),
        id,
        name,
        ext
    ));
    p
}

fn cfg() -> EngineConfig {
    EngineConfig {
        default_new_lifecycle_state: 0,
        default_new_representation_mode: 0,
        default_new_compressed_flag: 0,
        quarantine_span_events: 7,
    }
}

#[test]
fn projection_determinism() {
    let ledger = unique_temp_path("proj_ledger", "bin");
    let index = unique_temp_path("proj_index", "bin");
    let mut e = Engine::create(
        ledger.to_str().unwrap(),
        index.to_str().unwrap(),
        None,
        0,
        cfg(),
    )
    .unwrap();
    let a = e
        .insert_cme(codex_core::cme::CmeInput::Text("hello"))
        .unwrap();
    let b = e
        .insert_cme(codex_core::cme::CmeInput::Text("hello"))
        .unwrap();
    assert_eq!(a.projection, b.projection);
    drop(e);
    let _ = fs::remove_file(ledger);
    let _ = fs::remove_file(index);
}

#[test]
fn score_determinism() {
    let ledger1 = unique_temp_path("score1_ledger", "bin");
    let index1 = unique_temp_path("score1_index", "bin");
    let ledger2 = unique_temp_path("score2_ledger", "bin");
    let index2 = unique_temp_path("score2_index", "bin");
    let flags = codex_core::FEATURE_RECURSIVE_PROJECTION
        | codex_core::FEATURE_SCORE_COMMITMENT
        | codex_core::FEATURE_SCORE_PROOFS;

    let mut e1 = Engine::create(
        ledger1.to_str().unwrap(),
        index1.to_str().unwrap(),
        None,
        flags,
        cfg(),
    )
    .unwrap();
    let mut e2 = Engine::create(
        ledger2.to_str().unwrap(),
        index2.to_str().unwrap(),
        None,
        flags,
        cfg(),
    )
    .unwrap();
    let d1a = e1.insert_cme(codex_core::cme::CmeInput::Text("a")).unwrap();
    let d2a = e1.insert_cme(codex_core::cme::CmeInput::Text("b")).unwrap();
    let d1b = e2.insert_cme(codex_core::cme::CmeInput::Text("a")).unwrap();
    let d2b = e2.insert_cme(codex_core::cme::CmeInput::Text("b")).unwrap();
    let r1 = e1
        .score_evaluated(b"query", &[d1a.doc_id, d2a.doc_id])
        .unwrap();
    let r2 = e2
        .score_evaluated(b"query", &[d1b.doc_id, d2b.doc_id])
        .unwrap();
    assert_eq!(r1.scores, r2.scores);
    assert_eq!(r1.score_commitment, r2.score_commitment);
    drop(e1);
    drop(e2);
    let _ = fs::remove_file(ledger1);
    let _ = fs::remove_file(index1);
    let _ = fs::remove_file(ledger2);
    let _ = fs::remove_file(index2);
}

fn run_sequence(ledger: &Path, index: &Path, json: &Path) -> ([u8; 32], [u8; 32]) {
    let mut e = Engine::create(
        ledger.to_str().unwrap(),
        index.to_str().unwrap(),
        Some(json.to_str().unwrap()),
        FEATURE_JSON_MIRROR | FEATURE_SNAPSHOT_COMMITMENT,
        cfg(),
    )
    .unwrap();
    let d0 = e
        .insert_cme(codex_core::cme::CmeInput::Text("alpha"))
        .unwrap();
    let d1 = e
        .insert_cme(codex_core::cme::CmeInput::Text("beta"))
        .unwrap();
    let _ = e
        .score_evaluated(b"alpha", &[d0.doc_id, d1.doc_id])
        .unwrap();
    let snap_root = e.emit_snapshot().unwrap();
    let transcript = e.export_transcript_hash();
    drop(e);
    (snap_root, transcript)
}

#[test]
fn full_ledger_determinism() {
    let l1 = unique_temp_path("full1_ledger", "bin");
    let i1 = unique_temp_path("full1_index", "bin");
    let j1 = unique_temp_path("full1_json", "jsonl");
    let l2 = unique_temp_path("full2_ledger", "bin");
    let i2 = unique_temp_path("full2_index", "bin");
    let j2 = unique_temp_path("full2_json", "jsonl");

    let (snap1, t1) = run_sequence(&l1, &i1, &j1);
    let (snap2, t2) = run_sequence(&l2, &i2, &j2);
    assert_eq!(snap1, snap2);
    assert_eq!(t1, t2);
    assert_eq!(
        compute_transcript_hash(l1.to_str().unwrap()).unwrap(),
        compute_transcript_hash(l2.to_str().unwrap()).unwrap()
    );
    assert_eq!(fs::read(&l1).unwrap(), fs::read(&l2).unwrap());
    assert_eq!(
        fs::read_to_string(&j1).unwrap(),
        fs::read_to_string(&j2).unwrap()
    );

    let _ = fs::remove_file(l1);
    let _ = fs::remove_file(i1);
    let _ = fs::remove_file(j1);
    let _ = fs::remove_file(l2);
    let _ = fs::remove_file(i2);
    let _ = fs::remove_file(j2);
}

#[test]
fn protocol_hash_stability() {
    let a = protocol_hash();
    let b = protocol_hash();
    assert_eq!(a, b);
}

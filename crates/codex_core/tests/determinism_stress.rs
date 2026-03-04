use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use codex_core::cme::CmeInput;
use codex_core::engine::{Engine, EngineConfig, MutationDecision};
use codex_core::replay;
use codex_core::{FEATURE_JSON_MIRROR, FEATURE_SNAPSHOT_COMMITMENT};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_temp_path(name: &str, ext: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    p.push(format!(
        "codex_core_determinism_stress_{}_{}_{}.{}",
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
        quarantine_span_events: 4,
    }
}

fn run_replica(ledger: &Path, index: &Path, json: &Path) {
    let flags = FEATURE_JSON_MIRROR | FEATURE_SNAPSHOT_COMMITMENT;
    let mut engine = Engine::create(
        ledger.to_str().unwrap(),
        index.to_str().unwrap(),
        Some(json.to_str().unwrap()),
        flags,
        cfg(),
    )
    .unwrap();

    let d0 = engine.insert_cme(CmeInput::Text("alpha")).unwrap();
    let d1 = engine.insert_cme(CmeInput::Text("beta")).unwrap();
    let d2 = engine.insert_cme(CmeInput::Text("gamma")).unwrap();

    let q = engine
        .score_evaluated_cme(CmeInput::Text("alpha"), &[d2.doc_id, d0.doc_id, d1.doc_id])
        .unwrap();

    let _ = engine
        .lifecycle_mutation(
            q.ordered_doc_ids[0],
            MutationDecision::SetCompressed { compressed: 1 },
            q.candidate_commitment,
        )
        .unwrap();

    let _ = engine.emit_snapshot().unwrap();
    drop(engine);
}

#[test]
fn three_replicas_byte_identical() {
    let l1 = unique_temp_path("r1_ledger", "bin");
    let i1 = unique_temp_path("r1_index", "bin");
    let j1 = unique_temp_path("r1_json", "jsonl");
    let l2 = unique_temp_path("r2_ledger", "bin");
    let i2 = unique_temp_path("r2_index", "bin");
    let j2 = unique_temp_path("r2_json", "jsonl");
    let l3 = unique_temp_path("r3_ledger", "bin");
    let i3 = unique_temp_path("r3_index", "bin");
    let j3 = unique_temp_path("r3_json", "jsonl");

    run_replica(&l1, &i1, &j1);
    run_replica(&l2, &i2, &j2);
    run_replica(&l3, &i3, &j3);

    let l1_bytes = fs::read(&l1).unwrap();
    let i1_bytes = fs::read(&i1).unwrap();
    let j1_bytes = fs::read(&j1).unwrap();

    assert_eq!(l1_bytes, fs::read(&l2).unwrap());
    assert_eq!(l1_bytes, fs::read(&l3).unwrap());
    assert_eq!(i1_bytes, fs::read(&i2).unwrap());
    assert_eq!(i1_bytes, fs::read(&i3).unwrap());
    assert_eq!(j1_bytes, fs::read(&j2).unwrap());
    assert_eq!(j1_bytes, fs::read(&j3).unwrap());

    assert!(replay::verify_ledger(l1.to_str().unwrap()).is_ok());
    assert!(replay::verify_ledger(l2.to_str().unwrap()).is_ok());
    assert!(replay::verify_ledger(l3.to_str().unwrap()).is_ok());

    for p in [&l1, &i1, &j1, &l2, &i2, &j2, &l3, &i3, &j3] {
        let _ = fs::remove_file(p);
    }
}

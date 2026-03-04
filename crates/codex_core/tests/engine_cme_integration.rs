use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use codex_core::cme::CmeInput;
use codex_core::engine::{Engine, EngineConfig};
use codex_core::replay;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_temp_path(name: &str, ext: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    p.push(format!(
        "codex_core_engine_cme_{}_{}_{}.{}",
        std::process::id(),
        id,
        name,
        ext
    ));
    p
}

fn cfg() -> EngineConfig {
    EngineConfig {
        default_new_lifecycle_state: 1,
        default_new_representation_mode: 2,
        default_new_compressed_flag: 0,
        quarantine_span_events: 5,
    }
}

#[test]
fn engine_cme_equivalent_inputs_stable() {
    let ledger_path = unique_temp_path("ledger", "bin");
    let index_path = unique_temp_path("index", "bin");

    let mut engine = Engine::create(
        ledger_path.to_str().unwrap(),
        index_path.to_str().unwrap(),
        None,
        0,
        cfg(),
    )
    .unwrap();

    let a = engine
        .insert_cme(CmeInput::Text(" hello \n world "))
        .unwrap();
    let b = engine.insert_cme(CmeInput::Text("hello world")).unwrap();
    let c = engine.insert_cme(CmeInput::Text("other doc")).unwrap();
    assert_eq!(a.doc_id, b.doc_id);
    assert_eq!(a.projection, b.projection);

    let candidates = vec![c.doc_id, a.doc_id];
    let q1 = engine
        .score_evaluated_cme(CmeInput::Text(" query\tterm "), &candidates)
        .unwrap();
    let q2 = engine
        .score_evaluated_cme(CmeInput::Text("query term"), &candidates)
        .unwrap();

    assert_eq!(q1.ordered_doc_ids, q2.ordered_doc_ids);
    assert_eq!(q1.scores, q2.scores);
    assert_eq!(q1.candidate_commitment, q2.candidate_commitment);
    drop(engine);

    let report = replay::verify_ledger(ledger_path.to_str().unwrap()).unwrap();
    assert_eq!(report.events_verified, 5);

    let _ = fs::remove_file(ledger_path);
    let _ = fs::remove_file(index_path);
}

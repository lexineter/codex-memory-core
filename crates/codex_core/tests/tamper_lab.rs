use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use codex_core::engine::{Engine, EngineConfig};
use codex_core::ledger::index::IndexReader;
use codex_core::replay::{self, FailCode};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_temp_path(name: &str, ext: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    p.push(format!(
        "codex_core_tamper_lab_{}_{}_{}.{}",
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

#[test]
fn byte_flip_causes_replay_failcode() {
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
    let _ = engine.insert(b"doc-1").unwrap();
    drop(engine);

    let index = IndexReader::open(index_path.to_str().unwrap()).unwrap();
    let offset = index.get_offset(0).unwrap() as usize;

    let mut ledger_bytes = fs::read(&ledger_path).unwrap();
    let event_len = u32::from_be_bytes([
        ledger_bytes[offset],
        ledger_bytes[offset + 1],
        ledger_bytes[offset + 2],
        ledger_bytes[offset + 3],
    ]) as usize;
    assert!(event_len >= 32);
    let commitment_pos = offset + 4 + (event_len - 32);
    ledger_bytes[commitment_pos] ^= 0x01;
    fs::write(&ledger_path, &ledger_bytes).unwrap();

    let err = replay::verify_ledger(ledger_path.to_str().unwrap()).unwrap_err();
    assert_eq!(
        replay::classify_error(&err),
        FailCode::EventCommitmentMismatch
    );

    let _ = fs::remove_file(ledger_path);
    let _ = fs::remove_file(index_path);
}

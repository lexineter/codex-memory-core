use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use codex_core::bytes;
use codex_core::engine::{Engine, EngineConfig};
use codex_core::ledger::index::IndexReader;
use codex_core::replay::{classify_error, verify_ledger, FailCode};
use codex_core::{
    hash, CodexError, DOMAIN_EVENT, FEATURE_JSON_MIRROR, FEATURE_OBSERVER_BLOCK,
    FEATURE_RECURSIVE_PROJECTION, MAX_QUERY_BYTES,
};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_temp_path(name: &str, ext: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    p.push(format!(
        "codex_core_recursive_{}_{}_{}.{}",
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
fn replay_verifies_recursive_projection_enabled_no_observer() {
    let ledger_path = unique_temp_path("a_ledger", "bin");
    let index_path = unique_temp_path("a_index", "bin");
    let json_path = unique_temp_path("a_json", "jsonl");
    let mut engine = Engine::create(
        ledger_path.to_str().unwrap(),
        index_path.to_str().unwrap(),
        Some(json_path.to_str().unwrap()),
        FEATURE_RECURSIVE_PROJECTION | FEATURE_JSON_MIRROR,
        cfg(),
    )
    .unwrap();
    let ins = engine.insert(b"doc-r0").unwrap();
    let qr = engine.score_evaluated(b"hello", &[ins.doc_id]).unwrap();
    assert!(qr.query_projection_commitment.is_some());
    drop(engine);

    let report = verify_ledger(ledger_path.to_str().unwrap()).unwrap();
    assert_eq!(report.events_verified, 2);

    let json = fs::read_to_string(&json_path).unwrap();
    let lines: Vec<&str> = json.lines().collect();
    assert!(lines[1].contains("\"query_len\":5"));
    assert!(lines[1].contains("\"query_projection_commitment\":\""));

    let _ = fs::remove_file(ledger_path);
    let _ = fs::remove_file(index_path);
    let _ = fs::remove_file(json_path);
}

#[test]
fn replay_verifies_recursive_projection_enabled_with_observer() {
    let ledger_path0 = unique_temp_path("b0_ledger", "bin");
    let index_path0 = unique_temp_path("b0_index", "bin");
    let mut eng0 = Engine::create(
        ledger_path0.to_str().unwrap(),
        index_path0.to_str().unwrap(),
        None,
        FEATURE_RECURSIVE_PROJECTION,
        cfg(),
    )
    .unwrap();
    let ins0 = eng0.insert(b"doc-r1").unwrap();
    let qr0 = eng0.score_evaluated(b"hello", &[ins0.doc_id]).unwrap();
    let c0 = qr0.query_projection_commitment.unwrap();
    drop(eng0);

    let ledger_path1 = unique_temp_path("b1_ledger", "bin");
    let index_path1 = unique_temp_path("b1_index", "bin");
    let mut eng1 = Engine::create(
        ledger_path1.to_str().unwrap(),
        index_path1.to_str().unwrap(),
        None,
        FEATURE_RECURSIVE_PROJECTION | FEATURE_OBSERVER_BLOCK,
        cfg(),
    )
    .unwrap();
    let ins1 = eng1.insert(b"doc-r1").unwrap();
    let qr1 = eng1
        .score_evaluated_obs(b"hello", b"ctx", &[ins1.doc_id], [2u8; 16], 1, 2, 0, 7)
        .unwrap();
    let c1 = qr1.query_projection_commitment.unwrap();
    assert_ne!(c0, c1);
    drop(eng1);

    verify_ledger(ledger_path1.to_str().unwrap()).unwrap();

    let _ = fs::remove_file(ledger_path0);
    let _ = fs::remove_file(index_path0);
    let _ = fs::remove_file(ledger_path1);
    let _ = fs::remove_file(index_path1);
}

#[test]
fn tamper_query_projection_commitment_fails() {
    let ledger_path = unique_temp_path("c_ledger", "bin");
    let index_path = unique_temp_path("c_index", "bin");
    let mut engine = Engine::create(
        ledger_path.to_str().unwrap(),
        index_path.to_str().unwrap(),
        None,
        FEATURE_RECURSIVE_PROJECTION,
        cfg(),
    )
    .unwrap();
    let ins = engine.insert(b"doc-r2").unwrap();
    let _ = engine.score_evaluated(b"hello", &[ins.doc_id]).unwrap();
    drop(engine);

    let idx = IndexReader::open(index_path.to_str().unwrap()).unwrap();
    let offset = idx.get_offset(1).unwrap();
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&ledger_path)
        .unwrap();
    f.seek(SeekFrom::Start(offset)).unwrap();
    let mut len_buf = [0u8; 4];
    f.read_exact(&mut len_buf).unwrap();
    let event_len = bytes::read_u32_be(&len_buf).unwrap() as usize;
    let mut payload = vec![0u8; event_len - 32];
    f.read_exact(&mut payload).unwrap();

    let base = 1 + 8 + 8 + 32 + 32 + 32;
    let qlen = bytes::read_u32_be(&payload[base..base + 4]).unwrap() as usize;
    let qproj_at = base + 4 + qlen;
    payload[qproj_at] ^= 0x01;
    let new_event_commitment = hash::hash_domain(DOMAIN_EVENT, &payload);

    f.seek(SeekFrom::Start(offset + 4)).unwrap();
    f.write_all(&payload).unwrap();
    f.write_all(&new_event_commitment).unwrap();
    drop(f);

    let err = verify_ledger(ledger_path.to_str().unwrap()).unwrap_err();
    assert_eq!(
        classify_error(&err),
        FailCode::QueryProjectionCommitmentMismatch
    );

    let _ = fs::remove_file(ledger_path);
    let _ = fs::remove_file(index_path);
}

#[test]
fn query_len_overflow_rejected() {
    let ledger_path = unique_temp_path("d_ledger", "bin");
    let index_path = unique_temp_path("d_index", "bin");
    let mut engine = Engine::create(
        ledger_path.to_str().unwrap(),
        index_path.to_str().unwrap(),
        None,
        FEATURE_RECURSIVE_PROJECTION,
        cfg(),
    )
    .unwrap();
    let ins = engine.insert(b"doc-r3").unwrap();
    let huge = vec![b'x'; MAX_QUERY_BYTES + 1];
    let err = engine.score_evaluated(&huge, &[ins.doc_id]).unwrap_err();
    assert_eq!(err, CodexError::InvalidInput("QUERY_BYTES_TOO_LARGE"));
    drop(engine);

    let _ = fs::remove_file(ledger_path);
    let _ = fs::remove_file(index_path);
}

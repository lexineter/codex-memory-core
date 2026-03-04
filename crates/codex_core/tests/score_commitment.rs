use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use codex_core::bytes;
use codex_core::engine::{Engine, EngineConfig};
use codex_core::ledger::index::IndexReader;
use codex_core::ledger::reader::LedgerReader;
use codex_core::replay::{classify_error, verify_ledger, FailCode};
use codex_core::schema::Event;
use codex_core::{
    hash, CodexError, DOMAIN_EVENT, FEATURE_OBSERVER_BLOCK, FEATURE_RECURSIVE_PROJECTION,
    FEATURE_SCORE_COMMITMENT, FEATURE_SCORE_PROOFS,
};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_temp_path(name: &str, ext: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    p.push(format!(
        "codex_core_score_commit_{}_{}_{}.{}",
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
fn replay_verifies_score_commitment_compact() {
    let ledger_path = unique_temp_path("a_ledger", "bin");
    let index_path = unique_temp_path("a_index", "bin");
    let mut engine = Engine::create(
        ledger_path.to_str().unwrap(),
        index_path.to_str().unwrap(),
        None,
        FEATURE_RECURSIVE_PROJECTION | FEATURE_SCORE_COMMITMENT,
        cfg(),
    )
    .unwrap();
    let d0 = engine.insert(b"a").unwrap();
    let d1 = engine.insert(b"b").unwrap();
    let d2 = engine.insert(b"c").unwrap();
    let _ = engine
        .score_evaluated(b"hello", &[d2.doc_id, d0.doc_id, d1.doc_id])
        .unwrap();
    drop(engine);

    verify_ledger(ledger_path.to_str().unwrap()).unwrap();
    let idx = IndexReader::open(index_path.to_str().unwrap()).unwrap();
    let offset = idx.get_offset(3).unwrap();
    let mut reader = LedgerReader::open(ledger_path.to_str().unwrap()).unwrap();
    let (payload, _) = reader.read_raw_at(offset).unwrap();
    match codex_core::schema::decode_event_payload(
        &payload,
        FEATURE_RECURSIVE_PROJECTION | FEATURE_SCORE_COMMITMENT,
    )
    .unwrap()
    {
        Event::ScoreEvaluated { score, .. } => {
            assert!(score.is_some());
            assert!(score.unwrap().score_bytes.is_none());
        }
        _ => panic!("expected score event"),
    }

    let _ = fs::remove_file(ledger_path);
    let _ = fs::remove_file(index_path);
}

#[test]
fn replay_verifies_score_commitment_with_observer_recursion() {
    let ledger_path = unique_temp_path("b_ledger", "bin");
    let index_path = unique_temp_path("b_index", "bin");
    let mut engine = Engine::create(
        ledger_path.to_str().unwrap(),
        index_path.to_str().unwrap(),
        None,
        FEATURE_OBSERVER_BLOCK | FEATURE_RECURSIVE_PROJECTION | FEATURE_SCORE_COMMITMENT,
        cfg(),
    )
    .unwrap();
    let d0 = engine.insert(b"x").unwrap();
    let d1 = engine.insert(b"y").unwrap();
    let _ = engine
        .score_evaluated_obs(
            b"hello",
            b"ctx",
            &[d1.doc_id, d0.doc_id],
            [1u8; 16],
            1,
            2,
            0,
            9,
        )
        .unwrap();
    drop(engine);

    verify_ledger(ledger_path.to_str().unwrap()).unwrap();

    let _ = fs::remove_file(ledger_path);
    let _ = fs::remove_file(index_path);
}

#[test]
fn proofs_mode_exact_bytes_match() {
    let ledger_path = unique_temp_path("c_ledger", "bin");
    let index_path = unique_temp_path("c_index", "bin");
    let mut engine = Engine::create(
        ledger_path.to_str().unwrap(),
        index_path.to_str().unwrap(),
        None,
        FEATURE_RECURSIVE_PROJECTION | FEATURE_SCORE_COMMITMENT | FEATURE_SCORE_PROOFS,
        cfg(),
    )
    .unwrap();
    let d0 = engine.insert(b"m").unwrap();
    let d1 = engine.insert(b"n").unwrap();
    let _ = engine
        .score_evaluated(b"hello", &[d1.doc_id, d0.doc_id])
        .unwrap();
    drop(engine);

    verify_ledger(ledger_path.to_str().unwrap()).unwrap();

    let _ = fs::remove_file(ledger_path);
    let _ = fs::remove_file(index_path);
}

#[test]
fn tamper_score_commitment_fails() {
    let ledger_path = unique_temp_path("d_ledger", "bin");
    let index_path = unique_temp_path("d_index", "bin");
    let mut engine = Engine::create(
        ledger_path.to_str().unwrap(),
        index_path.to_str().unwrap(),
        None,
        FEATURE_RECURSIVE_PROJECTION | FEATURE_SCORE_COMMITMENT,
        cfg(),
    )
    .unwrap();
    let d0 = engine.insert(b"u").unwrap();
    let d1 = engine.insert(b"v").unwrap();
    let _ = engine
        .score_evaluated(b"hello", &[d1.doc_id, d0.doc_id])
        .unwrap();
    drop(engine);

    let idx = IndexReader::open(index_path.to_str().unwrap()).unwrap();
    let offset = idx.get_offset(2).unwrap();
    let mut f = std::fs::OpenOptions::new()
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
    let mut at = base + 4 + qlen + 32; // query_proj_commit
    at += 32; // candidate commitment
    let ordered_k = bytes::read_u32_be(&payload[at..at + 4]).unwrap() as usize;
    at += 4 + ordered_k * 32;
    at += 4; // top_k
    payload[at] ^= 0x01; // score commitment first byte

    let new_event_commitment = hash::hash_domain(DOMAIN_EVENT, &payload);
    f.seek(SeekFrom::Start(offset + 4)).unwrap();
    f.write_all(&payload).unwrap();
    f.write_all(&new_event_commitment).unwrap();
    drop(f);

    let err = verify_ledger(ledger_path.to_str().unwrap()).unwrap_err();
    assert_eq!(classify_error(&err), FailCode::ScoreCommitmentMismatch);

    let _ = fs::remove_file(ledger_path);
    let _ = fs::remove_file(index_path);
}

#[test]
fn header_requires_recursive_projection() {
    let ledger_path = unique_temp_path("e_ledger", "bin");
    let index_path = unique_temp_path("e_index", "bin");
    let err = Engine::create(
        ledger_path.to_str().unwrap(),
        index_path.to_str().unwrap(),
        None,
        FEATURE_SCORE_COMMITMENT,
        cfg(),
    )
    .unwrap_err();
    assert_eq!(
        err,
        CodexError::InvalidInput("SCORE_COMMITMENT_REQUIRES_QUERY_BYTES")
    );
}

#[test]
fn score_proofs_requires_score_commitment() {
    let ledger_path = unique_temp_path("f_ledger", "bin");
    let index_path = unique_temp_path("f_index", "bin");
    let err = Engine::create(
        ledger_path.to_str().unwrap(),
        index_path.to_str().unwrap(),
        None,
        FEATURE_RECURSIVE_PROJECTION | FEATURE_SCORE_PROOFS,
        cfg(),
    )
    .unwrap_err();
    assert_eq!(
        err,
        CodexError::InvalidInput("SCORE_PROOFS_REQUIRES_SCORE_COMMITMENT")
    );
}

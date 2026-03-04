use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use codex_core::bytes;
use codex_core::engine::{Engine, EngineConfig, MutationDecision};
use codex_core::ledger::index::IndexReader;
use codex_core::replay::{classify_error, verify_ledger, FailCode};
use codex_core::{CodexError, DOMAIN_EVENT, FEATURE_OBSERVER_BLOCK};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_temp_path(name: &str, ext: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    p.push(format!(
        "codex_core_observer_{}_{}_{}.{}",
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
fn replay_verifies_with_observer_block_enabled() {
    let ledger_path = unique_temp_path("ledger_ok", "bin");
    let index_path = unique_temp_path("index_ok", "bin");
    let mut engine = Engine::create(
        ledger_path.to_str().unwrap(),
        index_path.to_str().unwrap(),
        None,
        FEATURE_OBSERVER_BLOCK,
        cfg(),
    )
    .unwrap();

    let ins = engine.insert(b"doc-one").unwrap();
    let qr = engine
        .score_evaluated_obs(
            b"Q",
            b"ctx-123",
            &[ins.doc_id],
            [1u8; 16],
            0x0001,
            2,
            0,
            12_345,
        )
        .unwrap();
    let _ = engine
        .lifecycle_mutation_obs(
            ins.doc_id,
            MutationDecision::SetCompressed { compressed: 1 },
            qr.candidate_commitment,
            b"ctx-123",
            [1u8; 16],
            0x0001,
            2,
            0,
            12_345,
        )
        .unwrap();
    drop(engine);

    let report = verify_ledger(ledger_path.to_str().unwrap()).unwrap();
    assert_eq!(report.events_verified, 3);

    let _ = fs::remove_file(ledger_path);
    let _ = fs::remove_file(index_path);
}

#[test]
fn observer_commitment_tamper_fails() {
    let ledger_path = unique_temp_path("ledger_tamper", "bin");
    let index_path = unique_temp_path("index_tamper", "bin");
    let mut engine = Engine::create(
        ledger_path.to_str().unwrap(),
        index_path.to_str().unwrap(),
        None,
        FEATURE_OBSERVER_BLOCK,
        cfg(),
    )
    .unwrap();
    let ins = engine.insert(b"doc-two").unwrap();
    let _ = engine
        .score_evaluated_obs(
            b"Q",
            b"ctx-123",
            &[ins.doc_id],
            [1u8; 16],
            0x0001,
            2,
            0,
            12_345,
        )
        .unwrap();
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

    let base = 1 + 8 + 8 + 32 + 32 + 32 + 32 + 128;
    let qctx_len = bytes::read_u32_be(&payload[base..base + 4]).unwrap() as usize;
    let qctx_commit_offset = base + 4 + qctx_len + 16 + 2 + 1 + 1 + 4;
    payload[qctx_commit_offset] ^= 0x01;
    let new_event_commitment = codex_core::hash::hash_domain(DOMAIN_EVENT, &payload);

    f.seek(SeekFrom::Start(offset + 4)).unwrap();
    f.write_all(&payload).unwrap();
    f.write_all(&new_event_commitment).unwrap();
    drop(f);

    let err = verify_ledger(ledger_path.to_str().unwrap()).unwrap_err();
    assert_eq!(
        classify_error(&err),
        FailCode::ObserverOrQueryCommitmentMismatch
    );

    let _ = fs::remove_file(ledger_path);
    let _ = fs::remove_file(index_path);
}

#[test]
fn breath_phase_invalid_fails() {
    let ledger_path = unique_temp_path("ledger_bad_phase", "bin");
    let index_path = unique_temp_path("index_bad_phase", "bin");
    let mut engine = Engine::create(
        ledger_path.to_str().unwrap(),
        index_path.to_str().unwrap(),
        None,
        FEATURE_OBSERVER_BLOCK,
        cfg(),
    )
    .unwrap();
    let ins = engine.insert(b"doc-three").unwrap();
    let err = engine
        .score_evaluated_obs(
            b"Q",
            b"ctx-123",
            &[ins.doc_id],
            [1u8; 16],
            0x0001,
            9,
            0,
            12_345,
        )
        .unwrap_err();
    assert_eq!(err, CodexError::InvalidInput("BREATH_PHASE_INVALID"));
    drop(engine);

    let idx = IndexReader::open(index_path.to_str().unwrap()).unwrap();
    assert_eq!(idx.get_offset(1), None);

    let _ = fs::remove_file(ledger_path);
    let _ = fs::remove_file(index_path);
}

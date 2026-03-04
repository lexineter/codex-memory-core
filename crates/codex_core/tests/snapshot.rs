use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use codex_core::engine::{Engine, EngineConfig, MutationDecision};
use codex_core::hash;
use codex_core::ledger::index::IndexReader;
use codex_core::ledger::reader::LedgerReader;
use codex_core::replay::{classify_error, verify_ledger, FailCode};
use codex_core::schema::{decode_event_payload, encode_event_payload, Event};
use codex_core::{
    DOMAIN_EVENT, FEATURE_LIFECYCLE_GOVERNANCE, FEATURE_RECURSIVE_PROJECTION,
    FEATURE_SCORE_COMMITMENT, FEATURE_SNAPSHOT_COMMITMENT,
};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_temp_path(name: &str, ext: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    p.push(format!(
        "codex_core_snapshot_{}_{}_{}.{}",
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
        quarantine_span_events: 10,
    }
}

fn snapshot_flags() -> u32 {
    FEATURE_RECURSIVE_PROJECTION
        | FEATURE_SCORE_COMMITMENT
        | FEATURE_LIFECYCLE_GOVERNANCE
        | FEATURE_SNAPSHOT_COMMITMENT
}

fn read_snapshot_event(
    ledger_path: &str,
    index_path: &str,
    event_index: u64,
    flags: u32,
) -> (
    codex_core::schema::SnapshotCommon,
    codex_core::schema::SnapshotFields,
    [u8; 32],
) {
    let idx = IndexReader::open(index_path).unwrap();
    let off = idx.get_offset(event_index).unwrap();
    let mut reader = LedgerReader::open(ledger_path).unwrap();
    let (payload, commit) = reader.read_raw_at(off).unwrap();
    let ev = decode_event_payload(&payload, flags).unwrap();
    match ev {
        Event::Snapshot { common, snap } => (common, snap, commit),
        _ => panic!("expected snapshot event"),
    }
}

#[test]
fn snapshot_replay_verifies() {
    let ledger_path = unique_temp_path("a_ledger", "bin");
    let index_path = unique_temp_path("a_index", "bin");
    let mut engine = Engine::create(
        ledger_path.to_str().unwrap(),
        index_path.to_str().unwrap(),
        None,
        snapshot_flags(),
        cfg(),
    )
    .unwrap();

    let d0 = engine
        .insert_cme(codex_core::cme::CmeInput::Text("doc-a"))
        .unwrap();
    let d1 = engine
        .insert_cme(codex_core::cme::CmeInput::Text("doc-b"))
        .unwrap();
    let q = engine
        .score_evaluated(b"doc-a", &[d0.doc_id, d1.doc_id])
        .unwrap();
    engine
        .lifecycle_mutation(
            q.ordered_doc_ids[0],
            MutationDecision::NoChange,
            q.candidate_commitment,
        )
        .unwrap();
    engine.emit_snapshot().unwrap();
    drop(engine);

    let report = verify_ledger(ledger_path.to_str().unwrap()).unwrap();
    assert_eq!(report.events_verified, 5);

    let (common, snap, _) = read_snapshot_event(
        ledger_path.to_str().unwrap(),
        index_path.to_str().unwrap(),
        4,
        snapshot_flags(),
    );
    assert_eq!(common.event_type, 0x04);
    assert_eq!(snap.snapshot_state_hash, common.pre_state_hash);
    assert_eq!(snap.snapshot_mmr_root, common.parent_auth_root);

    let _ = fs::remove_file(ledger_path);
    let _ = fs::remove_file(index_path);
}

#[test]
fn snapshot_convergence_between_two_replicas() {
    let ledger_a = unique_temp_path("b_a_ledger", "bin");
    let index_a = unique_temp_path("b_a_index", "bin");
    let ledger_b = unique_temp_path("b_b_ledger", "bin");
    let index_b = unique_temp_path("b_b_index", "bin");

    for (ledger, index) in [(&ledger_a, &index_a), (&ledger_b, &index_b)] {
        let mut e = Engine::create(
            ledger.to_str().unwrap(),
            index.to_str().unwrap(),
            None,
            snapshot_flags(),
            cfg(),
        )
        .unwrap();
        let d0 = e
            .insert_cme(codex_core::cme::CmeInput::Text("same-1"))
            .unwrap();
        let d1 = e
            .insert_cme(codex_core::cme::CmeInput::Text("same-2"))
            .unwrap();
        let q = e
            .score_evaluated(b"same-1", &[d0.doc_id, d1.doc_id])
            .unwrap();
        e.lifecycle_mutation(
            q.ordered_doc_ids[0],
            MutationDecision::NoChange,
            q.candidate_commitment,
        )
        .unwrap();
        e.emit_snapshot().unwrap();
    }

    let (_, snap_a, _) = read_snapshot_event(
        ledger_a.to_str().unwrap(),
        index_a.to_str().unwrap(),
        4,
        snapshot_flags(),
    );
    let (_, snap_b, _) = read_snapshot_event(
        ledger_b.to_str().unwrap(),
        index_b.to_str().unwrap(),
        4,
        snapshot_flags(),
    );
    assert_eq!(snap_a.snapshot_state_hash, snap_b.snapshot_state_hash);
    assert_eq!(snap_a.snapshot_mmr_root, snap_b.snapshot_mmr_root);
    assert_eq!(snap_a.doc_aggregate_hash, snap_b.doc_aggregate_hash);

    let _ = fs::remove_file(ledger_a);
    let _ = fs::remove_file(index_a);
    let _ = fs::remove_file(ledger_b);
    let _ = fs::remove_file(index_b);
}

#[test]
fn tamper_doc_aggregate_hash_fails() {
    let ledger_path = unique_temp_path("c_ledger", "bin");
    let index_path = unique_temp_path("c_index", "bin");
    let mut engine = Engine::create(
        ledger_path.to_str().unwrap(),
        index_path.to_str().unwrap(),
        None,
        snapshot_flags(),
        cfg(),
    )
    .unwrap();
    let d = engine
        .insert_cme(codex_core::cme::CmeInput::Text("tamper"))
        .unwrap();
    let q = engine.score_evaluated(b"tamper", &[d.doc_id]).unwrap();
    engine
        .lifecycle_mutation(d.doc_id, MutationDecision::NoChange, q.candidate_commitment)
        .unwrap();
    engine.emit_snapshot().unwrap();
    drop(engine);

    let idx = IndexReader::open(index_path.to_str().unwrap()).unwrap();
    let off = idx.get_offset(3).unwrap();
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&ledger_path)
        .unwrap();
    f.seek(SeekFrom::Start(off)).unwrap();
    let mut len_buf = [0u8; 4];
    f.read_exact(&mut len_buf).unwrap();
    let event_len = u32::from_be_bytes(len_buf) as usize;
    let payload_len = event_len - 32;
    let mut payload = vec![0u8; payload_len];
    let mut commitment = [0u8; 32];
    f.read_exact(&mut payload).unwrap();
    f.read_exact(&mut commitment).unwrap();

    let mut ev = decode_event_payload(&payload, snapshot_flags()).unwrap();
    match &mut ev {
        Event::Snapshot { snap, .. } => {
            let mut v = snap.doc_aggregate_hash.unwrap();
            v[0] ^= 0x01;
            snap.doc_aggregate_hash = Some(v);
        }
        _ => panic!("expected snapshot"),
    }
    let new_payload = encode_event_payload(&ev, snapshot_flags()).unwrap();
    assert_eq!(new_payload.len(), payload_len);
    let new_commitment = hash::hash_domain(DOMAIN_EVENT, &new_payload);
    f.seek(SeekFrom::Start(off + 4)).unwrap();
    f.write_all(&new_payload).unwrap();
    f.write_all(&new_commitment).unwrap();
    drop(f);

    let err = verify_ledger(ledger_path.to_str().unwrap()).unwrap_err();
    assert_eq!(classify_error(&err), FailCode::SnapshotMismatch);

    let _ = fs::remove_file(ledger_path);
    let _ = fs::remove_file(index_path);
}

#[test]
fn snapshot_requires_flag() {
    let ledger_path = unique_temp_path("d_ledger", "bin");
    let index_path = unique_temp_path("d_index", "bin");
    let mut engine = Engine::create(
        ledger_path.to_str().unwrap(),
        index_path.to_str().unwrap(),
        None,
        0,
        cfg(),
    )
    .unwrap();

    let err = engine.emit_snapshot().unwrap_err();
    assert_eq!(
        err,
        codex_core::CodexError::InvalidInput("SNAPSHOT_FEATURE_DISABLED")
    );

    let _ = fs::remove_file(ledger_path);
    let _ = fs::remove_file(index_path);
}

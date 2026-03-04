use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use codex_core::engine::{Engine, EngineConfig};
use codex_core::hash;
use codex_core::ledger::index::IndexReader;
use codex_core::ledger::reader::LedgerReader;
use codex_core::replay::{classify_error, verify_ledger, FailCode};
use codex_core::schema::{decode_event_payload, encode_event_payload, Event};
use codex_core::{
    DOMAIN_EVENT, FEATURE_DOC_MERKLE_STATE, FEATURE_SNAPSHOT_COMMITMENT,
    FEATURE_SNAPSHOT_DELTA_PROOF,
};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_temp_path(name: &str, ext: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    p.push(format!(
        "codex_core_snapshot_delta_{}_{}_{}.{}",
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

fn flags() -> u32 {
    FEATURE_SNAPSHOT_COMMITMENT | FEATURE_DOC_MERKLE_STATE | FEATURE_SNAPSHOT_DELTA_PROOF
}

fn read_snapshot_root(ledger_path: &str, index_path: &str, event_index: u64) -> [u8; 32] {
    let idx = IndexReader::open(index_path).unwrap();
    let off = idx.get_offset(event_index).unwrap();
    let mut r = LedgerReader::open(ledger_path).unwrap();
    let (payload, _) = r.read_raw_at(off).unwrap();
    let ev = decode_event_payload(&payload, flags()).unwrap();
    match ev {
        Event::Snapshot { snap, .. } => snap.snapshot_mmr_root,
        _ => panic!("expected snapshot"),
    }
}

fn read_delta_count(ledger_path: &str, index_path: &str, event_index: u64) -> u32 {
    let idx = IndexReader::open(index_path).unwrap();
    let off = idx.get_offset(event_index).unwrap();
    let mut r = LedgerReader::open(ledger_path).unwrap();
    let (payload, _) = r.read_raw_at(off).unwrap();
    let ev = decode_event_payload(&payload, flags()).unwrap();
    match ev {
        Event::SnapshotDelta { delta, .. } => delta.delta_doc_count,
        _ => panic!("expected snapshot delta"),
    }
}

#[test]
fn delta_zero_when_identical() {
    let ledger = unique_temp_path("a_ledger", "bin");
    let index = unique_temp_path("a_index", "bin");
    let mut e = Engine::create(
        ledger.to_str().unwrap(),
        index.to_str().unwrap(),
        None,
        flags(),
        cfg(),
    )
    .unwrap();
    let _ = e.insert_cme(codex_core::cme::CmeInput::Text("d1")).unwrap();
    let _ = e.insert_cme(codex_core::cme::CmeInput::Text("d2")).unwrap();
    e.emit_snapshot().unwrap();
    let s0 = read_snapshot_root(ledger.to_str().unwrap(), index.to_str().unwrap(), 2);
    e.emit_snapshot().unwrap();
    let s1 = read_snapshot_root(ledger.to_str().unwrap(), index.to_str().unwrap(), 3);
    e.emit_snapshot_delta(s0, s1).unwrap();
    drop(e);

    assert_eq!(
        read_delta_count(ledger.to_str().unwrap(), index.to_str().unwrap(), 4),
        0
    );
    verify_ledger(ledger.to_str().unwrap()).unwrap();

    let _ = fs::remove_file(ledger);
    let _ = fs::remove_file(index);
}

#[test]
fn delta_detects_single_doc_change() {
    let ledger = unique_temp_path("b_ledger", "bin");
    let index = unique_temp_path("b_index", "bin");
    let mut e = Engine::create(
        ledger.to_str().unwrap(),
        index.to_str().unwrap(),
        None,
        flags(),
        cfg(),
    )
    .unwrap();
    let _ = e.insert_cme(codex_core::cme::CmeInput::Text("d1")).unwrap();
    e.emit_snapshot().unwrap();
    let s0 = read_snapshot_root(ledger.to_str().unwrap(), index.to_str().unwrap(), 1);
    let _ = e.insert_cme(codex_core::cme::CmeInput::Text("d1")).unwrap(); // same doc_id, new state hash
    e.emit_snapshot().unwrap();
    let s1 = read_snapshot_root(ledger.to_str().unwrap(), index.to_str().unwrap(), 3);
    e.emit_snapshot_delta(s0, s1).unwrap();
    drop(e);

    assert_eq!(
        read_delta_count(ledger.to_str().unwrap(), index.to_str().unwrap(), 4),
        1
    );
    verify_ledger(ledger.to_str().unwrap()).unwrap();

    let _ = fs::remove_file(ledger);
    let _ = fs::remove_file(index);
}

#[test]
fn delta_detects_add_and_remove() {
    let mut base: codex_core::delta_proof::DocStore = vec![
        (hash::sha256(b"a"), hash::sha256(b"la")),
        (hash::sha256(b"b"), hash::sha256(b"lb")),
    ];
    let mut target: codex_core::delta_proof::DocStore = vec![
        (hash::sha256(b"b"), hash::sha256(b"lb")),
        (hash::sha256(b"c"), hash::sha256(b"lc")),
    ];
    base.sort_by(|a, b| a.0.cmp(&b.0));
    target.sort_by(|a, b| a.0.cmp(&b.0));
    let d = codex_core::delta_proof::compute_snapshot_delta(&base, &target);
    assert_eq!(d.delta_doc_count, 2);
}

#[test]
fn tamper_delta_root_fails() {
    let ledger = unique_temp_path("c_ledger", "bin");
    let index = unique_temp_path("c_index", "bin");
    let mut e = Engine::create(
        ledger.to_str().unwrap(),
        index.to_str().unwrap(),
        None,
        flags(),
        cfg(),
    )
    .unwrap();
    let _ = e.insert_cme(codex_core::cme::CmeInput::Text("q")).unwrap();
    e.emit_snapshot().unwrap();
    let s0 = read_snapshot_root(ledger.to_str().unwrap(), index.to_str().unwrap(), 1);
    let _ = e.insert_cme(codex_core::cme::CmeInput::Text("q")).unwrap();
    e.emit_snapshot().unwrap();
    let s1 = read_snapshot_root(ledger.to_str().unwrap(), index.to_str().unwrap(), 3);
    e.emit_snapshot_delta(s0, s1).unwrap();
    drop(e);

    let idx = IndexReader::open(index.to_str().unwrap()).unwrap();
    let off = idx.get_offset(4).unwrap();
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&ledger)
        .unwrap();
    f.seek(SeekFrom::Start(off)).unwrap();
    let mut len_buf = [0u8; 4];
    f.read_exact(&mut len_buf).unwrap();
    let payload_len = u32::from_be_bytes(len_buf) as usize - 32;
    let mut payload = vec![0u8; payload_len];
    let mut commitment = [0u8; 32];
    f.read_exact(&mut payload).unwrap();
    f.read_exact(&mut commitment).unwrap();
    let mut ev = decode_event_payload(&payload, flags()).unwrap();
    match &mut ev {
        Event::SnapshotDelta { delta, .. } => delta.delta_root[0] ^= 0x01,
        _ => panic!("expected snapshot delta"),
    }
    let new_payload = encode_event_payload(&ev, flags()).unwrap();
    let new_commit = hash::hash_domain(DOMAIN_EVENT, &new_payload);
    f.seek(SeekFrom::Start(off + 4)).unwrap();
    f.write_all(&new_payload).unwrap();
    f.write_all(&new_commit).unwrap();
    drop(f);

    let err = verify_ledger(ledger.to_str().unwrap()).unwrap_err();
    assert_eq!(classify_error(&err), FailCode::SnapshotDeltaMismatch);

    let _ = fs::remove_file(ledger);
    let _ = fs::remove_file(index);
}

#[test]
fn feature_flag_required() {
    let ledger = unique_temp_path("d_ledger", "bin");
    let index = unique_temp_path("d_index", "bin");
    let mut e = Engine::create(
        ledger.to_str().unwrap(),
        index.to_str().unwrap(),
        None,
        FEATURE_SNAPSHOT_COMMITMENT | FEATURE_DOC_MERKLE_STATE,
        cfg(),
    )
    .unwrap();
    let err = e.emit_snapshot_delta([0u8; 32], [0u8; 32]).unwrap_err();
    assert_eq!(
        err,
        codex_core::CodexError::InvalidInput("SNAPSHOT_DELTA_DISABLED")
    );

    let _ = fs::remove_file(ledger);
    let _ = fs::remove_file(index);
}

#[test]
fn replay_rejects_reversed_snapshot_delta_order() {
    let ledger = unique_temp_path("e_ledger", "bin");
    let index = unique_temp_path("e_index", "bin");
    let mut e = Engine::create(
        ledger.to_str().unwrap(),
        index.to_str().unwrap(),
        None,
        flags(),
        cfg(),
    )
    .unwrap();
    let _ = e.insert_cme(codex_core::cme::CmeInput::Text("d1")).unwrap();
    e.emit_snapshot().unwrap();
    let s0 = read_snapshot_root(ledger.to_str().unwrap(), index.to_str().unwrap(), 1);
    let _ = e.insert_cme(codex_core::cme::CmeInput::Text("d2")).unwrap();
    e.emit_snapshot().unwrap();
    let s1 = read_snapshot_root(ledger.to_str().unwrap(), index.to_str().unwrap(), 3);

    // Reverse order is malformed for replay semantics.
    e.emit_snapshot_delta(s1, s0).unwrap();
    drop(e);

    let err = verify_ledger(ledger.to_str().unwrap()).unwrap_err();
    assert_eq!(classify_error(&err), FailCode::SnapshotDeltaMismatch);

    let _ = fs::remove_file(ledger);
    let _ = fs::remove_file(index);
}

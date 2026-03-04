use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use codex_core::bytes;
use codex_core::cme::CmeInput;
use codex_core::engine::{Engine, EngineConfig};
use codex_core::hash;
use codex_core::ledger::index::IndexReader;
use codex_core::ledger::reader::LedgerReader;
use codex_core::replay::{classify_error, verify_ledger, FailCode};
use codex_core::schema::Event;
use codex_core::{DOMAIN_CONTENT, DOMAIN_DOC, DOMAIN_EVENT, DOMAIN_PROJECTION};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_temp_path(name: &str, ext: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    p.push(format!(
        "codex_core_doc_upsert_{}_{}_{}.{}",
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

fn recompute_doc_commitment(
    doc_id: &[u8; 32],
    content_commitment: &[u8; 32],
    projection_commitment: &[u8; 32],
) -> [u8; 32] {
    let mut payload = Vec::with_capacity(96);
    payload.extend_from_slice(doc_id);
    payload.extend_from_slice(content_commitment);
    payload.extend_from_slice(projection_commitment);
    hash::hash_domain(DOMAIN_DOC, &payload)
}

#[test]
fn doc_upsert_replay_and_commitments() {
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

    let _ = engine.insert_cme(CmeInput::Text("alpha")).unwrap();
    let _ = engine.insert_cme(CmeInput::Text("beta")).unwrap();
    let _ = engine.insert_cme(CmeInput::Text("gamma")).unwrap();
    drop(engine);

    let report = verify_ledger(ledger_path.to_str().unwrap()).unwrap();
    assert_eq!(report.events_verified, 3);

    let idx = IndexReader::open(index_path.to_str().unwrap()).unwrap();
    let mut reader = LedgerReader::open(ledger_path.to_str().unwrap()).unwrap();
    for event_index in 0..3u64 {
        let offset = idx.get_offset(event_index).unwrap();
        let (payload, _) = reader.read_raw_at(offset).unwrap();
        match codex_core::schema::decode_event_payload(&payload, 0).unwrap() {
            Event::DocUpsert { common, up } => {
                let content = hash::hash_domain(DOMAIN_CONTENT, &up.canon_bytes);
                let proj = hash::hash_domain(DOMAIN_PROJECTION, &up.projection_bytes);
                let doc = recompute_doc_commitment(&common.doc_id, &content, &proj);
                assert_eq!(content, up.content_commitment);
                assert_eq!(proj, up.projection_commitment);
                assert_eq!(doc, up.doc_commitment);
            }
            _ => panic!("expected doc upsert"),
        }
    }

    let _ = fs::remove_file(ledger_path);
    let _ = fs::remove_file(index_path);
}

#[test]
fn replay_fails_when_upsert_canon_tampered() {
    let ledger_path = unique_temp_path("tamper_ledger", "bin");
    let index_path = unique_temp_path("tamper_index", "bin");
    let mut engine = Engine::create(
        ledger_path.to_str().unwrap(),
        index_path.to_str().unwrap(),
        None,
        0,
        cfg(),
    )
    .unwrap();
    let _ = engine.insert_cme(CmeInput::Text("to-be-tampered")).unwrap();
    drop(engine);

    let idx = IndexReader::open(index_path.to_str().unwrap()).unwrap();
    let offset = idx.get_offset(0).unwrap();

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

    let mut at = 1 + 8 + 8 + 32 + 32 + 32 + 32 + 32 + 32 + 32;
    let canon_len = bytes::read_u32_be(&payload[at..at + 4]).unwrap() as usize;
    at += 4;
    assert!(canon_len > 0);
    payload[at] ^= 0x01;
    let new_event_commitment = hash::hash_domain(DOMAIN_EVENT, &payload);

    f.seek(SeekFrom::Start(offset + 4)).unwrap();
    f.write_all(&payload).unwrap();
    f.write_all(&new_event_commitment).unwrap();
    drop(f);

    let err = verify_ledger(ledger_path.to_str().unwrap()).unwrap_err();
    assert_eq!(classify_error(&err), FailCode::DocCommitmentMismatch);

    let _ = fs::remove_file(ledger_path);
    let _ = fs::remove_file(index_path);
}

use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use codex_core::bytes;
use codex_core::engine::{Engine, EngineConfig, MutationDecision};
use codex_core::hash;
use codex_core::ledger::index::IndexReader;
use codex_core::ledger::reader::LedgerReader;
use codex_core::replay::{classify_error, verify_ledger, FailCode};
use codex_core::schema::{decode_event_payload, encode_event_payload, Event};
use codex_core::{
    DOMAIN_PROJECTION, FEATURE_LIFECYCLE_GOVERNANCE, FEATURE_RECURSIVE_PROJECTION,
    FEATURE_SCORE_COMMITMENT,
};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_temp_path(name: &str, ext: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    p.push(format!(
        "codex_core_lifecycle_governance_{}_{}_{}.{}",
        std::process::id(),
        id,
        name,
        ext
    ));
    p
}

fn governance_flags() -> u32 {
    FEATURE_RECURSIVE_PROJECTION | FEATURE_SCORE_COMMITMENT | FEATURE_LIFECYCLE_GOVERNANCE
}

fn cfg() -> EngineConfig {
    EngineConfig {
        default_new_lifecycle_state: 0,
        default_new_representation_mode: 0,
        default_new_compressed_flag: 0,
        quarantine_span_events: 25,
    }
}

fn project(input: &[u8]) -> [i16; 128] {
    let mut expanded = [0u8; 256];
    let mut at = 0usize;
    for counter in 0u8..8u8 {
        let mut payload = Vec::with_capacity(1 + input.len());
        payload.push(counter);
        payload.extend_from_slice(input);
        let block = hash::hash_domain(DOMAIN_PROJECTION, &payload);
        expanded[at..at + 32].copy_from_slice(&block);
        at += 32;
    }
    let mut out = [0i16; 128];
    for i in 0..128usize {
        out[i] = i16::from_be_bytes([expanded[i * 2], expanded[i * 2 + 1]]);
    }
    out
}

fn dot(a: &[i16; 128], b: &[i16; 128]) -> i64 {
    let mut acc = 0i64;
    for i in 0..128usize {
        acc += (a[i] as i32 as i64) * (b[i] as i32 as i64);
    }
    acc
}

#[test]
fn governance_transition_high_score() {
    let ledger_path = unique_temp_path("high_ledger", "bin");
    let index_path = unique_temp_path("high_index", "bin");
    let mut engine = Engine::create(
        ledger_path.to_str().unwrap(),
        index_path.to_str().unwrap(),
        None,
        governance_flags(),
        cfg(),
    )
    .unwrap();

    let ins = engine
        .insert_cme(codex_core::cme::CmeInput::Text("alpha"))
        .unwrap();
    let query = b"alpha";
    let qr = engine.score_evaluated(query, &[ins.doc_id]).unwrap();
    assert!(qr.scores[0] >= 0);
    engine
        .lifecycle_mutation(
            ins.doc_id,
            MutationDecision::NoChange,
            qr.candidate_commitment,
        )
        .unwrap();
    drop(engine);

    let report = verify_ledger(ledger_path.to_str().unwrap()).unwrap();
    assert_eq!(report.events_verified, 3);

    let idx = IndexReader::open(index_path.to_str().unwrap()).unwrap();
    let offset = idx.get_offset(2).unwrap();
    let mut reader = LedgerReader::open(ledger_path.to_str().unwrap()).unwrap();
    let (payload, _) = reader.read_raw_at(offset).unwrap();
    let ev = decode_event_payload(&payload, governance_flags()).unwrap();
    match ev {
        Event::LifecycleMutation {
            life, governance, ..
        } => {
            assert_eq!(life.new_lifecycle_state, 1);
            assert_eq!(life.new_compressed_flag, 0);
            assert_eq!(life.quarantined_until_event_index, 0);
            assert!(governance.is_some());
        }
        _ => panic!("expected lifecycle event"),
    }

    let _ = fs::remove_file(ledger_path);
    let _ = fs::remove_file(index_path);
}

#[test]
fn governance_transition_low_score() {
    let ledger_path = unique_temp_path("low_ledger", "bin");
    let index_path = unique_temp_path("low_index", "bin");
    let mut engine = Engine::create(
        ledger_path.to_str().unwrap(),
        index_path.to_str().unwrap(),
        None,
        governance_flags(),
        cfg(),
    )
    .unwrap();

    let ins = engine
        .insert_cme(codex_core::cme::CmeInput::Text("beta"))
        .unwrap();
    let mut low_query = None;
    for i in 0..20_000u32 {
        let q = format!("low-{i}");
        let score = dot(&project(q.as_bytes()), &ins.projection);
        if score < -50_000 {
            low_query = Some(q);
            break;
        }
    }
    let query = low_query.expect("expected to find low-score query");
    let qr = engine
        .score_evaluated(query.as_bytes(), &[ins.doc_id])
        .unwrap();
    assert!(qr.scores[0] < -50_000);
    engine
        .lifecycle_mutation(
            ins.doc_id,
            MutationDecision::NoChange,
            qr.candidate_commitment,
        )
        .unwrap();
    drop(engine);

    let report = verify_ledger(ledger_path.to_str().unwrap()).unwrap();
    assert_eq!(report.events_verified, 3);

    let idx = IndexReader::open(index_path.to_str().unwrap()).unwrap();
    let offset = idx.get_offset(2).unwrap();
    let mut reader = LedgerReader::open(ledger_path.to_str().unwrap()).unwrap();
    let (payload, _) = reader.read_raw_at(offset).unwrap();
    let ev = decode_event_payload(&payload, governance_flags()).unwrap();
    match ev {
        Event::LifecycleMutation { life, .. } => {
            assert_eq!(life.new_lifecycle_state, 2);
            assert_eq!(life.new_compressed_flag, 1);
            assert!(life.quarantined_until_event_index > 0);
        }
        _ => panic!("expected lifecycle event"),
    }

    let _ = fs::remove_file(ledger_path);
    let _ = fs::remove_file(index_path);
}

#[test]
fn tamper_post_hash_fails() {
    let ledger_path = unique_temp_path("tamper_ledger", "bin");
    let index_path = unique_temp_path("tamper_index", "bin");
    let mut engine = Engine::create(
        ledger_path.to_str().unwrap(),
        index_path.to_str().unwrap(),
        None,
        governance_flags(),
        cfg(),
    )
    .unwrap();

    let ins = engine
        .insert_cme(codex_core::cme::CmeInput::Text("gamma"))
        .unwrap();
    let qr = engine.score_evaluated(b"gamma", &[ins.doc_id]).unwrap();
    engine
        .lifecycle_mutation(
            ins.doc_id,
            MutationDecision::NoChange,
            qr.candidate_commitment,
        )
        .unwrap();
    drop(engine);

    let idx = IndexReader::open(index_path.to_str().unwrap()).unwrap();
    let offset = idx.get_offset(2).unwrap();

    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&ledger_path)
        .unwrap();
    f.seek(SeekFrom::Start(offset)).unwrap();
    let mut len_buf = [0u8; 4];
    f.read_exact(&mut len_buf).unwrap();
    let event_len = bytes::read_u32_be(&len_buf).unwrap() as usize;
    let payload_len = event_len - 32;
    let mut payload = vec![0u8; payload_len];
    let mut commitment = [0u8; 32];
    f.read_exact(&mut payload).unwrap();
    f.read_exact(&mut commitment).unwrap();

    let mut ev = decode_event_payload(&payload, governance_flags()).unwrap();
    match &mut ev {
        Event::LifecycleMutation { governance, .. } => {
            let g = governance.as_mut().unwrap();
            g.post_doc_lifecycle_hash[0] ^= 0x01;
        }
        _ => panic!("expected lifecycle event"),
    }
    let new_payload = encode_event_payload(&ev, governance_flags()).unwrap();
    let new_commit = hash::hash_domain(codex_core::DOMAIN_EVENT, &new_payload);
    assert_eq!(new_payload.len(), payload_len);

    f.seek(SeekFrom::Start(offset + 4)).unwrap();
    f.write_all(&new_payload).unwrap();
    f.write_all(&new_commit).unwrap();
    drop(f);

    let err = verify_ledger(ledger_path.to_str().unwrap()).unwrap_err();
    assert_eq!(classify_error(&err), FailCode::LifecycleGovernanceViolation);

    let _ = fs::remove_file(ledger_path);
    let _ = fs::remove_file(index_path);
}

#[test]
fn lifecycle_requires_score() {
    let ledger_path = unique_temp_path("reqscore_ledger", "bin");
    let index_path = unique_temp_path("reqscore_index", "bin");
    let mut engine = Engine::create(
        ledger_path.to_str().unwrap(),
        index_path.to_str().unwrap(),
        None,
        governance_flags(),
        cfg(),
    )
    .unwrap();

    let ins = engine
        .insert_cme(codex_core::cme::CmeInput::Text("delta"))
        .unwrap();
    let err = engine
        .lifecycle_mutation(
            ins.doc_id,
            MutationDecision::NoChange,
            hash::sha256(b"cand-delta"),
        )
        .unwrap_err();
    assert_eq!(err, codex_core::CodexError::InvalidInput("NO_LAST_SCORE"));

    let _ = fs::remove_file(ledger_path);
    let _ = fs::remove_file(index_path);
}

#[test]
fn governance_flag_required_fields() {
    let ledger_path = unique_temp_path("nogov_ledger", "bin");
    let index_path = unique_temp_path("nogov_index", "bin");
    let mut engine = Engine::create(
        ledger_path.to_str().unwrap(),
        index_path.to_str().unwrap(),
        None,
        FEATURE_RECURSIVE_PROJECTION | FEATURE_SCORE_COMMITMENT,
        cfg(),
    )
    .unwrap();

    let ins = engine
        .insert_cme(codex_core::cme::CmeInput::Text("epsilon"))
        .unwrap();
    let qr = engine.score_evaluated(b"epsilon", &[ins.doc_id]).unwrap();
    engine
        .lifecycle_mutation(
            ins.doc_id,
            MutationDecision::SetCompressed { compressed: 1 },
            qr.candidate_commitment,
        )
        .unwrap();
    drop(engine);

    let idx = IndexReader::open(index_path.to_str().unwrap()).unwrap();
    let offset = idx.get_offset(2).unwrap();
    let mut reader = LedgerReader::open(ledger_path.to_str().unwrap()).unwrap();
    let (payload, _) = reader.read_raw_at(offset).unwrap();
    let ev = decode_event_payload(
        &payload,
        FEATURE_RECURSIVE_PROJECTION | FEATURE_SCORE_COMMITMENT,
    )
    .unwrap();
    match ev {
        Event::LifecycleMutation { governance, .. } => assert!(governance.is_none()),
        _ => panic!("expected lifecycle event"),
    }

    let report = verify_ledger(ledger_path.to_str().unwrap()).unwrap();
    assert_eq!(report.events_verified, 3);

    let _ = fs::remove_file(ledger_path);
    let _ = fs::remove_file(index_path);
}

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use codex_core::bytes;
use codex_core::engine::{Engine, EngineConfig, MutationDecision};
use codex_core::hash;
use codex_core::ledger::index::IndexReader;
use codex_core::ledger::reader::LedgerReader;
use codex_core::replay;
use codex_core::schema::{self, Event};
use codex_core::{DOMAIN_CANDIDATE, DOMAIN_PROJECTION};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_temp_path(name: &str, ext: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    p.push(format!(
        "codex_core_engine_{}_{}_{}.{}",
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
        quarantine_span_events: 50,
    }
}

fn project_spec(input: &[u8]) -> [i16; 128] {
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

fn dot_spec(a: &[i16; 128], b: &[i16; 128]) -> i64 {
    let mut acc = 0i64;
    for i in 0..128usize {
        acc += (a[i] as i32 as i64) * (b[i] as i32 as i64);
    }
    acc
}

fn cand_commit(ids: &[[u8; 32]]) -> [u8; 32] {
    let mut payload = Vec::with_capacity(4 + ids.len() * 32);
    bytes::write_u32_be(&mut payload, ids.len() as u32);
    for id in ids {
        payload.extend_from_slice(id);
    }
    hash::hash_domain(DOMAIN_CANDIDATE, &payload)
}

#[test]
fn projection_is_deterministic() {
    let ledger_path = unique_temp_path("proj_ledger", "bin");
    let index_path = unique_temp_path("proj_index", "bin");

    let mut engine = Engine::create(
        ledger_path.to_str().unwrap(),
        index_path.to_str().unwrap(),
        None,
        0,
        cfg(),
    )
    .unwrap();

    let a1 = engine.insert(b"hello").unwrap();
    let a2 = engine.insert(b"hello").unwrap();
    let b = engine.insert(b"hello!").unwrap();

    assert_eq!(a1.doc_id, a2.doc_id);
    assert_eq!(a1.projection, a2.projection);
    assert_ne!(a1.projection[0], b.projection[0]);

    drop(engine);
    let _ = fs::remove_file(ledger_path);
    let _ = fs::remove_file(index_path);
}

#[test]
fn scoring_and_sorting_is_deterministic() {
    let ledger_path = unique_temp_path("score_ledger", "bin");
    let index_path = unique_temp_path("score_index", "bin");

    let mut engine = Engine::create(
        ledger_path.to_str().unwrap(),
        index_path.to_str().unwrap(),
        None,
        0,
        cfg(),
    )
    .unwrap();

    let d0 = engine.insert(b"doc-a").unwrap();
    let d1 = engine.insert(b"doc-b").unwrap();
    let d2 = engine.insert(b"doc-c").unwrap();

    let candidates = vec![d2.doc_id, d0.doc_id, d1.doc_id];
    let result = engine.score_evaluated(b"query-x", &candidates).unwrap();

    let q = project_spec(b"query-x");
    let mut expected = [
        (d0.doc_id, dot_spec(&q, &d0.projection)),
        (d1.doc_id, dot_spec(&q, &d1.projection)),
        (d2.doc_id, dot_spec(&q, &d2.projection)),
    ];
    expected.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    let expected_ids: Vec<[u8; 32]> = expected.iter().map(|x| x.0).collect();
    let expected_scores: Vec<i64> = expected.iter().map(|x| x.1).collect();
    assert_eq!(result.ordered_doc_ids, expected_ids);
    assert_eq!(result.scores, expected_scores);
    assert_eq!(result.candidate_commitment, cand_commit(&expected_ids));

    drop(engine);
    let _ = fs::remove_file(ledger_path);
    let _ = fs::remove_file(index_path);
}

#[test]
fn engine_events_replay_verified() {
    let ledger_path = unique_temp_path("replay_ledger", "bin");
    let index_path = unique_temp_path("replay_index", "bin");

    let mut engine = Engine::create(
        ledger_path.to_str().unwrap(),
        index_path.to_str().unwrap(),
        None,
        0,
        cfg(),
    )
    .unwrap();

    let d0 = engine.insert(b"alpha").unwrap();
    let d1 = engine.insert(b"beta").unwrap();
    let qr = engine
        .score_evaluated(b"find-alpha", &[d1.doc_id, d0.doc_id])
        .unwrap();
    let target = qr.ordered_doc_ids[0];
    let _ = engine
        .lifecycle_mutation(
            target,
            MutationDecision::SetCompressed { compressed: 1 },
            qr.candidate_commitment,
        )
        .unwrap();
    drop(engine);

    let report = replay::verify_ledger(ledger_path.to_str().unwrap()).unwrap();
    assert_eq!(report.events_verified, 4);

    let _ = fs::remove_file(ledger_path);
    let _ = fs::remove_file(index_path);
}

#[test]
fn mutation_state_delta_encoding() {
    let ledger_path = unique_temp_path("delta_ledger", "bin");
    let index_path = unique_temp_path("delta_index", "bin");

    let mut engine = Engine::create(
        ledger_path.to_str().unwrap(),
        index_path.to_str().unwrap(),
        None,
        0,
        cfg(),
    )
    .unwrap();

    let ins = engine.insert(b"delta-doc").unwrap();
    let cand = hash::sha256(b"cand-delta");
    let _ = engine
        .lifecycle_mutation(
            ins.doc_id,
            MutationDecision::Full {
                life_state: 7,
                repr_mode: 3,
                compressed: 1,
                quarantine_until: 42,
            },
            cand,
        )
        .unwrap();
    drop(engine);

    let idx = IndexReader::open(index_path.to_str().unwrap()).unwrap();
    let offset = idx.get_offset(1).unwrap();
    let mut reader = LedgerReader::open(ledger_path.to_str().unwrap()).unwrap();
    let (payload, _) = reader.read_raw_at(offset).unwrap();
    let event = schema::decode_event_payload(&payload, 0).unwrap();

    match event {
        Event::LifecycleMutation { common, life, .. } => {
            assert_eq!(life.new_lifecycle_state, 7);
            assert_eq!(life.new_representation_mode, 3);
            assert_eq!(life.new_compressed_flag, 1);
            assert_eq!(life.quarantined_until_event_index, 42);

            assert_eq!(common.state_delta[0], 7);
            assert_eq!(common.state_delta[1], 3);
            assert_eq!(common.state_delta[2], 1);
            let mut q = [0u8; 8];
            q.copy_from_slice(&common.state_delta[3..11]);
            assert_eq!(u64::from_be_bytes(q), 42);
            assert!(common.state_delta[11..].iter().all(|b| *b == 0));
        }
        _ => panic!("expected lifecycle mutation"),
    }

    let _ = fs::remove_file(ledger_path);
    let _ = fs::remove_file(index_path);
}

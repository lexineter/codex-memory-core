use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use codex_core::hash;
use codex_core::ledger::header::LedgerHeaderV1;
use codex_core::ledger::index::IndexReader;
use codex_core::ledger::json_mirror::hex_lower;
use codex_core::ledger::reader::LedgerReader;
use codex_core::ledger::writer::LedgerWriter;
use codex_core::schema::{
    Event, EventCommon, LifecycleFields, EVENT_TYPE_LIFECYCLE_MUTATION, EVENT_TYPE_SCORE_EVALUATED,
};
use codex_core::{
    CodexError, DOMAIN_EVENT, FEATURE_JSON_MIRROR, FEATURE_RECURSIVE_PROJECTION,
    FEATURE_SCORE_PROOFS,
};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_temp_path(name: &str, ext: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    p.push(format!(
        "codex_core_{}_{}_{}.{}",
        std::process::id(),
        id,
        name,
        ext
    ));
    p
}

fn make_state_delta(seed: u8) -> [u8; 128] {
    let mut out = [0u8; 128];
    for (i, b) in out.iter_mut().enumerate() {
        *b = seed.wrapping_add(i as u8);
    }
    out
}

fn make_common(event_type: u8, event_index: u64, doc_seed: u8) -> EventCommon {
    EventCommon {
        event_type,
        timestamp: 1_700_000_000 + event_index,
        event_index,
        doc_id: hash::sha256(&[b'd', b'o', b'c', doc_seed]),
        parent_auth_root: hash::sha256(&[b'p', doc_seed, event_index as u8]),
        pre_state_hash: hash::sha256(&[b's', doc_seed, event_index as u8]),
        candidate_commitment: hash::sha256(&[b'c', doc_seed, event_index as u8]),
        state_delta: make_state_delta(doc_seed.wrapping_add(event_index as u8)),
    }
}

#[test]
fn header_roundtrip_and_commitment() {
    let hdr = LedgerHeaderV1::default_v1(FEATURE_JSON_MIRROR);
    let enc = hdr.encode();
    let dec = LedgerHeaderV1::decode(&enc).unwrap();
    assert_eq!(hdr, dec);
    dec.verify_commitment().unwrap();

    let mut tampered = enc.clone();
    let reserved_start = 28usize;
    tampered[reserved_start] ^= 0x01;
    let err = LedgerHeaderV1::decode(&tampered).unwrap_err();
    assert_eq!(
        err,
        CodexError::IntegrityError("LEDGER_HEADER_RESERVED_NONZERO")
    );
}

#[test]
fn header_rejects_score_proofs_without_score_commitment() {
    let hdr = LedgerHeaderV1::default_v1(FEATURE_RECURSIVE_PROJECTION | FEATURE_SCORE_PROOFS);
    let err = LedgerHeaderV1::decode(&hdr.encode()).unwrap_err();
    assert_eq!(
        err,
        CodexError::InvalidInput("SCORE_PROOFS_REQUIRES_SCORE_COMMITMENT")
    );
}

#[test]
fn append_and_readback_integrity() {
    let ledger_path = unique_temp_path("ledger_integrity", "bin");
    let index_path = unique_temp_path("index_integrity", "bin");
    let json_path = unique_temp_path("ledger_integrity", "jsonl");

    let mut writer = LedgerWriter::create(
        ledger_path.to_str().unwrap(),
        index_path.to_str().unwrap(),
        Some(json_path.to_str().unwrap()),
        FEATURE_JSON_MIRROR,
    )
    .unwrap();

    let mut expected_events = Vec::new();
    let mut append_results = Vec::new();
    let mut expected_latest = Vec::<([u8; 32], u64)>::new();
    for i in 0..10u64 {
        let doc_seed = (i % 3) as u8;
        let ev = if i % 2 == 0 {
            Event::ScoreEvaluated {
                common: make_common(EVENT_TYPE_SCORE_EVALUATED, i, doc_seed),
                extra: None,
                ordered: None,
                score: None,
                observer: None,
            }
        } else {
            Event::LifecycleMutation {
                common: make_common(EVENT_TYPE_LIFECYCLE_MUTATION, i, doc_seed),
                life: LifecycleFields {
                    new_lifecycle_state: (i as u8) % 5,
                    new_representation_mode: (i as u8) % 7,
                    new_compressed_flag: (i as u8) % 2,
                    quarantined_until_event_index: i + 100,
                },
                governance: None,
                observer: None,
            }
        };
        let doc = match &ev {
            Event::DocUpsert { .. } => unreachable!(),
            Event::ScoreEvaluated { common, .. } => common.doc_id,
            Event::LifecycleMutation { common, .. } => common.doc_id,
            Event::Snapshot { .. } => unreachable!(),
            Event::DivergenceLocator { .. } => unreachable!(),
            Event::SnapshotDelta { .. } => unreachable!(),
            Event::ProtocolLock { .. } => unreachable!(),
        };
        let mut updated = false;
        for (seen_doc, seen_idx) in &mut expected_latest {
            if *seen_doc == doc {
                *seen_idx = i;
                updated = true;
                break;
            }
        }
        if !updated {
            expected_latest.push((doc, i));
        }
        append_results.push(writer.append(&ev).unwrap());
        expected_events.push(ev);
    }
    drop(writer);

    let mut reader = LedgerReader::open(ledger_path.to_str().unwrap()).unwrap();
    let mut read_back = Vec::new();
    let mut offsets = Vec::new();
    for item in reader.iter() {
        let (offset, ev, commitment) = item.unwrap();
        let payload = codex_core::schema::encode_event_payload(&ev, 0).unwrap();
        let computed = hash::hash_domain(DOMAIN_EVENT, &payload);
        assert_eq!(computed, commitment);
        offsets.push(offset);
        read_back.push((ev, commitment));
    }
    assert_eq!(read_back.len(), expected_events.len());

    for i in 0..expected_events.len() {
        assert_eq!(read_back[i].0, expected_events[i]);
        assert_eq!(read_back[i].1, append_results[i].event_commitment);
        assert_eq!(offsets[i], append_results[i].ledger_offset);
        if i > 0 {
            assert!(offsets[i] > offsets[i - 1]);
        }
    }

    let idx = IndexReader::open(index_path.to_str().unwrap()).unwrap();
    for i in 0..10u64 {
        assert_eq!(
            idx.get_offset(i),
            Some(append_results[i as usize].ledger_offset)
        );
    }
    for (doc_id, latest_idx) in expected_latest {
        assert_eq!(idx.get_latest(doc_id), Some(latest_idx));
    }

    let _ = fs::remove_file(ledger_path);
    let _ = fs::remove_file(index_path);
    let _ = fs::remove_file(json_path);
}

#[test]
fn json_mirror_is_deterministic() {
    let ledger_path = unique_temp_path("ledger_json", "bin");
    let index_path = unique_temp_path("index_json", "bin");
    let json_path = unique_temp_path("ledger_json", "jsonl");

    let mut writer = LedgerWriter::create(
        ledger_path.to_str().unwrap(),
        index_path.to_str().unwrap(),
        Some(json_path.to_str().unwrap()),
        FEATURE_JSON_MIRROR,
    )
    .unwrap();

    let ev0 = Event::ScoreEvaluated {
        common: make_common(EVENT_TYPE_SCORE_EVALUATED, 0, 1),
        extra: None,
        ordered: None,
        score: None,
        observer: None,
    };
    let ev1 = Event::LifecycleMutation {
        common: make_common(EVENT_TYPE_LIFECYCLE_MUTATION, 1, 2),
        life: LifecycleFields {
            new_lifecycle_state: 4,
            new_representation_mode: 2,
            new_compressed_flag: 1,
            quarantined_until_event_index: 123,
        },
        governance: None,
        observer: None,
    };
    let ev2 = Event::ScoreEvaluated {
        common: make_common(EVENT_TYPE_SCORE_EVALUATED, 2, 3),
        extra: None,
        ordered: None,
        score: None,
        observer: None,
    };

    let r0 = writer.append(&ev0).unwrap();
    let r1 = writer.append(&ev1).unwrap();
    let r2 = writer.append(&ev2).unwrap();
    drop(writer);

    let content = fs::read_to_string(&json_path).unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines.len(), 3);

    let c0 = match &ev0 {
        Event::ScoreEvaluated { common, .. } => common,
        _ => unreachable!(),
    };
    let c1 = match &ev1 {
        Event::LifecycleMutation { common, .. } => common,
        _ => unreachable!(),
    };
    let l1 = match &ev1 {
        Event::LifecycleMutation { life, .. } => life,
        _ => unreachable!(),
    };
    let c2 = match &ev2 {
        Event::ScoreEvaluated { common, .. } => common,
        _ => unreachable!(),
    };

    let expected0 = format!(
        "{{\"doc_id\":\"{}\",\"event_commitment\":\"{}\",\"event_index\":{},\"event_type\":{},\"root_after\":\"{}\",\"timestamp\":{}}}",
        hex_lower(&c0.doc_id),
        hex_lower(&r0.event_commitment),
        c0.event_index,
        c0.event_type,
        hex_lower(&r0.root_after),
        c0.timestamp
    );
    let expected1 = format!(
        "{{\"doc_id\":\"{}\",\"event_commitment\":\"{}\",\"event_index\":{},\"event_type\":{},\"new_compressed_flag\":{},\"new_lifecycle_state\":{},\"new_representation_mode\":{},\"quarantined_until_event_index\":{},\"root_after\":\"{}\",\"timestamp\":{}}}",
        hex_lower(&c1.doc_id),
        hex_lower(&r1.event_commitment),
        c1.event_index,
        c1.event_type,
        l1.new_compressed_flag,
        l1.new_lifecycle_state,
        l1.new_representation_mode,
        l1.quarantined_until_event_index,
        hex_lower(&r1.root_after),
        c1.timestamp
    );
    let expected2 = format!(
        "{{\"doc_id\":\"{}\",\"event_commitment\":\"{}\",\"event_index\":{},\"event_type\":{},\"root_after\":\"{}\",\"timestamp\":{}}}",
        hex_lower(&c2.doc_id),
        hex_lower(&r2.event_commitment),
        c2.event_index,
        c2.event_type,
        hex_lower(&r2.root_after),
        c2.timestamp
    );

    assert_eq!(lines[0], expected0);
    assert_eq!(lines[1], expected1);
    assert_eq!(lines[2], expected2);
    assert!(!lines[0].contains(' '));
    assert!(!lines[1].contains(' '));
    assert!(!lines[2].contains(' '));

    let _ = fs::remove_file(ledger_path);
    let _ = fs::remove_file(index_path);
    let _ = fs::remove_file(json_path);
}

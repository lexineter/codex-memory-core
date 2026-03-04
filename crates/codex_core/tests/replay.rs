use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use codex_core::bytes;
use codex_core::hash;
use codex_core::ledger::index::IndexReader;
use codex_core::ledger::writer::LedgerWriter;
use codex_core::mmr::Mmr;
use codex_core::replay::{classify_error, verify_ledger, FailCode};
use codex_core::schema::{
    encode_event_payload, Event, EventCommon, LifecycleFields, EVENT_TYPE_LIFECYCLE_MUTATION,
    EVENT_TYPE_SCORE_EVALUATED,
};
use codex_core::{DOMAIN_EVENT, DOMAIN_PRESTATE};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_temp_path(name: &str, ext: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    p.push(format!(
        "codex_core_replay_{}_{}_{}.{}",
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

fn common_for(
    event_type: u8,
    event_index: u64,
    parent_auth_root: [u8; 32],
    pre_state_hash: [u8; 32],
    candidate_commitment: [u8; 32],
) -> EventCommon {
    EventCommon {
        event_type,
        timestamp: 1_800_000_000 + event_index,
        event_index,
        doc_id: hash::sha256(format!("doc-{event_index}").as_bytes()),
        parent_auth_root,
        pre_state_hash,
        candidate_commitment,
        state_delta: make_state_delta(event_index as u8),
    }
}

fn build_valid_ledger(ledger_path: &str, index_path: &str, n: u64) -> ([u8; 32], [u8; 32]) {
    let mut writer = LedgerWriter::create(ledger_path, index_path, None, 0).unwrap();
    let mut mmr = Mmr::new();
    let mut state_hash = hash::hash_domain(DOMAIN_PRESTATE, b"");

    for i in 0..n {
        let parent_auth_root = mmr.root();
        let candidate_commitment = hash::sha256(format!("cand-{i}").as_bytes());
        let event = if i % 2 == 0 {
            Event::ScoreEvaluated {
                common: common_for(
                    EVENT_TYPE_SCORE_EVALUATED,
                    i,
                    parent_auth_root,
                    state_hash,
                    candidate_commitment,
                ),
                extra: None,
                ordered: None,
                score: None,
                observer: None,
            }
        } else {
            Event::LifecycleMutation {
                common: common_for(
                    EVENT_TYPE_LIFECYCLE_MUTATION,
                    i,
                    parent_auth_root,
                    state_hash,
                    candidate_commitment,
                ),
                life: LifecycleFields {
                    new_lifecycle_state: (i as u8) % 5,
                    new_representation_mode: (i as u8) % 7,
                    new_compressed_flag: (i as u8) % 2,
                    quarantined_until_event_index: i + 10,
                },
                governance: None,
                observer: None,
            }
        };
        let payload = encode_event_payload(&event, 0).unwrap();
        let commitment = hash::hash_domain(DOMAIN_EVENT, &payload);
        writer.append(&event).unwrap();
        mmr.append(commitment);
        let mut s = Vec::with_capacity(64);
        s.extend_from_slice(&state_hash);
        s.extend_from_slice(&commitment);
        state_hash = hash::hash_domain(DOMAIN_PRESTATE, &s);
    }
    drop(writer);
    (mmr.root(), state_hash)
}

#[test]
fn replay_verify_success() {
    let ledger_path = unique_temp_path("ok_ledger", "bin");
    let index_path = unique_temp_path("ok_index", "bin");
    let (expected_root, expected_state) = build_valid_ledger(
        ledger_path.to_str().unwrap(),
        index_path.to_str().unwrap(),
        10,
    );

    let report = verify_ledger(ledger_path.to_str().unwrap()).unwrap();
    assert_eq!(report.events_verified, 10);
    assert_eq!(report.final_root, expected_root);
    assert_eq!(report.final_state_hash, expected_state);

    let _ = fs::remove_file(ledger_path);
    let _ = fs::remove_file(index_path);
}

#[test]
fn replay_fails_when_commitment_tampered() {
    let ledger_path = unique_temp_path("tamper_ledger", "bin");
    let index_path = unique_temp_path("tamper_index", "bin");
    build_valid_ledger(
        ledger_path.to_str().unwrap(),
        index_path.to_str().unwrap(),
        10,
    );

    let idx = IndexReader::open(index_path.to_str().unwrap()).unwrap();
    let target_offset = idx.get_offset(4).unwrap();

    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&ledger_path)
        .unwrap();
    f.seek(SeekFrom::Start(target_offset)).unwrap();
    let mut len_buf = [0u8; 4];
    f.read_exact(&mut len_buf).unwrap();
    let event_len = bytes::read_u32_be(&len_buf).unwrap() as u64;
    let tamper_at = target_offset + 4 + event_len - 1;
    f.seek(SeekFrom::Start(tamper_at)).unwrap();
    let mut b = [0u8; 1];
    f.read_exact(&mut b).unwrap();
    b[0] ^= 0x01;
    f.seek(SeekFrom::Start(tamper_at)).unwrap();
    f.write_all(&b).unwrap();
    drop(f);

    let err = verify_ledger(ledger_path.to_str().unwrap()).unwrap_err();
    assert_eq!(classify_error(&err), FailCode::EventCommitmentMismatch);

    let _ = fs::remove_file(ledger_path);
    let _ = fs::remove_file(index_path);
}

#[test]
fn replay_fails_when_parent_root_wrong() {
    let ledger_path = unique_temp_path("bad_parent_ledger", "bin");
    let index_path = unique_temp_path("bad_parent_index", "bin");
    let mut writer = LedgerWriter::create(
        ledger_path.to_str().unwrap(),
        index_path.to_str().unwrap(),
        None,
        0,
    )
    .unwrap();

    let mut mmr = Mmr::new();
    let mut state_hash = hash::hash_domain(DOMAIN_PRESTATE, b"");
    for i in 0..4u64 {
        let mut parent = mmr.root();
        if i == 2 {
            parent[0] ^= 0x01;
        }
        let event = Event::ScoreEvaluated {
            common: common_for(
                EVENT_TYPE_SCORE_EVALUATED,
                i,
                parent,
                state_hash,
                hash::sha256(format!("cand-{i}").as_bytes()),
            ),
            extra: None,
            ordered: None,
            score: None,
            observer: None,
        };
        let payload = encode_event_payload(&event, 0).unwrap();
        let commitment = hash::hash_domain(DOMAIN_EVENT, &payload);
        writer.append(&event).unwrap();
        mmr.append(commitment);
        let mut s = Vec::with_capacity(64);
        s.extend_from_slice(&state_hash);
        s.extend_from_slice(&commitment);
        state_hash = hash::hash_domain(DOMAIN_PRESTATE, &s);
    }
    drop(writer);

    let err = verify_ledger(ledger_path.to_str().unwrap()).unwrap_err();
    assert_eq!(classify_error(&err), FailCode::ParentAuthRootMismatch);

    let _ = fs::remove_file(ledger_path);
    let _ = fs::remove_file(index_path);
}

#[test]
fn replay_fails_when_candidate_zero() {
    let ledger_path = unique_temp_path("bad_cand_ledger", "bin");
    let index_path = unique_temp_path("bad_cand_index", "bin");
    let mut writer = LedgerWriter::create(
        ledger_path.to_str().unwrap(),
        index_path.to_str().unwrap(),
        None,
        0,
    )
    .unwrap();

    let mut mmr = Mmr::new();
    let mut state_hash = hash::hash_domain(DOMAIN_PRESTATE, b"");
    for i in 0..4u64 {
        let candidate = if i == 1 {
            [0u8; 32]
        } else {
            hash::sha256(format!("cand-{i}").as_bytes())
        };
        let event = Event::ScoreEvaluated {
            common: common_for(
                EVENT_TYPE_SCORE_EVALUATED,
                i,
                mmr.root(),
                state_hash,
                candidate,
            ),
            extra: None,
            ordered: None,
            score: None,
            observer: None,
        };
        let payload = encode_event_payload(&event, 0).unwrap();
        let commitment = hash::hash_domain(DOMAIN_EVENT, &payload);
        writer.append(&event).unwrap();
        mmr.append(commitment);
        let mut s = Vec::with_capacity(64);
        s.extend_from_slice(&state_hash);
        s.extend_from_slice(&commitment);
        state_hash = hash::hash_domain(DOMAIN_PRESTATE, &s);
    }
    drop(writer);

    let err = verify_ledger(ledger_path.to_str().unwrap()).unwrap_err();
    assert_eq!(classify_error(&err), FailCode::CandidateCommitmentZero);

    let _ = fs::remove_file(ledger_path);
    let _ = fs::remove_file(index_path);
}

#[test]
fn replay_fails_when_pre_state_wrong() {
    let ledger_path = unique_temp_path("bad_state_ledger", "bin");
    let index_path = unique_temp_path("bad_state_index", "bin");
    let mut writer = LedgerWriter::create(
        ledger_path.to_str().unwrap(),
        index_path.to_str().unwrap(),
        None,
        0,
    )
    .unwrap();

    let mut mmr = Mmr::new();
    let mut state_hash = hash::hash_domain(DOMAIN_PRESTATE, b"");
    for i in 0..4u64 {
        let mut pre = state_hash;
        if i == 3 {
            pre[0] ^= 0x01;
        }
        let event = Event::ScoreEvaluated {
            common: common_for(
                EVENT_TYPE_SCORE_EVALUATED,
                i,
                mmr.root(),
                pre,
                hash::sha256(format!("cand-{i}").as_bytes()),
            ),
            extra: None,
            ordered: None,
            score: None,
            observer: None,
        };
        let payload = encode_event_payload(&event, 0).unwrap();
        let commitment = hash::hash_domain(DOMAIN_EVENT, &payload);
        writer.append(&event).unwrap();
        mmr.append(commitment);
        let mut s = Vec::with_capacity(64);
        s.extend_from_slice(&state_hash);
        s.extend_from_slice(&commitment);
        state_hash = hash::hash_domain(DOMAIN_PRESTATE, &s);
    }
    drop(writer);

    let err = verify_ledger(ledger_path.to_str().unwrap()).unwrap_err();
    assert_eq!(classify_error(&err), FailCode::PreStateHashMismatch);

    let _ = fs::remove_file(ledger_path);
    let _ = fs::remove_file(index_path);
}

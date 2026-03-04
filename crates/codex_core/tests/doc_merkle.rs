use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use codex_core::doc_proof::{
    doc_leaf_hash, verify_doc_non_membership, verify_doc_proof, DocNonMembershipProof,
};
use codex_core::engine::{Engine, EngineConfig};
use codex_core::hash;
use codex_core::ledger::index::IndexReader;
use codex_core::ledger::reader::LedgerReader;
use codex_core::replay::{classify_error, verify_ledger, FailCode};
use codex_core::schema::{decode_event_payload, encode_event_payload, Event};
use codex_core::{
    DOMAIN_DOCSTATE, DOMAIN_EVENT, FEATURE_DOC_MERKLE_STATE, FEATURE_SNAPSHOT_COMMITMENT,
};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_temp_path(name: &str, ext: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    p.push(format!(
        "codex_core_doc_merkle_{}_{}_{}.{}",
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
    FEATURE_SNAPSHOT_COMMITMENT | FEATURE_DOC_MERKLE_STATE
}

#[test]
fn merkle_root_matches_replay() {
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
    for txt in ["d1", "d2", "d3"] {
        let _ = e.insert_cme(codex_core::cme::CmeInput::Text(txt)).unwrap();
    }
    e.emit_snapshot().unwrap();
    let expected_root = e.current_doc_merkle_root();
    drop(e);

    verify_ledger(ledger.to_str().unwrap()).unwrap();
    let idx = IndexReader::open(index.to_str().unwrap()).unwrap();
    let off = idx.get_offset(3).unwrap();
    let mut r = LedgerReader::open(ledger.to_str().unwrap()).unwrap();
    let (payload, _) = r.read_raw_at(off).unwrap();
    let ev = decode_event_payload(&payload, flags()).unwrap();
    match ev {
        Event::Snapshot { snap, .. } => {
            assert_eq!(snap.doc_count, Some(3));
            assert_eq!(snap.doc_merkle_root, Some(expected_root));
        }
        _ => panic!("expected snapshot"),
    }

    let _ = fs::remove_file(ledger);
    let _ = fs::remove_file(index);
}

#[test]
fn inclusion_proof_valid() {
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
    let mut ids = Vec::new();
    for txt in ["a", "b", "c", "d", "e"] {
        ids.push(
            e.insert_cme(codex_core::cme::CmeInput::Text(txt))
                .unwrap()
                .doc_id,
        );
    }
    let target = ids[3];
    let proof = e.generate_doc_proof(target).unwrap();
    let root = e.current_doc_merkle_root();
    assert!(verify_doc_proof(root, &proof).unwrap());
    let _ = e.emit_snapshot();
    drop(e);

    let _ = fs::remove_file(ledger);
    let _ = fs::remove_file(index);
}

#[test]
fn tamper_leaf_fails() {
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
    let id = e
        .insert_cme(codex_core::cme::CmeInput::Text("x"))
        .unwrap()
        .doc_id;
    let mut proof = e.generate_doc_proof(id).unwrap();
    let root = e.current_doc_merkle_root();
    proof.leaf_hash[0] ^= 0x01;
    assert!(!verify_doc_proof(root, &proof).unwrap());
    drop(e);

    let _ = fs::remove_file(ledger);
    let _ = fs::remove_file(index);
}

#[test]
fn non_membership_proof_valid() {
    let ledger = unique_temp_path("d_ledger", "bin");
    let index = unique_temp_path("d_index", "bin");
    let mut e = Engine::create(
        ledger.to_str().unwrap(),
        index.to_str().unwrap(),
        None,
        flags(),
        cfg(),
    )
    .unwrap();
    let mut ids = Vec::new();
    for txt in ["k1", "k2", "k3"] {
        ids.push(
            e.insert_cme(codex_core::cme::CmeInput::Text(txt))
                .unwrap()
                .doc_id,
        );
    }
    ids.sort();
    let left = ids[0];
    let right = ids[1];
    let mut target = left;
    loop {
        let mut i = 31usize;
        loop {
            target[i] = target[i].wrapping_add(1);
            if target[i] != 0 || i == 0 {
                break;
            }
            i -= 1;
        }
        if left < target && target < right {
            break;
        }
    }
    let left_proof = e.generate_doc_proof(left).unwrap();
    let right_proof = e.generate_doc_proof(right).unwrap();
    let non = DocNonMembershipProof {
        target_doc_id: target,
        left_proof: Some(left_proof),
        right_proof: Some(right_proof),
    };
    assert!(verify_doc_non_membership(e.current_doc_merkle_root(), &non).unwrap());
    drop(e);

    let _ = fs::remove_file(ledger);
    let _ = fs::remove_file(index);
}

#[test]
fn snapshot_requires_flag() {
    let ledger = unique_temp_path("e_ledger", "bin");
    let index = unique_temp_path("e_index", "bin");
    let mut e = Engine::create(
        ledger.to_str().unwrap(),
        index.to_str().unwrap(),
        None,
        FEATURE_SNAPSHOT_COMMITMENT,
        cfg(),
    )
    .unwrap();
    let id = e
        .insert_cme(codex_core::cme::CmeInput::Text("z"))
        .unwrap()
        .doc_id;
    let err = e.generate_doc_proof(id).unwrap_err();
    assert_eq!(
        err,
        codex_core::CodexError::InvalidInput("DOC_MERKLE_DISABLED")
    );
    drop(e);

    let _ = fs::remove_file(ledger);
    let _ = fs::remove_file(index);
}

#[test]
fn tamper_doc_merkle_root_fails() {
    let ledger = unique_temp_path("f_ledger", "bin");
    let index = unique_temp_path("f_index", "bin");
    let mut e = Engine::create(
        ledger.to_str().unwrap(),
        index.to_str().unwrap(),
        None,
        flags(),
        cfg(),
    )
    .unwrap();
    let _ = e.insert_cme(codex_core::cme::CmeInput::Text("z1")).unwrap();
    e.emit_snapshot().unwrap();
    drop(e);

    let idx = IndexReader::open(index.to_str().unwrap()).unwrap();
    let off = idx.get_offset(1).unwrap();
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&ledger)
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
    let mut ev = decode_event_payload(&payload, flags()).unwrap();
    match &mut ev {
        Event::Snapshot { snap, .. } => {
            let mut r = snap.doc_merkle_root.unwrap();
            r[0] ^= 0x01;
            snap.doc_merkle_root = Some(r);
        }
        _ => panic!("expected snapshot"),
    }
    let new_payload = encode_event_payload(&ev, flags()).unwrap();
    let new_commitment = hash::hash_domain(DOMAIN_EVENT, &new_payload);
    f.seek(SeekFrom::Start(off + 4)).unwrap();
    f.write_all(&new_payload).unwrap();
    f.write_all(&new_commitment).unwrap();
    drop(f);

    let err = verify_ledger(ledger.to_str().unwrap()).unwrap_err();
    assert_eq!(classify_error(&err), FailCode::DocMerkleRootMismatch);

    let _ = fs::remove_file(ledger);
    let _ = fs::remove_file(index);
}

#[test]
fn doc_leaf_hash_matches_replay_materialization() {
    let ledger = unique_temp_path("g_ledger", "bin");
    let index = unique_temp_path("g_index", "bin");
    let mut e = Engine::create(
        ledger.to_str().unwrap(),
        index.to_str().unwrap(),
        None,
        flags(),
        cfg(),
    )
    .unwrap();
    let doc_id = e
        .insert_cme(codex_core::cme::CmeInput::Text("leaf-cross-check"))
        .unwrap()
        .doc_id;
    let proof = e.generate_doc_proof(doc_id).unwrap();
    drop(e);

    let idx = IndexReader::open(index.to_str().unwrap()).unwrap();
    let off = idx.get_offset(0).unwrap();
    let mut reader = LedgerReader::open(ledger.to_str().unwrap()).unwrap();
    let (event, commitment) = reader.read_at(off).unwrap();
    let up = match event {
        Event::DocUpsert { up, .. } => up,
        _ => panic!("expected upsert"),
    };

    let seed = hash::hash_domain(DOMAIN_DOCSTATE, &doc_id);
    let mut payload = Vec::with_capacity(64);
    payload.extend_from_slice(&seed);
    payload.extend_from_slice(&commitment);
    let doc_state_hash = hash::hash_domain(DOMAIN_DOCSTATE, &payload);
    let expected_leaf = doc_leaf_hash(doc_id, doc_state_hash, up.projection_commitment);
    assert_eq!(proof.leaf_hash, expected_leaf);

    let _ = fs::remove_file(ledger);
    let _ = fs::remove_file(index);
}

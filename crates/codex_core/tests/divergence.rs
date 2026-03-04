use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use codex_core::engine::{Engine, EngineConfig};
use codex_core::hash;
use codex_core::ledger::index::IndexReader;
use codex_core::ledger::reader::LedgerReader;
use codex_core::mmr::{verify_proof, Mmr};
use codex_core::replay::{classify_error, verify_ledger, FailCode};
use codex_core::schema::{decode_event_payload, encode_event_payload, Event};
use codex_core::sync::find_divergence_index;
use codex_core::{DOMAIN_EVENT, FEATURE_DIVERGENCE_PROOF, FEATURE_SNAPSHOT_COMMITMENT};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_temp_path(name: &str, ext: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    p.push(format!(
        "codex_core_divergence_{}_{}_{}.{}",
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

#[test]
fn inclusion_proof_valid() {
    let mut mmr = Mmr::new();
    let mut leaves = Vec::new();
    for i in 0..10u8 {
        let h = hash::sha256(&[i]);
        leaves.push(h);
        mmr.append(h);
    }
    let p = mmr.generate_proof(4).unwrap();
    assert!(verify_proof(mmr.root(), leaves[4], &p).unwrap());
}

#[test]
fn divergence_locator_replay_verifies() {
    let ledger = unique_temp_path("loc_ledger", "bin");
    let index = unique_temp_path("loc_index", "bin");
    let mut e = Engine::create(
        ledger.to_str().unwrap(),
        index.to_str().unwrap(),
        None,
        FEATURE_DIVERGENCE_PROOF,
        cfg(),
    )
    .unwrap();
    let _ = e
        .insert_cme(codex_core::cme::CmeInput::Text("doc-1"))
        .unwrap();
    e.emit_divergence_locator().unwrap();
    drop(e);

    let rep = verify_ledger(ledger.to_str().unwrap()).unwrap();
    assert_eq!(rep.events_verified, 2);

    let _ = fs::remove_file(ledger);
    let _ = fs::remove_file(index);
}

fn build_mmr_from_ledger(ledger_path: &str) -> Mmr {
    let mut r = LedgerReader::open(ledger_path).unwrap();
    let mut mmr = Mmr::new();
    for item in r.iter_raw() {
        let (_, payload, _) = item.unwrap();
        mmr.append(hash::hash_domain(DOMAIN_EVENT, &payload));
    }
    mmr
}

#[test]
fn divergence_between_replicas_detected() {
    let la = unique_temp_path("rep_a_ledger", "bin");
    let ia = unique_temp_path("rep_a_index", "bin");
    let lb = unique_temp_path("rep_b_ledger", "bin");
    let ib = unique_temp_path("rep_b_index", "bin");
    let flags = FEATURE_SNAPSHOT_COMMITMENT;

    let mut a = Engine::create(
        la.to_str().unwrap(),
        ia.to_str().unwrap(),
        None,
        flags,
        cfg(),
    )
    .unwrap();
    let mut b = Engine::create(
        lb.to_str().unwrap(),
        ib.to_str().unwrap(),
        None,
        flags,
        cfg(),
    )
    .unwrap();
    for txt in ["a", "b", "c"] {
        let _ = a.insert_cme(codex_core::cme::CmeInput::Text(txt)).unwrap();
        let _ = b.insert_cme(codex_core::cme::CmeInput::Text(txt)).unwrap();
    }
    a.emit_snapshot().unwrap();
    b.emit_snapshot().unwrap();
    let _ = b
        .insert_cme(codex_core::cme::CmeInput::Text("extra"))
        .unwrap();
    drop(a);
    drop(b);

    let local_mmr = build_mmr_from_ledger(la.to_str().unwrap());
    let remote_report = verify_ledger(lb.to_str().unwrap()).unwrap();
    let div = find_divergence_index(
        &local_mmr,
        remote_report.final_root,
        remote_report.events_verified,
    )
    .unwrap();
    assert_eq!(div, Some(4));

    let _ = fs::remove_file(la);
    let _ = fs::remove_file(ia);
    let _ = fs::remove_file(lb);
    let _ = fs::remove_file(ib);
}

#[test]
fn tamper_locator_commitment_fails() {
    let ledger = unique_temp_path("tamper_ledger", "bin");
    let index = unique_temp_path("tamper_index", "bin");
    let flags = FEATURE_DIVERGENCE_PROOF;
    let mut e = Engine::create(
        ledger.to_str().unwrap(),
        index.to_str().unwrap(),
        None,
        flags,
        cfg(),
    )
    .unwrap();
    let _ = e
        .insert_cme(codex_core::cme::CmeInput::Text("doc-x"))
        .unwrap();
    e.emit_divergence_locator().unwrap();
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

    let mut ev = decode_event_payload(&payload, flags).unwrap();
    match &mut ev {
        Event::DivergenceLocator { loc, .. } => loc.locator_commitment[0] ^= 0x01,
        _ => panic!("expected divergence locator"),
    }
    let new_payload = encode_event_payload(&ev, flags).unwrap();
    let new_commitment = hash::hash_domain(DOMAIN_EVENT, &new_payload);
    f.seek(SeekFrom::Start(off + 4)).unwrap();
    f.write_all(&new_payload).unwrap();
    f.write_all(&new_commitment).unwrap();
    drop(f);

    let err = verify_ledger(ledger.to_str().unwrap()).unwrap_err();
    assert_eq!(classify_error(&err), FailCode::DivergenceLocatorMismatch);

    let _ = fs::remove_file(ledger);
    let _ = fs::remove_file(index);
}

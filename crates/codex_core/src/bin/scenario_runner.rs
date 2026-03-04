use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use codex_core::engine::{Engine, EngineConfig, MutationDecision};
use codex_core::hex::to_hex_lower;
use codex_core::ledger::reader::LedgerReader;
use codex_core::mmr::{verify_proof, Mmr};
use codex_core::protocol::protocol_hash;
use codex_core::replay::{compute_transcript_hash, verify_ledger};
use codex_core::schema::Event;
use codex_core::sync::find_divergence_index;
use codex_core::{
    hash, CodexError, DOMAIN_EVENT, FEATURE_DIVERGENCE_PROOF, FEATURE_DOC_MERKLE_STATE,
    FEATURE_JSON_MIRROR, FEATURE_LIFECYCLE_GOVERNANCE, FEATURE_RECURSIVE_PROJECTION,
    FEATURE_SCORE_COMMITMENT, FEATURE_SNAPSHOT_COMMITMENT, FEATURE_SNAPSHOT_DELTA_PROOF,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SnapshotSummary {
    event_index: u64,
    snapshot_state_hash: [u8; 32],
    snapshot_mmr_root: [u8; 32],
    doc_count: Option<u32>,
    doc_merkle_root: Option<[u8; 32]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MetricsStruct {
    execution_ms: u64,
    snapshot_ms: u64,
    replay_ms: u64,
    delta_ms: u64,
    inclusion_proof_us: u64,
    divergence_search_ms: u64,
}

fn export_metrics_json(path: &Path, metrics: &MetricsStruct) -> Result<(), CodexError> {
    let json = format!(
        concat!(
            "{{",
            "\"delta_ms\":{},",
            "\"divergence_search_ms\":{},",
            "\"execution_ms\":{},",
            "\"inclusion_proof_us\":{},",
            "\"replay_ms\":{},",
            "\"snapshot_ms\":{}",
            "}}\n"
        ),
        metrics.delta_ms,
        metrics.divergence_search_ms,
        metrics.execution_ms,
        metrics.inclusion_proof_us,
        metrics.replay_ms,
        metrics.snapshot_ms,
    );
    fs::write(path, json).map_err(|_| CodexError::InvalidInput("METRICS_WRITE_FAILED"))
}

fn parse_outdir() -> Result<PathBuf, CodexError> {
    let mut args = std::env::args().skip(1);
    let mut outdir = None;
    while let Some(arg) = args.next() {
        if arg == "--outdir" {
            let val = args
                .next()
                .ok_or(CodexError::InvalidInput("OUTDIR_ARG_MISSING"))?;
            outdir = Some(PathBuf::from(val));
        } else {
            return Err(CodexError::InvalidInput("SCENARIO_RUNNER_UNKNOWN_ARG"));
        }
    }
    outdir.ok_or(CodexError::InvalidInput("OUTDIR_ARG_REQUIRED"))
}

fn deterministic_flags() -> u32 {
    FEATURE_JSON_MIRROR
        | FEATURE_RECURSIVE_PROJECTION
        | FEATURE_SCORE_COMMITMENT
        | FEATURE_LIFECYCLE_GOVERNANCE
        | FEATURE_SNAPSHOT_COMMITMENT
        | FEATURE_DIVERGENCE_PROOF
        | FEATURE_DOC_MERKLE_STATE
        | FEATURE_SNAPSHOT_DELTA_PROOF
}

fn cfg() -> EngineConfig {
    EngineConfig {
        default_new_lifecycle_state: 0,
        default_new_representation_mode: 0,
        default_new_compressed_flag: 0,
        quarantine_span_events: 4,
    }
}

fn summarize_ledger(ledger_path: &Path) -> Result<(u32, u64, Vec<SnapshotSummary>), CodexError> {
    let mut reader = LedgerReader::open(
        ledger_path
            .to_str()
            .ok_or(CodexError::InvalidInput("LEDGER_PATH_UTF8"))?,
    )?;
    let flags = reader.header().flags;
    let mut event_count = 0u64;
    let mut snapshots = Vec::new();

    for item in reader.iter() {
        let (_, event, _) = item?;
        event_count += 1;
        if let Event::Snapshot { common, snap } = event {
            snapshots.push(SnapshotSummary {
                event_index: common.event_index,
                snapshot_state_hash: snap.snapshot_state_hash,
                snapshot_mmr_root: snap.snapshot_mmr_root,
                doc_count: snap.doc_count,
                doc_merkle_root: snap.doc_merkle_root,
            });
        }
    }
    Ok((flags, event_count, snapshots))
}

fn build_mmr_from_ledger(ledger_path: &Path) -> Result<(Mmr, Vec<[u8; 32]>), CodexError> {
    let mut reader = LedgerReader::open(
        ledger_path
            .to_str()
            .ok_or(CodexError::InvalidInput("LEDGER_PATH_UTF8"))?,
    )?;
    let mut mmr = Mmr::new();
    let mut commitments = Vec::new();
    for item in reader.iter_raw() {
        let (_, payload, _) = item?;
        let commitment = hash::hash_domain(DOMAIN_EVENT, &payload);
        mmr.append(commitment);
        commitments.push(commitment);
    }
    Ok((mmr, commitments))
}

fn main() {
    if let Err(e) = run() {
        eprintln!("scenario_runner error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), CodexError> {
    let outdir = parse_outdir()?;
    fs::create_dir_all(&outdir).map_err(|_| CodexError::InvalidInput("OUTDIR_CREATE_FAILED"))?;

    let ledger_path = outdir.join("ledger.bin");
    let index_path = outdir.join("index.bin");
    let json_path = outdir.join("ledger.jsonl");
    let metrics_path = outdir.join("metrics.json");
    let manifest_path = outdir.join("proof_manifest.json");

    let flags = deterministic_flags();

    let started_all = Instant::now();
    let mut snapshot_ms = 0u64;
    let mut delta_ms = 0u64;

    let mut engine = Engine::create(
        ledger_path
            .to_str()
            .ok_or(CodexError::InvalidInput("LEDGER_PATH_UTF8"))?,
        index_path
            .to_str()
            .ok_or(CodexError::InvalidInput("INDEX_PATH_UTF8"))?,
        Some(
            json_path
                .to_str()
                .ok_or(CodexError::InvalidInput("JSON_PATH_UTF8"))?,
        ),
        flags,
        cfg(),
    )?;

    let d0 = engine.insert_cme(codex_core::cme::CmeInput::Text("alpha"))?;
    let d1 = engine.insert_cme(codex_core::cme::CmeInput::Text("beta"))?;
    let d2 = engine.insert_cme(codex_core::cme::CmeInput::Text("gamma"))?;

    let q1 = engine.score_evaluated(b"hello", &[d2.doc_id, d0.doc_id, d1.doc_id])?;
    let base_snapshot_root = engine.lifecycle_mutation(
        q1.ordered_doc_ids[0],
        MutationDecision::NoChange,
        q1.candidate_commitment,
    )?;

    let snap_start = Instant::now();
    let _ = engine.emit_snapshot()?;
    snapshot_ms += snap_start.elapsed().as_millis() as u64;

    let d3 = engine.insert_cme(codex_core::cme::CmeInput::Text("delta"))?;
    let q2 = engine.score_evaluated(b"hello", &[d3.doc_id, d0.doc_id, d1.doc_id])?;
    let target_snapshot_root = q2.root_after;

    let snap2_start = Instant::now();
    let _ = engine.emit_snapshot()?;
    snapshot_ms += snap2_start.elapsed().as_millis() as u64;

    if (flags & FEATURE_SNAPSHOT_DELTA_PROOF) != 0 {
        let delta_start = Instant::now();
        let _ = engine.emit_snapshot_delta(base_snapshot_root, target_snapshot_root)?;
        delta_ms = delta_start.elapsed().as_millis() as u64;
    }

    if (flags & FEATURE_DIVERGENCE_PROOF) != 0 {
        let _ = engine.emit_divergence_locator()?;
    }

    let _engine_transcript = engine.export_transcript_hash();
    drop(engine);

    let replay_start = Instant::now();
    let replay_report = verify_ledger(
        ledger_path
            .to_str()
            .ok_or(CodexError::InvalidInput("LEDGER_PATH_UTF8"))?,
    )?;
    let replay_ms = replay_start.elapsed().as_millis() as u64;

    let (hdr_flags, event_count, snapshots) = summarize_ledger(&ledger_path)?;
    let latest_snapshot = snapshots
        .last()
        .copied()
        .ok_or(CodexError::InvalidInput("SNAPSHOT_NOT_FOUND"))?;

    let (mmr, leaves) = build_mmr_from_ledger(&ledger_path)?;

    let mut inclusion_proof_us = 0u64;
    if !leaves.is_empty() {
        let mid = (leaves.len() / 2) as u64;
        let started = Instant::now();
        let proof = mmr.generate_proof(mid)?;
        let ok = verify_proof(mmr.root(), leaves[mid as usize], &proof)?;
        inclusion_proof_us = started.elapsed().as_micros() as u64;
        if !ok {
            return Err(CodexError::IntegrityError("INCLUSION_PROOF_VERIFY_FAILED"));
        }
    }

    let mut divergence_search_ms = 0u64;
    if (flags & FEATURE_DIVERGENCE_PROOF) != 0 {
        let base = snapshots
            .first()
            .copied()
            .ok_or(CodexError::InvalidInput("BASE_SNAPSHOT_NOT_FOUND"))?;
        let started = Instant::now();
        let _ = find_divergence_index(&mmr, base.snapshot_mmr_root, base.event_index)?;
        divergence_search_ms = started.elapsed().as_millis() as u64;
    }

    let metrics = MetricsStruct {
        execution_ms: started_all.elapsed().as_millis() as u64,
        snapshot_ms,
        replay_ms,
        delta_ms,
        inclusion_proof_us,
        divergence_search_ms,
    };
    export_metrics_json(&metrics_path, &metrics)?;

    let transcript_hash = compute_transcript_hash(
        ledger_path
            .to_str()
            .ok_or(CodexError::InvalidInput("LEDGER_PATH_UTF8"))?,
    )?;
    let ledger_bytes =
        fs::read(&ledger_path).map_err(|_| CodexError::InvalidInput("LEDGER_READ_FAILED"))?;
    let ledger_sha256 = hash::sha256(&ledger_bytes);
    let protocol = protocol_hash();

    let manifest_json = format!(
        concat!(
            "{{",
            "\"doc_count\":{},",
            "\"doc_merkle_root\":\"{}\",",
            "\"event_count\":{},",
            "\"feature_flags\":{},",
            "\"final_mmr_root\":\"{}\",",
            "\"final_state_hash\":\"{}\",",
            "\"latest_snapshot_mmr_root\":\"{}\",",
            "\"latest_snapshot_state_hash\":\"{}\",",
            "\"ledger_sha256\":\"{}\",",
            "\"protocol_hash\":\"{}\"",
            ",\"transcript_hash\":\"{}\"",
            "}}\n"
        ),
        latest_snapshot.doc_count.unwrap_or(0),
        latest_snapshot
            .doc_merkle_root
            .map(|h| to_hex_lower(&h))
            .unwrap_or_default(),
        event_count,
        hdr_flags,
        to_hex_lower(&replay_report.final_root),
        to_hex_lower(&replay_report.final_state_hash),
        to_hex_lower(&latest_snapshot.snapshot_mmr_root),
        to_hex_lower(&latest_snapshot.snapshot_state_hash),
        to_hex_lower(&ledger_sha256),
        to_hex_lower(&protocol),
        to_hex_lower(&transcript_hash),
    );
    fs::write(&manifest_path, manifest_json)
        .map_err(|_| CodexError::InvalidInput("MANIFEST_WRITE_FAILED"))?;

    Ok(())
}

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use codex_core::delta_proof::{compute_snapshot_delta, DocStore};
use codex_core::engine::{Engine, EngineConfig};
use codex_core::hash;
use codex_core::replay::verify_ledger;
use codex_core::{
    CodexError, FEATURE_DIVERGENCE_PROOF, FEATURE_DOC_MERKLE_STATE, FEATURE_JSON_MIRROR,
    FEATURE_LIFECYCLE_GOVERNANCE, FEATURE_RECURSIVE_PROJECTION, FEATURE_SCORE_COMMITMENT,
    FEATURE_SNAPSHOT_COMMITMENT, FEATURE_SNAPSHOT_DELTA_PROOF,
};

fn parse_out() -> Result<PathBuf, CodexError> {
    let mut args = std::env::args().skip(1);
    let mut out = None;
    while let Some(arg) = args.next() {
        if arg == "--out" {
            out = Some(
                args.next()
                    .ok_or(CodexError::InvalidInput("BENCH_OUT_ARG_MISSING"))?,
            );
        } else if arg == "--bench" {
            // Passed by cargo bench; ignored for deterministic output handling.
        } else {
            return Err(CodexError::InvalidInput("BENCH_UNKNOWN_ARG"));
        }
    }
    Ok(out
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("dist/benchmarks.json")))
}

fn cfg() -> EngineConfig {
    EngineConfig {
        default_new_lifecycle_state: 0,
        default_new_representation_mode: 0,
        default_new_compressed_flag: 0,
        quarantine_span_events: 4,
    }
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

fn ensure_parent(path: &Path) -> Result<(), CodexError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| CodexError::InvalidInput("BENCH_OUTDIR_CREATE"))?;
    }
    Ok(())
}

fn write_json(path: &Path, s: &str) -> Result<(), CodexError> {
    fs::write(path, s).map_err(|_| CodexError::InvalidInput("BENCH_WRITE_FAILED"))
}

fn dir_size_bytes(dir: &Path) -> Result<u64, CodexError> {
    let mut total = 0u64;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(cur) = stack.pop() {
        for ent in fs::read_dir(&cur).map_err(|_| CodexError::InvalidInput("BENCH_DIR_READ"))? {
            let ent = ent.map_err(|_| CodexError::InvalidInput("BENCH_DIR_READ"))?;
            let p = ent.path();
            let meta = fs::metadata(&p).map_err(|_| CodexError::InvalidInput("BENCH_META"))?;
            if meta.is_dir() {
                stack.push(p);
            } else if meta.is_file() {
                total = total.saturating_add(meta.len());
            }
        }
    }
    Ok(total)
}

fn make_doc_store(base: usize, mut_count: usize) -> (DocStore, DocStore) {
    let mut a = Vec::with_capacity(base);
    let mut b = Vec::with_capacity(base + mut_count);

    for i in 0..base {
        let id = hash::sha256(format!("bench-doc-id-{i:04}").as_bytes());
        let leaf_a = hash::sha256(format!("bench-doc-a-{i:04}").as_bytes());
        let leaf_b = if i < mut_count {
            hash::sha256(format!("bench-doc-b-{i:04}").as_bytes())
        } else {
            leaf_a
        };
        a.push((id, leaf_a));
        b.push((id, leaf_b));
    }

    for j in 0..mut_count {
        let id = hash::sha256(format!("bench-new-id-{j:04}").as_bytes());
        let leaf = hash::sha256(format!("bench-new-leaf-{j:04}").as_bytes());
        b.push((id, leaf));
    }

    a.sort_by(|x, y| x.0.cmp(&y.0));
    b.sort_by(|x, y| x.0.cmp(&y.0));
    (a, b)
}

fn run() -> Result<(), CodexError> {
    let out_path = parse_out()?;
    ensure_parent(&out_path)?;

    let bench_dir = PathBuf::from("bench_run");
    let _ = fs::remove_dir_all(&bench_dir);
    fs::create_dir_all(&bench_dir).map_err(|_| CodexError::InvalidInput("BENCH_DIR_CREATE"))?;

    let ledger = bench_dir.join("ledger.bin");
    let index = bench_dir.join("index.bin");
    let json = bench_dir.join("ledger.jsonl");

    let flags = deterministic_flags();
    let mut engine = Engine::create(
        ledger
            .to_str()
            .ok_or(CodexError::InvalidInput("BENCH_LEDGER_UTF8"))?,
        index
            .to_str()
            .ok_or(CodexError::InvalidInput("BENCH_INDEX_UTF8"))?,
        Some(
            json.to_str()
                .ok_or(CodexError::InvalidInput("BENCH_JSON_UTF8"))?,
        ),
        flags,
        cfg(),
    )?;

    let append_events = 256u64;
    let append_start = Instant::now();
    for i in 0..append_events {
        let bytes = format!("bench-insert-{i:04}");
        let _ = engine.insert(bytes.as_bytes())?;
    }
    let append_ms = append_start.elapsed().as_millis() as u64;
    let append_events_per_sec = if append_ms == 0 {
        append_events.saturating_mul(1000)
    } else {
        append_events.saturating_mul(1000) / append_ms
    };

    let snap_start = Instant::now();
    let _ = engine.emit_snapshot()?;
    let snapshot_ms = snap_start.elapsed().as_millis() as u64;

    let mutation_count = 64usize;
    for i in 0..mutation_count {
        let bytes = format!("bench-mut-insert-{i:04}");
        let _ = engine.insert(bytes.as_bytes())?;
    }
    let _ = engine.emit_snapshot()?;

    drop(engine);

    let replay_start = Instant::now();
    let replay = verify_ledger(
        ledger
            .to_str()
            .ok_or(CodexError::InvalidInput("BENCH_LEDGER_UTF8"))?,
    )?;
    let replay_ms = replay_start.elapsed().as_millis() as u64;
    let replay_events_per_sec = if replay_ms == 0 {
        replay.events_verified.saturating_mul(1000)
    } else {
        replay.events_verified.saturating_mul(1000) / replay_ms
    };

    let (base_store, target_store) = make_doc_store(512, mutation_count);
    let delta_start = Instant::now();
    let _delta = compute_snapshot_delta(&base_store, &target_store);
    let delta_ms = delta_start.elapsed().as_millis() as u64;

    let ledger_bytes = fs::metadata(&ledger)
        .map_err(|_| CodexError::InvalidInput("BENCH_LEDGER_META"))?
        .len();
    let bundle_bytes = dir_size_bytes(&bench_dir)?;

    let json = format!(
        concat!(
            "{{",
            "\"append_events_per_sec\":{},",
            "\"bundle_bytes\":{},",
            "\"delta_ms\":{},",
            "\"ledger_bytes\":{},",
            "\"replay_events_per_sec\":{},",
            "\"snapshot_ms\":{},",
            "\"timestamp\":0",
            "}}\\n"
        ),
        append_events_per_sec,
        bundle_bytes,
        delta_ms,
        ledger_bytes,
        replay_events_per_sec,
        snapshot_ms,
    );

    write_json(&out_path, &json)
}

fn main() {
    if let Err(e) = run() {
        eprintln!("benchmarks error: {e}");
        std::process::exit(1);
    }
}

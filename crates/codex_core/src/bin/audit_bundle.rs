use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use codex_core::hex::to_hex_lower;
use codex_core::ledger::reader::LedgerReader;
use codex_core::protocol::protocol_hash;
use codex_core::replay::verify_ledger;
use codex_core::schema::Event;
use codex_core::{hash, CodexError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SnapshotSummary {
    snapshot_state_hash: [u8; 32],
    snapshot_mmr_root: [u8; 32],
    doc_merkle_root: Option<[u8; 32]>,
}

fn parse_dir() -> Result<PathBuf, CodexError> {
    let mut args = std::env::args().skip(1);
    match args.next() {
        Some(path) => {
            if args.next().is_some() {
                Err(CodexError::InvalidInput("AUDIT_BUNDLE_TOO_MANY_ARGS"))
            } else {
                Ok(PathBuf::from(path))
            }
        }
        None => Err(CodexError::InvalidInput("AUDIT_BUNDLE_DIR_REQUIRED")),
    }
}

fn rust_version() -> String {
    match Command::new("rustc").arg("--version").output() {
        Ok(out) if out.status.success() => String::from_utf8(out.stdout)
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string()),
        _ => "unknown".to_string(),
    }
}

fn read_snapshot_and_count(ledger_path: &Path) -> Result<(u32, u64, SnapshotSummary), CodexError> {
    let mut reader = LedgerReader::open(
        ledger_path
            .to_str()
            .ok_or(CodexError::InvalidInput("LEDGER_PATH_UTF8"))?,
    )?;
    let flags = reader.header().flags;
    let mut event_count = 0u64;
    let mut last_snapshot = None;

    for item in reader.iter() {
        let (_, event, _) = item?;
        event_count += 1;
        if let Event::Snapshot { snap, .. } = event {
            last_snapshot = Some(SnapshotSummary {
                snapshot_state_hash: snap.snapshot_state_hash,
                snapshot_mmr_root: snap.snapshot_mmr_root,
                doc_merkle_root: snap.doc_merkle_root,
            });
        }
    }

    let snapshot = last_snapshot.ok_or(CodexError::InvalidInput("SNAPSHOT_NOT_FOUND"))?;
    Ok((flags, event_count, snapshot))
}

fn write_audit_bundle(path: &Path, json: &str) -> Result<(), CodexError> {
    fs::write(path, json).map_err(|_| CodexError::InvalidInput("AUDIT_BUNDLE_WRITE_FAILED"))
}

fn main() {
    if let Err(e) = run() {
        eprintln!("audit_bundle error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), CodexError> {
    let dir = parse_dir()?;
    let ledger_path = dir.join("ledger.bin");
    let audit_path = dir.join("audit_bundle.json");

    let (feature_flags, event_count, snapshot) = read_snapshot_and_count(&ledger_path)?;
    let report = verify_ledger(
        ledger_path
            .to_str()
            .ok_or(CodexError::InvalidInput("LEDGER_PATH_UTF8"))?,
    )?;

    let ledger_bytes =
        fs::read(&ledger_path).map_err(|_| CodexError::InvalidInput("LEDGER_READ_FAILED"))?;
    let ledger_sha = hash::sha256(&ledger_bytes);

    let protocol = protocol_hash();
    let build_target = option_env!("TARGET").unwrap_or("unknown");
    let build_rust_version = rust_version();

    let json = format!(
        concat!(
            "{{",
            "\"build_rust_version\":\"{}\",",
            "\"build_target\":\"{}\",",
            "\"doc_merkle_root\":\"{}\",",
            "\"event_count\":{},",
            "\"feature_flags\":{},",
            "\"ledger_sha256\":\"{}\",",
            "\"mmr_root\":\"{}\",",
            "\"protocol_hash\":\"{}\",",
            "\"snapshot_mmr_root\":\"{}\",",
            "\"snapshot_state_hash\":\"{}\",",
            "\"state_hash\":\"{}\",",
            "\"timestamp\":{}",
            "}}\n"
        ),
        build_rust_version,
        build_target,
        snapshot
            .doc_merkle_root
            .map(|h| to_hex_lower(&h))
            .unwrap_or_default(),
        event_count,
        feature_flags,
        to_hex_lower(&ledger_sha),
        to_hex_lower(&report.final_root),
        to_hex_lower(&protocol),
        to_hex_lower(&snapshot.snapshot_mmr_root),
        to_hex_lower(&snapshot.snapshot_state_hash),
        to_hex_lower(&report.final_state_hash),
        0u64,
    );

    write_audit_bundle(&audit_path, &json)
}

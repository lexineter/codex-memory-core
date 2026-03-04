use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .unwrap()
        .to_path_buf()
}

fn unique_temp_dir(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    p.push(format!(
        "codex_core_json_stability_{}_{}_{}",
        std::process::id(),
        id,
        name
    ));
    p
}

fn run_scenario(outdir: &Path) {
    let root = workspace_root();
    let status = Command::new("cargo")
        .current_dir(&root)
        .arg("run")
        .arg("-q")
        .arg("-p")
        .arg("codex_core")
        .arg("--bin")
        .arg("scenario_runner")
        .arg("--")
        .arg("--outdir")
        .arg(outdir)
        .status()
        .unwrap();
    assert!(status.success());
}

fn run_audit(outdir: &Path) {
    let root = workspace_root();
    let status = Command::new("cargo")
        .current_dir(&root)
        .arg("run")
        .arg("-q")
        .arg("-p")
        .arg("codex_core")
        .arg("--bin")
        .arg("audit_bundle")
        .arg("--")
        .arg(outdir)
        .status()
        .unwrap();
    assert!(status.success());
}

fn key_pos(text: &str, key: &str) -> usize {
    text.find(&format!("\"{}\":", key)).unwrap()
}

fn assert_key_order(text: &str, keys: &[&str]) {
    let mut prev = 0usize;
    for (i, k) in keys.iter().enumerate() {
        let p = key_pos(text, k);
        if i > 0 {
            assert!(p > prev, "key order violation: {}", k);
        }
        prev = p;
    }
}

fn extract_string(text: &str, key: &str) -> String {
    let start = text.find(&format!("\"{}\":\"", key)).unwrap();
    let tail = &text[start + key.len() + 4..];
    let end = tail.find('"').unwrap();
    tail[..end].to_string()
}

fn is_lower_hex(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[test]
fn scenario_and_audit_json_are_stable_ordered_and_compact() {
    let out = unique_temp_dir("bundle");
    let _ = fs::remove_dir_all(&out);
    run_scenario(&out);
    run_audit(&out);

    let manifest = fs::read_to_string(out.join("proof_manifest.json")).unwrap();
    let metrics = fs::read_to_string(out.join("metrics.json")).unwrap();
    let audit = fs::read_to_string(out.join("audit_bundle.json")).unwrap();

    assert!(manifest.ends_with('\n'));
    assert!(metrics.ends_with('\n'));
    assert!(audit.ends_with('\n'));

    assert!(!manifest.contains(": "));
    assert!(!manifest.contains(", "));
    assert!(!metrics.contains(": "));
    assert!(!metrics.contains(", "));
    assert!(!audit.contains(": "));
    assert!(!audit.contains(", "));

    assert_key_order(
        &manifest,
        &[
            "doc_count",
            "doc_merkle_root",
            "event_count",
            "feature_flags",
            "final_mmr_root",
            "final_state_hash",
            "latest_snapshot_mmr_root",
            "latest_snapshot_state_hash",
            "ledger_sha256",
            "protocol_hash",
            "transcript_hash",
        ],
    );

    assert_key_order(
        &metrics,
        &[
            "delta_ms",
            "divergence_search_ms",
            "execution_ms",
            "inclusion_proof_us",
            "replay_ms",
            "snapshot_ms",
        ],
    );

    assert_key_order(
        &audit,
        &[
            "build_rust_version",
            "build_target",
            "doc_merkle_root",
            "event_count",
            "feature_flags",
            "ledger_sha256",
            "mmr_root",
            "protocol_hash",
            "snapshot_mmr_root",
            "snapshot_state_hash",
            "state_hash",
            "timestamp",
        ],
    );

    for key in [
        "doc_merkle_root",
        "final_mmr_root",
        "final_state_hash",
        "latest_snapshot_mmr_root",
        "latest_snapshot_state_hash",
        "ledger_sha256",
        "protocol_hash",
        "transcript_hash",
    ] {
        assert!(is_lower_hex(&extract_string(&manifest, key)));
    }

    for key in [
        "doc_merkle_root",
        "ledger_sha256",
        "mmr_root",
        "protocol_hash",
        "snapshot_mmr_root",
        "snapshot_state_hash",
        "state_hash",
    ] {
        assert!(is_lower_hex(&extract_string(&audit, key)));
    }

    let _ = fs::remove_dir_all(out);
}

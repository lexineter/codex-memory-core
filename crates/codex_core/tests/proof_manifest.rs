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
        "codex_core_proof_manifest_{}_{}_{}",
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

#[test]
fn scenario_runner_manifest_is_deterministic() {
    let out_a = unique_temp_dir("a");
    let out_b = unique_temp_dir("b");
    let _ = fs::remove_dir_all(&out_a);
    let _ = fs::remove_dir_all(&out_b);

    run_scenario(&out_a);
    run_scenario(&out_b);

    let a = fs::read(out_a.join("proof_manifest.json")).unwrap();
    let b = fs::read(out_b.join("proof_manifest.json")).unwrap();
    assert_eq!(a, b);

    let text = String::from_utf8(a).unwrap();
    assert!(text.contains("\"final_state_hash\":\""));
    assert!(text.contains("\"final_mmr_root\":\""));
    assert!(text.contains("\"latest_snapshot_state_hash\":\""));
    assert!(text.contains("\"latest_snapshot_mmr_root\":\""));
    assert!(text.contains("\"event_count\":"));
    assert!(text.contains("\"feature_flags\":"));

    let _ = fs::remove_dir_all(out_a);
    let _ = fs::remove_dir_all(out_b);
}

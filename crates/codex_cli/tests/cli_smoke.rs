use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .unwrap()
        .to_path_buf()
}

#[test]
fn cli_replay_smoke() {
    if std::env::var("SKIP_RELEASE_BUNDLE_TEST").ok().as_deref() == Some("1") {
        return;
    }

    let root = workspace_root();

    let bundle_status = Command::new("bash")
        .current_dir(&root)
        .arg("./scripts/release_bundle.sh")
        .env("SKIP_HEAVY", "1")
        .status()
        .unwrap();
    assert!(bundle_status.success());

    let replay_out = Command::new("cargo")
        .current_dir(&root)
        .arg("run")
        .arg("-q")
        .arg("-p")
        .arg("codex_cli")
        .arg("--")
        .arg("replay")
        .arg("--ledger")
        .arg("dist/proof_bundle/proof_a/ledger.bin")
        .output()
        .unwrap();
    assert!(replay_out.status.success());

    let stdout = String::from_utf8(replay_out.stdout).unwrap();
    assert!(stdout.contains("\"status\":\"VERIFIED\""));
    assert!(stdout.contains("\"final_mmr_root\":"));
    assert!(stdout.contains("\"final_state_hash\":"));
    assert!(stdout.contains("\"transcript_hash\":"));
}

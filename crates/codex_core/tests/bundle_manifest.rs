use std::fs;
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
fn bundle_manifest_and_verify_script_work() {
    if std::env::var("SKIP_RELEASE_BUNDLE_TEST").ok().as_deref() == Some("1") {
        return;
    }

    let root = workspace_root();
    let script_text = fs::read_to_string(root.join("scripts/release_bundle.sh")).unwrap();
    assert!(script_text.contains("--bin scenario_runner"));
    assert!(script_text.contains("--bin audit_bundle"));
    assert!(script_text.contains("--bin demo"));

    let status = Command::new("bash")
        .current_dir(&root)
        .arg("./scripts/release_bundle.sh")
        .env("SKIP_HEAVY", "1")
        .status()
        .unwrap();
    assert!(status.success());

    let bundle = root.join("dist/proof_bundle");
    let manifest_path = bundle.join("bundle_manifest.json");
    assert!(manifest_path.exists());
    let content = fs::read_to_string(&manifest_path).unwrap();
    assert!(content.ends_with('\n'));
    assert!(content.contains("\"proof_manifest.json\""));
    assert!(content.contains("\"proof_a/ledger.bin\""));
    assert!(content.contains("\"SHA256SUMS.txt\""));
    assert!(content.contains("\"VERSION.json\""));

    let verify_status = Command::new("bash")
        .current_dir(&root)
        .arg("./scripts/verify_bundle.sh")
        .arg("dist/proof_bundle")
        .status()
        .unwrap();
    assert!(verify_status.success());
}

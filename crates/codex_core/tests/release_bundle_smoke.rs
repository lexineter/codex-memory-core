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
fn release_bundle_script_wires_bins_and_outputs() {
    if std::env::var("SKIP_RELEASE_BUNDLE_TEST").ok().as_deref() == Some("1") {
        return;
    }

    let root = workspace_root();
    let script = root.join("scripts/release_bundle.sh");
    let script_text = fs::read_to_string(&script).unwrap();
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
    assert!(bundle.join("proof_manifest.json").exists());
    assert!(bundle.join("proof_a/audit_bundle.json").exists());
    assert!(bundle.join("proof_a/demo_transcript.txt").exists());
    assert!(bundle.join("VERSION.json").exists());
    assert!(bundle.join("SHA256SUMS.txt").exists());
}

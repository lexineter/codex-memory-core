use std::path::{Path, PathBuf};
use std::process::Command;

use codex_core::hex::to_hex_lower;
use codex_core::protocol::protocol_hash;
use codex_core::replay::{compute_transcript_hash, verify_ledger};
use codex_core::PROTOCOL_VERSION;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .unwrap()
        .to_path_buf()
}

fn copy_dir_recursive(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst)
        .unwrap_or_else(|_| fail("codex_cli bundle: failed to create output dir"));
    let mut entries = Vec::new();
    for ent in std::fs::read_dir(src).unwrap_or_else(|_| fail("codex_cli bundle: read_dir failed"))
    {
        let ent = ent.unwrap_or_else(|_| fail("codex_cli bundle: read_dir failed"));
        entries.push(ent.path());
    }
    entries.sort();
    for path in entries {
        let name = path
            .file_name()
            .unwrap_or_else(|| fail("codex_cli bundle: invalid path"));
        let target = dst.join(name);
        let meta =
            std::fs::metadata(&path).unwrap_or_else(|_| fail("codex_cli bundle: metadata failed"));
        if meta.is_dir() {
            copy_dir_recursive(&path, &target);
        } else if meta.is_file() {
            std::fs::copy(&path, &target)
                .unwrap_or_else(|_| fail("codex_cli bundle: file copy failed"));
        }
    }
}

fn fail(msg: &str) -> ! {
    eprintln!("{msg}");
    std::process::exit(1);
}

fn run_replay(args: &[String]) {
    let mut ledger: Option<&str> = None;
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--ledger" => {
                if i + 1 >= args.len() {
                    fail("codex_cli replay: missing --ledger value");
                }
                ledger = Some(&args[i + 1]);
                i += 2;
            }
            _ => fail("codex_cli replay: unknown argument"),
        }
    }
    let ledger = ledger.unwrap_or_else(|| fail("codex_cli replay: --ledger is required"));

    let report = verify_ledger(ledger).unwrap_or_else(|_| fail("codex_cli replay: verify failed"));
    let transcript = compute_transcript_hash(ledger)
        .unwrap_or_else(|_| fail("codex_cli replay: transcript failed"));
    println!(
        "{{\"final_mmr_root\":\"{}\",\"final_state_hash\":\"{}\",\"status\":\"VERIFIED\",\"transcript_hash\":\"{}\"}}",
        to_hex_lower(&report.final_root),
        to_hex_lower(&report.final_state_hash),
        to_hex_lower(&transcript),
    );
}

fn run_bundle(args: &[String]) {
    let mut out: Option<&str> = None;
    let mut skip_heavy = false;
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--out" => {
                if i + 1 >= args.len() {
                    fail("codex_cli bundle: missing --out value");
                }
                out = Some(&args[i + 1]);
                i += 2;
            }
            "--skip-heavy" => {
                skip_heavy = true;
                i += 1;
            }
            _ => fail("codex_cli bundle: unknown argument"),
        }
    }
    let out = out.unwrap_or_else(|| fail("codex_cli bundle: --out is required"));
    let root = workspace_root();

    let mut release = Command::new("bash");
    release
        .current_dir(&root)
        .arg("./scripts/release_bundle.sh");
    if skip_heavy {
        release.env("SKIP_HEAVY", "1");
    }
    let release_status = release
        .status()
        .unwrap_or_else(|_| fail("codex_cli bundle: failed to run release_bundle.sh"));
    if !release_status.success() {
        fail("codex_cli bundle: release_bundle.sh failed");
    }

    if out != "dist/proof_bundle" {
        let src = root.join("dist/proof_bundle");
        let dst = root.join(out);
        let _ = std::fs::remove_dir_all(&dst);
        copy_dir_recursive(&src, &dst);
    }

    let verify_status = Command::new("bash")
        .current_dir(&root)
        .arg("./scripts/verify_bundle.sh")
        .arg(out)
        .status()
        .unwrap_or_else(|_| fail("codex_cli bundle: failed to run verify_bundle.sh"));
    if !verify_status.success() {
        fail("codex_cli bundle: verify_bundle.sh failed");
    }
    println!("BUNDLE_READY:{out}");
}

fn run_demo(args: &[String]) {
    if !args.is_empty() {
        fail("codex_cli demo: no arguments expected");
    }
    let root = workspace_root();
    let status = Command::new("cargo")
        .current_dir(&root)
        .arg("run")
        .arg("-q")
        .arg("-p")
        .arg("codex_core")
        .arg("--bin")
        .arg("demo")
        .status()
        .unwrap_or_else(|_| fail("codex_cli demo: failed to run demo"));
    if !status.success() {
        fail("codex_cli demo: demo failed");
    }
}

fn run_version(args: &[String]) {
    if !args.is_empty() {
        fail("codex_cli version: no arguments expected");
    }
    let protocol = protocol_hash();
    println!(
        "{{\"crate_version\":\"{}\",\"protocol_hash\":\"{}\",\"protocol_version\":\"{}\",\"timestamp\":0}}",
        env!("CARGO_PKG_VERSION"),
        to_hex_lower(&protocol),
        PROTOCOL_VERSION,
    );
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        fail("codex_cli: expected command");
    }
    let cmd = &args[0];
    let rest = &args[1..];
    match cmd.as_str() {
        "replay" => run_replay(rest),
        "bundle" => run_bundle(rest),
        "demo" => run_demo(rest),
        "version" => run_version(rest),
        _ => fail("codex_cli: unknown command"),
    }
}

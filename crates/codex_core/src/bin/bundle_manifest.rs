use std::fs;
use std::path::{Path, PathBuf};

use codex_core::hex::to_hex_lower;
use codex_core::{hash, CodexError};

fn json_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c <= '\u{1F}' => {
                let code = c as u32;
                out.push_str("\\u");
                out.push_str(&format!("{code:04x}"));
            }
            c => out.push(c),
        }
    }
    out
}

fn parse_args() -> Result<(PathBuf, PathBuf), CodexError> {
    let mut args = std::env::args().skip(1);
    let mut dir = None;
    let mut out = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--dir" => {
                dir = Some(
                    args.next()
                        .ok_or(CodexError::InvalidInput("BUNDLE_MANIFEST_DIR_MISSING"))?,
                )
            }
            "--out" => {
                out = Some(
                    args.next()
                        .ok_or(CodexError::InvalidInput("BUNDLE_MANIFEST_OUT_MISSING"))?,
                )
            }
            _ => return Err(CodexError::InvalidInput("BUNDLE_MANIFEST_UNKNOWN_ARG")),
        }
    }
    let dir = dir.ok_or(CodexError::InvalidInput("BUNDLE_MANIFEST_DIR_REQUIRED"))?;
    let out = out.ok_or(CodexError::InvalidInput("BUNDLE_MANIFEST_OUT_REQUIRED"))?;
    Ok((PathBuf::from(dir), PathBuf::from(out)))
}

fn walk_files(root: &Path, current: &Path, out: &mut Vec<PathBuf>) -> Result<(), CodexError> {
    let mut entries = Vec::new();
    for ent in
        fs::read_dir(current).map_err(|_| CodexError::InvalidInput("BUNDLE_MANIFEST_READ_DIR"))?
    {
        let ent = ent.map_err(|_| CodexError::InvalidInput("BUNDLE_MANIFEST_READ_DIR"))?;
        entries.push(ent.path());
    }
    entries.sort();

    for path in entries {
        let meta =
            fs::metadata(&path).map_err(|_| CodexError::InvalidInput("BUNDLE_MANIFEST_META"))?;
        if meta.is_dir() {
            walk_files(root, &path, out)?;
        } else if meta.is_file() {
            let rel = path
                .strip_prefix(root)
                .map_err(|_| CodexError::InvalidInput("BUNDLE_MANIFEST_REL"))?
                .to_path_buf();
            out.push(rel);
        }
    }
    Ok(())
}

fn rel_to_forward_slash(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

fn run() -> Result<(), CodexError> {
    let (dir, out_file) = parse_args()?;
    let out_name = out_file
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or(CodexError::InvalidInput("BUNDLE_MANIFEST_OUT_INVALID"))?;

    let mut rel_files = Vec::new();
    walk_files(&dir, &dir, &mut rel_files)?;

    let mut rows = Vec::<(String, String)>::new();
    for rel in rel_files {
        let rel_s = rel_to_forward_slash(&rel);
        if rel_s == out_name {
            continue;
        }
        let bytes = fs::read(dir.join(&rel))
            .map_err(|_| CodexError::InvalidInput("BUNDLE_MANIFEST_READ_FILE"))?;
        let sha = to_hex_lower(&hash::sha256(&bytes));
        rows.push((rel_s, sha));
    }
    rows.sort_by(|a, b| a.0.cmp(&b.0));

    let mut json = String::new();
    json.push_str("{\"files\":[");
    for (i, (path, sha)) in rows.iter().enumerate() {
        if i > 0 {
            json.push(',');
        }
        json.push_str("{\"path\":\"");
        json.push_str(&json_escape(path));
        json.push_str("\",\"sha256\":\"");
        json.push_str(sha);
        json.push_str("\"}");
    }
    json.push_str("],\"timestamp\":0}\n");

    fs::write(&out_file, json).map_err(|_| CodexError::InvalidInput("BUNDLE_MANIFEST_WRITE"))
}

fn main() {
    if let Err(e) = run() {
        eprintln!("bundle_manifest error: {e}");
        std::process::exit(1);
    }
}

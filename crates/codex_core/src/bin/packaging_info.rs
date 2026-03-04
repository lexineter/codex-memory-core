use std::fs;
use std::path::PathBuf;
use std::process::Command;

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

fn parse_manifest_path() -> Result<PathBuf, String> {
    let mut args = std::env::args().skip(1);
    let mut manifest = None;
    while let Some(arg) = args.next() {
        if arg == "--manifest" {
            manifest = Some(
                args.next()
                    .ok_or_else(|| "packaging_info: missing --manifest value".to_string())?,
            );
        } else {
            return Err("packaging_info: unknown argument".to_string());
        }
    }
    manifest
        .map(PathBuf::from)
        .ok_or_else(|| "packaging_info: --manifest is required".to_string())
}

fn extract_json_string(src: &str, key: &str) -> Result<String, String> {
    let prefix = format!("\"{key}\":\"");
    let start = src
        .find(&prefix)
        .ok_or_else(|| format!("packaging_info: missing key {key}"))?;
    let rest = &src[start + prefix.len()..];
    let end = rest
        .find('"')
        .ok_or_else(|| format!("packaging_info: malformed string for key {key}"))?;
    Ok(rest[..end].to_string())
}

fn extract_json_u32(src: &str, key: &str) -> Result<u32, String> {
    let prefix = format!("\"{key}\":");
    let start = src
        .find(&prefix)
        .ok_or_else(|| format!("packaging_info: missing key {key}"))?;
    let rest = &src[start + prefix.len()..];
    let len = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    if len == 0 {
        return Err(format!("packaging_info: malformed number for key {key}"));
    }
    rest[..len]
        .parse::<u32>()
        .map_err(|_| format!("packaging_info: parse failure for key {key}"))
}

fn run_cmd(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?;
    Some(s.trim().to_string())
}

fn git_commit() -> String {
    run_cmd("git", &["rev-parse", "HEAD"])
        .filter(|s| s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit()))
        .map(|s| s.to_lowercase())
        .unwrap_or_else(|| "0000000000000000000000000000000000000000".to_string())
}

fn rustc_version() -> String {
    run_cmd("rustc", &["--version"]).unwrap_or_else(|| "unknown".to_string())
}

fn target_triple() -> String {
    let vv = run_cmd("rustc", &["-vV"]);
    if let Some(text) = vv {
        for line in text.lines() {
            if let Some(host) = line.strip_prefix("host: ") {
                return host.trim().to_string();
            }
        }
    }
    "unknown".to_string()
}

fn main() {
    let result = (|| -> Result<(), String> {
        let manifest_path = parse_manifest_path()?;
        let manifest = fs::read_to_string(&manifest_path)
            .map_err(|_| "packaging_info: failed to read manifest".to_string())?;

        let protocol_hash = extract_json_string(&manifest, "protocol_hash")?;
        let feature_flags = extract_json_u32(&manifest, "feature_flags")?;

        let json = format!(
            concat!(
                "{{",
                "\"feature_flags\":{},",
                "\"git_commit\":\"{}\",",
                "\"protocol_hash\":\"{}\",",
                "\"rustc_version\":\"{}\",",
                "\"target\":\"{}\",",
                "\"timestamp\":0",
                "}}\\n"
            ),
            feature_flags,
            json_escape(&git_commit()),
            json_escape(&protocol_hash),
            json_escape(&rustc_version()),
            json_escape(&target_triple()),
        );

        print!("{json}");
        Ok(())
    })();

    if let Err(e) = result {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

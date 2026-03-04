# Proof Bundle Verification

## Generate Bundle
Run exactly:

```bash
./scripts/release_bundle.sh
```

This produces `dist/proof_bundle/` with deterministic artifacts, checksums, and verification metadata.

## Compare Determinism Manifests
For full runs (non-`SKIP_HEAVY`), manifests must match:

```bash
cmp -s proof_a/proof_manifest.json proof_b/proof_manifest.json
cmp -s proof_a/proof_manifest.json proof_c/proof_manifest.json
```

## Replay Verify Ledger Directly
Verify the bundled ledger:

```bash
cargo run -q -p codex_cli -- replay --ledger dist/proof_bundle/proof_a/ledger.bin --transcript-hash
```

Expected result begins with `VERIFIED` and includes deterministic final hashes.

## Audit Bundle Field Notes
`proof_a/audit_bundle.json` contains:
- `protocol_hash`: canonical protocol manifest hash
- `snapshot_state_hash` / `snapshot_mmr_root`: latest snapshot anchor
- `mmr_root` / `state_hash`: replay-verified terminal ledger state
- `ledger_sha256`: full ledger file digest
- `feature_flags` / `event_count`: header + stream summary
- `build_rust_version` / `build_target`: toolchain metadata
- `timestamp`: fixed `0` for deterministic packaging

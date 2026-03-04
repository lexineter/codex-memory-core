# Contributing

## Run tests
Run the full test suite before opening a pull request:

```bash
cargo test --all
```

## Run replay verification
Validate deterministic replay against the generated proof ledger:

```bash
cargo run -q -p codex_cli -- replay --ledger dist/proof_bundle/proof_a/ledger.bin
```

## Build the proof bundle
Generate and verify release artifacts:

```bash
./scripts/ship.sh
./scripts/verify_bundle.sh dist/proof_bundle
```

## Coding standards
All changes must pass formatting and lint checks:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
```

## Scope and review rules
- Do not change protocol semantics, replay rules, event schema ordering, or hash preimages/domains in packaging-only work.
- Keep behavior deterministic and fail-closed.
- Prefer small, auditable patches with tests when behavior changes.

# Proof Bundle Pipeline

```mermaid
flowchart TD
    A[scripts/ship.sh] --> B[scripts/release_bundle.sh]
    B --> C[dist/proof_bundle]
    C --> D[scripts/verify_bundle.sh]
    D --> E[codex_cli replay]
    E --> F[Deterministic Verification Output]
```

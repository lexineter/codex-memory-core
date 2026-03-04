# Security Policy

## Responsible disclosure
Report vulnerabilities privately via the repository security reporting channel.
Include deterministic reproduction steps, affected commit hash, and expected vs observed verifier behavior.

Maintainers target acknowledgement within 3 business days and coordinated disclosure within 30 days, adjusted when downstream coordination requires a longer window.

## Deterministic verification guarantees
The system is designed to fail closed under deterministic replay verification.
Any tampering in commitments, ordering, feature dependencies, or committed state transitions must produce deterministic verification failure.

If you discover a bypass, provide a minimal reproducer ledger and command sequence so maintainers can validate impact exactly.

## Threat model reference
Security assumptions, adversary capabilities, guarantees, and out-of-scope areas are documented in:

- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)

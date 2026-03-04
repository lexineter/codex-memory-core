# Whitepaper

## 1. Abstract
The codex-memory-core platform is implemented as a deterministic state machine over an append-only authenticated ledger. Every event payload is framed in canonical binary form and committed with SHA-256 domain-separated hashes, then appended into an MMR-backed transcript. Replay verification reconstructs state from first principles and rejects any mismatch in ordering, commitments, or causal bindings.

The system is designed so independent replicas can derive identical results from identical bytes, without hidden entropy, implicit clocks, or unordered maps. This gives byte-level reproducibility for scoring, lifecycle transitions, snapshots, divergence anchors, and delta proofs.

## 2. Deterministic State Machine Model
State evolution is driven by strictly sequential event indices and explicit pre-state commitments. For each event, replay verifies parent MMR root and pre-state hash before applying transition logic. The global state hash evolves by `H(DOMAIN_PRESTATE, previous_state_hash || event_commitment)`.

Document-local causality is modeled with a per-doc doc-state hash seeded by `H(DOMAIN_DOCSTATE, doc_id)` and updated with each document-affecting event commitment. This allows replay to validate document lineage independently of global history while preserving a single deterministic transcript.

All event commitments are appended into an MMR with deterministic root derivation. This root anchors inclusion proofs, divergence detection, and snapshot-boundary references.

## 3. Canonicalization & Projection
CME canonicalization supports Text, JSON, KV, and Blob input kinds with strict deterministic encodings. V1 enforces ASCII-only policy for text and JSON keys/strings, rejects unsupported Unicode code points, and canonicalizes whitespace and key ordering under explicit rules.

Canonical bytes feed both identity and representation steps. `doc_id` is raw SHA-256 over canonical bytes, while projection vectors are derived from chained domain-separated hash expansion into fixed `i16[128]` coordinates using big-endian decoding.

Query projection follows the same deterministic projector, with optional recursion-aware augmentation when the corresponding feature flags are enabled and observer recursion context is present.

## 4. Cryptographic Score Commitments
Scoring is integer-only dot product accumulation in `i64` across query and document vectors. Candidate ranking is deterministic by `(score desc, doc_id asc)` so ties produce stable order.

Candidate ordering is bound through candidate commitment over ordered doc IDs. When score commitment features are enabled, SCORE_EVALUATED events also carry ordered candidate IDs, top-k metadata, and commitment over exact `(doc_id, score)` tuples.

Optional proof mode includes exact score bytes in payload, enabling replay to verify not only commitment correctness but byte-for-byte score transcript correctness.

## 5. Lifecycle Governance Enforcement
Lifecycle mutations update document lifecycle fields (`life_state`, `repr_mode`, `compressed`, `quarantine_until`) and must match deterministic state-delta encoding. Governance mode introduces rule ID and pre/post lifecycle hashes committed in event payload.

V1 replay-enforced governance uses SCORE_THRESHOLD_RULE with fixed thresholds and quarantine span parameterization. Replay reconstructs last known scores from verified score commitments and recomputes the allowed transition.

If any lifecycle field, lifecycle hash, or governance rule application differs from deterministic recomputation, replay fails with governance violation codes.

## 6. Snapshot Convergence Anchors
STATE_SNAPSHOT events commit the current global state hash and current MMR root at a defined event boundary. This gives replicas a compact convergence anchor without re-sending full history.

When document Merkle mode is disabled, snapshots include deterministic doc aggregate hash over sorted document fingerprints. When enabled, snapshots commit doc count and deterministic document Merkle root.

Replay verifies snapshot fields against reconstructed state and document store. Snapshot mismatches are deterministic integrity failures.

## 7. Divergence Detection
DIVERGENCE_LOCATOR events commit event count, current MMR root, current state hash, and derived locator commitment under domain separation. These events provide compact boundary descriptors for replica comparisons.

MMR inclusion proof support allows deterministic proof generation and verification for event commitments. This enables bounded checks over event positions and supports divergence localization primitives.

Sync helpers compute deterministic divergence index outcomes from available roots and counts, without introducing nondeterministic data structures or random probes.

## 8. Document-Level Merkle Proofs
With doc Merkle feature enabled, each document contributes a leaf hash over `(doc_id, doc_state_hash, projection_commitment)` and leaves are sorted lexicographically by `doc_id`. The Merkle tree uses deterministic left-right hashing and promotes odd nodes unchanged.

Inclusion proofs provide index and sibling path to reconstruct snapshot doc Merkle roots. Non-membership proofs are built from verified neighbor inclusion proofs plus ordering constraints.

These proofs enable selective state verifiability for specific documents while preserving full-state convergence anchors.

## 9. Cross-Snapshot Delta Compression
SNAPSHOT_DELTA events commit deterministic delta root between two referenced snapshot MMR roots. Delta construction compares doc leaf states between base and target snapshots and hashes changed-doc tuples under explicit domain constants.

Delta lists are sorted by `doc_id` and include add, remove, and mutate cases by zero-hash conventions for absent sides. Delta root commits both count and ordered delta-doc hashes.

Replay verifies referenced snapshots exist, recomputes delta deterministically from replay-maintained snapshot stores, and rejects mismatches.

## 10. Security Model
Integrity relies on SHA-256 domain-separated commitments, strict schema parsing, and deterministic replay checks for every causal link. No event is trusted by declaration alone; all commitments are recomputed and compared.

The model addresses tampering, reordering, truncation, field substitution, and protocol drift. Header commitments and protocol lock semantics bind feature/format interpretation before event processing.

Confidentiality is out of scope for this layer. The implementation focuses on verifiable integrity, deterministic reproducibility, and auditable failure behavior.

## 11. Determinism Guarantees
Determinism is enforced through fixed-width big-endian encodings, explicit lexicographic ordering rules, domain-separated hash preimages, and elimination of nondeterministic containers in protocol-critical paths.

Tests include cross-run determinism checks, replay integrity checks, tamper labs, and stress-style replica equivalence. Build and packaging tooling now produces reproducible proof artifacts and transcript-level hashes for external comparison.

The protocol manifest and protocol hash make compatibility checks machine-verifiable: any schema/domain/limit drift changes manifest bytes and therefore protocol hash.

## 12. Failure Codes & Integrity Model
Replay and CLI surfaces deterministic failure code mappings for header errors, parse failures, commitment mismatches, governance violations, snapshot mismatch, divergence mismatch, delta mismatch, and protocol-hash mismatch.

Failure handling is fail-fast and explicit: ambiguous input or missing required feature-conditioned fields are hard failures, not soft warnings. This behavior is part of the protocol contract.

Because all critical checks produce stable failure classes, operators can automate incident triage and compliance checks with deterministic interpretation across environments.

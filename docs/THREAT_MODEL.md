# Threat Model

## 1. System Model
The system is an append-only binary ledger with deterministic event framing and domain-separated commitments. Every event contributes a fixed event commitment and is accumulated into an authenticated Merkle Mountain Range root.

Replay verification is deterministic and stateful. The verifier reconstructs global state hash evolution, per-document state transitions, optional score/projection commitments, observer/query commitments, lifecycle governance checks, snapshot anchors, divergence locators, and delta proofs.

Snapshot anchoring commits replay state, authenticated event root, and document-state summary (aggregate hash or document Merkle root based on feature flags). Snapshot delta events commit deterministic cross-snapshot change sets without changing protocol state.

Governance enforcement is encoded in event payloads and rechecked in replay. Any mismatch in commitments, ordering, bounds, feature dependencies, or governed state transitions fails deterministically.

## 2. Trust Assumptions
Security assumes SHA-256 preimage and collision resistance for all domain-separated commitments.

No honest-majority assumption is required; verification is local and deterministic from bytes on disk.

No wall-clock trust is required. Timestamp fields are informational and replay logic is causally bound to commitments and deterministic state transitions.

No randomness is required. All canonicalization, projection, ordering, and proof generation rules are deterministic.

## 3. Adversary Model
Adversaries may tamper ledger bytes, reorder records, substitute fields, or alter event trailers. Replay detects commitment mismatches, index/order violations, and schema violations.

Adversaries may attempt snapshot spoofing by forging snapshot state/MMR/doc roots. Replay recomputes and verifies snapshot commitments from reconstructed state.

Adversaries may attempt delta forgery by supplying inconsistent base/target roots, counts, or delta root. Replay reconstructs both snapshot document views and recomputes deterministic delta commitments.

Adversaries may attempt governance bypass by submitting lifecycle transitions inconsistent with deterministic rule inputs. Replay recomputes expected pre/post lifecycle hashes and transition outputs.

Adversaries may attempt feature-flag drift or protocol downgrade. Header validation enforces flag dependency rules and protocol-lock checks bind ledgers to a concrete protocol hash.

## 4. Security Guarantees
Deterministic replay failure: malformed or tampered ledgers fail with deterministic failure codes and messages.

Snapshot mismatch detection: replay verifies snapshot fields against reconstructed state and authenticated roots.

Inclusion proof integrity: MMR inclusion proof verification binds leaf commitments to an authenticated root.

Delta proof integrity: snapshot delta verification recomputes deterministic changed-document set and commitment.

Header enforcement of feature dependencies: incompatible flag combinations fail early and deterministically.

Protocol hash drift detection: protocol-lock events and protocol-hash tooling detect domain/schema/limit drift.

## 5. Out-of-Scope
Confidentiality is out of scope. Ledger and proof artifacts are integrity-focused and may contain metadata.

Key management is out of scope. No signing key lifecycle or trust PKI is defined in this layer.

Network transport is out of scope. Replication/exchange channels are not part of this protocol layer.

Access control is out of scope. Authorization policy and identity management are external concerns.

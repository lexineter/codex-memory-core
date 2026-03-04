use crate::delta_proof::{compute_snapshot_delta, DocStore};
use crate::doc_proof::{
    compute_doc_merkle_root, generate_doc_proof as gen_doc_proof, DocInclusionProof,
};
use crate::ledger::writer::LedgerWriter;
use crate::protocol::protocol_hash;
use crate::schema::{
    DivergenceLocatorCommon, DivergenceLocatorFields, DocUpsertFields, Event, EventCommon,
    EventCommonUpsert, LifecycleFields, LifecycleGovernanceFields, ObserverBlock,
    OrderedCandidates, ProtocolLockCommon, ProtocolLockFields, ScoreCommitmentFields,
    ScoreEvaluatedExtra, SnapshotCommon, SnapshotDeltaCommon, SnapshotDeltaFields, SnapshotFields,
    EVENT_TYPE_DIVERGENCE_LOCATOR, EVENT_TYPE_DOC_UPSERT, EVENT_TYPE_LIFECYCLE_MUTATION,
    EVENT_TYPE_PROTOCOL_LOCK, EVENT_TYPE_SCORE_EVALUATED, EVENT_TYPE_SNAPSHOT,
    EVENT_TYPE_SNAPSHOT_DELTA, MAX_CANON_BYTES,
};
use crate::{
    bytes, cme, hash, CodexError, DIM, DOC_ID_BYTES, DOMAIN_CANDIDATE, DOMAIN_CONTENT,
    DOMAIN_DIVERGENCE, DOMAIN_DOC, DOMAIN_DOCSTATE, DOMAIN_DOC_AGG, DOMAIN_LIFECYCLE,
    DOMAIN_MMR_ROOT, DOMAIN_OBSERVER, DOMAIN_PRESTATE, DOMAIN_PROJECTION, DOMAIN_QUERY,
    DOMAIN_QUERY_CONTEXT, DOMAIN_QUERY_PROJECTION_COMMITMENT, DOMAIN_RECURSION_CONTEXT,
    DOMAIN_SCORE, FEATURE_DIVERGENCE_PROOF, FEATURE_DOC_MERKLE_STATE, FEATURE_LIFECYCLE_GOVERNANCE,
    FEATURE_OBSERVER_BLOCK, FEATURE_RECURSIVE_PROJECTION, FEATURE_SCORE_COMMITMENT,
    FEATURE_SCORE_PROOFS, FEATURE_SNAPSHOT_COMMITMENT, FEATURE_SNAPSHOT_DELTA_PROOF, HASH_LEN,
    MAX_QUERY_BYTES, MAX_QUERY_CONTEXT_BYTES, MAX_SCORE_BYTES, MAX_TOP_K, STATE_DELTA_BYTES,
};

const DIM_USIZE: usize = DIM as usize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineConfig {
    pub default_new_lifecycle_state: u8,
    pub default_new_representation_mode: u8,
    pub default_new_compressed_flag: u8,
    pub quarantine_span_events: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DocRecord {
    doc_id: [u8; DOC_ID_BYTES],
    vec: [i16; DIM_USIZE],
    life_state: u8,
    repr_mode: u8,
    compressed: u8,
    quarantine_until: u64,
    doc_state_hash: [u8; HASH_LEN],
    last_score: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SnapshotCheckpoint {
    snapshot_mmr_root: [u8; HASH_LEN],
    store: DocStore,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InsertResult {
    pub doc_id: [u8; DOC_ID_BYTES],
    pub projection: [i16; DIM_USIZE],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryResult {
    pub ordered_doc_ids: Vec<[u8; DOC_ID_BYTES]>,
    pub scores: Vec<i64>,
    pub candidate_commitment: [u8; HASH_LEN],
    pub query_projection_commitment: Option<[u8; HASH_LEN]>,
    pub score_commitment: Option<[u8; HASH_LEN]>,
    pub root_after: [u8; HASH_LEN],
    pub event_commitment: [u8; HASH_LEN],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationDecision {
    NoChange,
    SetCompressed {
        compressed: u8,
    },
    SetLifecycle {
        life_state: u8,
    },
    Quarantine {
        until_event_index: u64,
    },
    Full {
        life_state: u8,
        repr_mode: u8,
        compressed: u8,
        quarantine_until: u64,
    },
}

#[derive(Debug)]
pub struct Engine {
    config: EngineConfig,
    docs: Vec<DocRecord>,
    next_event_index: u64,
    current_auth_root: [u8; HASH_LEN],
    current_state_hash: [u8; HASH_LEN],
    ledger: LedgerWriter,
    ledger_flags: u32,
    snapshots: Vec<SnapshotCheckpoint>,
    transcript_commitments: Vec<[u8; HASH_LEN]>,
}

fn project(input: &[u8]) -> [i16; DIM_USIZE] {
    let mut expanded = [0u8; DIM_USIZE * 2];
    let mut at = 0usize;
    for counter in 0u8..8u8 {
        let mut payload = Vec::with_capacity(1 + input.len());
        payload.push(counter);
        payload.extend_from_slice(input);
        let block = hash::hash_domain(DOMAIN_PROJECTION, &payload);
        expanded[at..at + HASH_LEN].copy_from_slice(&block);
        at += HASH_LEN;
    }
    let mut out = [0i16; DIM_USIZE];
    let mut i = 0usize;
    while i < DIM_USIZE {
        out[i] = i16::from_be_bytes([expanded[i * 2], expanded[i * 2 + 1]]);
        i += 1;
    }
    out
}

fn dot(q: &[i16; DIM_USIZE], d: &[i16; DIM_USIZE]) -> i64 {
    let mut acc = 0i64;
    let mut i = 0usize;
    while i < DIM_USIZE {
        acc += (q[i] as i32 as i64) * (d[i] as i32 as i64);
        i += 1;
    }
    acc
}

fn candidate_commitment(doc_ids: &[[u8; DOC_ID_BYTES]]) -> [u8; HASH_LEN] {
    let mut payload = Vec::with_capacity(4 + doc_ids.len() * DOC_ID_BYTES);
    bytes::write_u32_be(&mut payload, doc_ids.len() as u32);
    for id in doc_ids {
        payload.extend_from_slice(id);
    }
    hash::hash_domain(DOMAIN_CANDIDATE, &payload)
}

fn is_all_zero_32(x: &[u8; HASH_LEN]) -> bool {
    x.iter().all(|b| *b == 0)
}

fn state_hash_next(prev: &[u8; HASH_LEN], commitment: &[u8; HASH_LEN]) -> [u8; HASH_LEN] {
    let mut payload = Vec::with_capacity(HASH_LEN * 2);
    payload.extend_from_slice(prev);
    payload.extend_from_slice(commitment);
    hash::hash_domain(DOMAIN_PRESTATE, &payload)
}

fn doc_state_next(prev: &[u8; HASH_LEN], commitment: &[u8; HASH_LEN]) -> [u8; HASH_LEN] {
    let mut payload = Vec::with_capacity(HASH_LEN * 2);
    payload.extend_from_slice(prev);
    payload.extend_from_slice(commitment);
    hash::hash_domain(DOMAIN_DOCSTATE, &payload)
}

fn state_delta_bytes(
    life_state: u8,
    repr_mode: u8,
    compressed: u8,
    quarantine_until: u64,
) -> [u8; STATE_DELTA_BYTES] {
    let mut out = [0u8; STATE_DELTA_BYTES];
    out[0] = life_state;
    out[1] = repr_mode;
    out[2] = compressed;
    out[3..11].copy_from_slice(&quarantine_until.to_be_bytes());
    out
}

fn projection_bytes(vec: &[i16; DIM_USIZE]) -> [u8; 256] {
    let mut out = [0u8; 256];
    let mut i = 0usize;
    while i < DIM_USIZE {
        let b = vec[i].to_be_bytes();
        out[i * 2] = b[0];
        out[i * 2 + 1] = b[1];
        i += 1;
    }
    out
}

fn doc_state_seed(doc_id: &[u8; HASH_LEN]) -> [u8; HASH_LEN] {
    hash::hash_domain(DOMAIN_DOCSTATE, doc_id)
}

fn doc_commitment(
    doc_id: &[u8; HASH_LEN],
    content_commitment: &[u8; HASH_LEN],
    projection_commitment: &[u8; HASH_LEN],
) -> [u8; HASH_LEN] {
    let mut payload = Vec::with_capacity(HASH_LEN * 3);
    payload.extend_from_slice(doc_id);
    payload.extend_from_slice(content_commitment);
    payload.extend_from_slice(projection_commitment);
    hash::hash_domain(DOMAIN_DOC, &payload)
}

fn recursive_projection_enabled(flags: u32) -> bool {
    (flags & FEATURE_RECURSIVE_PROJECTION) != 0
}

fn score_commitment_enabled(flags: u32) -> bool {
    (flags & FEATURE_SCORE_COMMITMENT) != 0
}

fn score_proofs_enabled(flags: u32) -> bool {
    (flags & FEATURE_SCORE_PROOFS) != 0
}

fn lifecycle_governance_enabled(flags: u32) -> bool {
    (flags & FEATURE_LIFECYCLE_GOVERNANCE) != 0
}

fn snapshot_enabled(flags: u32) -> bool {
    (flags & FEATURE_SNAPSHOT_COMMITMENT) != 0
}

fn divergence_enabled(flags: u32) -> bool {
    (flags & FEATURE_DIVERGENCE_PROOF) != 0
}

fn doc_merkle_enabled(flags: u32) -> bool {
    (flags & FEATURE_DOC_MERKLE_STATE) != 0
}

fn snapshot_delta_enabled(flags: u32) -> bool {
    (flags & FEATURE_SNAPSHOT_DELTA_PROOF) != 0
}

fn make_recursive_input(query_bytes: &[u8], observer: Option<&ObserverBlock>) -> Vec<u8> {
    if let Some(ob) = observer {
        let mut out = Vec::with_capacity(query_bytes.len() + HASH_LEN + 4);
        out.extend_from_slice(query_bytes);
        out.extend_from_slice(&ob.observer_signature);
        bytes::write_u32_be(&mut out, ob.field_coherence_enc);
        out
    } else {
        query_bytes.to_vec()
    }
}

fn query_projection_commitment_from_vec(qvec: &[i16; DIM_USIZE]) -> [u8; HASH_LEN] {
    let packed = projection_bytes(qvec);
    hash::hash_domain(DOMAIN_QUERY_PROJECTION_COMMITMENT, &packed)
}

fn build_score_bytes(
    ordered_doc_ids: &[[u8; DOC_ID_BYTES]],
    scores: &[i64],
) -> Result<(u32, Vec<u8>), CodexError> {
    if ordered_doc_ids.len() != scores.len() {
        return Err(CodexError::InvalidInput("SCORE_LEN_MISMATCH"));
    }
    if ordered_doc_ids.len() > MAX_TOP_K {
        return Err(CodexError::InvalidInput("TOP_K_EXCEEDS_MAX"));
    }
    let k = ordered_doc_ids.len() as u32;
    let mut out = Vec::with_capacity(4 + ordered_doc_ids.len() * 40);
    bytes::write_u32_be(&mut out, k);
    for (doc_id, score) in ordered_doc_ids.iter().zip(scores.iter()) {
        out.extend_from_slice(doc_id);
        out.extend_from_slice(&score.to_be_bytes());
    }
    if out.len() > MAX_SCORE_BYTES {
        return Err(CodexError::InvalidInput("SCORE_BYTES_TOO_LARGE"));
    }
    Ok((k, out))
}

fn lifecycle_hash(
    life_state: u8,
    repr_mode: u8,
    compressed: u8,
    quarantine_until: u64,
) -> [u8; HASH_LEN] {
    let mut payload = Vec::with_capacity(11);
    payload.push(life_state);
    payload.push(repr_mode);
    payload.push(compressed);
    bytes::write_u64_be(&mut payload, quarantine_until);
    hash::hash_domain(DOMAIN_LIFECYCLE, &payload)
}

fn apply_threshold_rule(
    last_score: i64,
    current_event_index: u64,
    quarantine_span_events: u64,
    life_state: u8,
    repr_mode: u8,
    compressed: u8,
    quarantine_until: u64,
) -> (u8, u8, u8, u64) {
    if last_score >= 0 {
        (1, repr_mode, 0, 0)
    } else if last_score < -50_000 {
        (
            2,
            repr_mode,
            1,
            current_event_index + quarantine_span_events,
        )
    } else {
        (life_state, repr_mode, compressed, quarantine_until)
    }
}

fn doc_aggregate_hash(docs: &[DocRecord]) -> [u8; HASH_LEN] {
    let mut agg_payload = Vec::with_capacity(4 + (HASH_LEN * docs.len()));
    bytes::write_u32_be(&mut agg_payload, docs.len() as u32);
    for rec in docs {
        let proj_bytes = projection_bytes(&rec.vec);
        let projection_commitment = hash::hash_domain(DOMAIN_PROJECTION, &proj_bytes);
        let mut fp_preimage = Vec::with_capacity(HASH_LEN * 3);
        fp_preimage.extend_from_slice(&rec.doc_id);
        fp_preimage.extend_from_slice(&rec.doc_state_hash);
        fp_preimage.extend_from_slice(&projection_commitment);
        let fp = hash::hash_domain(DOMAIN_DOC_AGG, &fp_preimage);
        agg_payload.extend_from_slice(&fp);
    }
    hash::hash_domain(DOMAIN_DOC_AGG, &agg_payload)
}

fn doc_store_from_docs(docs: &[DocRecord]) -> DocStore {
    docs.iter()
        .map(|r| {
            let projection_commitment =
                hash::hash_domain(DOMAIN_PROJECTION, &projection_bytes(&r.vec));
            let leaf =
                crate::doc_proof::doc_leaf_hash(r.doc_id, r.doc_state_hash, projection_commitment);
            (r.doc_id, leaf)
        })
        .collect()
}

fn divergence_locator_commitment(
    event_count: u64,
    mmr_root: [u8; HASH_LEN],
    state_hash: [u8; HASH_LEN],
) -> [u8; HASH_LEN] {
    let mut payload = Vec::with_capacity(8 + HASH_LEN * 2);
    bytes::write_u64_be(&mut payload, event_count);
    payload.extend_from_slice(&mmr_root);
    payload.extend_from_slice(&state_hash);
    hash::hash_domain(DOMAIN_DIVERGENCE, &payload)
}

impl Engine {
    pub fn create(
        ledger_path: &str,
        index_path: &str,
        json_path: Option<&str>,
        flags: u32,
        config: EngineConfig,
    ) -> Result<Engine, CodexError> {
        let ledger = LedgerWriter::create(ledger_path, index_path, json_path, flags)?;
        Ok(Engine {
            config,
            docs: Vec::new(),
            next_event_index: 0,
            current_auth_root: hash::hash_domain(DOMAIN_MMR_ROOT, b""),
            current_state_hash: hash::hash_domain(DOMAIN_PRESTATE, b""),
            ledger,
            ledger_flags: flags,
            snapshots: Vec::new(),
            transcript_commitments: Vec::new(),
        })
    }

    pub fn insert(&mut self, content_bytes: &[u8]) -> Result<InsertResult, CodexError> {
        if content_bytes.len() > MAX_CANON_BYTES {
            return Err(CodexError::InvalidInput("CANON_BYTES_TOO_LARGE"));
        }
        let doc_id = hash::sha256(content_bytes);
        let projection = project(content_bytes);
        let proj_bytes = projection_bytes(&projection);

        let content_commitment = hash::hash_domain(DOMAIN_CONTENT, content_bytes);
        let projection_commitment = hash::hash_domain(DOMAIN_PROJECTION, &proj_bytes);
        let doc_commitment = doc_commitment(&doc_id, &content_commitment, &projection_commitment);

        let existing_idx = self.docs.binary_search_by(|r| r.doc_id.cmp(&doc_id));
        let pre_doc_state_hash = match existing_idx {
            Ok(i) => self.docs[i].doc_state_hash,
            Err(_) => doc_state_seed(&doc_id),
        };

        let up_common = EventCommonUpsert {
            event_type: EVENT_TYPE_DOC_UPSERT,
            timestamp: 0,
            event_index: self.next_event_index,
            doc_id,
            parent_auth_root: self.current_auth_root,
            pre_state_hash: self.current_state_hash,
        };
        let up_fields = DocUpsertFields {
            pre_doc_state_hash,
            content_commitment,
            projection_commitment,
            doc_commitment,
            canon_bytes: content_bytes.to_vec(),
            projection_bytes: proj_bytes,
        };
        let event = Event::DocUpsert {
            common: up_common,
            up: up_fields,
        };
        let appended = self.ledger.append(&event)?;
        self.transcript_commitments.push(appended.event_commitment);
        self.next_event_index += 1;
        self.current_auth_root = appended.root_after;
        self.current_state_hash =
            state_hash_next(&self.current_state_hash, &appended.event_commitment);
        let new_doc_state_hash = doc_state_next(&pre_doc_state_hash, &appended.event_commitment);

        match existing_idx {
            Ok(i) => {
                self.docs[i].vec = projection;
                self.docs[i].life_state = self.config.default_new_lifecycle_state;
                self.docs[i].repr_mode = self.config.default_new_representation_mode;
                self.docs[i].compressed = self.config.default_new_compressed_flag;
                self.docs[i].quarantine_until = 0;
                self.docs[i].doc_state_hash = new_doc_state_hash;
                self.docs[i].last_score = None;
            }
            Err(i) => {
                self.docs.insert(
                    i,
                    DocRecord {
                        doc_id,
                        vec: projection,
                        life_state: self.config.default_new_lifecycle_state,
                        repr_mode: self.config.default_new_representation_mode,
                        compressed: self.config.default_new_compressed_flag,
                        quarantine_until: 0,
                        doc_state_hash: new_doc_state_hash,
                        last_score: None,
                    },
                );
            }
        }
        Ok(InsertResult { doc_id, projection })
    }

    pub fn insert_cme(&mut self, input: cme::CmeInput<'_>) -> Result<InsertResult, CodexError> {
        let canon = cme::canonicalize(input)?;
        self.insert(&canon.canonical_bytes)
    }

    pub fn score_evaluated(
        &mut self,
        query_bytes: &[u8],
        candidate_doc_ids: &[[u8; DOC_ID_BYTES]],
    ) -> Result<QueryResult, CodexError> {
        if candidate_doc_ids.is_empty() {
            return Err(CodexError::InvalidInput("EMPTY_CANDIDATE_SET"));
        }

        let recursive_enabled = recursive_projection_enabled(self.ledger_flags);
        let score_enabled = score_commitment_enabled(self.ledger_flags);
        let proofs_enabled = score_proofs_enabled(self.ledger_flags);
        if recursive_enabled && query_bytes.len() > MAX_QUERY_BYTES {
            return Err(CodexError::InvalidInput("QUERY_BYTES_TOO_LARGE"));
        }
        let q_input = make_recursive_input(query_bytes, None);
        let qvec = project(&q_input);
        let query_proj_commitment = if recursive_enabled {
            Some(query_projection_commitment_from_vec(&qvec))
        } else {
            None
        };
        let mut scored = Vec::<([u8; DOC_ID_BYTES], i64)>::with_capacity(candidate_doc_ids.len());
        for doc_id in candidate_doc_ids {
            let idx = self
                .docs
                .binary_search_by(|r| r.doc_id.cmp(doc_id))
                .map_err(|_| CodexError::InvalidInput("CANDIDATE_DOC_ID_NOT_FOUND"))?;
            let score = dot(&qvec, &self.docs[idx].vec);
            scored.push((*doc_id, score));
        }

        scored.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

        let mut ordered_doc_ids = Vec::with_capacity(scored.len());
        let mut scores = Vec::with_capacity(scored.len());
        for (doc_id, score) in &scored {
            ordered_doc_ids.push(*doc_id);
            scores.push(*score);
        }

        let cand_commit = candidate_commitment(&ordered_doc_ids);
        if is_all_zero_32(&cand_commit) {
            return Err(CodexError::IntegrityError("CANDIDATE_COMMITMENT_ZERO"));
        }
        let (ordered_field, score_field, score_commitment) = if score_enabled {
            let (k, score_bytes) = build_score_bytes(&ordered_doc_ids, &scores)?;
            let score_commit = hash::hash_domain(DOMAIN_SCORE, &score_bytes);
            let ordered = OrderedCandidates {
                k,
                doc_ids: ordered_doc_ids.clone(),
            };
            let score = ScoreCommitmentFields {
                top_k: k,
                score_commitment: score_commit,
                score_bytes: if proofs_enabled {
                    Some(score_bytes)
                } else {
                    None
                },
            };
            (Some(ordered), Some(score), Some(score_commit))
        } else {
            (None, None, None)
        };
        if score_enabled {
            for (doc_id, score) in ordered_doc_ids.iter().zip(scores.iter()) {
                let idx = self
                    .docs
                    .binary_search_by(|r| r.doc_id.cmp(doc_id))
                    .map_err(|_| CodexError::InvalidInput("CANDIDATE_DOC_ID_NOT_FOUND"))?;
                self.docs[idx].last_score = Some(*score);
            }
        }

        let common = EventCommon {
            event_type: EVENT_TYPE_SCORE_EVALUATED,
            timestamp: 0,
            event_index: self.next_event_index,
            doc_id: ordered_doc_ids[0],
            parent_auth_root: self.current_auth_root,
            pre_state_hash: self.current_state_hash,
            candidate_commitment: cand_commit,
            state_delta: [0u8; STATE_DELTA_BYTES],
        };
        let event = Event::ScoreEvaluated {
            common,
            extra: query_proj_commitment.map(|c| ScoreEvaluatedExtra {
                query_bytes: query_bytes.to_vec(),
                query_projection_commitment: c,
            }),
            ordered: ordered_field,
            score: score_field,
            observer: None,
        };
        let appended = self.ledger.append(&event)?;
        self.transcript_commitments.push(appended.event_commitment);
        self.next_event_index += 1;
        self.current_auth_root = appended.root_after;
        self.current_state_hash =
            state_hash_next(&self.current_state_hash, &appended.event_commitment);

        Ok(QueryResult {
            ordered_doc_ids,
            scores,
            candidate_commitment: cand_commit,
            query_projection_commitment: query_proj_commitment,
            score_commitment,
            root_after: appended.root_after,
            event_commitment: appended.event_commitment,
        })
    }

    pub fn score_evaluated_cme(
        &mut self,
        query: cme::CmeInput<'_>,
        candidate_doc_ids: &[[u8; DOC_ID_BYTES]],
    ) -> Result<QueryResult, CodexError> {
        let canon = cme::canonicalize(query)?;
        self.score_evaluated(&canon.canonical_bytes, candidate_doc_ids)
    }

    pub fn lifecycle_mutation(
        &mut self,
        target_doc_id: [u8; DOC_ID_BYTES],
        decision: MutationDecision,
        candidate_commitment: [u8; HASH_LEN],
    ) -> Result<[u8; HASH_LEN], CodexError> {
        if is_all_zero_32(&candidate_commitment) {
            return Err(CodexError::InvalidInput("CANDIDATE_COMMITMENT_ZERO"));
        }
        let idx = self
            .docs
            .binary_search_by(|r| r.doc_id.cmp(&target_doc_id))
            .map_err(|_| CodexError::InvalidInput("DOC_NOT_FOUND"))?;

        let rec = &mut self.docs[idx];
        let (new_life, new_repr, new_comp, new_quarantine, governance) =
            if lifecycle_governance_enabled(self.ledger_flags) {
                let last_score = rec
                    .last_score
                    .ok_or(CodexError::InvalidInput("NO_LAST_SCORE"))?;
                let pre_hash = lifecycle_hash(
                    rec.life_state,
                    rec.repr_mode,
                    rec.compressed,
                    rec.quarantine_until,
                );
                let (nl, nr, nc, nq) = apply_threshold_rule(
                    last_score,
                    self.next_event_index,
                    self.config.quarantine_span_events,
                    rec.life_state,
                    rec.repr_mode,
                    rec.compressed,
                    rec.quarantine_until,
                );
                let post_hash = lifecycle_hash(nl, nr, nc, nq);
                (
                    nl,
                    nr,
                    nc,
                    nq,
                    Some(LifecycleGovernanceFields {
                        rule_id: 1,
                        pre_doc_lifecycle_hash: pre_hash,
                        post_doc_lifecycle_hash: post_hash,
                    }),
                )
            } else {
                let mut new_life = rec.life_state;
                let mut new_repr = rec.repr_mode;
                let mut new_comp = rec.compressed;
                let mut new_quarantine = rec.quarantine_until;
                match decision {
                    MutationDecision::NoChange => {}
                    MutationDecision::SetCompressed { compressed } => new_comp = compressed,
                    MutationDecision::SetLifecycle { life_state } => new_life = life_state,
                    MutationDecision::Quarantine { until_event_index } => {
                        new_quarantine = if until_event_index == 0 {
                            self.next_event_index + self.config.quarantine_span_events
                        } else {
                            until_event_index
                        };
                    }
                    MutationDecision::Full {
                        life_state,
                        repr_mode,
                        compressed,
                        quarantine_until,
                    } => {
                        new_life = life_state;
                        new_repr = repr_mode;
                        new_comp = compressed;
                        new_quarantine = quarantine_until;
                    }
                }
                (new_life, new_repr, new_comp, new_quarantine, None)
            };

        rec.life_state = new_life;
        rec.repr_mode = new_repr;
        rec.compressed = new_comp;
        rec.quarantine_until = new_quarantine;

        let delta = state_delta_bytes(new_life, new_repr, new_comp, new_quarantine);
        let common = EventCommon {
            event_type: EVENT_TYPE_LIFECYCLE_MUTATION,
            timestamp: 0,
            event_index: self.next_event_index,
            doc_id: target_doc_id,
            parent_auth_root: self.current_auth_root,
            pre_state_hash: self.current_state_hash,
            candidate_commitment,
            state_delta: delta,
        };
        let life = LifecycleFields {
            new_lifecycle_state: new_life,
            new_representation_mode: new_repr,
            new_compressed_flag: new_comp,
            quarantined_until_event_index: new_quarantine,
        };
        let event = Event::LifecycleMutation {
            common,
            life,
            governance,
            observer: None,
        };
        let appended = self.ledger.append(&event)?;
        self.transcript_commitments.push(appended.event_commitment);
        self.next_event_index += 1;
        self.current_auth_root = appended.root_after;
        self.current_state_hash =
            state_hash_next(&self.current_state_hash, &appended.event_commitment);

        Ok(appended.root_after)
    }

    fn make_observer_block(
        &self,
        query_context_bytes: &[u8],
        observer_id: [u8; 16],
        observer_state_flags: u16,
        breath_phase: u8,
        mirror_mode: u8,
        field_coherence_enc: u32,
    ) -> Result<ObserverBlock, CodexError> {
        if breath_phase > 3 {
            return Err(CodexError::InvalidInput("BREATH_PHASE_INVALID"));
        }
        if query_context_bytes.len() > MAX_QUERY_CONTEXT_BYTES {
            return Err(CodexError::InvalidInput("QUERY_CONTEXT_TOO_LARGE"));
        }

        let query_context_commitment = hash::hash_domain(DOMAIN_QUERY_CONTEXT, query_context_bytes);
        let query_commitment = hash::hash_domain(DOMAIN_QUERY, query_context_bytes);

        let mut observer_preimage = Vec::with_capacity(16 + 1 + 2 + HASH_LEN);
        observer_preimage.extend_from_slice(&observer_id);
        observer_preimage.push(breath_phase);
        bytes::write_u16_be(&mut observer_preimage, observer_state_flags);
        observer_preimage.extend_from_slice(&query_context_commitment);
        let observer_signature = hash::hash_domain(DOMAIN_OBSERVER, &observer_preimage);

        let mut recursion_preimage = Vec::with_capacity(HASH_LEN + 4);
        recursion_preimage.extend_from_slice(&observer_signature);
        bytes::write_u32_be(&mut recursion_preimage, field_coherence_enc);
        let recursion_context_commitment =
            hash::hash_domain(DOMAIN_RECURSION_CONTEXT, &recursion_preimage);

        Ok(ObserverBlock {
            observer_id,
            observer_state_flags,
            breath_phase,
            mirror_mode,
            field_coherence_enc,
            query_context_commitment,
            query_commitment,
            observer_signature,
            recursion_context_commitment,
            query_context_bytes: query_context_bytes.to_vec(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn score_evaluated_obs(
        &mut self,
        query_bytes: &[u8],
        query_context_bytes: &[u8],
        candidate_doc_ids: &[[u8; 32]],
        observer_id: [u8; 16],
        observer_state_flags: u16,
        breath_phase: u8,
        mirror_mode: u8,
        field_coherence_enc: u32,
    ) -> Result<QueryResult, CodexError> {
        if (self.ledger_flags & FEATURE_OBSERVER_BLOCK) == 0 {
            return Err(CodexError::InvalidInput("OBSERVER_BLOCK_DISABLED"));
        }
        if candidate_doc_ids.is_empty() {
            return Err(CodexError::InvalidInput("EMPTY_CANDIDATE_SET"));
        }
        let observer = self.make_observer_block(
            query_context_bytes,
            observer_id,
            observer_state_flags,
            breath_phase,
            mirror_mode,
            field_coherence_enc,
        )?;
        let recursive_enabled = recursive_projection_enabled(self.ledger_flags);
        let score_enabled = score_commitment_enabled(self.ledger_flags);
        let proofs_enabled = score_proofs_enabled(self.ledger_flags);
        if recursive_enabled && query_bytes.len() > MAX_QUERY_BYTES {
            return Err(CodexError::InvalidInput("QUERY_BYTES_TOO_LARGE"));
        }
        let q_input = make_recursive_input(query_bytes, Some(&observer));
        let qvec = project(&q_input);
        let query_proj_commitment = if recursive_enabled {
            Some(query_projection_commitment_from_vec(&qvec))
        } else {
            None
        };
        let mut scored = Vec::<([u8; DOC_ID_BYTES], i64)>::with_capacity(candidate_doc_ids.len());
        for doc_id in candidate_doc_ids {
            let idx = self
                .docs
                .binary_search_by(|r| r.doc_id.cmp(doc_id))
                .map_err(|_| CodexError::InvalidInput("CANDIDATE_DOC_ID_NOT_FOUND"))?;
            let score = dot(&qvec, &self.docs[idx].vec);
            scored.push((*doc_id, score));
        }
        scored.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

        let mut ordered_doc_ids = Vec::with_capacity(scored.len());
        let mut scores = Vec::with_capacity(scored.len());
        for (doc_id, score) in &scored {
            ordered_doc_ids.push(*doc_id);
            scores.push(*score);
        }

        let cand_commit = candidate_commitment(&ordered_doc_ids);
        if is_all_zero_32(&cand_commit) {
            return Err(CodexError::IntegrityError("CANDIDATE_COMMITMENT_ZERO"));
        }
        let (ordered_field, score_field, score_commitment) = if score_enabled {
            let (k, score_bytes) = build_score_bytes(&ordered_doc_ids, &scores)?;
            let score_commit = hash::hash_domain(DOMAIN_SCORE, &score_bytes);
            let ordered = OrderedCandidates {
                k,
                doc_ids: ordered_doc_ids.clone(),
            };
            let score = ScoreCommitmentFields {
                top_k: k,
                score_commitment: score_commit,
                score_bytes: if proofs_enabled {
                    Some(score_bytes)
                } else {
                    None
                },
            };
            (Some(ordered), Some(score), Some(score_commit))
        } else {
            (None, None, None)
        };
        if score_enabled {
            for (doc_id, score) in ordered_doc_ids.iter().zip(scores.iter()) {
                let idx = self
                    .docs
                    .binary_search_by(|r| r.doc_id.cmp(doc_id))
                    .map_err(|_| CodexError::InvalidInput("CANDIDATE_DOC_ID_NOT_FOUND"))?;
                self.docs[idx].last_score = Some(*score);
            }
        }

        let common = EventCommon {
            event_type: EVENT_TYPE_SCORE_EVALUATED,
            timestamp: 0,
            event_index: self.next_event_index,
            doc_id: ordered_doc_ids[0],
            parent_auth_root: self.current_auth_root,
            pre_state_hash: self.current_state_hash,
            candidate_commitment: cand_commit,
            state_delta: [0u8; STATE_DELTA_BYTES],
        };
        let event = Event::ScoreEvaluated {
            common,
            extra: query_proj_commitment.map(|c| ScoreEvaluatedExtra {
                query_bytes: query_bytes.to_vec(),
                query_projection_commitment: c,
            }),
            ordered: ordered_field,
            score: score_field,
            observer: Some(observer),
        };
        let appended = self.ledger.append(&event)?;
        self.transcript_commitments.push(appended.event_commitment);
        self.next_event_index += 1;
        self.current_auth_root = appended.root_after;
        self.current_state_hash =
            state_hash_next(&self.current_state_hash, &appended.event_commitment);

        Ok(QueryResult {
            ordered_doc_ids,
            scores,
            candidate_commitment: cand_commit,
            query_projection_commitment: query_proj_commitment,
            score_commitment,
            root_after: appended.root_after,
            event_commitment: appended.event_commitment,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn lifecycle_mutation_obs(
        &mut self,
        target_doc_id: [u8; 32],
        decision: MutationDecision,
        candidate_commitment: [u8; 32],
        query_context_bytes: &[u8],
        observer_id: [u8; 16],
        observer_state_flags: u16,
        breath_phase: u8,
        mirror_mode: u8,
        field_coherence_enc: u32,
    ) -> Result<[u8; 32], CodexError> {
        if (self.ledger_flags & FEATURE_OBSERVER_BLOCK) == 0 {
            return Err(CodexError::InvalidInput("OBSERVER_BLOCK_DISABLED"));
        }
        if is_all_zero_32(&candidate_commitment) {
            return Err(CodexError::InvalidInput("CANDIDATE_COMMITMENT_ZERO"));
        }
        let observer = self.make_observer_block(
            query_context_bytes,
            observer_id,
            observer_state_flags,
            breath_phase,
            mirror_mode,
            field_coherence_enc,
        )?;
        let idx = self
            .docs
            .binary_search_by(|r| r.doc_id.cmp(&target_doc_id))
            .map_err(|_| CodexError::InvalidInput("DOC_NOT_FOUND"))?;

        let rec = &mut self.docs[idx];
        let (new_life, new_repr, new_comp, new_quarantine, governance) =
            if lifecycle_governance_enabled(self.ledger_flags) {
                let last_score = rec
                    .last_score
                    .ok_or(CodexError::InvalidInput("NO_LAST_SCORE"))?;
                let pre_hash = lifecycle_hash(
                    rec.life_state,
                    rec.repr_mode,
                    rec.compressed,
                    rec.quarantine_until,
                );
                let (nl, nr, nc, nq) = apply_threshold_rule(
                    last_score,
                    self.next_event_index,
                    self.config.quarantine_span_events,
                    rec.life_state,
                    rec.repr_mode,
                    rec.compressed,
                    rec.quarantine_until,
                );
                let post_hash = lifecycle_hash(nl, nr, nc, nq);
                (
                    nl,
                    nr,
                    nc,
                    nq,
                    Some(LifecycleGovernanceFields {
                        rule_id: 1,
                        pre_doc_lifecycle_hash: pre_hash,
                        post_doc_lifecycle_hash: post_hash,
                    }),
                )
            } else {
                let mut new_life = rec.life_state;
                let mut new_repr = rec.repr_mode;
                let mut new_comp = rec.compressed;
                let mut new_quarantine = rec.quarantine_until;
                match decision {
                    MutationDecision::NoChange => {}
                    MutationDecision::SetCompressed { compressed } => new_comp = compressed,
                    MutationDecision::SetLifecycle { life_state } => new_life = life_state,
                    MutationDecision::Quarantine { until_event_index } => {
                        new_quarantine = if until_event_index == 0 {
                            self.next_event_index + self.config.quarantine_span_events
                        } else {
                            until_event_index
                        };
                    }
                    MutationDecision::Full {
                        life_state,
                        repr_mode,
                        compressed,
                        quarantine_until,
                    } => {
                        new_life = life_state;
                        new_repr = repr_mode;
                        new_comp = compressed;
                        new_quarantine = quarantine_until;
                    }
                }
                (new_life, new_repr, new_comp, new_quarantine, None)
            };
        rec.life_state = new_life;
        rec.repr_mode = new_repr;
        rec.compressed = new_comp;
        rec.quarantine_until = new_quarantine;

        let delta = state_delta_bytes(new_life, new_repr, new_comp, new_quarantine);
        let common = EventCommon {
            event_type: EVENT_TYPE_LIFECYCLE_MUTATION,
            timestamp: 0,
            event_index: self.next_event_index,
            doc_id: target_doc_id,
            parent_auth_root: self.current_auth_root,
            pre_state_hash: self.current_state_hash,
            candidate_commitment,
            state_delta: delta,
        };
        let life = LifecycleFields {
            new_lifecycle_state: new_life,
            new_representation_mode: new_repr,
            new_compressed_flag: new_comp,
            quarantined_until_event_index: new_quarantine,
        };
        let event = Event::LifecycleMutation {
            common,
            life,
            governance,
            observer: Some(observer),
        };
        let appended = self.ledger.append(&event)?;
        self.transcript_commitments.push(appended.event_commitment);
        self.next_event_index += 1;
        self.current_auth_root = appended.root_after;
        self.current_state_hash =
            state_hash_next(&self.current_state_hash, &appended.event_commitment);
        Ok(appended.root_after)
    }

    pub fn emit_snapshot(&mut self) -> Result<[u8; HASH_LEN], CodexError> {
        if !snapshot_enabled(self.ledger_flags) {
            return Err(CodexError::InvalidInput("SNAPSHOT_FEATURE_DISABLED"));
        }
        let docs_for_merkle: Vec<([u8; HASH_LEN], [u8; HASH_LEN], [u8; HASH_LEN])> = self
            .docs
            .iter()
            .map(|r| {
                (
                    r.doc_id,
                    r.doc_state_hash,
                    hash::hash_domain(DOMAIN_PROJECTION, &projection_bytes(&r.vec)),
                )
            })
            .collect();
        let common = SnapshotCommon {
            event_type: EVENT_TYPE_SNAPSHOT,
            timestamp: 0,
            event_index: self.next_event_index,
            parent_auth_root: self.current_auth_root,
            pre_state_hash: self.current_state_hash,
        };
        let snapshot_root = common.parent_auth_root;
        let snap = SnapshotFields {
            snapshot_state_hash: self.current_state_hash,
            snapshot_mmr_root: self.current_auth_root,
            doc_aggregate_hash: if doc_merkle_enabled(self.ledger_flags) {
                None
            } else {
                Some(doc_aggregate_hash(&self.docs))
            },
            doc_count: if doc_merkle_enabled(self.ledger_flags) {
                Some(docs_for_merkle.len() as u32)
            } else {
                None
            },
            doc_merkle_root: if doc_merkle_enabled(self.ledger_flags) {
                Some(compute_doc_merkle_root(&docs_for_merkle))
            } else {
                None
            },
        };
        let event = Event::Snapshot { common, snap };
        let appended = self.ledger.append(&event)?;
        self.transcript_commitments.push(appended.event_commitment);
        if doc_merkle_enabled(self.ledger_flags) {
            self.snapshots.push(SnapshotCheckpoint {
                snapshot_mmr_root: snapshot_root,
                store: doc_store_from_docs(&self.docs),
            });
        }
        self.next_event_index += 1;
        self.current_auth_root = appended.root_after;
        self.current_state_hash =
            state_hash_next(&self.current_state_hash, &appended.event_commitment);
        Ok(appended.root_after)
    }

    pub fn current_doc_merkle_root(&self) -> [u8; HASH_LEN] {
        let docs_for_merkle: Vec<([u8; HASH_LEN], [u8; HASH_LEN], [u8; HASH_LEN])> = self
            .docs
            .iter()
            .map(|r| {
                (
                    r.doc_id,
                    r.doc_state_hash,
                    hash::hash_domain(DOMAIN_PROJECTION, &projection_bytes(&r.vec)),
                )
            })
            .collect();
        compute_doc_merkle_root(&docs_for_merkle)
    }

    pub fn generate_doc_proof(
        &self,
        doc_id: [u8; HASH_LEN],
    ) -> Result<DocInclusionProof, CodexError> {
        if !doc_merkle_enabled(self.ledger_flags) {
            return Err(CodexError::InvalidInput("DOC_MERKLE_DISABLED"));
        }
        let docs_for_merkle: Vec<([u8; HASH_LEN], [u8; HASH_LEN], [u8; HASH_LEN])> = self
            .docs
            .iter()
            .map(|r| {
                (
                    r.doc_id,
                    r.doc_state_hash,
                    hash::hash_domain(DOMAIN_PROJECTION, &projection_bytes(&r.vec)),
                )
            })
            .collect();
        gen_doc_proof(&docs_for_merkle, doc_id)
    }

    pub fn emit_snapshot_delta(
        &mut self,
        base_snapshot_root: [u8; HASH_LEN],
        target_snapshot_root: [u8; HASH_LEN],
    ) -> Result<[u8; HASH_LEN], CodexError> {
        if !doc_merkle_enabled(self.ledger_flags) || !snapshot_delta_enabled(self.ledger_flags) {
            return Err(CodexError::InvalidInput("SNAPSHOT_DELTA_DISABLED"));
        }
        let base = self
            .snapshots
            .iter()
            .find(|s| s.snapshot_mmr_root == base_snapshot_root)
            .ok_or(CodexError::InvalidInput("SNAPSHOT_ROOT_NOT_FOUND"))?;
        let target = self
            .snapshots
            .iter()
            .find(|s| s.snapshot_mmr_root == target_snapshot_root)
            .ok_or(CodexError::InvalidInput("SNAPSHOT_ROOT_NOT_FOUND"))?;
        let delta = compute_snapshot_delta(&base.store, &target.store);
        let common = SnapshotDeltaCommon {
            event_type: EVENT_TYPE_SNAPSHOT_DELTA,
            timestamp: 0,
            event_index: self.next_event_index,
            parent_auth_root: self.current_auth_root,
            pre_state_hash: self.current_state_hash,
        };
        let delta_fields = SnapshotDeltaFields {
            base_snapshot_mmr_root: base_snapshot_root,
            target_snapshot_mmr_root: target_snapshot_root,
            delta_doc_count: delta.delta_doc_count,
            delta_root: delta.delta_root,
        };
        let event = Event::SnapshotDelta {
            common,
            delta: delta_fields,
        };
        let appended = self.ledger.append(&event)?;
        self.transcript_commitments.push(appended.event_commitment);
        self.next_event_index += 1;
        self.current_auth_root = appended.root_after;
        self.current_state_hash =
            state_hash_next(&self.current_state_hash, &appended.event_commitment);
        Ok(appended.root_after)
    }

    pub fn emit_divergence_locator(&mut self) -> Result<[u8; HASH_LEN], CodexError> {
        if !divergence_enabled(self.ledger_flags) {
            return Err(CodexError::InvalidInput("DIVERGENCE_FEATURE_DISABLED"));
        }
        let common = DivergenceLocatorCommon {
            event_type: EVENT_TYPE_DIVERGENCE_LOCATOR,
            timestamp: 0,
            event_index: self.next_event_index,
            parent_auth_root: self.current_auth_root,
            pre_state_hash: self.current_state_hash,
        };
        let loc = DivergenceLocatorFields {
            locator_event_count: self.next_event_index,
            locator_mmr_root: self.current_auth_root,
            locator_state_hash: self.current_state_hash,
            locator_commitment: divergence_locator_commitment(
                self.next_event_index,
                self.current_auth_root,
                self.current_state_hash,
            ),
        };
        let event = Event::DivergenceLocator { common, loc };
        let appended = self.ledger.append(&event)?;
        self.transcript_commitments.push(appended.event_commitment);
        self.next_event_index += 1;
        self.current_auth_root = appended.root_after;
        self.current_state_hash =
            state_hash_next(&self.current_state_hash, &appended.event_commitment);
        Ok(appended.root_after)
    }

    pub fn emit_protocol_lock(&mut self) -> Result<[u8; HASH_LEN], CodexError> {
        if self.next_event_index != 0 {
            return Err(CodexError::InvalidInput("PROTOCOL_LOCK_ORDER_INVALID"));
        }
        let common = ProtocolLockCommon {
            event_type: EVENT_TYPE_PROTOCOL_LOCK,
            timestamp: 0,
            event_index: self.next_event_index,
            parent_auth_root: self.current_auth_root,
            pre_state_hash: self.current_state_hash,
        };
        let lock = ProtocolLockFields {
            protocol_hash: protocol_hash(),
        };
        let event = Event::ProtocolLock { common, lock };
        let appended = self.ledger.append(&event)?;
        self.transcript_commitments.push(appended.event_commitment);
        self.next_event_index += 1;
        self.current_auth_root = appended.root_after;
        self.current_state_hash =
            state_hash_next(&self.current_state_hash, &appended.event_commitment);
        Ok(appended.root_after)
    }

    pub fn export_transcript_hash(&self) -> [u8; HASH_LEN] {
        let mut payload = Vec::with_capacity(8 + self.transcript_commitments.len() * HASH_LEN);
        bytes::write_u64_be(&mut payload, self.transcript_commitments.len() as u64);
        for c in &self.transcript_commitments {
            payload.extend_from_slice(c);
        }
        hash::hash_domain(crate::DOMAIN_TRANSCRIPT, &payload)
    }
}

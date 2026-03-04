use crate::delta_proof::{compute_snapshot_delta, DocStore};
use crate::doc_proof::compute_doc_merkle_root;
use crate::ledger::reader::LedgerReader;
use crate::mmr::Mmr;
use crate::protocol::protocol_hash;
use crate::schema::{self, Event, ObserverBlock};
use crate::{
    bytes, hash, CodexError, DOMAIN_CANDIDATE, DOMAIN_CONTENT, DOMAIN_DIVERGENCE, DOMAIN_DOC,
    DOMAIN_DOCSTATE, DOMAIN_DOC_AGG, DOMAIN_EVENT, DOMAIN_LIFECYCLE, DOMAIN_OBSERVER,
    DOMAIN_PRESTATE, DOMAIN_PROJECTION, DOMAIN_QUERY, DOMAIN_QUERY_CONTEXT,
    DOMAIN_QUERY_PROJECTION_COMMITMENT, DOMAIN_RECURSION_CONTEXT, DOMAIN_SCORE, DOMAIN_TRANSCRIPT,
    FEATURE_DIVERGENCE_PROOF, FEATURE_DOC_MERKLE_STATE, FEATURE_LIFECYCLE_GOVERNANCE,
    FEATURE_OBSERVER_BLOCK, FEATURE_PROTOCOL_LOCK_REQUIRED, FEATURE_RECURSIVE_PROJECTION,
    FEATURE_SCORE_COMMITMENT, FEATURE_SCORE_PROOFS, FEATURE_SNAPSHOT_COMMITMENT,
    FEATURE_SNAPSHOT_DELTA_PROOF, HASH_LEN, MAX_SCORE_BYTES,
};

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailCode {
    LedgerHeaderInvalid = 0x01,
    EventIndexNotSequential = 0x02,
    EventCommitmentMismatch = 0x03,
    ParentAuthRootMismatch = 0x04,
    PreStateHashMismatch = 0x05,
    CandidateCommitmentZero = 0x06,
    EventParseError = 0x07,
    IoError = 0x08,
    FinalRootMismatch = 0x09,
    DocCommitmentMismatch = 0x0A,
    ObserverOrQueryCommitmentMismatch = 0x0D,
    QueryProjectionCommitmentMismatch = 0x0E,
    ScoreCommitmentMismatch = 0x10,
    ScoreBytesMismatch = 0x11,
    LifecycleGovernanceViolation = 0x20,
    SnapshotMismatch = 0x30,
    DivergenceLocatorMismatch = 0x40,
    DocMerkleRootMismatch = 0x50,
    SnapshotDeltaMismatch = 0x60,
    ProtocolHashMismatch = 0x70,
}

impl FailCode {
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn message(self) -> &'static str {
        match self {
            FailCode::LedgerHeaderInvalid => "LEDGER_HEADER_INVALID",
            FailCode::EventIndexNotSequential => "EVENT_INDEX_NOT_SEQUENTIAL",
            FailCode::EventCommitmentMismatch => "EVENT_COMMITMENT_MISMATCH",
            FailCode::ParentAuthRootMismatch => "PARENT_AUTH_ROOT_MISMATCH",
            FailCode::PreStateHashMismatch => "PRE_STATE_HASH_MISMATCH",
            FailCode::CandidateCommitmentZero => "CANDIDATE_COMMITMENT_ZERO",
            FailCode::EventParseError => "EVENT_PARSE_ERROR",
            FailCode::IoError => "IO_ERROR",
            FailCode::FinalRootMismatch => "FINAL_ROOT_MISMATCH",
            FailCode::DocCommitmentMismatch => "DOC_COMMITMENT_MISMATCH",
            FailCode::ObserverOrQueryCommitmentMismatch => "OBSERVER_OR_QUERY_COMMITMENT_MISMATCH",
            FailCode::QueryProjectionCommitmentMismatch => "QUERY_PROJECTION_COMMITMENT_MISMATCH",
            FailCode::ScoreCommitmentMismatch => "SCORE_COMMITMENT_MISMATCH",
            FailCode::ScoreBytesMismatch => "SCORE_BYTES_MISMATCH",
            FailCode::LifecycleGovernanceViolation => "LIFECYCLE_GOVERNANCE_VIOLATION",
            FailCode::SnapshotMismatch => "SNAPSHOT_MISMATCH",
            FailCode::DivergenceLocatorMismatch => "DIVERGENCE_LOCATOR_MISMATCH",
            FailCode::DocMerkleRootMismatch => "DOC_MERKLE_ROOT_MISMATCH",
            FailCode::SnapshotDeltaMismatch => "SNAPSHOT_DELTA_MISMATCH",
            FailCode::ProtocolHashMismatch => "PROTOCOL_HASH_MISMATCH",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayReport {
    pub events_verified: u64,
    pub final_root: [u8; HASH_LEN],
    pub final_state_hash: [u8; HASH_LEN],
}

fn fail(code: FailCode) -> CodexError {
    CodexError::IntegrityError(code.message())
}

pub fn classify_error(err: &CodexError) -> FailCode {
    match err {
        CodexError::IntegrityError(s) | CodexError::InvalidInput(s) | CodexError::ParseError(s) => {
            match *s {
                "LEDGER_HEADER_INVALID" => FailCode::LedgerHeaderInvalid,
                "EVENT_INDEX_NOT_SEQUENTIAL" => FailCode::EventIndexNotSequential,
                "EVENT_COMMITMENT_MISMATCH" => FailCode::EventCommitmentMismatch,
                "PARENT_AUTH_ROOT_MISMATCH" => FailCode::ParentAuthRootMismatch,
                "PRE_STATE_HASH_MISMATCH" => FailCode::PreStateHashMismatch,
                "CANDIDATE_COMMITMENT_ZERO" => FailCode::CandidateCommitmentZero,
                "EVENT_PARSE_ERROR" => FailCode::EventParseError,
                "FINAL_ROOT_MISMATCH" => FailCode::FinalRootMismatch,
                "DOC_COMMITMENT_MISMATCH" => FailCode::DocCommitmentMismatch,
                "OBSERVER_OR_QUERY_COMMITMENT_MISMATCH" => {
                    FailCode::ObserverOrQueryCommitmentMismatch
                }
                "QUERY_PROJECTION_COMMITMENT_MISMATCH" => {
                    FailCode::QueryProjectionCommitmentMismatch
                }
                "SCORE_COMMITMENT_MISMATCH" => FailCode::ScoreCommitmentMismatch,
                "SCORE_BYTES_MISMATCH" => FailCode::ScoreBytesMismatch,
                "LIFECYCLE_GOVERNANCE_VIOLATION" => FailCode::LifecycleGovernanceViolation,
                "SNAPSHOT_MISMATCH" => FailCode::SnapshotMismatch,
                "DIVERGENCE_LOCATOR_MISMATCH" => FailCode::DivergenceLocatorMismatch,
                "DOC_MERKLE_ROOT_MISMATCH" => FailCode::DocMerkleRootMismatch,
                "SNAPSHOT_DELTA_MISMATCH" => FailCode::SnapshotDeltaMismatch,
                "PROTOCOL_HASH_MISMATCH"
                | "PROTOCOL_LOCK_REQUIRED"
                | "PROTOCOL_LOCK_DUPLICATE"
                | "PROTOCOL_LOCK_ORDER_INVALID" => FailCode::ProtocolHashMismatch,
                "LEDGER_OPEN_FAILED"
                | "LEDGER_READ_HEADER_FAILED"
                | "LEDGER_METADATA_FAILED"
                | "LEDGER_SEEK_FAILED"
                | "LEDGER_READ_EVENT_LEN_FAILED"
                | "LEDGER_READ_PAYLOAD_FAILED"
                | "LEDGER_READ_COMMITMENT_FAILED" => FailCode::IoError,
                "LEDGER_HEADER_MAGIC_MISMATCH"
                | "LEDGER_HEADER_MISMATCH"
                | "LEDGER_HEADER_RESERVED_NONZERO"
                | "LEDGER_HEADER_COMMITMENT_MISMATCH"
                | "LEDGER_HEADER_BAD_LENGTH" => FailCode::LedgerHeaderInvalid,
                _ => FailCode::IoError,
            }
        }
    }
}

fn verify_observer_block(ob: &ObserverBlock) -> Result<(), CodexError> {
    if ob.breath_phase > 3 {
        return Err(fail(FailCode::ObserverOrQueryCommitmentMismatch));
    }

    let qctx_commitment = hash::hash_domain(DOMAIN_QUERY_CONTEXT, &ob.query_context_bytes);
    if qctx_commitment != ob.query_context_commitment {
        return Err(fail(FailCode::ObserverOrQueryCommitmentMismatch));
    }
    let query_commitment = hash::hash_domain(DOMAIN_QUERY, &ob.query_context_bytes);
    if query_commitment != ob.query_commitment {
        return Err(fail(FailCode::ObserverOrQueryCommitmentMismatch));
    }

    let mut obs_preimage = Vec::with_capacity(16 + 1 + 2 + HASH_LEN);
    obs_preimage.extend_from_slice(&ob.observer_id);
    obs_preimage.push(ob.breath_phase);
    bytes::write_u16_be(&mut obs_preimage, ob.observer_state_flags);
    obs_preimage.extend_from_slice(&ob.query_context_commitment);
    let obs_sig = hash::hash_domain(DOMAIN_OBSERVER, &obs_preimage);
    if obs_sig != ob.observer_signature {
        return Err(fail(FailCode::ObserverOrQueryCommitmentMismatch));
    }

    let mut recursion_preimage = Vec::with_capacity(HASH_LEN + 4);
    recursion_preimage.extend_from_slice(&ob.observer_signature);
    bytes::write_u32_be(&mut recursion_preimage, ob.field_coherence_enc);
    let recursion_commitment = hash::hash_domain(DOMAIN_RECURSION_CONTEXT, &recursion_preimage);
    if recursion_commitment != ob.recursion_context_commitment {
        return Err(fail(FailCode::ObserverOrQueryCommitmentMismatch));
    }
    Ok(())
}

fn project(input: &[u8]) -> [i16; 128] {
    let mut expanded = [0u8; 256];
    let mut at = 0usize;
    for counter in 0u8..8u8 {
        let mut payload = Vec::with_capacity(1 + input.len());
        payload.push(counter);
        payload.extend_from_slice(input);
        let block = hash::hash_domain(DOMAIN_PROJECTION, &payload);
        expanded[at..at + 32].copy_from_slice(&block);
        at += 32;
    }
    let mut out = [0i16; 128];
    for i in 0..128usize {
        out[i] = i16::from_be_bytes([expanded[i * 2], expanded[i * 2 + 1]]);
    }
    out
}

fn projection_commitment(input: &[u8]) -> [u8; 32] {
    let qvec = project(input);
    let mut packed = [0u8; 256];
    for i in 0..128usize {
        let b = qvec[i].to_be_bytes();
        packed[i * 2] = b[0];
        packed[i * 2 + 1] = b[1];
    }
    hash::hash_domain(DOMAIN_QUERY_PROJECTION_COMMITMENT, &packed)
}

fn dot_from_projection_bytes(qvec: &[i16; 128], projection_bytes: &[u8; 256]) -> i64 {
    let mut acc = 0i64;
    for i in 0..128usize {
        let d = i16::from_be_bytes([projection_bytes[i * 2], projection_bytes[i * 2 + 1]]);
        acc += (qvec[i] as i32 as i64) * (d as i32 as i64);
    }
    acc
}

fn candidate_commitment_from_ordered(doc_ids: &[[u8; 32]]) -> [u8; 32] {
    let mut payload = Vec::with_capacity(4 + doc_ids.len() * 32);
    bytes::write_u32_be(&mut payload, doc_ids.len() as u32);
    for id in doc_ids {
        payload.extend_from_slice(id);
    }
    hash::hash_domain(DOMAIN_CANDIDATE, &payload)
}

fn score_bytes_from_ordered(doc_ids: &[[u8; 32]], scores: &[i64]) -> Result<Vec<u8>, CodexError> {
    if doc_ids.len() != scores.len() {
        return Err(fail(FailCode::ScoreBytesMismatch));
    }
    let mut out = Vec::with_capacity(4 + doc_ids.len() * 40);
    bytes::write_u32_be(&mut out, doc_ids.len() as u32);
    for (doc_id, score) in doc_ids.iter().zip(scores.iter()) {
        out.extend_from_slice(doc_id);
        out.extend_from_slice(&score.to_be_bytes());
    }
    if out.len() > MAX_SCORE_BYTES {
        return Err(fail(FailCode::ScoreBytesMismatch));
    }
    Ok(out)
}

fn doc_state_seed(doc_id: &[u8; HASH_LEN]) -> [u8; HASH_LEN] {
    hash::hash_domain(DOMAIN_DOCSTATE, doc_id)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReplayLifecycleState {
    life_state: u8,
    repr_mode: u8,
    compressed: u8,
    quarantine_until: u64,
    known: bool,
}

type ReplayDocEntry = ([u8; 32], [u8; 256], Option<i64>, ReplayLifecycleState);

fn lifecycle_hash(state: &ReplayLifecycleState) -> [u8; HASH_LEN] {
    let mut payload = Vec::with_capacity(11);
    payload.push(state.life_state);
    payload.push(state.repr_mode);
    payload.push(state.compressed);
    bytes::write_u64_be(&mut payload, state.quarantine_until);
    hash::hash_domain(DOMAIN_LIFECYCLE, &payload)
}

fn state_delta_matches(
    delta: &[u8; 128],
    life_state: u8,
    repr_mode: u8,
    compressed: u8,
    quarantine_until: u64,
) -> bool {
    if delta[0] != life_state || delta[1] != repr_mode || delta[2] != compressed {
        return false;
    }
    let mut q = [0u8; 8];
    q.copy_from_slice(&delta[3..11]);
    if u64::from_be_bytes(q) != quarantine_until {
        return false;
    }
    delta[11..].iter().all(|b| *b == 0)
}

fn find_doc_meta(docs: &[ReplayDocEntry], doc_id: &[u8; 32]) -> Result<usize, usize> {
    docs.binary_search_by(|(id, _, _, _)| id.cmp(doc_id))
}

fn update_doc_projection_and_meta(
    docs: &mut Vec<ReplayDocEntry>,
    doc_id: [u8; 32],
    projection_bytes: [u8; 256],
) {
    let default_lifecycle = ReplayLifecycleState {
        life_state: 0,
        repr_mode: 0,
        compressed: 0,
        quarantine_until: 0,
        known: false,
    };
    match find_doc_meta(docs, &doc_id) {
        Ok(i) => {
            docs[i].1 = projection_bytes;
            docs[i].2 = None;
            docs[i].3 = default_lifecycle;
        }
        Err(i) => docs.insert(i, (doc_id, projection_bytes, None, default_lifecycle)),
    }
}

fn doc_state_next(prev: &[u8; HASH_LEN], event_commitment: &[u8; HASH_LEN]) -> [u8; HASH_LEN] {
    let mut payload = Vec::with_capacity(HASH_LEN * 2);
    payload.extend_from_slice(prev);
    payload.extend_from_slice(event_commitment);
    hash::hash_domain(DOMAIN_DOCSTATE, &payload)
}

fn find_doc_state(
    doc_states: &[([u8; HASH_LEN], [u8; HASH_LEN])],
    doc_id: &[u8; HASH_LEN],
) -> Result<usize, usize> {
    doc_states.binary_search_by(|(id, _)| id.cmp(doc_id))
}

fn hash_doc_commitment(
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

fn update_doc_state(
    doc_states: &mut Vec<([u8; HASH_LEN], [u8; HASH_LEN])>,
    doc_id: [u8; HASH_LEN],
    state: [u8; HASH_LEN],
) {
    match find_doc_state(doc_states, &doc_id) {
        Ok(i) => doc_states[i].1 = state,
        Err(i) => doc_states.insert(i, (doc_id, state)),
    }
}

fn doc_aggregate_hash_replay(
    docs: &[ReplayDocEntry],
    doc_states: &[([u8; HASH_LEN], [u8; HASH_LEN])],
) -> Result<[u8; HASH_LEN], CodexError> {
    let mut agg_payload = Vec::with_capacity(4 + docs.len() * HASH_LEN);
    bytes::write_u32_be(&mut agg_payload, docs.len() as u32);
    for (doc_id, projection_bytes, _, _) in docs {
        let state_idx =
            find_doc_state(doc_states, doc_id).map_err(|_| fail(FailCode::SnapshotMismatch))?;
        let doc_state_hash = doc_states[state_idx].1;
        let projection_commitment = hash::hash_domain(DOMAIN_PROJECTION, projection_bytes);
        let mut fp_preimage = Vec::with_capacity(HASH_LEN * 3);
        fp_preimage.extend_from_slice(doc_id);
        fp_preimage.extend_from_slice(&doc_state_hash);
        fp_preimage.extend_from_slice(&projection_commitment);
        let fp = hash::hash_domain(DOMAIN_DOC_AGG, &fp_preimage);
        agg_payload.extend_from_slice(&fp);
    }
    Ok(hash::hash_domain(DOMAIN_DOC_AGG, &agg_payload))
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

fn doc_store_from_replay(
    docs: &[ReplayDocEntry],
    doc_states: &[([u8; HASH_LEN], [u8; HASH_LEN])],
) -> Result<DocStore, CodexError> {
    let mut out = Vec::with_capacity(docs.len());
    for (doc_id, projection_bytes, _, _) in docs {
        let sidx = find_doc_state(doc_states, doc_id)
            .map_err(|_| fail(FailCode::SnapshotDeltaMismatch))?;
        let projection_commitment = hash::hash_domain(DOMAIN_PROJECTION, projection_bytes);
        let leaf =
            crate::doc_proof::doc_leaf_hash(*doc_id, doc_states[sidx].1, projection_commitment);
        out.push((*doc_id, leaf));
    }
    Ok(out)
}

fn transcript_hash_from_commitments(commitments: &[[u8; HASH_LEN]]) -> [u8; HASH_LEN] {
    let mut payload = Vec::with_capacity(8 + commitments.len() * HASH_LEN);
    bytes::write_u64_be(&mut payload, commitments.len() as u64);
    for c in commitments {
        payload.extend_from_slice(c);
    }
    hash::hash_domain(DOMAIN_TRANSCRIPT, &payload)
}

pub fn compute_transcript_hash(ledger_path: &str) -> Result<[u8; HASH_LEN], CodexError> {
    let mut reader = LedgerReader::open(ledger_path)?;
    let mut commitments = Vec::<[u8; HASH_LEN]>::new();
    for item in reader.iter_raw() {
        let (_, payload, _) = item?;
        commitments.push(hash::hash_domain(DOMAIN_EVENT, &payload));
    }
    Ok(transcript_hash_from_commitments(&commitments))
}

pub fn verify_ledger(ledger_path: &str) -> Result<ReplayReport, CodexError> {
    let mut reader = match LedgerReader::open(ledger_path) {
        Ok(r) => r,
        Err(e) => {
            let code = match classify_error(&e) {
                FailCode::IoError => FailCode::IoError,
                _ => FailCode::LedgerHeaderInvalid,
            };
            return Err(fail(code));
        }
    };

    let mut mmr = Mmr::new();
    let mut expected_event_index = 0u64;
    let mut state_hash = hash::hash_domain(DOMAIN_PRESTATE, b"");
    let mut doc_states: Vec<([u8; HASH_LEN], [u8; HASH_LEN])> = Vec::new();
    let mut docs: Vec<ReplayDocEntry> = Vec::new();
    let mut snapshot_stores: Vec<([u8; HASH_LEN], DocStore)> = Vec::new();
    let mut seen_protocol_lock = false;
    let mut seen_non_lock = false;
    let mut transcript_commitments: Vec<[u8; HASH_LEN]> = Vec::new();
    let flags = reader.header().flags;

    for item in reader.iter_raw() {
        let (_, payload, stored_commitment) = match item {
            Ok(v) => v,
            Err(e) => {
                let code = classify_error(&e);
                return Err(fail(code));
            }
        };

        let recomputed = hash::hash_domain(DOMAIN_EVENT, &payload);
        if recomputed != stored_commitment {
            return Err(fail(FailCode::EventCommitmentMismatch));
        }
        transcript_commitments.push(recomputed);

        let event = match schema::decode_event_payload(&payload, flags) {
            Ok(ev) => ev,
            Err(_) => return Err(fail(FailCode::EventParseError)),
        };

        let current_root = mmr.root();
        match &event {
            Event::DocUpsert { common, up } => {
                if (flags & FEATURE_PROTOCOL_LOCK_REQUIRED) != 0 && !seen_protocol_lock {
                    return Err(fail(FailCode::ProtocolHashMismatch));
                }
                seen_non_lock = true;
                if common.event_index != expected_event_index {
                    return Err(fail(FailCode::EventIndexNotSequential));
                }
                if common.parent_auth_root != current_root {
                    return Err(fail(FailCode::ParentAuthRootMismatch));
                }
                if common.pre_state_hash != state_hash {
                    return Err(fail(FailCode::PreStateHashMismatch));
                }

                let prev_doc_state = match find_doc_state(&doc_states, &common.doc_id) {
                    Ok(i) => doc_states[i].1,
                    Err(_) => doc_state_seed(&common.doc_id),
                };
                if up.pre_doc_state_hash != prev_doc_state {
                    return Err(fail(FailCode::DocCommitmentMismatch));
                }

                let content_commitment = hash::hash_domain(DOMAIN_CONTENT, &up.canon_bytes);
                let projection_commitment =
                    hash::hash_domain(DOMAIN_PROJECTION, &up.projection_bytes);
                let doc_commitment = hash_doc_commitment(
                    &common.doc_id,
                    &content_commitment,
                    &projection_commitment,
                );

                if content_commitment != up.content_commitment
                    || projection_commitment != up.projection_commitment
                    || doc_commitment != up.doc_commitment
                {
                    return Err(fail(FailCode::DocCommitmentMismatch));
                }

                mmr.append(stored_commitment);
                let mut state_payload = Vec::with_capacity(HASH_LEN * 2);
                state_payload.extend_from_slice(&state_hash);
                state_payload.extend_from_slice(&stored_commitment);
                state_hash = hash::hash_domain(DOMAIN_PRESTATE, &state_payload);

                let new_doc_state = doc_state_next(&prev_doc_state, &stored_commitment);
                update_doc_state(&mut doc_states, common.doc_id, new_doc_state);
                update_doc_projection_and_meta(&mut docs, common.doc_id, up.projection_bytes);
            }
            Event::ScoreEvaluated {
                common,
                extra,
                ordered,
                score,
                observer,
            } => {
                if (flags & FEATURE_PROTOCOL_LOCK_REQUIRED) != 0 && !seen_protocol_lock {
                    return Err(fail(FailCode::ProtocolHashMismatch));
                }
                seen_non_lock = true;
                if common.event_index != expected_event_index {
                    return Err(fail(FailCode::EventIndexNotSequential));
                }
                if common.parent_auth_root != current_root {
                    return Err(fail(FailCode::ParentAuthRootMismatch));
                }
                if common.pre_state_hash != state_hash {
                    return Err(fail(FailCode::PreStateHashMismatch));
                }
                if common.candidate_commitment == [0u8; HASH_LEN] {
                    return Err(fail(FailCode::CandidateCommitmentZero));
                }
                let mut maybe_qvec = None;
                if (flags & FEATURE_RECURSIVE_PROJECTION) != 0 {
                    let extra = extra
                        .as_ref()
                        .ok_or_else(|| fail(FailCode::QueryProjectionCommitmentMismatch))?;
                    let mut input_for_projection = extra.query_bytes.clone();
                    if let Some(ob) = observer.as_ref() {
                        input_for_projection.extend_from_slice(&ob.observer_signature);
                        bytes::write_u32_be(&mut input_for_projection, ob.field_coherence_enc);
                    }
                    let expected = projection_commitment(&input_for_projection);
                    if expected != extra.query_projection_commitment {
                        return Err(fail(FailCode::QueryProjectionCommitmentMismatch));
                    }
                    maybe_qvec = Some(project(&input_for_projection));
                }
                if (flags & FEATURE_OBSERVER_BLOCK) != 0 {
                    let ob = observer
                        .as_ref()
                        .ok_or_else(|| fail(FailCode::ObserverOrQueryCommitmentMismatch))?;
                    verify_observer_block(ob)?;
                }
                if (flags & FEATURE_SCORE_COMMITMENT) != 0 {
                    let ordered = ordered
                        .as_ref()
                        .ok_or_else(|| fail(FailCode::ScoreCommitmentMismatch))?;
                    let score = score
                        .as_ref()
                        .ok_or_else(|| fail(FailCode::ScoreCommitmentMismatch))?;
                    if ordered.k != score.top_k || ordered.doc_ids.len() != ordered.k as usize {
                        return Err(fail(FailCode::ScoreCommitmentMismatch));
                    }
                    let candidate_commitment = candidate_commitment_from_ordered(&ordered.doc_ids);
                    if candidate_commitment != common.candidate_commitment {
                        return Err(fail(FailCode::ScoreCommitmentMismatch));
                    }

                    let qvec = maybe_qvec
                        .as_ref()
                        .ok_or_else(|| fail(FailCode::ScoreCommitmentMismatch))?;
                    let mut scores = Vec::with_capacity(ordered.doc_ids.len());
                    for doc_id in &ordered.doc_ids {
                        let idx = find_doc_meta(&docs, doc_id)
                            .map_err(|_| fail(FailCode::ScoreCommitmentMismatch))?;
                        let sc = dot_from_projection_bytes(qvec, &docs[idx].1);
                        scores.push(sc);
                    }
                    let expected_score_bytes = score_bytes_from_ordered(&ordered.doc_ids, &scores)?;
                    let expected_score_commitment =
                        hash::hash_domain(DOMAIN_SCORE, &expected_score_bytes);
                    if expected_score_commitment != score.score_commitment {
                        return Err(fail(FailCode::ScoreCommitmentMismatch));
                    }
                    if (flags & FEATURE_SCORE_PROOFS) != 0 {
                        let actual = score
                            .score_bytes
                            .as_ref()
                            .ok_or_else(|| fail(FailCode::ScoreBytesMismatch))?;
                        if *actual != expected_score_bytes {
                            return Err(fail(FailCode::ScoreBytesMismatch));
                        }
                    }
                    for (doc_id, score) in ordered.doc_ids.iter().zip(scores.iter()) {
                        if let Ok(i) = find_doc_meta(&docs, doc_id) {
                            docs[i].2 = Some(*score);
                        }
                    }
                }

                mmr.append(stored_commitment);
                let mut state_payload = Vec::with_capacity(HASH_LEN * 2);
                state_payload.extend_from_slice(&state_hash);
                state_payload.extend_from_slice(&stored_commitment);
                state_hash = hash::hash_domain(DOMAIN_PRESTATE, &state_payload);
            }
            Event::LifecycleMutation {
                common,
                life,
                governance,
                observer,
            } => {
                if (flags & FEATURE_PROTOCOL_LOCK_REQUIRED) != 0 && !seen_protocol_lock {
                    return Err(fail(FailCode::ProtocolHashMismatch));
                }
                seen_non_lock = true;
                if common.event_index != expected_event_index {
                    return Err(fail(FailCode::EventIndexNotSequential));
                }
                if common.parent_auth_root != current_root {
                    return Err(fail(FailCode::ParentAuthRootMismatch));
                }
                if common.pre_state_hash != state_hash {
                    return Err(fail(FailCode::PreStateHashMismatch));
                }
                if common.candidate_commitment == [0u8; HASH_LEN] {
                    return Err(fail(FailCode::CandidateCommitmentZero));
                }
                if (flags & FEATURE_OBSERVER_BLOCK) != 0 {
                    let ob = observer
                        .as_ref()
                        .ok_or_else(|| fail(FailCode::ObserverOrQueryCommitmentMismatch))?;
                    verify_observer_block(ob)?;
                }
                if (flags & FEATURE_LIFECYCLE_GOVERNANCE) != 0 {
                    let gov = governance
                        .as_ref()
                        .ok_or_else(|| fail(FailCode::LifecycleGovernanceViolation))?;
                    if gov.rule_id != 1 {
                        return Err(fail(FailCode::LifecycleGovernanceViolation));
                    }
                    let idx = find_doc_meta(&docs, &common.doc_id)
                        .map_err(|_| fail(FailCode::LifecycleGovernanceViolation))?;
                    let last_score = docs[idx]
                        .2
                        .ok_or_else(|| fail(FailCode::LifecycleGovernanceViolation))?;
                    let prev = docs[idx].3;
                    if prev.known {
                        let expected_pre = lifecycle_hash(&prev);
                        if expected_pre != gov.pre_doc_lifecycle_hash {
                            return Err(fail(FailCode::LifecycleGovernanceViolation));
                        }
                    }

                    let mut expected = prev;
                    if last_score >= 0 {
                        expected.life_state = 1;
                        expected.compressed = 0;
                        expected.quarantine_until = 0;
                    } else if last_score < -50_000 {
                        expected.life_state = 2;
                        expected.compressed = 1;
                        if life.quarantined_until_event_index <= common.event_index {
                            return Err(fail(FailCode::LifecycleGovernanceViolation));
                        }
                        expected.quarantine_until = life.quarantined_until_event_index;
                    }
                    if prev.known && life.new_representation_mode != prev.repr_mode {
                        return Err(fail(FailCode::LifecycleGovernanceViolation));
                    }
                    expected.repr_mode = life.new_representation_mode;
                    if life.new_lifecycle_state != expected.life_state
                        || life.new_compressed_flag != expected.compressed
                        || life.quarantined_until_event_index != expected.quarantine_until
                    {
                        return Err(fail(FailCode::LifecycleGovernanceViolation));
                    }
                    expected.known = true;
                    let expected_post = lifecycle_hash(&expected);
                    if expected_post != gov.post_doc_lifecycle_hash {
                        return Err(fail(FailCode::LifecycleGovernanceViolation));
                    }
                    if !state_delta_matches(
                        &common.state_delta,
                        life.new_lifecycle_state,
                        life.new_representation_mode,
                        life.new_compressed_flag,
                        life.quarantined_until_event_index,
                    ) {
                        return Err(fail(FailCode::LifecycleGovernanceViolation));
                    }
                    docs[idx].3 = expected;
                }

                mmr.append(stored_commitment);
                let mut state_payload = Vec::with_capacity(HASH_LEN * 2);
                state_payload.extend_from_slice(&state_hash);
                state_payload.extend_from_slice(&stored_commitment);
                state_hash = hash::hash_domain(DOMAIN_PRESTATE, &state_payload);
            }
            Event::Snapshot { common, snap } => {
                if (flags & FEATURE_PROTOCOL_LOCK_REQUIRED) != 0 && !seen_protocol_lock {
                    return Err(fail(FailCode::ProtocolHashMismatch));
                }
                seen_non_lock = true;
                if (flags & FEATURE_SNAPSHOT_COMMITMENT) == 0 {
                    return Err(fail(FailCode::SnapshotMismatch));
                }
                if common.event_index != expected_event_index {
                    return Err(fail(FailCode::EventIndexNotSequential));
                }
                if common.parent_auth_root != current_root {
                    return Err(fail(FailCode::ParentAuthRootMismatch));
                }
                if common.pre_state_hash != state_hash {
                    return Err(fail(FailCode::PreStateHashMismatch));
                }
                if snap.snapshot_state_hash != state_hash || snap.snapshot_mmr_root != current_root
                {
                    return Err(fail(FailCode::SnapshotMismatch));
                }
                if (flags & FEATURE_DOC_MERKLE_STATE) != 0 {
                    let expected_doc_count = docs.len() as u32;
                    let docs_for_merkle: Vec<([u8; HASH_LEN], [u8; HASH_LEN], [u8; HASH_LEN])> =
                        docs.iter()
                            .map(|(doc_id, projection_bytes, _, _)| {
                                let sidx = find_doc_state(&doc_states, doc_id)
                                    .map_err(|_| fail(FailCode::DocMerkleRootMismatch))?;
                                let projection_commitment =
                                    hash::hash_domain(DOMAIN_PROJECTION, projection_bytes);
                                Ok((*doc_id, doc_states[sidx].1, projection_commitment))
                            })
                            .collect::<Result<Vec<_>, CodexError>>()?;
                    let expected_root = compute_doc_merkle_root(&docs_for_merkle);
                    if snap.doc_count != Some(expected_doc_count)
                        || snap.doc_merkle_root != Some(expected_root)
                    {
                        return Err(fail(FailCode::DocMerkleRootMismatch));
                    }
                    snapshot_stores
                        .push((current_root, doc_store_from_replay(&docs, &doc_states)?));
                } else {
                    let expected_doc_agg = doc_aggregate_hash_replay(&docs, &doc_states)?;
                    if snap.doc_aggregate_hash != Some(expected_doc_agg) {
                        return Err(fail(FailCode::SnapshotMismatch));
                    }
                }

                mmr.append(stored_commitment);
                let mut state_payload = Vec::with_capacity(HASH_LEN * 2);
                state_payload.extend_from_slice(&state_hash);
                state_payload.extend_from_slice(&stored_commitment);
                state_hash = hash::hash_domain(DOMAIN_PRESTATE, &state_payload);
            }
            Event::SnapshotDelta { common, delta } => {
                if (flags & FEATURE_PROTOCOL_LOCK_REQUIRED) != 0 && !seen_protocol_lock {
                    return Err(fail(FailCode::ProtocolHashMismatch));
                }
                seen_non_lock = true;
                if (flags & FEATURE_SNAPSHOT_DELTA_PROOF) == 0
                    || (flags & FEATURE_DOC_MERKLE_STATE) == 0
                {
                    return Err(fail(FailCode::SnapshotDeltaMismatch));
                }
                if common.event_index != expected_event_index {
                    return Err(fail(FailCode::EventIndexNotSequential));
                }
                if common.parent_auth_root != current_root {
                    return Err(fail(FailCode::ParentAuthRootMismatch));
                }
                if common.pre_state_hash != state_hash {
                    return Err(fail(FailCode::PreStateHashMismatch));
                }
                let base_idx = snapshot_stores
                    .iter()
                    .position(|(root, _)| *root == delta.base_snapshot_mmr_root)
                    .ok_or_else(|| fail(FailCode::SnapshotDeltaMismatch))?;
                let target_idx = snapshot_stores
                    .iter()
                    .position(|(root, _)| *root == delta.target_snapshot_mmr_root)
                    .ok_or_else(|| fail(FailCode::SnapshotDeltaMismatch))?;
                if base_idx >= target_idx {
                    return Err(fail(FailCode::SnapshotDeltaMismatch));
                }
                let base = &snapshot_stores[base_idx];
                let target = &snapshot_stores[target_idx];
                let d = compute_snapshot_delta(&base.1, &target.1);
                if d.delta_doc_count != delta.delta_doc_count || d.delta_root != delta.delta_root {
                    return Err(fail(FailCode::SnapshotDeltaMismatch));
                }

                mmr.append(stored_commitment);
                let mut state_payload = Vec::with_capacity(HASH_LEN * 2);
                state_payload.extend_from_slice(&state_hash);
                state_payload.extend_from_slice(&stored_commitment);
                state_hash = hash::hash_domain(DOMAIN_PRESTATE, &state_payload);
            }
            Event::DivergenceLocator { common, loc } => {
                if (flags & FEATURE_PROTOCOL_LOCK_REQUIRED) != 0 && !seen_protocol_lock {
                    return Err(fail(FailCode::ProtocolHashMismatch));
                }
                seen_non_lock = true;
                if (flags & FEATURE_DIVERGENCE_PROOF) == 0 {
                    return Err(fail(FailCode::DivergenceLocatorMismatch));
                }
                if common.event_index != expected_event_index {
                    return Err(fail(FailCode::EventIndexNotSequential));
                }
                if common.parent_auth_root != current_root {
                    return Err(fail(FailCode::ParentAuthRootMismatch));
                }
                if common.pre_state_hash != state_hash {
                    return Err(fail(FailCode::PreStateHashMismatch));
                }
                let expected_locator_commitment =
                    divergence_locator_commitment(expected_event_index, current_root, state_hash);
                if loc.locator_event_count != expected_event_index
                    || loc.locator_mmr_root != current_root
                    || loc.locator_state_hash != state_hash
                    || loc.locator_commitment != expected_locator_commitment
                {
                    return Err(fail(FailCode::DivergenceLocatorMismatch));
                }

                mmr.append(stored_commitment);
                let mut state_payload = Vec::with_capacity(HASH_LEN * 2);
                state_payload.extend_from_slice(&state_hash);
                state_payload.extend_from_slice(&stored_commitment);
                state_hash = hash::hash_domain(DOMAIN_PRESTATE, &state_payload);
            }
            Event::ProtocolLock { common, lock } => {
                if seen_protocol_lock || seen_non_lock {
                    return Err(fail(FailCode::ProtocolHashMismatch));
                }
                if common.event_index != expected_event_index {
                    return Err(fail(FailCode::EventIndexNotSequential));
                }
                if common.parent_auth_root != current_root {
                    return Err(fail(FailCode::ParentAuthRootMismatch));
                }
                if common.pre_state_hash != state_hash {
                    return Err(fail(FailCode::PreStateHashMismatch));
                }
                if lock.protocol_hash != protocol_hash() {
                    return Err(fail(FailCode::ProtocolHashMismatch));
                }
                seen_protocol_lock = true;

                mmr.append(stored_commitment);
                let mut state_payload = Vec::with_capacity(HASH_LEN * 2);
                state_payload.extend_from_slice(&state_hash);
                state_payload.extend_from_slice(&stored_commitment);
                state_hash = hash::hash_domain(DOMAIN_PRESTATE, &state_payload);
            }
        }

        expected_event_index += 1;
    }
    if (flags & FEATURE_PROTOCOL_LOCK_REQUIRED) != 0 && !seen_protocol_lock {
        return Err(fail(FailCode::ProtocolHashMismatch));
    }
    let _ = transcript_hash_from_commitments(&transcript_commitments);

    Ok(ReplayReport {
        events_verified: expected_event_index,
        final_root: mmr.root(),
        final_state_hash: state_hash,
    })
}

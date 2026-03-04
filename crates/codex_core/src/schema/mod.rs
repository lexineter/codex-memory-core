use crate::{
    bytes, CodexError, DOC_ID_BYTES, FEATURE_DIVERGENCE_PROOF, FEATURE_DOC_MERKLE_STATE,
    FEATURE_LIFECYCLE_GOVERNANCE, FEATURE_OBSERVER_BLOCK, FEATURE_RECURSIVE_PROJECTION,
    FEATURE_SCORE_COMMITMENT, FEATURE_SCORE_PROOFS, FEATURE_SNAPSHOT_COMMITMENT,
    FEATURE_SNAPSHOT_DELTA_PROOF, HASH_LEN, MAX_QUERY_BYTES, MAX_QUERY_CONTEXT_BYTES,
    MAX_SCORE_BYTES, MAX_TOP_K, STATE_DELTA_BYTES,
};

pub const EVENT_TYPE_DOC_UPSERT: u8 = 0x01;
pub const EVENT_TYPE_SCORE_EVALUATED: u8 = 0x02;
pub const EVENT_TYPE_LIFECYCLE_MUTATION: u8 = 0x03;
pub const EVENT_TYPE_SNAPSHOT: u8 = 0x04;
pub const EVENT_TYPE_DIVERGENCE_LOCATOR: u8 = 0x05;
pub const EVENT_TYPE_SNAPSHOT_DELTA: u8 = 0x06;
pub const EVENT_TYPE_PROTOCOL_LOCK: u8 = 0x07;
pub const MAX_CANON_BYTES: usize = 64 * 1024;
pub const PROJECTION_BYTES_LEN: usize = 256;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    DocUpsert = EVENT_TYPE_DOC_UPSERT,
    ScoreEvaluated = EVENT_TYPE_SCORE_EVALUATED,
    LifecycleMutation = EVENT_TYPE_LIFECYCLE_MUTATION,
    Snapshot = EVENT_TYPE_SNAPSHOT,
    DivergenceLocator = EVENT_TYPE_DIVERGENCE_LOCATOR,
    SnapshotDelta = EVENT_TYPE_SNAPSHOT_DELTA,
    ProtocolLock = EVENT_TYPE_PROTOCOL_LOCK,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventCommon {
    pub event_type: u8,
    pub timestamp: u64,
    pub event_index: u64,
    pub doc_id: [u8; DOC_ID_BYTES],
    pub parent_auth_root: [u8; HASH_LEN],
    pub pre_state_hash: [u8; HASH_LEN],
    pub candidate_commitment: [u8; HASH_LEN],
    pub state_delta: [u8; STATE_DELTA_BYTES],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScoreEvaluatedExtra {
    pub query_bytes: Vec<u8>,
    pub query_projection_commitment: [u8; HASH_LEN],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderedCandidates {
    pub k: u32,
    pub doc_ids: Vec<[u8; HASH_LEN]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScoreCommitmentFields {
    pub top_k: u32,
    pub score_commitment: [u8; HASH_LEN],
    pub score_bytes: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventCommonUpsert {
    pub event_type: u8,
    pub timestamp: u64,
    pub event_index: u64,
    pub doc_id: [u8; DOC_ID_BYTES],
    pub parent_auth_root: [u8; HASH_LEN],
    pub pre_state_hash: [u8; HASH_LEN],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotCommon {
    pub event_type: u8,
    pub timestamp: u64,
    pub event_index: u64,
    pub parent_auth_root: [u8; HASH_LEN],
    pub pre_state_hash: [u8; HASH_LEN],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DivergenceLocatorCommon {
    pub event_type: u8,
    pub timestamp: u64,
    pub event_index: u64,
    pub parent_auth_root: [u8; HASH_LEN],
    pub pre_state_hash: [u8; HASH_LEN],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotDeltaCommon {
    pub event_type: u8,
    pub timestamp: u64,
    pub event_index: u64,
    pub parent_auth_root: [u8; HASH_LEN],
    pub pre_state_hash: [u8; HASH_LEN],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolLockCommon {
    pub event_type: u8,
    pub timestamp: u64,
    pub event_index: u64,
    pub parent_auth_root: [u8; HASH_LEN],
    pub pre_state_hash: [u8; HASH_LEN],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocUpsertFields {
    pub pre_doc_state_hash: [u8; HASH_LEN],
    pub content_commitment: [u8; HASH_LEN],
    pub projection_commitment: [u8; HASH_LEN],
    pub doc_commitment: [u8; HASH_LEN],
    pub canon_bytes: Vec<u8>,
    pub projection_bytes: [u8; PROJECTION_BYTES_LEN],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleFields {
    pub new_lifecycle_state: u8,
    pub new_representation_mode: u8,
    pub new_compressed_flag: u8,
    pub quarantined_until_event_index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleGovernanceFields {
    pub rule_id: u8,
    pub pre_doc_lifecycle_hash: [u8; HASH_LEN],
    pub post_doc_lifecycle_hash: [u8; HASH_LEN],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotFields {
    pub snapshot_state_hash: [u8; HASH_LEN],
    pub snapshot_mmr_root: [u8; HASH_LEN],
    pub doc_aggregate_hash: Option<[u8; HASH_LEN]>,
    pub doc_count: Option<u32>,
    pub doc_merkle_root: Option<[u8; HASH_LEN]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DivergenceLocatorFields {
    pub locator_event_count: u64,
    pub locator_mmr_root: [u8; HASH_LEN],
    pub locator_state_hash: [u8; HASH_LEN],
    pub locator_commitment: [u8; HASH_LEN],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotDeltaFields {
    pub base_snapshot_mmr_root: [u8; HASH_LEN],
    pub target_snapshot_mmr_root: [u8; HASH_LEN],
    pub delta_doc_count: u32,
    pub delta_root: [u8; HASH_LEN],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolLockFields {
    pub protocol_hash: [u8; HASH_LEN],
}

type EventPrefix = (u64, u64, [u8; 32], [u8; 32], [u8; 32], u8);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObserverBlock {
    pub observer_id: [u8; 16],
    pub observer_state_flags: u16,
    pub breath_phase: u8,
    pub mirror_mode: u8,
    pub field_coherence_enc: u32,
    pub query_context_commitment: [u8; HASH_LEN],
    pub query_commitment: [u8; HASH_LEN],
    pub observer_signature: [u8; HASH_LEN],
    pub recursion_context_commitment: [u8; HASH_LEN],
    pub query_context_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    DocUpsert {
        common: EventCommonUpsert,
        up: DocUpsertFields,
    },
    ScoreEvaluated {
        common: EventCommon,
        extra: Option<ScoreEvaluatedExtra>,
        ordered: Option<OrderedCandidates>,
        score: Option<ScoreCommitmentFields>,
        observer: Option<ObserverBlock>,
    },
    LifecycleMutation {
        common: EventCommon,
        life: LifecycleFields,
        governance: Option<LifecycleGovernanceFields>,
        observer: Option<ObserverBlock>,
    },
    Snapshot {
        common: SnapshotCommon,
        snap: SnapshotFields,
    },
    DivergenceLocator {
        common: DivergenceLocatorCommon,
        loc: DivergenceLocatorFields,
    },
    SnapshotDelta {
        common: SnapshotDeltaCommon,
        delta: SnapshotDeltaFields,
    },
    ProtocolLock {
        common: ProtocolLockCommon,
        lock: ProtocolLockFields,
    },
}

fn observer_enabled(flags: u32) -> bool {
    (flags & FEATURE_OBSERVER_BLOCK) != 0
}

fn recursive_enabled(flags: u32) -> bool {
    (flags & FEATURE_RECURSIVE_PROJECTION) != 0
}

fn score_enabled(flags: u32) -> bool {
    (flags & FEATURE_SCORE_COMMITMENT) != 0
}

fn proofs_enabled(flags: u32) -> bool {
    (flags & FEATURE_SCORE_PROOFS) != 0
}

fn governance_enabled(flags: u32) -> bool {
    (flags & FEATURE_LIFECYCLE_GOVERNANCE) != 0
}

fn snapshot_enabled(flags: u32) -> bool {
    (flags & FEATURE_SNAPSHOT_COMMITMENT) != 0
}

fn doc_merkle_enabled(flags: u32) -> bool {
    (flags & FEATURE_DOC_MERKLE_STATE) != 0
}

fn divergence_enabled(flags: u32) -> bool {
    (flags & FEATURE_DIVERGENCE_PROOF) != 0
}

fn snapshot_delta_enabled(flags: u32) -> bool {
    (flags & FEATURE_SNAPSHOT_DELTA_PROOF) != 0
}

fn validate_breath_phase(breath_phase: u8) -> Result<(), CodexError> {
    if breath_phase <= 3 {
        Ok(())
    } else {
        Err(CodexError::InvalidInput("BREATH_PHASE_INVALID"))
    }
}

fn encode_common_upsert(common: &EventCommonUpsert, out: &mut Vec<u8>) {
    out.push(common.event_type);
    bytes::write_u64_be(out, common.timestamp);
    bytes::write_u64_be(out, common.event_index);
    out.extend_from_slice(&common.doc_id);
    out.extend_from_slice(&common.parent_auth_root);
    out.extend_from_slice(&common.pre_state_hash);
}

fn encode_common_score_prefix(common: &EventCommon, out: &mut Vec<u8>) {
    out.push(common.event_type);
    bytes::write_u64_be(out, common.timestamp);
    bytes::write_u64_be(out, common.event_index);
    out.extend_from_slice(&common.doc_id);
    out.extend_from_slice(&common.parent_auth_root);
    out.extend_from_slice(&common.pre_state_hash);
}

fn encode_common_lifecycle_prefix(common: &EventCommon, out: &mut Vec<u8>) {
    out.push(common.event_type);
    bytes::write_u64_be(out, common.timestamp);
    bytes::write_u64_be(out, common.event_index);
    out.extend_from_slice(&common.doc_id);
    out.extend_from_slice(&common.parent_auth_root);
    out.extend_from_slice(&common.pre_state_hash);
}

fn encode_common_snapshot_prefix(common: &SnapshotCommon, out: &mut Vec<u8>) {
    out.push(common.event_type);
    bytes::write_u64_be(out, common.timestamp);
    bytes::write_u64_be(out, common.event_index);
    out.extend_from_slice(&common.parent_auth_root);
    out.extend_from_slice(&common.pre_state_hash);
}

fn encode_common_divergence_prefix(common: &DivergenceLocatorCommon, out: &mut Vec<u8>) {
    out.push(common.event_type);
    bytes::write_u64_be(out, common.timestamp);
    bytes::write_u64_be(out, common.event_index);
    out.extend_from_slice(&common.parent_auth_root);
    out.extend_from_slice(&common.pre_state_hash);
}

fn encode_common_snapshot_delta_prefix(common: &SnapshotDeltaCommon, out: &mut Vec<u8>) {
    out.push(common.event_type);
    bytes::write_u64_be(out, common.timestamp);
    bytes::write_u64_be(out, common.event_index);
    out.extend_from_slice(&common.parent_auth_root);
    out.extend_from_slice(&common.pre_state_hash);
}

fn encode_common_protocol_lock_prefix(common: &ProtocolLockCommon, out: &mut Vec<u8>) {
    out.push(common.event_type);
    bytes::write_u64_be(out, common.timestamp);
    bytes::write_u64_be(out, common.event_index);
    out.extend_from_slice(&common.parent_auth_root);
    out.extend_from_slice(&common.pre_state_hash);
}

fn encode_observer(ob: &ObserverBlock, out: &mut Vec<u8>) -> Result<(), CodexError> {
    validate_breath_phase(ob.breath_phase)?;
    if ob.query_context_bytes.len() > MAX_QUERY_CONTEXT_BYTES {
        return Err(CodexError::InvalidInput("QUERY_CONTEXT_TOO_LARGE"));
    }
    bytes::write_u32_be(out, ob.query_context_bytes.len() as u32);
    out.extend_from_slice(&ob.query_context_bytes);
    out.extend_from_slice(&ob.observer_id);
    bytes::write_u16_be(out, ob.observer_state_flags);
    out.push(ob.breath_phase);
    out.push(ob.mirror_mode);
    bytes::write_u32_be(out, ob.field_coherence_enc);
    out.extend_from_slice(&ob.query_context_commitment);
    out.extend_from_slice(&ob.query_commitment);
    out.extend_from_slice(&ob.observer_signature);
    out.extend_from_slice(&ob.recursion_context_commitment);
    Ok(())
}

fn decode_u8(input: &[u8], at: &mut usize) -> Result<u8, CodexError> {
    if *at >= input.len() {
        return Err(CodexError::ParseError("EVENT_PARSE_UNDERFLOW_U8"));
    }
    let v = input[*at];
    *at += 1;
    Ok(v)
}

fn decode_u16(input: &[u8], at: &mut usize) -> Result<u16, CodexError> {
    if *at + 2 > input.len() {
        return Err(CodexError::ParseError("EVENT_PARSE_UNDERFLOW_U16"));
    }
    let v = bytes::read_u16_be(&input[*at..*at + 2])?;
    *at += 2;
    Ok(v)
}

fn decode_u32(input: &[u8], at: &mut usize) -> Result<u32, CodexError> {
    if *at + 4 > input.len() {
        return Err(CodexError::ParseError("EVENT_PARSE_UNDERFLOW_U32"));
    }
    let v = bytes::read_u32_be(&input[*at..*at + 4])?;
    *at += 4;
    Ok(v)
}

fn decode_u64(input: &[u8], at: &mut usize) -> Result<u64, CodexError> {
    if *at + 8 > input.len() {
        return Err(CodexError::ParseError("EVENT_PARSE_UNDERFLOW_U64"));
    }
    let v = bytes::read_u64_be(&input[*at..*at + 8])?;
    *at += 8;
    Ok(v)
}

fn decode_arr<const N: usize>(input: &[u8], at: &mut usize) -> Result<[u8; N], CodexError> {
    if *at + N > input.len() {
        return Err(CodexError::ParseError("EVENT_PARSE_UNDERFLOW_BYTES"));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&input[*at..*at + N]);
    *at += N;
    Ok(out)
}

fn decode_common_upsert(
    input: &[u8],
    at: &mut usize,
    event_type: u8,
) -> Result<EventCommonUpsert, CodexError> {
    let timestamp = decode_u64(input, at)?;
    let event_index = decode_u64(input, at)?;
    let doc_id = decode_arr::<DOC_ID_BYTES>(input, at)?;
    let parent_auth_root = decode_arr::<HASH_LEN>(input, at)?;
    let pre_state_hash = decode_arr::<HASH_LEN>(input, at)?;
    Ok(EventCommonUpsert {
        event_type,
        timestamp,
        event_index,
        doc_id,
        parent_auth_root,
        pre_state_hash,
    })
}

fn decode_common_score_prefix(
    input: &[u8],
    at: &mut usize,
    event_type: u8,
) -> Result<EventPrefix, CodexError> {
    let timestamp = decode_u64(input, at)?;
    let event_index = decode_u64(input, at)?;
    let doc_id = decode_arr::<DOC_ID_BYTES>(input, at)?;
    let parent_auth_root = decode_arr::<HASH_LEN>(input, at)?;
    let pre_state_hash = decode_arr::<HASH_LEN>(input, at)?;
    Ok((
        timestamp,
        event_index,
        doc_id,
        parent_auth_root,
        pre_state_hash,
        event_type,
    ))
}

fn decode_common_lifecycle_prefix(
    input: &[u8],
    at: &mut usize,
    event_type: u8,
) -> Result<EventPrefix, CodexError> {
    let timestamp = decode_u64(input, at)?;
    let event_index = decode_u64(input, at)?;
    let doc_id = decode_arr::<DOC_ID_BYTES>(input, at)?;
    let parent_auth_root = decode_arr::<HASH_LEN>(input, at)?;
    let pre_state_hash = decode_arr::<HASH_LEN>(input, at)?;
    Ok((
        timestamp,
        event_index,
        doc_id,
        parent_auth_root,
        pre_state_hash,
        event_type,
    ))
}

fn decode_common_snapshot_prefix(
    input: &[u8],
    at: &mut usize,
    event_type: u8,
) -> Result<SnapshotCommon, CodexError> {
    let timestamp = decode_u64(input, at)?;
    let event_index = decode_u64(input, at)?;
    let parent_auth_root = decode_arr::<HASH_LEN>(input, at)?;
    let pre_state_hash = decode_arr::<HASH_LEN>(input, at)?;
    Ok(SnapshotCommon {
        event_type,
        timestamp,
        event_index,
        parent_auth_root,
        pre_state_hash,
    })
}

fn decode_common_divergence_prefix(
    input: &[u8],
    at: &mut usize,
    event_type: u8,
) -> Result<DivergenceLocatorCommon, CodexError> {
    let timestamp = decode_u64(input, at)?;
    let event_index = decode_u64(input, at)?;
    let parent_auth_root = decode_arr::<HASH_LEN>(input, at)?;
    let pre_state_hash = decode_arr::<HASH_LEN>(input, at)?;
    Ok(DivergenceLocatorCommon {
        event_type,
        timestamp,
        event_index,
        parent_auth_root,
        pre_state_hash,
    })
}

fn decode_common_snapshot_delta_prefix(
    input: &[u8],
    at: &mut usize,
    event_type: u8,
) -> Result<SnapshotDeltaCommon, CodexError> {
    let timestamp = decode_u64(input, at)?;
    let event_index = decode_u64(input, at)?;
    let parent_auth_root = decode_arr::<HASH_LEN>(input, at)?;
    let pre_state_hash = decode_arr::<HASH_LEN>(input, at)?;
    Ok(SnapshotDeltaCommon {
        event_type,
        timestamp,
        event_index,
        parent_auth_root,
        pre_state_hash,
    })
}

fn decode_common_protocol_lock_prefix(
    input: &[u8],
    at: &mut usize,
    event_type: u8,
) -> Result<ProtocolLockCommon, CodexError> {
    let timestamp = decode_u64(input, at)?;
    let event_index = decode_u64(input, at)?;
    let parent_auth_root = decode_arr::<HASH_LEN>(input, at)?;
    let pre_state_hash = decode_arr::<HASH_LEN>(input, at)?;
    Ok(ProtocolLockCommon {
        event_type,
        timestamp,
        event_index,
        parent_auth_root,
        pre_state_hash,
    })
}

fn decode_observer(input: &[u8], at: &mut usize) -> Result<ObserverBlock, CodexError> {
    let qctx_len = decode_u32(input, at)? as usize;
    if qctx_len > MAX_QUERY_CONTEXT_BYTES {
        return Err(CodexError::ParseError("QUERY_CONTEXT_TOO_LARGE"));
    }
    if *at + qctx_len > input.len() {
        return Err(CodexError::ParseError("QUERY_CONTEXT_TRUNCATED"));
    }
    let mut query_context_bytes = vec![0u8; qctx_len];
    query_context_bytes.copy_from_slice(&input[*at..*at + qctx_len]);
    *at += qctx_len;

    let observer_id = decode_arr::<16>(input, at)?;
    let observer_state_flags = decode_u16(input, at)?;
    let breath_phase = decode_u8(input, at)?;
    validate_breath_phase(breath_phase)?;
    let mirror_mode = decode_u8(input, at)?;
    let field_coherence_enc = decode_u32(input, at)?;
    let query_context_commitment = decode_arr::<HASH_LEN>(input, at)?;
    let query_commitment = decode_arr::<HASH_LEN>(input, at)?;
    let observer_signature = decode_arr::<HASH_LEN>(input, at)?;
    let recursion_context_commitment = decode_arr::<HASH_LEN>(input, at)?;

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
        query_context_bytes,
    })
}

pub fn encode_event_payload(ev: &Event, flags: u32) -> Result<Vec<u8>, CodexError> {
    let mut out = Vec::new();
    match ev {
        Event::DocUpsert { common, up } => {
            encode_common_upsert(common, &mut out);
            out.extend_from_slice(&up.pre_doc_state_hash);
            out.extend_from_slice(&up.content_commitment);
            out.extend_from_slice(&up.projection_commitment);
            out.extend_from_slice(&up.doc_commitment);
            bytes::write_u32_be(&mut out, up.canon_bytes.len() as u32);
            out.extend_from_slice(&up.canon_bytes);
            out.extend_from_slice(&up.projection_bytes);
        }
        Event::ScoreEvaluated {
            common,
            extra,
            ordered,
            score,
            observer,
        } => {
            encode_common_score_prefix(common, &mut out);
            if recursive_enabled(flags) {
                let extra = extra
                    .as_ref()
                    .ok_or(CodexError::InvalidInput("QUERY_PROJECTION_EXTRA_REQUIRED"))?;
                if extra.query_bytes.len() > MAX_QUERY_BYTES {
                    return Err(CodexError::InvalidInput("QUERY_BYTES_TOO_LARGE"));
                }
                bytes::write_u32_be(&mut out, extra.query_bytes.len() as u32);
                out.extend_from_slice(&extra.query_bytes);
                out.extend_from_slice(&extra.query_projection_commitment);
            } else if extra.is_some() {
                return Err(CodexError::InvalidInput("QUERY_PROJECTION_EXTRA_DISABLED"));
            }

            out.extend_from_slice(&common.candidate_commitment);

            if score_enabled(flags) {
                let ordered = ordered
                    .as_ref()
                    .ok_or(CodexError::InvalidInput("ORDERED_CANDIDATES_REQUIRED"))?;
                let score = score
                    .as_ref()
                    .ok_or(CodexError::InvalidInput("SCORE_COMMITMENT_REQUIRED"))?;
                if ordered.k as usize > MAX_TOP_K || ordered.doc_ids.len() != ordered.k as usize {
                    return Err(CodexError::InvalidInput("TOP_K_EXCEEDS_MAX"));
                }
                if score.top_k != ordered.k {
                    return Err(CodexError::InvalidInput("TOP_K_MISMATCH"));
                }
                bytes::write_u32_be(&mut out, ordered.k);
                for id in &ordered.doc_ids {
                    out.extend_from_slice(id);
                }
                bytes::write_u32_be(&mut out, score.top_k);
                out.extend_from_slice(&score.score_commitment);
                if proofs_enabled(flags) {
                    let score_bytes = score
                        .score_bytes
                        .as_ref()
                        .ok_or(CodexError::InvalidInput("SCORE_BYTES_REQUIRED"))?;
                    if score_bytes.len() > MAX_SCORE_BYTES {
                        return Err(CodexError::InvalidInput("SCORE_BYTES_TOO_LARGE"));
                    }
                    bytes::write_u32_be(&mut out, score_bytes.len() as u32);
                    out.extend_from_slice(score_bytes);
                } else if score.score_bytes.is_some() {
                    return Err(CodexError::InvalidInput("SCORE_BYTES_DISABLED"));
                }
            } else if ordered.is_some() || score.is_some() {
                return Err(CodexError::InvalidInput("SCORE_COMMITMENT_DISABLED"));
            }

            out.extend_from_slice(&common.state_delta);

            if observer_enabled(flags) {
                let ob = observer
                    .as_ref()
                    .ok_or(CodexError::InvalidInput("OBSERVER_BLOCK_REQUIRED"))?;
                encode_observer(ob, &mut out)?;
            } else if observer.is_some() {
                return Err(CodexError::InvalidInput("OBSERVER_BLOCK_DISABLED"));
            }
        }
        Event::LifecycleMutation {
            common,
            life,
            governance,
            observer,
        } => {
            encode_common_lifecycle_prefix(common, &mut out);
            out.extend_from_slice(&common.candidate_commitment);
            if governance_enabled(flags) {
                let gov = governance
                    .as_ref()
                    .ok_or(CodexError::InvalidInput("LIFECYCLE_GOVERNANCE_REQUIRED"))?;
                out.push(gov.rule_id);
                out.extend_from_slice(&gov.pre_doc_lifecycle_hash);
                out.push(life.new_lifecycle_state);
                out.push(life.new_representation_mode);
                out.push(life.new_compressed_flag);
                bytes::write_u64_be(&mut out, life.quarantined_until_event_index);
                out.extend_from_slice(&gov.post_doc_lifecycle_hash);
                out.extend_from_slice(&common.state_delta);
            } else {
                if governance.is_some() {
                    return Err(CodexError::InvalidInput("LIFECYCLE_GOVERNANCE_DISABLED"));
                }
                out.extend_from_slice(&common.state_delta);
                out.push(life.new_lifecycle_state);
                out.push(life.new_representation_mode);
                out.push(life.new_compressed_flag);
                bytes::write_u64_be(&mut out, life.quarantined_until_event_index);
            }
            if observer_enabled(flags) {
                let ob = observer
                    .as_ref()
                    .ok_or(CodexError::InvalidInput("OBSERVER_BLOCK_REQUIRED"))?;
                encode_observer(ob, &mut out)?;
            } else if observer.is_some() {
                return Err(CodexError::InvalidInput("OBSERVER_BLOCK_DISABLED"));
            }
        }
        Event::Snapshot { common, snap } => {
            if !snapshot_enabled(flags) {
                return Err(CodexError::InvalidInput("SNAPSHOT_FEATURE_DISABLED"));
            }
            encode_common_snapshot_prefix(common, &mut out);
            out.extend_from_slice(&snap.snapshot_state_hash);
            out.extend_from_slice(&snap.snapshot_mmr_root);
            if doc_merkle_enabled(flags) {
                let doc_count = snap
                    .doc_count
                    .ok_or(CodexError::InvalidInput("DOC_MERKLE_FIELDS_REQUIRED"))?;
                let doc_merkle_root = snap
                    .doc_merkle_root
                    .ok_or(CodexError::InvalidInput("DOC_MERKLE_FIELDS_REQUIRED"))?;
                if snap.doc_aggregate_hash.is_some() {
                    return Err(CodexError::InvalidInput(
                        "DOC_AGGREGATE_DISABLED_IN_MERKLE_MODE",
                    ));
                }
                bytes::write_u32_be(&mut out, doc_count);
                out.extend_from_slice(&doc_merkle_root);
            } else {
                let doc_aggregate_hash = snap
                    .doc_aggregate_hash
                    .ok_or(CodexError::InvalidInput("DOC_AGGREGATE_REQUIRED"))?;
                if snap.doc_count.is_some() || snap.doc_merkle_root.is_some() {
                    return Err(CodexError::InvalidInput("DOC_MERKLE_FIELDS_DISABLED"));
                }
                out.extend_from_slice(&doc_aggregate_hash);
            }
        }
        Event::DivergenceLocator { common, loc } => {
            if !divergence_enabled(flags) {
                return Err(CodexError::InvalidInput("DIVERGENCE_FEATURE_DISABLED"));
            }
            encode_common_divergence_prefix(common, &mut out);
            bytes::write_u64_be(&mut out, loc.locator_event_count);
            out.extend_from_slice(&loc.locator_mmr_root);
            out.extend_from_slice(&loc.locator_state_hash);
            out.extend_from_slice(&loc.locator_commitment);
        }
        Event::SnapshotDelta { common, delta } => {
            if !snapshot_delta_enabled(flags) {
                return Err(CodexError::InvalidInput("SNAPSHOT_DELTA_DISABLED"));
            }
            encode_common_snapshot_delta_prefix(common, &mut out);
            out.extend_from_slice(&delta.base_snapshot_mmr_root);
            out.extend_from_slice(&delta.target_snapshot_mmr_root);
            bytes::write_u32_be(&mut out, delta.delta_doc_count);
            out.extend_from_slice(&delta.delta_root);
        }
        Event::ProtocolLock { common, lock } => {
            encode_common_protocol_lock_prefix(common, &mut out);
            out.extend_from_slice(&lock.protocol_hash);
        }
    }
    Ok(out)
}

pub fn decode_event_payload(input: &[u8], flags: u32) -> Result<Event, CodexError> {
    let mut at = 0usize;
    let event_type = decode_u8(input, &mut at)?;

    match event_type {
        EVENT_TYPE_DOC_UPSERT => {
            let common = decode_common_upsert(input, &mut at, event_type)?;
            let up = DocUpsertFields {
                pre_doc_state_hash: decode_arr::<HASH_LEN>(input, &mut at)?,
                content_commitment: decode_arr::<HASH_LEN>(input, &mut at)?,
                projection_commitment: decode_arr::<HASH_LEN>(input, &mut at)?,
                doc_commitment: decode_arr::<HASH_LEN>(input, &mut at)?,
                canon_bytes: {
                    let canon_len = decode_u32(input, &mut at)? as usize;
                    if canon_len > MAX_CANON_BYTES {
                        return Err(CodexError::ParseError("DOC_UPSERT_CANON_TOO_LARGE"));
                    }
                    if at + canon_len > input.len() {
                        return Err(CodexError::ParseError("DOC_UPSERT_CANON_TRUNCATED"));
                    }
                    let mut v = vec![0u8; canon_len];
                    v.copy_from_slice(&input[at..at + canon_len]);
                    at += canon_len;
                    v
                },
                projection_bytes: decode_arr::<PROJECTION_BYTES_LEN>(input, &mut at)?,
            };
            if at != input.len() {
                return Err(CodexError::ParseError("EVENT_PARSE_TRAILING_BYTES"));
            }
            Ok(Event::DocUpsert { common, up })
        }
        EVENT_TYPE_SCORE_EVALUATED => {
            let (timestamp, event_index, doc_id, parent_auth_root, pre_state_hash, event_type) =
                decode_common_score_prefix(input, &mut at, event_type)?;

            let extra = if recursive_enabled(flags) {
                let query_len = decode_u32(input, &mut at)? as usize;
                if query_len > MAX_QUERY_BYTES {
                    return Err(CodexError::ParseError("QUERY_BYTES_TOO_LARGE"));
                }
                if at + query_len > input.len() {
                    return Err(CodexError::ParseError("QUERY_BYTES_TRUNCATED"));
                }
                let mut query_bytes = vec![0u8; query_len];
                query_bytes.copy_from_slice(&input[at..at + query_len]);
                at += query_len;
                Some(ScoreEvaluatedExtra {
                    query_bytes,
                    query_projection_commitment: decode_arr::<HASH_LEN>(input, &mut at)?,
                })
            } else {
                None
            };

            let candidate_commitment = decode_arr::<HASH_LEN>(input, &mut at)?;

            let (ordered, score) = if score_enabled(flags) {
                let k = decode_u32(input, &mut at)?;
                if k as usize > MAX_TOP_K {
                    return Err(CodexError::ParseError("TOP_K_EXCEEDS_MAX"));
                }
                let mut doc_ids = Vec::with_capacity(k as usize);
                for _ in 0..k {
                    doc_ids.push(decode_arr::<HASH_LEN>(input, &mut at)?);
                }
                let top_k = decode_u32(input, &mut at)?;
                if top_k != k {
                    return Err(CodexError::ParseError("TOP_K_MISMATCH"));
                }
                let score_commitment = decode_arr::<HASH_LEN>(input, &mut at)?;
                let score_bytes = if proofs_enabled(flags) {
                    let len = decode_u32(input, &mut at)? as usize;
                    if len > MAX_SCORE_BYTES {
                        return Err(CodexError::ParseError("SCORE_BYTES_TOO_LARGE"));
                    }
                    if at + len > input.len() {
                        return Err(CodexError::ParseError("SCORE_BYTES_TRUNCATED"));
                    }
                    let mut v = vec![0u8; len];
                    v.copy_from_slice(&input[at..at + len]);
                    at += len;
                    Some(v)
                } else {
                    None
                };
                (
                    Some(OrderedCandidates { k, doc_ids }),
                    Some(ScoreCommitmentFields {
                        top_k,
                        score_commitment,
                        score_bytes,
                    }),
                )
            } else {
                (None, None)
            };

            let state_delta = decode_arr::<STATE_DELTA_BYTES>(input, &mut at)?;
            let common = EventCommon {
                event_type,
                timestamp,
                event_index,
                doc_id,
                parent_auth_root,
                pre_state_hash,
                candidate_commitment,
                state_delta,
            };

            let observer = if observer_enabled(flags) {
                Some(decode_observer(input, &mut at)?)
            } else {
                None
            };
            if at != input.len() {
                return Err(CodexError::ParseError("EVENT_PARSE_TRAILING_BYTES"));
            }
            Ok(Event::ScoreEvaluated {
                common,
                extra,
                ordered,
                score,
                observer,
            })
        }
        EVENT_TYPE_LIFECYCLE_MUTATION => {
            let (timestamp, event_index, doc_id, parent_auth_root, pre_state_hash, event_type) =
                decode_common_lifecycle_prefix(input, &mut at, event_type)?;
            let candidate_commitment = decode_arr::<HASH_LEN>(input, &mut at)?;
            let (governance, life, state_delta) = if governance_enabled(flags) {
                let rule_id = decode_u8(input, &mut at)?;
                let pre_doc_lifecycle_hash = decode_arr::<HASH_LEN>(input, &mut at)?;
                let life = LifecycleFields {
                    new_lifecycle_state: decode_u8(input, &mut at)?,
                    new_representation_mode: decode_u8(input, &mut at)?,
                    new_compressed_flag: decode_u8(input, &mut at)?,
                    quarantined_until_event_index: decode_u64(input, &mut at)?,
                };
                let post_doc_lifecycle_hash = decode_arr::<HASH_LEN>(input, &mut at)?;
                let state_delta = decode_arr::<STATE_DELTA_BYTES>(input, &mut at)?;
                (
                    Some(LifecycleGovernanceFields {
                        rule_id,
                        pre_doc_lifecycle_hash,
                        post_doc_lifecycle_hash,
                    }),
                    life,
                    state_delta,
                )
            } else {
                let state_delta = decode_arr::<STATE_DELTA_BYTES>(input, &mut at)?;
                let life = LifecycleFields {
                    new_lifecycle_state: decode_u8(input, &mut at)?,
                    new_representation_mode: decode_u8(input, &mut at)?,
                    new_compressed_flag: decode_u8(input, &mut at)?,
                    quarantined_until_event_index: decode_u64(input, &mut at)?,
                };
                (None, life, state_delta)
            };
            let common = EventCommon {
                event_type,
                timestamp,
                event_index,
                doc_id,
                parent_auth_root,
                pre_state_hash,
                candidate_commitment,
                state_delta,
            };
            let observer = if observer_enabled(flags) {
                Some(decode_observer(input, &mut at)?)
            } else {
                None
            };
            if at != input.len() {
                return Err(CodexError::ParseError("EVENT_PARSE_TRAILING_BYTES"));
            }
            Ok(Event::LifecycleMutation {
                common,
                life,
                governance,
                observer,
            })
        }
        EVENT_TYPE_SNAPSHOT => {
            if !snapshot_enabled(flags) {
                return Err(CodexError::ParseError("SNAPSHOT_FEATURE_DISABLED"));
            }
            let common = decode_common_snapshot_prefix(input, &mut at, event_type)?;
            let snapshot_state_hash = decode_arr::<HASH_LEN>(input, &mut at)?;
            let snapshot_mmr_root = decode_arr::<HASH_LEN>(input, &mut at)?;
            let snap = if doc_merkle_enabled(flags) {
                SnapshotFields {
                    snapshot_state_hash,
                    snapshot_mmr_root,
                    doc_aggregate_hash: None,
                    doc_count: Some(decode_u32(input, &mut at)?),
                    doc_merkle_root: Some(decode_arr::<HASH_LEN>(input, &mut at)?),
                }
            } else {
                SnapshotFields {
                    snapshot_state_hash,
                    snapshot_mmr_root,
                    doc_aggregate_hash: Some(decode_arr::<HASH_LEN>(input, &mut at)?),
                    doc_count: None,
                    doc_merkle_root: None,
                }
            };
            if at != input.len() {
                return Err(CodexError::ParseError("EVENT_PARSE_TRAILING_BYTES"));
            }
            Ok(Event::Snapshot { common, snap })
        }
        EVENT_TYPE_DIVERGENCE_LOCATOR => {
            if !divergence_enabled(flags) {
                return Err(CodexError::ParseError("DIVERGENCE_FEATURE_DISABLED"));
            }
            let common = decode_common_divergence_prefix(input, &mut at, event_type)?;
            let loc = DivergenceLocatorFields {
                locator_event_count: decode_u64(input, &mut at)?,
                locator_mmr_root: decode_arr::<HASH_LEN>(input, &mut at)?,
                locator_state_hash: decode_arr::<HASH_LEN>(input, &mut at)?,
                locator_commitment: decode_arr::<HASH_LEN>(input, &mut at)?,
            };
            if at != input.len() {
                return Err(CodexError::ParseError("EVENT_PARSE_TRAILING_BYTES"));
            }
            Ok(Event::DivergenceLocator { common, loc })
        }
        EVENT_TYPE_SNAPSHOT_DELTA => {
            if !snapshot_delta_enabled(flags) {
                return Err(CodexError::ParseError("SNAPSHOT_DELTA_DISABLED"));
            }
            let common = decode_common_snapshot_delta_prefix(input, &mut at, event_type)?;
            let delta = SnapshotDeltaFields {
                base_snapshot_mmr_root: decode_arr::<HASH_LEN>(input, &mut at)?,
                target_snapshot_mmr_root: decode_arr::<HASH_LEN>(input, &mut at)?,
                delta_doc_count: decode_u32(input, &mut at)?,
                delta_root: decode_arr::<HASH_LEN>(input, &mut at)?,
            };
            if at != input.len() {
                return Err(CodexError::ParseError("EVENT_PARSE_TRAILING_BYTES"));
            }
            Ok(Event::SnapshotDelta { common, delta })
        }
        EVENT_TYPE_PROTOCOL_LOCK => {
            let common = decode_common_protocol_lock_prefix(input, &mut at, event_type)?;
            let lock = ProtocolLockFields {
                protocol_hash: decode_arr::<HASH_LEN>(input, &mut at)?,
            };
            if at != input.len() {
                return Err(CodexError::ParseError("EVENT_PARSE_TRAILING_BYTES"));
            }
            Ok(Event::ProtocolLock { common, lock })
        }
        _ => Err(CodexError::ParseError("EVENT_TYPE_UNSUPPORTED")),
    }
}

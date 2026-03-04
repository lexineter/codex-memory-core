use crate::schema::MAX_CANON_BYTES;
use crate::{
    bytes, hash, CodexError, COORD_TYPE_I16, DIM, DOC_ID_BYTES, DOMAIN_CANDIDATE, DOMAIN_CONTENT,
    DOMAIN_DELTA_DOC, DOMAIN_DIVERGENCE, DOMAIN_DOC, DOMAIN_DOCSTATE, DOMAIN_DOC_AGG,
    DOMAIN_DOC_LEAF, DOMAIN_DOC_MERKLE, DOMAIN_DOC_NONMEM, DOMAIN_EVENT, DOMAIN_INCLUSION_PROOF,
    DOMAIN_LEDGER_HEADER, DOMAIN_LIFECYCLE, DOMAIN_MMR_NODE, DOMAIN_MMR_ROOT, DOMAIN_OBSERVER,
    DOMAIN_PRESTATE, DOMAIN_PROJECTION, DOMAIN_PROTOCOL, DOMAIN_QUERY, DOMAIN_QUERY_CONTEXT,
    DOMAIN_QUERY_PROJECTION_COMMITMENT, DOMAIN_RECURSION_CONTEXT, DOMAIN_SCORE, DOMAIN_SNAPSHOT,
    DOMAIN_SNAPSHOT_DELTA, DOMAIN_TRANSCRIPT, FEATURE_DIVERGENCE_PROOF, FEATURE_DOC_MERKLE_STATE,
    FEATURE_JSON_MIRROR, FEATURE_LIFECYCLE_GOVERNANCE, FEATURE_OBSERVER_BLOCK,
    FEATURE_PROTOCOL_LOCK_REQUIRED, FEATURE_RECURSIVE_PROJECTION, FEATURE_SCORE_COMMITMENT,
    FEATURE_SCORE_PROOFS, FEATURE_SNAPSHOT_COMMITMENT, FEATURE_SNAPSHOT_DELTA_PROOF, HASH_LEN,
    MAX_QUERY_BYTES, MAX_QUERY_CONTEXT_BYTES, MAX_SCORE_BYTES, MAX_TOP_K, PARAMSET_ID_V1,
    SCHEMA_ID_V1, STATE_DELTA_BYTES,
};

pub struct ProtocolManifest {
    pub version: u32,
    pub feature_flags_supported: u32,
    pub domain_constants: Vec<(&'static str, &'static [u8])>,
    pub event_types: Vec<(u8, &'static str)>,
    pub max_limits: Vec<(&'static str, u64)>,
}

fn manifest() -> ProtocolManifest {
    let feature_flags_supported = FEATURE_JSON_MIRROR
        | FEATURE_OBSERVER_BLOCK
        | FEATURE_RECURSIVE_PROJECTION
        | FEATURE_SCORE_COMMITMENT
        | FEATURE_SCORE_PROOFS
        | FEATURE_LIFECYCLE_GOVERNANCE
        | FEATURE_SNAPSHOT_COMMITMENT
        | FEATURE_DIVERGENCE_PROOF
        | FEATURE_DOC_MERKLE_STATE
        | FEATURE_SNAPSHOT_DELTA_PROOF
        | FEATURE_PROTOCOL_LOCK_REQUIRED;
    ProtocolManifest {
        version: 1,
        feature_flags_supported,
        domain_constants: vec![
            ("DOMAIN_CANDIDATE", DOMAIN_CANDIDATE),
            ("DOMAIN_CONTENT", DOMAIN_CONTENT),
            ("DOMAIN_DELTA_DOC", DOMAIN_DELTA_DOC),
            ("DOMAIN_DIVERGENCE", DOMAIN_DIVERGENCE),
            ("DOMAIN_DOC", DOMAIN_DOC),
            ("DOMAIN_DOCSTATE", DOMAIN_DOCSTATE),
            ("DOMAIN_DOC_AGG", DOMAIN_DOC_AGG),
            ("DOMAIN_DOC_LEAF", DOMAIN_DOC_LEAF),
            ("DOMAIN_DOC_MERKLE", DOMAIN_DOC_MERKLE),
            ("DOMAIN_DOC_NONMEM", DOMAIN_DOC_NONMEM),
            ("DOMAIN_EVENT", DOMAIN_EVENT),
            ("DOMAIN_INCLUSION_PROOF", DOMAIN_INCLUSION_PROOF),
            ("DOMAIN_LEDGER_HEADER", DOMAIN_LEDGER_HEADER),
            ("DOMAIN_LIFECYCLE", DOMAIN_LIFECYCLE),
            ("DOMAIN_MMR_NODE", DOMAIN_MMR_NODE),
            ("DOMAIN_MMR_ROOT", DOMAIN_MMR_ROOT),
            ("DOMAIN_OBSERVER", DOMAIN_OBSERVER),
            ("DOMAIN_PRESTATE", DOMAIN_PRESTATE),
            ("DOMAIN_PROJECTION", DOMAIN_PROJECTION),
            ("DOMAIN_PROTOCOL", DOMAIN_PROTOCOL),
            ("DOMAIN_QUERY", DOMAIN_QUERY),
            ("DOMAIN_QUERY_CONTEXT", DOMAIN_QUERY_CONTEXT),
            (
                "DOMAIN_QUERY_PROJECTION_COMMITMENT",
                DOMAIN_QUERY_PROJECTION_COMMITMENT,
            ),
            ("DOMAIN_RECURSION_CONTEXT", DOMAIN_RECURSION_CONTEXT),
            ("DOMAIN_SCORE", DOMAIN_SCORE),
            ("DOMAIN_SNAPSHOT", DOMAIN_SNAPSHOT),
            ("DOMAIN_SNAPSHOT_DELTA", DOMAIN_SNAPSHOT_DELTA),
            ("DOMAIN_TRANSCRIPT", DOMAIN_TRANSCRIPT),
        ],
        event_types: vec![
            (0x01, "DOC_UPSERT"),
            (0x02, "SCORE_EVALUATED"),
            (0x03, "LIFECYCLE_MUTATION"),
            (0x04, "STATE_SNAPSHOT"),
            (0x05, "DIVERGENCE_LOCATOR"),
            (0x06, "SNAPSHOT_DELTA"),
            (0x07, "PROTOCOL_LOCK"),
        ],
        max_limits: vec![
            ("COORD_TYPE_I16", COORD_TYPE_I16 as u64),
            ("DIM", DIM as u64),
            ("DOC_ID_BYTES", DOC_ID_BYTES as u64),
            ("HASH_LEN", HASH_LEN as u64),
            ("MAX_CANON_BYTES", MAX_CANON_BYTES as u64),
            ("MAX_QUERY_BYTES", MAX_QUERY_BYTES as u64),
            ("MAX_QUERY_CONTEXT_BYTES", MAX_QUERY_CONTEXT_BYTES as u64),
            ("MAX_SCORE_BYTES", MAX_SCORE_BYTES as u64),
            ("MAX_TOP_K", MAX_TOP_K as u64),
            ("PARAMSET_ID_V1", PARAMSET_ID_V1 as u64),
            ("SCHEMA_ID_V1", SCHEMA_ID_V1 as u64),
            ("STATE_DELTA_BYTES", STATE_DELTA_BYTES as u64),
        ],
    }
}

pub fn canonical_protocol_bytes() -> Vec<u8> {
    let mut m = manifest();
    m.domain_constants.sort_by(|a, b| a.0.cmp(b.0));
    m.event_types.sort_by(|a, b| a.0.cmp(&b.0));
    m.max_limits.sort_by(|a, b| a.0.cmp(b.0));

    let mut out = Vec::new();
    bytes::write_u32_be(&mut out, m.version);
    bytes::write_u32_be(&mut out, m.feature_flags_supported);

    for (name, value) in m.domain_constants {
        bytes::write_u16_be(&mut out, name.len() as u16);
        out.extend_from_slice(name.as_bytes());
        bytes::write_u16_be(&mut out, value.len() as u16);
        out.extend_from_slice(value);
    }
    for (id, name) in m.event_types {
        out.push(id);
        bytes::write_u16_be(&mut out, name.len() as u16);
        out.extend_from_slice(name.as_bytes());
    }
    for (name, v) in m.max_limits {
        bytes::write_u16_be(&mut out, name.len() as u16);
        out.extend_from_slice(name.as_bytes());
        bytes::write_u64_be(&mut out, v);
    }
    out
}

pub fn protocol_hash() -> [u8; HASH_LEN] {
    hash::hash_domain(DOMAIN_PROTOCOL, &canonical_protocol_bytes())
}

pub fn ensure_protocol_hash(expected: [u8; HASH_LEN]) -> Result<(), CodexError> {
    if protocol_hash() == expected {
        Ok(())
    } else {
        Err(CodexError::IntegrityError("PROTOCOL_HASH_MISMATCH"))
    }
}

use std::fs::File;
use std::io::Write;

use crate::schema::Event;

pub fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[derive(Debug)]
pub struct JsonMirrorWriter {
    file: File,
}

impl JsonMirrorWriter {
    pub fn create(path: &str) -> Result<Self, crate::CodexError> {
        let file = File::create(path)
            .map_err(|_| crate::CodexError::InvalidInput("JSON_MIRROR_CREATE_FAILED"))?;
        Ok(Self { file })
    }

    pub fn write_event_line(
        &mut self,
        event: &Event,
        event_commitment: [u8; 32],
        root_after: [u8; 32],
    ) -> Result<(), crate::CodexError> {
        let line = match event {
            Event::DocUpsert { common, up } => format!(
                "{{\"canon_len\":{},\"content_commitment\":\"{}\",\"doc_commitment\":\"{}\",\"doc_id\":\"{}\",\"event_commitment\":\"{}\",\"event_index\":{},\"event_type\":{},\"parent_auth_root\":\"{}\",\"pre_doc_state_hash\":\"{}\",\"pre_state_hash\":\"{}\",\"projection_commitment\":\"{}\",\"root_after\":\"{}\",\"timestamp\":{}}}\n",
                up.canon_bytes.len(),
                hex_lower(&up.content_commitment),
                hex_lower(&up.doc_commitment),
                hex_lower(&common.doc_id),
                hex_lower(&event_commitment),
                common.event_index,
                common.event_type,
                hex_lower(&common.parent_auth_root),
                hex_lower(&up.pre_doc_state_hash),
                hex_lower(&common.pre_state_hash),
                hex_lower(&up.projection_commitment),
                hex_lower(&root_after),
                common.timestamp
            ),
            Event::ScoreEvaluated {
                common,
                extra,
                ordered: _,
                score,
                observer,
            } => match (extra, score, observer) {
                (Some(ex), Some(sc), Some(ob)) => format!(
                    "{{\"breath_phase\":{},\"doc_id\":\"{}\",\"event_commitment\":\"{}\",\"event_index\":{},\"event_type\":{},\"field_coherence_enc\":{},\"mirror_mode\":{},\"observer_id\":\"{}\",\"observer_signature\":\"{}\",\"observer_state_flags\":{},\"query_commitment\":\"{}\",\"query_context_commitment\":\"{}\",\"query_context_len\":{},\"query_len\":{},\"query_projection_commitment\":\"{}\",\"recursion_context_commitment\":\"{}\",\"root_after\":\"{}\",\"score_bytes_len\":{},\"score_commitment\":\"{}\",\"timestamp\":{},\"top_k\":{}}}\n",
                    ob.breath_phase,
                    hex_lower(&common.doc_id),
                    hex_lower(&event_commitment),
                    common.event_index,
                    common.event_type,
                    ob.field_coherence_enc,
                    ob.mirror_mode,
                    hex_lower(&ob.observer_id),
                    hex_lower(&ob.observer_signature),
                    ob.observer_state_flags,
                    hex_lower(&ob.query_commitment),
                    hex_lower(&ob.query_context_commitment),
                    ob.query_context_bytes.len(),
                    ex.query_bytes.len(),
                    hex_lower(&ex.query_projection_commitment),
                    hex_lower(&ob.recursion_context_commitment),
                    hex_lower(&root_after),
                    sc.score_bytes.as_ref().map(|v| v.len()).unwrap_or(0),
                    hex_lower(&sc.score_commitment),
                    common.timestamp
                    ,
                    sc.top_k
                ),
                (Some(ex), Some(sc), None) => format!(
                    "{{\"doc_id\":\"{}\",\"event_commitment\":\"{}\",\"event_index\":{},\"event_type\":{},\"query_len\":{},\"query_projection_commitment\":\"{}\",\"root_after\":\"{}\",\"score_bytes_len\":{},\"score_commitment\":\"{}\",\"timestamp\":{},\"top_k\":{}}}\n",
                    hex_lower(&common.doc_id),
                    hex_lower(&event_commitment),
                    common.event_index,
                    common.event_type,
                    ex.query_bytes.len(),
                    hex_lower(&ex.query_projection_commitment),
                    hex_lower(&root_after),
                    sc.score_bytes.as_ref().map(|v| v.len()).unwrap_or(0),
                    hex_lower(&sc.score_commitment),
                    common.timestamp,
                    sc.top_k
                ),
                (None, Some(sc), Some(ob)) => format!(
                    "{{\"breath_phase\":{},\"doc_id\":\"{}\",\"event_commitment\":\"{}\",\"event_index\":{},\"event_type\":{},\"field_coherence_enc\":{},\"mirror_mode\":{},\"observer_id\":\"{}\",\"observer_signature\":\"{}\",\"observer_state_flags\":{},\"query_commitment\":\"{}\",\"query_context_commitment\":\"{}\",\"query_context_len\":{},\"recursion_context_commitment\":\"{}\",\"root_after\":\"{}\",\"score_bytes_len\":{},\"score_commitment\":\"{}\",\"timestamp\":{},\"top_k\":{}}}\n",
                    ob.breath_phase,
                    hex_lower(&common.doc_id),
                    hex_lower(&event_commitment),
                    common.event_index,
                    common.event_type,
                    ob.field_coherence_enc,
                    ob.mirror_mode,
                    hex_lower(&ob.observer_id),
                    hex_lower(&ob.observer_signature),
                    ob.observer_state_flags,
                    hex_lower(&ob.query_commitment),
                    hex_lower(&ob.query_context_commitment),
                    ob.query_context_bytes.len(),
                    hex_lower(&ob.recursion_context_commitment),
                    hex_lower(&root_after),
                    sc.score_bytes.as_ref().map(|v| v.len()).unwrap_or(0),
                    hex_lower(&sc.score_commitment),
                    common.timestamp,
                    sc.top_k
                ),
                (None, Some(sc), None) => format!(
                    "{{\"doc_id\":\"{}\",\"event_commitment\":\"{}\",\"event_index\":{},\"event_type\":{},\"root_after\":\"{}\",\"score_bytes_len\":{},\"score_commitment\":\"{}\",\"timestamp\":{},\"top_k\":{}}}\n",
                    hex_lower(&common.doc_id),
                    hex_lower(&event_commitment),
                    common.event_index,
                    common.event_type,
                    hex_lower(&root_after),
                    sc.score_bytes.as_ref().map(|v| v.len()).unwrap_or(0),
                    hex_lower(&sc.score_commitment),
                    common.timestamp,
                    sc.top_k
                ),
                (Some(ex), None, Some(ob)) => format!(
                    "{{\"breath_phase\":{},\"doc_id\":\"{}\",\"event_commitment\":\"{}\",\"event_index\":{},\"event_type\":{},\"field_coherence_enc\":{},\"mirror_mode\":{},\"observer_id\":\"{}\",\"observer_signature\":\"{}\",\"observer_state_flags\":{},\"query_commitment\":\"{}\",\"query_context_commitment\":\"{}\",\"query_context_len\":{},\"query_len\":{},\"query_projection_commitment\":\"{}\",\"recursion_context_commitment\":\"{}\",\"root_after\":\"{}\",\"timestamp\":{}}}\n",
                    ob.breath_phase,
                    hex_lower(&common.doc_id),
                    hex_lower(&event_commitment),
                    common.event_index,
                    common.event_type,
                    ob.field_coherence_enc,
                    ob.mirror_mode,
                    hex_lower(&ob.observer_id),
                    hex_lower(&ob.observer_signature),
                    ob.observer_state_flags,
                    hex_lower(&ob.query_commitment),
                    hex_lower(&ob.query_context_commitment),
                    ob.query_context_bytes.len(),
                    ex.query_bytes.len(),
                    hex_lower(&ex.query_projection_commitment),
                    hex_lower(&ob.recursion_context_commitment),
                    hex_lower(&root_after),
                    common.timestamp
                ),
                (Some(ex), None, None) => format!(
                    "{{\"doc_id\":\"{}\",\"event_commitment\":\"{}\",\"event_index\":{},\"event_type\":{},\"query_len\":{},\"query_projection_commitment\":\"{}\",\"root_after\":\"{}\",\"timestamp\":{}}}\n",
                    hex_lower(&common.doc_id),
                    hex_lower(&event_commitment),
                    common.event_index,
                    common.event_type,
                    ex.query_bytes.len(),
                    hex_lower(&ex.query_projection_commitment),
                    hex_lower(&root_after),
                    common.timestamp
                ),
                (None, None, Some(ob)) => format!(
                    "{{\"breath_phase\":{},\"doc_id\":\"{}\",\"event_commitment\":\"{}\",\"event_index\":{},\"event_type\":{},\"field_coherence_enc\":{},\"mirror_mode\":{},\"observer_id\":\"{}\",\"observer_signature\":\"{}\",\"observer_state_flags\":{},\"query_commitment\":\"{}\",\"query_context_commitment\":\"{}\",\"query_context_len\":{},\"recursion_context_commitment\":\"{}\",\"root_after\":\"{}\",\"timestamp\":{}}}\n",
                    ob.breath_phase,
                    hex_lower(&common.doc_id),
                    hex_lower(&event_commitment),
                    common.event_index,
                    common.event_type,
                    ob.field_coherence_enc,
                    ob.mirror_mode,
                    hex_lower(&ob.observer_id),
                    hex_lower(&ob.observer_signature),
                    ob.observer_state_flags,
                    hex_lower(&ob.query_commitment),
                    hex_lower(&ob.query_context_commitment),
                    ob.query_context_bytes.len(),
                    hex_lower(&ob.recursion_context_commitment),
                    hex_lower(&root_after),
                    common.timestamp
                ),
                (None, None, None) => format!(
                    "{{\"doc_id\":\"{}\",\"event_commitment\":\"{}\",\"event_index\":{},\"event_type\":{},\"root_after\":\"{}\",\"timestamp\":{}}}\n",
                    hex_lower(&common.doc_id),
                    hex_lower(&event_commitment),
                    common.event_index,
                    common.event_type,
                    hex_lower(&root_after),
                    common.timestamp
                ),
            },
            Event::LifecycleMutation {
                common,
                life,
                governance,
                observer,
            } => match (governance, observer) {
                (Some(g), Some(ob)) => format!(
                    "{{\"breath_phase\":{},\"doc_id\":\"{}\",\"event_commitment\":\"{}\",\"event_index\":{},\"event_type\":{},\"field_coherence_enc\":{},\"mirror_mode\":{},\"new_compressed_flag\":{},\"new_lifecycle_state\":{},\"new_representation_mode\":{},\"observer_id\":\"{}\",\"observer_signature\":\"{}\",\"observer_state_flags\":{},\"post_doc_lifecycle_hash\":\"{}\",\"pre_doc_lifecycle_hash\":\"{}\",\"query_commitment\":\"{}\",\"query_context_commitment\":\"{}\",\"query_context_len\":{},\"quarantined_until_event_index\":{},\"recursion_context_commitment\":\"{}\",\"root_after\":\"{}\",\"rule_id\":{},\"timestamp\":{}}}\n",
                    ob.breath_phase,
                    hex_lower(&common.doc_id),
                    hex_lower(&event_commitment),
                    common.event_index,
                    common.event_type,
                    ob.field_coherence_enc,
                    ob.mirror_mode,
                    life.new_compressed_flag,
                    life.new_lifecycle_state,
                    life.new_representation_mode,
                    hex_lower(&ob.observer_id),
                    hex_lower(&ob.observer_signature),
                    ob.observer_state_flags,
                    hex_lower(&g.post_doc_lifecycle_hash),
                    hex_lower(&g.pre_doc_lifecycle_hash),
                    hex_lower(&ob.query_commitment),
                    hex_lower(&ob.query_context_commitment),
                    ob.query_context_bytes.len(),
                    life.quarantined_until_event_index,
                    hex_lower(&ob.recursion_context_commitment),
                    hex_lower(&root_after),
                    g.rule_id,
                    common.timestamp
                ),
                (Some(g), None) => format!(
                    "{{\"doc_id\":\"{}\",\"event_commitment\":\"{}\",\"event_index\":{},\"event_type\":{},\"new_compressed_flag\":{},\"new_lifecycle_state\":{},\"new_representation_mode\":{},\"post_doc_lifecycle_hash\":\"{}\",\"pre_doc_lifecycle_hash\":\"{}\",\"quarantined_until_event_index\":{},\"root_after\":\"{}\",\"rule_id\":{},\"timestamp\":{}}}\n",
                    hex_lower(&common.doc_id),
                    hex_lower(&event_commitment),
                    common.event_index,
                    common.event_type,
                    life.new_compressed_flag,
                    life.new_lifecycle_state,
                    life.new_representation_mode,
                    hex_lower(&g.post_doc_lifecycle_hash),
                    hex_lower(&g.pre_doc_lifecycle_hash),
                    life.quarantined_until_event_index,
                    hex_lower(&root_after),
                    g.rule_id,
                    common.timestamp
                ),
                (None, Some(ob)) => format!(
                    "{{\"breath_phase\":{},\"doc_id\":\"{}\",\"event_commitment\":\"{}\",\"event_index\":{},\"event_type\":{},\"field_coherence_enc\":{},\"mirror_mode\":{},\"new_compressed_flag\":{},\"new_lifecycle_state\":{},\"new_representation_mode\":{},\"observer_id\":\"{}\",\"observer_signature\":\"{}\",\"observer_state_flags\":{},\"query_commitment\":\"{}\",\"query_context_commitment\":\"{}\",\"query_context_len\":{},\"quarantined_until_event_index\":{},\"recursion_context_commitment\":\"{}\",\"root_after\":\"{}\",\"timestamp\":{}}}\n",
                    ob.breath_phase,
                    hex_lower(&common.doc_id),
                    hex_lower(&event_commitment),
                    common.event_index,
                    common.event_type,
                    ob.field_coherence_enc,
                    ob.mirror_mode,
                    life.new_compressed_flag,
                    life.new_lifecycle_state,
                    life.new_representation_mode,
                    hex_lower(&ob.observer_id),
                    hex_lower(&ob.observer_signature),
                    ob.observer_state_flags,
                    hex_lower(&ob.query_commitment),
                    hex_lower(&ob.query_context_commitment),
                    ob.query_context_bytes.len(),
                    life.quarantined_until_event_index,
                    hex_lower(&ob.recursion_context_commitment),
                    hex_lower(&root_after),
                    common.timestamp
                ),
                (None, None) => format!(
                    "{{\"doc_id\":\"{}\",\"event_commitment\":\"{}\",\"event_index\":{},\"event_type\":{},\"new_compressed_flag\":{},\"new_lifecycle_state\":{},\"new_representation_mode\":{},\"quarantined_until_event_index\":{},\"root_after\":\"{}\",\"timestamp\":{}}}\n",
                    hex_lower(&common.doc_id),
                    hex_lower(&event_commitment),
                    common.event_index,
                    common.event_type,
                    life.new_compressed_flag,
                    life.new_lifecycle_state,
                    life.new_representation_mode,
                    life.quarantined_until_event_index,
                    hex_lower(&root_after),
                    common.timestamp
                ),
            },
            Event::Snapshot { common, snap } => {
                if let (Some(doc_count), Some(doc_merkle_root)) = (snap.doc_count, snap.doc_merkle_root) {
                    format!(
                        "{{\"doc_count\":{},\"doc_merkle_root\":\"{}\",\"event_commitment\":\"{}\",\"event_index\":{},\"event_type\":{},\"parent_auth_root\":\"{}\",\"pre_state_hash\":\"{}\",\"root_after\":\"{}\",\"snapshot_mmr_root\":\"{}\",\"snapshot_state_hash\":\"{}\",\"timestamp\":{}}}\n",
                        doc_count,
                        hex_lower(&doc_merkle_root),
                        hex_lower(&event_commitment),
                        common.event_index,
                        common.event_type,
                        hex_lower(&common.parent_auth_root),
                        hex_lower(&common.pre_state_hash),
                        hex_lower(&root_after),
                        hex_lower(&snap.snapshot_mmr_root),
                        hex_lower(&snap.snapshot_state_hash),
                        common.timestamp
                    )
                } else {
                    format!(
                        "{{\"doc_aggregate_hash\":\"{}\",\"event_commitment\":\"{}\",\"event_index\":{},\"event_type\":{},\"parent_auth_root\":\"{}\",\"pre_state_hash\":\"{}\",\"root_after\":\"{}\",\"snapshot_mmr_root\":\"{}\",\"snapshot_state_hash\":\"{}\",\"timestamp\":{}}}\n",
                        hex_lower(&snap.doc_aggregate_hash.unwrap_or([0u8; 32])),
                        hex_lower(&event_commitment),
                        common.event_index,
                        common.event_type,
                        hex_lower(&common.parent_auth_root),
                        hex_lower(&common.pre_state_hash),
                        hex_lower(&root_after),
                        hex_lower(&snap.snapshot_mmr_root),
                        hex_lower(&snap.snapshot_state_hash),
                        common.timestamp
                    )
                }
            }
            Event::DivergenceLocator { common, loc } => format!(
                "{{\"event_commitment\":\"{}\",\"event_index\":{},\"event_type\":{},\"locator_commitment\":\"{}\",\"locator_event_count\":{},\"locator_mmr_root\":\"{}\",\"locator_state_hash\":\"{}\",\"parent_auth_root\":\"{}\",\"pre_state_hash\":\"{}\",\"root_after\":\"{}\",\"timestamp\":{}}}\n",
                hex_lower(&event_commitment),
                common.event_index,
                common.event_type,
                hex_lower(&loc.locator_commitment),
                loc.locator_event_count,
                hex_lower(&loc.locator_mmr_root),
                hex_lower(&loc.locator_state_hash),
                hex_lower(&common.parent_auth_root),
                hex_lower(&common.pre_state_hash),
                hex_lower(&root_after),
                common.timestamp
            ),
            Event::SnapshotDelta { common, delta } => format!(
                "{{\"base_snapshot_root\":\"{}\",\"delta_doc_count\":{},\"delta_root\":\"{}\",\"event_commitment\":\"{}\",\"event_index\":{},\"event_type\":{},\"parent_auth_root\":\"{}\",\"pre_state_hash\":\"{}\",\"root_after\":\"{}\",\"target_snapshot_root\":\"{}\",\"timestamp\":{}}}\n",
                hex_lower(&delta.base_snapshot_mmr_root),
                delta.delta_doc_count,
                hex_lower(&delta.delta_root),
                hex_lower(&event_commitment),
                common.event_index,
                common.event_type,
                hex_lower(&common.parent_auth_root),
                hex_lower(&common.pre_state_hash),
                hex_lower(&root_after),
                hex_lower(&delta.target_snapshot_mmr_root),
                common.timestamp
            ),
            Event::ProtocolLock { common, lock } => format!(
                "{{\"event_commitment\":\"{}\",\"event_index\":{},\"event_type\":{},\"parent_auth_root\":\"{}\",\"pre_state_hash\":\"{}\",\"protocol_hash\":\"{}\",\"root_after\":\"{}\",\"timestamp\":{}}}\n",
                hex_lower(&event_commitment),
                common.event_index,
                common.event_type,
                hex_lower(&common.parent_auth_root),
                hex_lower(&common.pre_state_hash),
                hex_lower(&lock.protocol_hash),
                hex_lower(&root_after),
                common.timestamp
            ),
        };
        self.file
            .write_all(line.as_bytes())
            .map_err(|_| crate::CodexError::InvalidInput("JSON_MIRROR_WRITE_FAILED"))
    }
}

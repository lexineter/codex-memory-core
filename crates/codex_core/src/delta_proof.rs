use crate::{
    bytes, hash, CodexError, DOMAIN_DELTA_DOC, DOMAIN_DOC_MERKLE, DOMAIN_SNAPSHOT_DELTA, HASH_LEN,
};

pub type DocStore = Vec<([u8; HASH_LEN], [u8; HASH_LEN])>; // (doc_id, doc_leaf_hash), sorted by doc_id

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaEntry {
    pub doc_id: [u8; HASH_LEN],
    pub old_doc_leaf_hash: [u8; HASH_LEN],
    pub new_doc_leaf_hash: [u8; HASH_LEN],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaProof {
    pub delta_doc_count: u32,
    pub delta_root: [u8; HASH_LEN],
    pub entries: Vec<DeltaEntry>,
}

fn merkle_parent(left: [u8; HASH_LEN], right: [u8; HASH_LEN]) -> [u8; HASH_LEN] {
    let mut payload = [0u8; HASH_LEN * 2];
    payload[..HASH_LEN].copy_from_slice(&left);
    payload[HASH_LEN..].copy_from_slice(&right);
    hash::hash_domain(DOMAIN_DOC_MERKLE, &payload)
}

pub fn doc_store_merkle_root(store: &DocStore) -> [u8; HASH_LEN] {
    if store.is_empty() {
        let mut payload = Vec::with_capacity(4);
        bytes::write_u32_be(&mut payload, 0);
        return hash::hash_domain(DOMAIN_DOC_MERKLE, &payload);
    }
    let mut level: Vec<[u8; HASH_LEN]> = store.iter().map(|(_, leaf)| *leaf).collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0usize;
        while i + 1 < level.len() {
            next.push(merkle_parent(level[i], level[i + 1]));
            i += 2;
        }
        if i < level.len() {
            next.push(level[i]);
        }
        level = next;
    }
    level[0]
}

fn delta_doc_hash(
    doc_id: [u8; HASH_LEN],
    old_leaf: [u8; HASH_LEN],
    new_leaf: [u8; HASH_LEN],
) -> [u8; HASH_LEN] {
    let mut payload = [0u8; HASH_LEN * 3];
    payload[..HASH_LEN].copy_from_slice(&doc_id);
    payload[HASH_LEN..HASH_LEN * 2].copy_from_slice(&old_leaf);
    payload[HASH_LEN * 2..].copy_from_slice(&new_leaf);
    hash::hash_domain(DOMAIN_DELTA_DOC, &payload)
}

pub fn compute_snapshot_delta(base_docs: &DocStore, target_docs: &DocStore) -> DeltaProof {
    let mut i = 0usize;
    let mut j = 0usize;
    let mut entries = Vec::new();
    while i < base_docs.len() || j < target_docs.len() {
        if i < base_docs.len() && j < target_docs.len() {
            let (bid, bleaf) = base_docs[i];
            let (tid, tleaf) = target_docs[j];
            if bid == tid {
                if bleaf != tleaf {
                    entries.push(DeltaEntry {
                        doc_id: bid,
                        old_doc_leaf_hash: bleaf,
                        new_doc_leaf_hash: tleaf,
                    });
                }
                i += 1;
                j += 1;
            } else if bid < tid {
                entries.push(DeltaEntry {
                    doc_id: bid,
                    old_doc_leaf_hash: bleaf,
                    new_doc_leaf_hash: [0u8; HASH_LEN],
                });
                i += 1;
            } else {
                entries.push(DeltaEntry {
                    doc_id: tid,
                    old_doc_leaf_hash: [0u8; HASH_LEN],
                    new_doc_leaf_hash: tleaf,
                });
                j += 1;
            }
        } else if i < base_docs.len() {
            let (bid, bleaf) = base_docs[i];
            entries.push(DeltaEntry {
                doc_id: bid,
                old_doc_leaf_hash: bleaf,
                new_doc_leaf_hash: [0u8; HASH_LEN],
            });
            i += 1;
        } else {
            let (tid, tleaf) = target_docs[j];
            entries.push(DeltaEntry {
                doc_id: tid,
                old_doc_leaf_hash: [0u8; HASH_LEN],
                new_doc_leaf_hash: tleaf,
            });
            j += 1;
        }
    }

    let mut payload = Vec::with_capacity(4 + entries.len() * HASH_LEN);
    bytes::write_u32_be(&mut payload, entries.len() as u32);
    for e in &entries {
        let h = delta_doc_hash(e.doc_id, e.old_doc_leaf_hash, e.new_doc_leaf_hash);
        payload.extend_from_slice(&h);
    }
    let delta_root = hash::hash_domain(DOMAIN_SNAPSHOT_DELTA, &payload);
    DeltaProof {
        delta_doc_count: entries.len() as u32,
        delta_root,
        entries,
    }
}

pub fn verify_snapshot_delta(
    base_root: [u8; HASH_LEN],
    target_root: [u8; HASH_LEN],
    delta_root: [u8; HASH_LEN],
    delta_count: u32,
    base_docs: &DocStore,
    target_docs: &DocStore,
) -> Result<bool, CodexError> {
    if doc_store_merkle_root(base_docs) != base_root
        || doc_store_merkle_root(target_docs) != target_root
    {
        return Ok(false);
    }
    let d = compute_snapshot_delta(base_docs, target_docs);
    Ok(d.delta_doc_count == delta_count && d.delta_root == delta_root)
}

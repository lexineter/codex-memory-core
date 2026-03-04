use crate::{bytes, hash, CodexError, DOMAIN_DOC_LEAF, DOMAIN_DOC_MERKLE, HASH_LEN};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocInclusionProof {
    pub doc_id: [u8; HASH_LEN],
    pub leaf_hash: [u8; HASH_LEN],
    pub siblings: Vec<[u8; HASH_LEN]>,
    pub index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocNonMembershipProof {
    pub target_doc_id: [u8; HASH_LEN],
    pub left_proof: Option<DocInclusionProof>,
    pub right_proof: Option<DocInclusionProof>,
}

pub fn doc_leaf_hash(
    doc_id: [u8; HASH_LEN],
    doc_state_hash: [u8; HASH_LEN],
    projection_commitment: [u8; HASH_LEN],
) -> [u8; HASH_LEN] {
    let mut payload = [0u8; HASH_LEN * 3];
    payload[..HASH_LEN].copy_from_slice(&doc_id);
    payload[HASH_LEN..HASH_LEN * 2].copy_from_slice(&doc_state_hash);
    payload[HASH_LEN * 2..].copy_from_slice(&projection_commitment);
    hash::hash_domain(DOMAIN_DOC_LEAF, &payload)
}

fn doc_merkle_parent(left: [u8; HASH_LEN], right: [u8; HASH_LEN]) -> [u8; HASH_LEN] {
    let mut payload = [0u8; HASH_LEN * 2];
    payload[..HASH_LEN].copy_from_slice(&left);
    payload[HASH_LEN..].copy_from_slice(&right);
    hash::hash_domain(DOMAIN_DOC_MERKLE, &payload)
}

pub fn compute_doc_merkle_root(
    docs: &[([u8; HASH_LEN], [u8; HASH_LEN], [u8; HASH_LEN])],
) -> [u8; HASH_LEN] {
    if docs.is_empty() {
        let mut payload = Vec::with_capacity(4);
        bytes::write_u32_be(&mut payload, 0);
        return hash::hash_domain(DOMAIN_DOC_MERKLE, &payload);
    }
    let mut level: Vec<[u8; HASH_LEN]> = docs
        .iter()
        .map(|(doc_id, doc_state_hash, projection_commitment)| {
            doc_leaf_hash(*doc_id, *doc_state_hash, *projection_commitment)
        })
        .collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0usize;
        while i + 1 < level.len() {
            next.push(doc_merkle_parent(level[i], level[i + 1]));
            i += 2;
        }
        if i < level.len() {
            next.push(level[i]);
        }
        level = next;
    }
    level[0]
}

pub fn generate_doc_proof(
    docs: &[([u8; HASH_LEN], [u8; HASH_LEN], [u8; HASH_LEN])],
    target_doc_id: [u8; HASH_LEN],
) -> Result<DocInclusionProof, CodexError> {
    let pos = docs
        .binary_search_by(|(doc_id, _, _)| doc_id.cmp(&target_doc_id))
        .map_err(|_| CodexError::InvalidInput("DOC_NOT_FOUND"))?;
    let (_, doc_state_hash, projection_commitment) = docs[pos];
    let mut index = pos;
    let leaf_hash = doc_leaf_hash(target_doc_id, doc_state_hash, projection_commitment);
    let mut siblings = Vec::new();

    let mut level: Vec<[u8; HASH_LEN]> = docs
        .iter()
        .map(|(doc_id, ds, pc)| doc_leaf_hash(*doc_id, *ds, *pc))
        .collect();
    while level.len() > 1 {
        let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };
        if sibling_index < level.len() {
            siblings.push(level[sibling_index]);
        }

        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0usize;
        while i + 1 < level.len() {
            next.push(doc_merkle_parent(level[i], level[i + 1]));
            i += 2;
        }
        if i < level.len() {
            next.push(level[i]);
        }
        index /= 2;
        level = next;
    }

    Ok(DocInclusionProof {
        doc_id: target_doc_id,
        leaf_hash,
        siblings,
        index: pos as u32,
    })
}

pub fn verify_doc_proof(
    root: [u8; HASH_LEN],
    proof: &DocInclusionProof,
) -> Result<bool, CodexError> {
    let mut h = proof.leaf_hash;
    let mut index = proof.index as usize;
    for sibling in &proof.siblings {
        h = if (index & 1) == 0 {
            doc_merkle_parent(h, *sibling)
        } else {
            doc_merkle_parent(*sibling, h)
        };
        index /= 2;
    }
    Ok(h == root)
}

pub fn verify_doc_non_membership(
    root: [u8; HASH_LEN],
    proof: &DocNonMembershipProof,
) -> Result<bool, CodexError> {
    match (&proof.left_proof, &proof.right_proof) {
        (Some(left), Some(right)) => {
            if !verify_doc_proof(root, left)? || !verify_doc_proof(root, right)? {
                return Ok(false);
            }
            Ok(left.doc_id < proof.target_doc_id && proof.target_doc_id < right.doc_id)
        }
        (None, Some(right)) => {
            if !verify_doc_proof(root, right)? {
                return Ok(false);
            }
            Ok(proof.target_doc_id < right.doc_id)
        }
        (Some(left), None) => {
            if !verify_doc_proof(root, left)? {
                return Ok(false);
            }
            Ok(left.doc_id < proof.target_doc_id)
        }
        (None, None) => Ok(false),
    }
}

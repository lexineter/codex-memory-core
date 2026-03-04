use crate::{hash, CodexError, DOMAIN_MMR_NODE, DOMAIN_MMR_ROOT, HASH_LEN};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Left,
    Right,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    pub leaf_index: u64,
    pub leaf_hash: [u8; HASH_LEN],
    pub path: Vec<([u8; HASH_LEN], Side)>,
    pub peaks: Vec<[u8; HASH_LEN]>,
    pub leaf_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    pub leaf_index: u64,
    pub siblings: Vec<[u8; HASH_LEN]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Peak {
    height: u32,
    hash: [u8; HASH_LEN],
    span: u64,
}

#[derive(Debug, Clone, Default)]
pub struct Mmr {
    leaf_count: u64,
    peaks: Vec<Peak>,
    nodes: Vec<Vec<[u8; HASH_LEN]>>,
}

fn hash_node(left: [u8; HASH_LEN], right: [u8; HASH_LEN]) -> [u8; HASH_LEN] {
    let mut payload = [0u8; HASH_LEN * 2];
    payload[..HASH_LEN].copy_from_slice(&left);
    payload[HASH_LEN..].copy_from_slice(&right);
    hash::hash_domain(DOMAIN_MMR_NODE, &payload)
}

fn hash_root(peaks: &[[u8; HASH_LEN]]) -> [u8; HASH_LEN] {
    let mut payload = Vec::with_capacity(peaks.len() * HASH_LEN);
    for peak in peaks {
        payload.extend_from_slice(peak);
    }
    hash::hash_domain(DOMAIN_MMR_ROOT, &payload)
}

fn peak_heights_from_leaf_count(leaf_count: u64) -> Vec<u32> {
    let mut heights = Vec::new();
    for height in (0..64u32).rev() {
        if ((leaf_count >> height) & 1u64) == 1 {
            heights.push(height);
        }
    }
    heights
}

impl Mmr {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> u64 {
        self.leaf_count
    }

    pub fn is_empty(&self) -> bool {
        self.leaf_count == 0
    }

    pub fn append(&mut self, leaf: [u8; HASH_LEN]) -> [u8; HASH_LEN] {
        if self.nodes.is_empty() {
            self.nodes.push(Vec::new());
        }
        self.nodes[0].push(leaf);

        let mut carry_hash = leaf;
        let mut carry_height: u32 = 0;
        let mut carry_span: u64 = 1;

        while matches!(self.peaks.last(), Some(last) if last.height == carry_height) {
            let last = self.peaks.pop().expect("peak exists by matches check");
            carry_hash = hash_node(last.hash, carry_hash);
            carry_height += 1;
            carry_span <<= 1;

            if self.nodes.len() <= carry_height as usize {
                self.nodes.push(Vec::new());
            }
            self.nodes[carry_height as usize].push(carry_hash);
        }

        self.peaks.push(Peak {
            height: carry_height,
            hash: carry_hash,
            span: carry_span,
        });
        self.leaf_count += 1;
        self.root()
    }

    pub fn root(&self) -> [u8; HASH_LEN] {
        let peak_hashes: Vec<[u8; HASH_LEN]> = self.peaks.iter().map(|p| p.hash).collect();
        hash_root(&peak_hashes)
    }

    pub fn root_at(&self, leaf_count: u64) -> Result<[u8; HASH_LEN], CodexError> {
        if leaf_count > self.leaf_count {
            return Err(CodexError::InvalidInput("MMR_LEAF_COUNT_OUT_OF_RANGE"));
        }
        let mut tmp = Mmr::new();
        for i in 0..leaf_count as usize {
            let leaf = self
                .nodes
                .first()
                .and_then(|v| v.get(i))
                .copied()
                .ok_or(CodexError::InvalidInput("MMR_LEAF_NOT_FOUND"))?;
            tmp.append(leaf);
        }
        Ok(tmp.root())
    }

    pub fn generate_proof(&self, leaf_index: u64) -> Result<InclusionProof, CodexError> {
        let p = self.prove(leaf_index)?;
        // Encoding:
        // siblings[0]: leaf_count (u64 BE) in bytes [0..8], rest zero.
        // siblings[1..1+path_len]: path sibling hashes from leaf upward.
        // siblings[1+path_len..]: full peaks list left-to-right.
        let mut meta = [0u8; HASH_LEN];
        meta[..8].copy_from_slice(&p.leaf_count.to_be_bytes());
        let mut siblings = Vec::with_capacity(1 + p.path.len() + p.peaks.len());
        siblings.push(meta);
        for (sib, _) in p.path {
            siblings.push(sib);
        }
        for peak in p.peaks {
            siblings.push(peak);
        }
        Ok(InclusionProof {
            leaf_index,
            siblings,
        })
    }

    pub fn prove(&self, leaf_index: u64) -> Result<Proof, CodexError> {
        if leaf_index >= self.leaf_count {
            return Err(CodexError::InvalidInput("MMR_LEAF_INDEX_OUT_OF_RANGE"));
        }

        let leaf_hash = self
            .nodes
            .first()
            .and_then(|level0| level0.get(leaf_index as usize))
            .copied()
            .ok_or(CodexError::InvalidInput("MMR_LEAF_NOT_FOUND"))?;

        let mut start_offset = 0u64;
        let mut peak_idx = None;
        let mut peak_height = 0u32;
        for (i, peak) in self.peaks.iter().enumerate() {
            let end = start_offset + peak.span;
            if leaf_index < end {
                peak_idx = Some(i);
                peak_height = peak.height;
                break;
            }
            start_offset = end;
        }

        let selected_peak_idx =
            peak_idx.ok_or(CodexError::InvalidInput("MMR_PEAK_FOR_LEAF_NOT_FOUND"))?;
        let mut position = leaf_index - start_offset;
        let mut path = Vec::with_capacity(peak_height as usize);

        for level in 0..peak_height {
            let base = start_offset >> level;
            let idx = base + position;
            let sibling_idx = idx ^ 1;
            let sibling_hash = self
                .nodes
                .get(level as usize)
                .and_then(|nodes| nodes.get(sibling_idx as usize))
                .copied()
                .ok_or(CodexError::InvalidInput("MMR_SIBLING_NOT_FOUND"))?;
            let side = if (idx & 1) == 0 {
                Side::Right
            } else {
                Side::Left
            };
            path.push((sibling_hash, side));
            position >>= 1;
        }

        let mut peaks = Vec::with_capacity(self.peaks.len());
        for peak in &self.peaks {
            peaks.push(peak.hash);
        }

        if selected_peak_idx >= peaks.len() {
            return Err(CodexError::InvalidInput("MMR_PEAK_INDEX_INVALID"));
        }

        Ok(Proof {
            leaf_index,
            leaf_hash,
            path,
            peaks,
            leaf_count: self.leaf_count,
        })
    }
}

pub fn verify_proof(
    root: [u8; HASH_LEN],
    leaf_hash: [u8; HASH_LEN],
    proof: &InclusionProof,
) -> Result<bool, CodexError> {
    if proof.siblings.is_empty() {
        return Err(CodexError::InvalidInput("MMR_INCLUSION_PROOF_EMPTY"));
    }
    let mut leaf_count_bytes = [0u8; 8];
    leaf_count_bytes.copy_from_slice(&proof.siblings[0][..8]);
    let leaf_count = u64::from_be_bytes(leaf_count_bytes);
    if leaf_count == 0 || proof.leaf_index >= leaf_count {
        return Err(CodexError::InvalidInput("MMR_LEAF_INDEX_OUT_OF_RANGE"));
    }

    let peak_heights = peak_heights_from_leaf_count(leaf_count);
    let mut start_offset = 0u64;
    let mut target_peak_idx = None;
    let mut target_peak_height = 0u32;
    for (i, height) in peak_heights.iter().enumerate() {
        let span = 1u64 << *height;
        let end = start_offset + span;
        if proof.leaf_index < end {
            target_peak_idx = Some(i);
            target_peak_height = *height;
            break;
        }
        start_offset = end;
    }
    let target_peak_idx =
        target_peak_idx.ok_or(CodexError::InvalidInput("MMR_PEAK_FOR_LEAF_NOT_FOUND"))?;

    let path_len = target_peak_height as usize;
    let peak_count = peak_heights.len();
    if proof.siblings.len() != 1 + path_len + peak_count {
        return Err(CodexError::InvalidInput(
            "MMR_INCLUSION_PROOF_LENGTH_MISMATCH",
        ));
    }

    let path = &proof.siblings[1..1 + path_len];
    let mut h = leaf_hash;
    let position = proof.leaf_index - start_offset;
    for (level, sib) in path.iter().enumerate() {
        let is_left = ((position >> level) & 1) == 0;
        h = if is_left {
            hash_node(h, *sib)
        } else {
            hash_node(*sib, h)
        };
    }

    let mut peaks = proof.siblings[1 + path_len..].to_vec();
    if target_peak_idx >= peaks.len() {
        return Err(CodexError::InvalidInput("MMR_PEAK_INDEX_INVALID"));
    }
    peaks[target_peak_idx] = h;
    Ok(hash_root(&peaks) == root)
}

impl Proof {
    pub fn verify(&self, root: [u8; HASH_LEN]) -> Result<(), CodexError> {
        if self.leaf_count == 0 {
            return Err(CodexError::InvalidInput("MMR_EMPTY_PROOF"));
        }
        if self.leaf_index >= self.leaf_count {
            return Err(CodexError::InvalidInput("MMR_LEAF_INDEX_OUT_OF_RANGE"));
        }
        if self.peaks.is_empty() {
            return Err(CodexError::InvalidInput("MMR_EMPTY_PEAKS"));
        }

        let peak_heights = peak_heights_from_leaf_count(self.leaf_count);
        if peak_heights.len() != self.peaks.len() {
            return Err(CodexError::InvalidInput("MMR_PEAK_COUNT_MISMATCH"));
        }

        let mut start_offset = 0u64;
        let mut target_peak_idx = None;
        let mut target_peak_height = 0u32;
        for (i, height) in peak_heights.iter().enumerate() {
            let span = 1u64 << *height;
            let end = start_offset + span;
            if self.leaf_index < end {
                target_peak_idx = Some(i);
                target_peak_height = *height;
                break;
            }
            start_offset = end;
        }
        let target_peak_idx =
            target_peak_idx.ok_or(CodexError::InvalidInput("MMR_PEAK_FOR_LEAF_NOT_FOUND"))?;

        if self.path.len() != target_peak_height as usize {
            return Err(CodexError::InvalidInput("MMR_PATH_LENGTH_MISMATCH"));
        }

        let mut h = self.leaf_hash;
        for (sibling, side) in &self.path {
            h = match side {
                Side::Left => hash_node(*sibling, h),
                Side::Right => hash_node(h, *sibling),
            };
        }

        let mut peaks = self.peaks.clone();
        peaks[target_peak_idx] = h;
        let computed = hash_root(&peaks);
        if computed == root {
            Ok(())
        } else {
            Err(CodexError::IntegrityError("MMR_PROOF_MISMATCH"))
        }
    }
}

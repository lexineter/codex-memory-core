use codex_core::hash;
use codex_core::mmr::{verify_proof, Mmr};
use codex_core::{CodexError, DOMAIN_MMR_ROOT};

#[test]
fn empty_root_is_domain_hash_of_empty() {
    let mmr = Mmr::new();
    assert_eq!(mmr.root(), hash::hash_domain(DOMAIN_MMR_ROOT, b""));
}

#[test]
fn append_is_deterministic() {
    let leaves = [
        hash::sha256(b"a"),
        hash::sha256(b"b"),
        hash::sha256(b"c"),
        hash::sha256(b"d"),
        hash::sha256(b"e"),
        hash::sha256(b"f"),
        hash::sha256(b"g"),
        hash::sha256(b"h"),
    ];

    let mut a = Mmr::new();
    let mut b = Mmr::new();
    for leaf in leaves {
        let ra = a.append(leaf);
        let rb = b.append(leaf);
        assert_eq!(ra, rb);
    }
    assert_eq!(a.root(), b.root());
}

#[test]
fn different_sequences_different_root() {
    let seq1 = [hash::sha256(b"a"), hash::sha256(b"b"), hash::sha256(b"c")];
    let seq2 = [hash::sha256(b"a"), hash::sha256(b"c"), hash::sha256(b"b")];

    let mut a = Mmr::new();
    let mut b = Mmr::new();
    for leaf in seq1 {
        a.append(leaf);
    }
    for leaf in seq2 {
        b.append(leaf);
    }
    assert_ne!(a.root(), b.root());
}

#[test]
fn proof_verifies_for_each_leaf() {
    let mut mmr = Mmr::new();
    for i in 0..20u8 {
        let leaf = hash::sha256(&[i]);
        mmr.append(leaf);
    }

    let root = mmr.root();
    for i in 0..20u64 {
        let proof = mmr.prove(i).unwrap();
        proof.verify(root).unwrap();
    }
}

#[test]
fn proof_fails_if_leaf_hash_tampered() {
    let mut mmr = Mmr::new();
    for i in 0..10u8 {
        mmr.append(hash::sha256(&[i]));
    }
    let root = mmr.root();
    let mut proof = mmr.prove(3).unwrap();
    proof.leaf_hash[0] ^= 0x01;
    let err = proof.verify(root).unwrap_err();
    assert_eq!(err, CodexError::IntegrityError("MMR_PROOF_MISMATCH"));
}

#[test]
fn proof_fails_if_sibling_tampered() {
    let mut mmr = Mmr::new();
    for i in 0..10u8 {
        mmr.append(hash::sha256(&[i]));
    }
    let root = mmr.root();
    let mut proof = mmr.prove(5).unwrap();
    let (sib, _) = proof.path.get_mut(0).unwrap();
    sib[0] ^= 0x01;
    let err = proof.verify(root).unwrap_err();
    assert_eq!(err, CodexError::IntegrityError("MMR_PROOF_MISMATCH"));
}

#[test]
fn proof_fails_if_peaks_tampered() {
    let mut mmr = Mmr::new();
    for i in 0..10u8 {
        mmr.append(hash::sha256(&[i]));
    }
    let root = mmr.root();
    let mut proof = mmr.prove(7).unwrap();
    proof.peaks[1][0] ^= 0x01;
    let err = proof.verify(root).unwrap_err();
    assert_eq!(err, CodexError::IntegrityError("MMR_PROOF_MISMATCH"));
}

#[test]
fn inclusion_proof_validates_and_tamper_fails() {
    let mut mmr = Mmr::new();
    let mut leaves = Vec::new();
    for i in 0..10u8 {
        let leaf = hash::sha256(&[i]);
        leaves.push(leaf);
        mmr.append(leaf);
    }
    let root = mmr.root();
    let proof = mmr.generate_proof(3).unwrap();
    assert!(verify_proof(root, leaves[3], &proof).unwrap());

    let mut tampered = proof.clone();
    tampered.siblings[1][0] ^= 0x01;
    assert!(!verify_proof(root, leaves[3], &tampered).unwrap());
}

#[test]
fn inclusion_proof_fails_for_adjacent_leaf_index() {
    let mut mmr = Mmr::new();
    let mut leaves = Vec::new();
    for i in 0..10u8 {
        let leaf = hash::sha256(&[i]);
        leaves.push(leaf);
        mmr.append(leaf);
    }
    let root = mmr.root();
    let proof = mmr.generate_proof(4).unwrap();
    assert!(verify_proof(root, leaves[4], &proof).unwrap());
    assert!(!verify_proof(root, leaves[5], &proof).unwrap());
}

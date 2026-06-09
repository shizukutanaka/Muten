//! RFC 6962 / RFC 9162 Merkle tree over audit-log events.
//!
//! ## Why a Merkle tree on top of the linear chain
//!
//! [`crate::sink`]'s SHA-256 hash chain makes the log **tamper-evident**:
//! editing or deleting any line (except a torn final write) breaks the
//! chain at a detectable point. But the chain has two limits that the
//! transparency-log literature (RFC 9162 Certificate Transparency,
//! Trillian, Sigstore Rekor, Crosby–Wallach USENIX 2009) solves with a
//! Merkle tree:
//!
//! 1. **No compact inclusion proof.** To prove a specific event is in the
//!    log you need the *whole* log to re-walk the chain. A Merkle tree
//!    yields an `O(log n)` **inclusion proof**: a handful of sibling
//!    hashes that prove "event #k is in the tree with root R".
//! 2. **No external anchor.** The chain head is just the last link. A
//!    Merkle **root** is a single 32-byte commitment to the *entire*
//!    ordered set of events; publishing or signing it out-of-band (an MDM
//!    push, a SIEM record, a notary) anchors the log's state at a point in
//!    time, so later tampering is provable against the anchored root even
//!    by someone who never held the original file.
//!
//! ## Scope (CLAUDE.md I3 — focused, not over-built)
//!
//! This is the RFC 6962 **Merkle Tree Hash (MTH)** and **audit-path**
//! (inclusion proof) only — the two operations that give inclusion proofs
//! and an anchorable root. Consistency proofs between two tree sizes
//! (RFC 9162 §2.1.4) are a natural next step but deliberately deferred
//! until a rotation/checkpoint workflow needs them. Pure, offline,
//! deterministic; reuses the crate's existing `sha2` + `hex`, no new
//! dependency, and stays `#![forbid(unsafe_code)]`.
//!
//! ## Domain separation
//!
//! Per RFC 6962 §2.1, leaves and internal nodes are hashed with distinct
//! one-byte prefixes (`0x00` for a leaf, `0x01` for a node) so that no
//! internal node can be forged to collide with a leaf (second-preimage
//! resistance of the tree structure). The empty tree's hash is
//! `SHA-256("")`, also per the RFC.

use sha2::{Digest, Sha256};

/// A hex-encoded SHA-256 hash (matches the chain's hash encoding).
pub type Hash = String;

const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;

type H = [u8; 32];

fn sha256(parts: &[&[u8]]) -> H {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// RFC 6962 leaf hash: `SHA-256(0x00 || data)`.
fn hash_leaf(data: &[u8]) -> H {
    sha256(&[&[LEAF_PREFIX], data])
}

/// RFC 6962 node hash: `SHA-256(0x01 || left || right)`.
fn hash_node(left: &H, right: &H) -> H {
    sha256(&[&[NODE_PREFIX], left, right])
}

/// The largest power of two **strictly less than** `n` (for `n >= 2`),
/// the split point `k` in the RFC 6962 recursive definitions.
fn split_point(n: usize) -> usize {
    debug_assert!(n >= 2);
    let mut k = 1;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

/// RFC 6962 §2.1 Merkle Tree Hash over the ordered `leaves`.
fn mth(leaves: &[&[u8]]) -> H {
    match leaves.len() {
        0 => sha256(&[]), // SHA-256 of the empty string
        1 => hash_leaf(leaves[0]),
        n => {
            let k = split_point(n);
            let left = mth(&leaves[..k]);
            let right = mth(&leaves[k..]);
            hash_node(&left, &right)
        }
    }
}

/// RFC 6962 §2.1.1 audit path (inclusion proof) for the leaf at `m`,
/// returned bottom-up as raw sibling hashes.
fn path(m: usize, leaves: &[&[u8]]) -> Vec<H> {
    let n = leaves.len();
    if n <= 1 {
        return Vec::new();
    }
    let k = split_point(n);
    if m < k {
        let mut p = path(m, &leaves[..k]);
        p.push(mth(&leaves[k..]));
        p
    } else {
        let mut p = path(m - k, &leaves[k..]);
        p.push(mth(&leaves[..k]));
        p
    }
}

/// The Merkle Tree Hash (root) over `leaves`, hex-encoded. The empty
/// list hashes to `SHA-256("")` per RFC 6962.
#[must_use]
pub fn merkle_root(leaves: &[Vec<u8>]) -> Hash {
    let refs: Vec<&[u8]> = leaves.iter().map(Vec::as_slice).collect();
    hex::encode(mth(&refs))
}

/// The inclusion (audit) proof for the leaf at `index` among `leaves`,
/// as hex sibling hashes bottom-up. Returns `None` if `index` is out of
/// range. Verify it with [`verify_inclusion`].
#[must_use]
pub fn inclusion_proof(leaves: &[Vec<u8>], index: usize) -> Option<Vec<Hash>> {
    if index >= leaves.len() {
        return None;
    }
    let refs: Vec<&[u8]> = leaves.iter().map(Vec::as_slice).collect();
    Some(path(index, &refs).iter().map(hex::encode).collect())
}

fn decode32(hex_str: &str) -> Option<H> {
    let bytes = hex::decode(hex_str).ok()?;
    bytes.try_into().ok()
}

/// Verify an inclusion proof using the RFC 9162 §2.1.3.2 algorithm:
/// recompute the root from `leaf_data` at `index` in a tree of
/// `tree_size` leaves plus the `proof` siblings, and compare to `root`.
/// `leaf_data` is the raw leaf bytes (the same bytes passed in the
/// `leaves` slice), **not** a pre-hashed value.
#[must_use]
pub fn verify_inclusion(
    leaf_data: &[u8],
    index: usize,
    tree_size: usize,
    proof: &[Hash],
    root: &str,
) -> bool {
    if index >= tree_size {
        return false;
    }
    let mut siblings = Vec::with_capacity(proof.len());
    for p in proof {
        match decode32(p) {
            Some(h) => siblings.push(h),
            None => return false,
        }
    }
    let Some(expected) = decode32(root) else {
        return false;
    };

    let mut fnode = index;
    let mut snode = tree_size - 1;
    let mut r = hash_leaf(leaf_data);
    for p in &siblings {
        if snode == 0 {
            // More proof entries than the tree height allows.
            return false;
        }
        if fnode & 1 == 1 || fnode == snode {
            r = hash_node(p, &r);
            if fnode & 1 == 0 {
                while fnode != 0 && fnode & 1 == 0 {
                    fnode >>= 1;
                    snode >>= 1;
                }
            }
        } else {
            r = hash_node(&r, p);
        }
        fnode >>= 1;
        snode >>= 1;
    }
    snode == 0 && r == expected
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(items: &[&str]) -> Vec<Vec<u8>> {
        items.iter().map(|s| s.as_bytes().to_vec()).collect()
    }

    #[test]
    fn empty_tree_is_sha256_of_empty() {
        // RFC 6962: MTH({}) = SHA-256(""). Known-answer.
        assert_eq!(
            merkle_root(&[]),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn single_empty_leaf_is_sha256_of_one_zero_byte() {
        // MTH({""}) = SHA-256(0x00). Known-answer.
        assert_eq!(
            merkle_root(&[Vec::new()]),
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
        );
    }

    #[test]
    fn two_and_three_leaf_shape_matches_rfc() {
        // Recompute the RFC structure independently via the primitives
        // (which are themselves checked against raw sha2 above/below).
        let d = leaves(&["a", "b", "c"]);
        let la = hash_leaf(b"a");
        let lb = hash_leaf(b"b");
        let lc = hash_leaf(b"c");
        // 2 leaves: node(leaf a, leaf b).
        assert_eq!(merkle_root(&d[..2]), hex::encode(hash_node(&la, &lb)));
        // 3 leaves: k=2 → node(node(a,b), c) (left-heavy split).
        let expect3 = hash_node(&hash_node(&la, &lb), &lc);
        assert_eq!(merkle_root(&d), hex::encode(expect3));
    }

    #[test]
    fn leaf_and_node_prefixes_differ_from_raw_sha() {
        // Domain separation: a leaf is SHA-256(0x00 || data), not SHA-256(data).
        let raw = hex::encode(sha256(&[b"x"]));
        let leaf = hex::encode(hash_leaf(b"x"));
        assert_ne!(raw, leaf);
        assert_eq!(leaf, hex::encode(sha256(&[&[0x00], b"x"])));
    }

    #[test]
    fn every_leaf_inclusion_proof_verifies_for_all_sizes() {
        // Exhaustive over awkward sizes (powers of two and the off-by-one
        // neighbours that exercise the left-heavy split).
        for n in 1..=33usize {
            let items: Vec<String> = (0..n).map(|i| format!("event-{i}")).collect();
            let lv: Vec<Vec<u8>> = items.iter().map(|s| s.clone().into_bytes()).collect();
            let root = merkle_root(&lv);
            for i in 0..n {
                let proof = inclusion_proof(&lv, i).expect("in range");
                assert!(
                    verify_inclusion(&lv[i], i, n, &proof, &root),
                    "proof failed for leaf {i} of {n}"
                );
            }
        }
    }

    #[test]
    fn wrong_index_or_root_fails_verification() {
        let lv = leaves(&["a", "b", "c", "d", "e"]);
        let root = merkle_root(&lv);
        let proof = inclusion_proof(&lv, 2).unwrap();
        // Correct.
        assert!(verify_inclusion(&lv[2], 2, 5, &proof, &root));
        // Wrong index → wrong recomputed root.
        assert!(!verify_inclusion(&lv[2], 3, 5, &proof, &root));
        // Tampered leaf data.
        assert!(!verify_inclusion(b"X", 2, 5, &proof, &root));
        // Wrong root.
        let bad = "0".repeat(64);
        assert!(!verify_inclusion(&lv[2], 2, 5, &proof, &bad));
    }

    #[test]
    fn changing_any_leaf_changes_the_root() {
        let a = leaves(&["one", "two", "three", "four"]);
        let mut b = a.clone();
        b[2] = b"three!".to_vec();
        assert_ne!(merkle_root(&a), merkle_root(&b));
        // Reordering also changes the root (order is committed).
        let mut c = a.clone();
        c.swap(0, 1);
        assert_ne!(merkle_root(&a), merkle_root(&c));
    }

    #[test]
    fn inclusion_proof_out_of_range_is_none() {
        let lv = leaves(&["a", "b"]);
        assert!(inclusion_proof(&lv, 2).is_none());
    }
}

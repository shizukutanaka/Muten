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
//! ## Operations provided
//!
//! - **Merkle Tree Hash (MTH)** — RFC 6962 §2.1 root over an ordered leaf set.
//! - **Inclusion proof** (audit path) — RFC 6962 §2.1.1 O(log n) proof that a
//!   specific event is committed by a root; verify with [`verify_inclusion`].
//! - **Consistency proof** — RFC 9162 §2.1.4 O(log n) proof that a newer tree
//!   is an append-only extension of an older tree; allows any holder of two
//!   published roots to confirm no events were inserted or re-ordered between
//!   the two snapshots without fetching the full log.
//!
//! Pure, offline, deterministic; reuses `sha2` + `hex`, no new dependencies,
//! `#![forbid(unsafe_code)]`.
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

// ── RFC 9162 §2.1.4 Consistency proofs ────────────────────────────────

/// RFC 9162 §2.1.4 `SUBPROOF(m, D[n], b)` — internal proof generator.
fn subproof(m: usize, leaves: &[&[u8]], b: bool) -> Vec<H> {
    let n = leaves.len();
    if m == n {
        if b {
            return Vec::new();
        } else {
            return vec![mth(leaves)];
        }
    }
    let k = split_point(n);
    if m <= k {
        let mut proof = subproof(m, &leaves[..k], b);
        proof.push(mth(&leaves[k..]));
        proof
    } else {
        let mut out = vec![mth(&leaves[..k])];
        out.extend(subproof(m - k, &leaves[k..], false));
        out
    }
}

/// RFC 9162 §2.1.4 consistency proof.
///
/// Returns the O(log n) sibling hashes (hex-encoded) that prove
/// `leaves[..first]` forms the same Merkle tree as a `first`-leaf tree
/// whose root is `merkle_root(&leaves[..first])`.  Any verifier holding
/// the two roots can check this without the original leaves.
///
/// Returns an empty list when `first == 0` or `first == leaves.len()`
/// (trivially consistent — empty prefix or identical trees).
#[must_use]
pub fn consistency_proof(first: usize, leaves: &[Vec<u8>]) -> Vec<Hash> {
    let n = leaves.len();
    if first == 0 || first >= n {
        return Vec::new();
    }
    let refs: Vec<&[u8]> = leaves.iter().map(Vec::as_slice).collect();
    subproof(first, &refs, true)
        .iter()
        .map(hex::encode)
        .collect()
}

/// Recursive verifier that mirrors `subproof`.  Returns
/// `Some((old_subtree_root, new_subtree_root))` consuming exactly the
/// proof elements that `subproof(m, n, b)` generated, or `None` when
/// the proof is exhausted or malformed.
fn verify_consistency_inner(
    m: usize,
    n: usize,
    proof: &[H],
    pos: &mut usize,
    first_hash: &H,
    b: bool,
) -> Option<(H, H)> {
    if m == n {
        // When b=true and m==n: the whole old tree is this subtree;
        // its hash is `first_hash` (not in the proof).
        // When b=false:         read the subtree hash from the proof.
        let h = if b {
            *first_hash
        } else {
            let v = *proof.get(*pos)?;
            *pos += 1;
            v
        };
        return Some((h, h));
    }
    let k = split_point(n);
    if m <= k {
        // Left subtree contains the entire old tree.
        let (old_sub, new_left) = verify_consistency_inner(m, k, proof, pos, first_hash, b)?;
        let new_right = *proof.get(*pos)?;
        *pos += 1;
        Some((old_sub, hash_node(&new_left, &new_right)))
    } else {
        // Old tree spans into the right subtree; left is fully shared.
        let old_left = *proof.get(*pos)?;
        *pos += 1;
        let (old_sub, new_right) =
            verify_consistency_inner(m - k, n - k, proof, pos, first_hash, false)?;
        Some((
            hash_node(&old_left, &old_sub),
            hash_node(&old_left, &new_right),
        ))
    }
}

/// Verify a RFC 9162 §2.1.4 consistency proof.
///
/// Proves that the `first`-event tree (Merkle root `old_root`) is a
/// prefix of the `n`-event tree (Merkle root `new_root`).  Both roots
/// are hex-encoded SHA-256 values, as produced by [`merkle_root`].
///
/// Returns `true` iff the proof is cryptographically valid and all
/// proof elements are consumed (extra elements are rejected).
#[must_use]
pub fn verify_consistency(
    first: usize,
    n: usize,
    proof: &[Hash],
    old_root: &str,
    new_root: &str,
) -> bool {
    if first > n {
        return false;
    }
    if first == n {
        return proof.is_empty() && old_root == new_root;
    }
    if first == 0 {
        // Empty prefix is consistent with anything; old_root must be the
        // empty-tree hash (SHA-256 of the empty string per RFC 6962).
        return proof.is_empty() && old_root == merkle_root(&[]);
    }
    let Some(old_h) = decode32(old_root) else {
        return false;
    };
    let Some(new_h) = decode32(new_root) else {
        return false;
    };
    let mut decoded: Vec<H> = Vec::with_capacity(proof.len());
    for p in proof {
        match decode32(p) {
            Some(h) => decoded.push(h),
            None => return false,
        }
    }
    let mut pos = 0usize;
    match verify_consistency_inner(first, n, &decoded, &mut pos, &old_h, true) {
        Some((computed_old, computed_new)) => {
            pos == decoded.len()  // all proof elements consumed — no extras
                && computed_old == old_h
                && computed_new == new_h
        }
        None => false,
    }
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

    // ── RFC 9162 §2.1.4 Consistency proofs ──────────────────────────

    #[test]
    fn consistency_proof_trivial_same_tree() {
        let lv = leaves(&["a", "b", "c", "d"]);
        let root = merkle_root(&lv);
        // Same tree → empty proof.
        assert!(consistency_proof(4, &lv).is_empty());
        assert!(verify_consistency(4, 4, &[], &root, &root));
        // Different roots with same size → false.
        let bad = "0".repeat(64);
        assert!(!verify_consistency(4, 4, &[], &bad, &root));
    }

    #[test]
    fn consistency_proof_empty_first() {
        let lv = leaves(&["a", "b"]);
        assert!(consistency_proof(0, &lv).is_empty());
        let empty_root = merkle_root(&[]);
        let new_root = merkle_root(&lv);
        assert!(verify_consistency(0, 2, &[], &empty_root, &new_root));
    }

    #[test]
    fn consistency_proof_power_of_two_prefix() {
        // first=2, n=4 → proof is just MTH(D[2..4]); 1 element.
        let lv = leaves(&["a", "b", "c", "d"]);
        let old_root = merkle_root(&lv[..2]);
        let new_root = merkle_root(&lv);
        let proof = consistency_proof(2, &lv);
        assert_eq!(
            proof.len(),
            1,
            "power-of-2 prefix needs exactly 1 proof element"
        );
        assert!(verify_consistency(2, 4, &proof, &old_root, &new_root));
    }

    #[test]
    fn consistency_proof_non_power_prefix() {
        // first=3, n=4 → proof has 2 elements: MTH("a","b") and hash_leaf("d").
        let lv = leaves(&["a", "b", "c", "d"]);
        let old_root = merkle_root(&lv[..3]);
        let new_root = merkle_root(&lv);
        let proof = consistency_proof(3, &lv);
        assert!(verify_consistency(3, 4, &proof, &old_root, &new_root));
    }

    #[test]
    fn consistency_proof_verifies_for_all_prefix_sizes() {
        // Exhaustive check across awkward sizes (powers of two and
        // off-by-one neighbours that exercise every code path).
        for n in 2..=25usize {
            let items: Vec<Vec<u8>> = (0..n).map(|i| format!("ev-{i}").into_bytes()).collect();
            let new_root = merkle_root(&items);
            for m in 1..n {
                let old_root = merkle_root(&items[..m]);
                let proof = consistency_proof(m, &items);
                assert!(
                    verify_consistency(m, n, &proof, &old_root, &new_root),
                    "consistency failed for m={m}, n={n}"
                );
                // Tampered old_root must not verify.
                let bad = "0".repeat(64);
                assert!(
                    !verify_consistency(m, n, &proof, &bad, &new_root),
                    "tampered old_root should fail m={m}, n={n}"
                );
                // Tampered new_root must not verify.
                assert!(
                    !verify_consistency(m, n, &proof, &old_root, &bad),
                    "tampered new_root should fail m={m}, n={n}"
                );
            }
        }
    }

    #[test]
    fn consistency_proof_extra_element_rejected() {
        let lv = leaves(&["a", "b", "c", "d"]);
        let old_root = merkle_root(&lv[..2]);
        let new_root = merkle_root(&lv);
        let mut proof = consistency_proof(2, &lv);
        proof.push("0".repeat(64));
        // Extra element → verification must fail.
        assert!(!verify_consistency(2, 4, &proof, &old_root, &new_root));
    }

    #[test]
    fn consistency_proof_first_greater_than_n_is_false() {
        let lv = leaves(&["a", "b"]);
        let root = merkle_root(&lv);
        assert!(!verify_consistency(3, 2, &[], &root, &root));
    }
}

//! A REAL SHA-256 — not a stub in the usual sense.
//!
//! WHY THIS EXISTS. `src/merkle.rs` carries 15 tests that pin the audit
//! chain's RFC 6962 hashing, including known-answer tests against the
//! published SHA-256 of the empty string. Those tests had never been run:
//! `merkle.rs` imports `sha2`, and this environment cannot download
//! crates (static.crates.io is denied by the egress policy). So the
//! tamper-evidence at the heart of the product was *asserted in tests
//! that no machine had ever executed*.
//!
//! WHY IT IS NOT A DUMMY. Faking `sha2` would make those known-answer
//! tests meaningless — `merkle_root(&[])` would "pass" against whatever
//! the fake returned. This is therefore a genuine FIPS 180-4 SHA-256
//! implementation, and `scripts/check-merkle.sh` proves that claim
//! BEFORE running any merkle test, by hashing the two NIST vectors and
//! refusing to continue unless both match. If this file is wrong, the
//! self-test fails first and loudly; the merkle results are never
//! reported on top of a broken primitive.
//!
//! SCOPE. Only the surface `merkle.rs` uses: `Digest::new`, `update`,
//! `finalize`. Not constant-time, not streaming-optimised; correctness
//! and independent verifiability are the only goals here. The product
//! itself always links the real `sha2` crate.

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// The subset of the `sha2::Digest` trait that `merkle.rs` uses.
pub trait Digest {
    fn new() -> Self;
    fn update(&mut self, data: impl AsRef<[u8]>);
    fn finalize(self) -> [u8; 32];
    /// One-shot convenience, as in the real crate.
    fn digest(data: impl AsRef<[u8]>) -> [u8; 32]
    where
        Self: Sized,
    {
        let mut h = Self::new();
        h.update(data);
        h.finalize()
    }
}

/// FIPS 180-4 SHA-256.
pub struct Sha256 {
    state: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

impl Sha256 {
    fn compress(&mut self) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            let b = &self.buf[i * 4..i * 4 + 4];
            w[i] = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        let add = [a, b, c, d, e, f, g, h];
        for i in 0..8 {
            self.state[i] = self.state[i].wrapping_add(add[i]);
        }
    }
}

impl Digest for Sha256 {
    fn new() -> Self {
        Sha256 {
            state: IV,
            buf: [0u8; 64],
            buf_len: 0,
            total_len: 0,
        }
    }

    fn update(&mut self, data: impl AsRef<[u8]>) {
        let mut data = data.as_ref();
        self.total_len = self.total_len.wrapping_add(data.len() as u64);
        while !data.is_empty() {
            let take = core::cmp::min(64 - self.buf_len, data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 64 {
                self.compress();
                self.buf_len = 0;
            }
        }
    }

    fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_len.wrapping_mul(8);
        self.update([0x80u8]);
        // `update` advanced total_len; that is fine, bit_len was captured.
        while self.buf_len != 56 {
            self.update([0x00u8]);
        }
        self.update(bit_len.to_be_bytes());
        debug_assert_eq!(self.buf_len, 0);
        let mut out = [0u8; 32];
        for i in 0..8 {
            out[i * 4..i * 4 + 4].copy_from_slice(&self.state[i].to_be_bytes());
        }
        out
    }
}

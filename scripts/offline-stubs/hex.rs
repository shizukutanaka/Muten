//! Minimal `hex` replacement for registry-less verification runs.
//!
//! WHY THIS EXISTS. `src/merkle.rs` hex-encodes hashes and decodes proof
//! elements; the real `hex` crate cannot be downloaded here. Encoding is
//! lowercase, two digits per byte; decoding rejects odd lengths and
//! non-hex digits, which is what `merkle.rs` relies on when it treats a
//! malformed proof element as "not verifiable".
//!
//! Round-tripping is checked by `scripts/check-merkle.sh` before any
//! merkle test result is reported.

/// Returned when a string is not valid hex. `merkle.rs` only calls
/// `.ok()` on the result, so the payload is deliberately opaque.
#[derive(Debug, PartialEq, Eq)]
pub struct FromHexError;

#[must_use]
pub fn encode(data: impl AsRef<[u8]>) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let bytes = data.as_ref();
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    s
}

fn nibble(c: u8) -> Result<u8, FromHexError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(FromHexError),
    }
}

pub fn decode(data: impl AsRef<[u8]>) -> Result<Vec<u8>, FromHexError> {
    let bytes = data.as_ref();
    if bytes.len() % 2 != 0 {
        return Err(FromHexError);
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        out.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    Ok(out)
}

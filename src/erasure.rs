//! Erasure
//!
//! Chunking with Erasure Codes
//!
//! A Sparse Continuous Key Agreement (SCKA) protocol sends large messages
//! in pieces and must do this in a way that is robust, even in an adversarial
//! network environment. To accomplish this a protocol can use erasure codes
//! or fountain codes. Informally this can be thought of as breaking a
//! message into a stream of chunks, and in this document any mention
//! of a “chunk” of a message refers to a codeword of an erasure code.
//!
//! [Reference](https://signal.org/docs/specifications/mlkembraid/#chunking-with-erasure-codes)
//! [Reference Section 2.4 Chunk Encoding](https://eprint.iacr.org/2025/078)
//! [Reference Section 5.1 Experimental Setup](https://www.usenix.org/system/files/usenixsecurity25-auerbach.pdf)
//!
//! For our implementation we will use reed-solomon erasure codes. Initially,
//! we looked at:
//! - `reed-solomon-erasure`
//! - `reed-solomon-16`
//! - `reed-solomon-simd`
//!
//! However, it appears that if we want compatibility with Signal, our
//! implementation must meet the following criteria
//! 1. The Galois Field (GF) must be 16 (i.e., GF(2^16))
//!   - GF(2^16)^(w/2) with 'w' byte chunks
//! 2. The modulus must match Signal's 0x1100B
//! 3. Signal generates/shares points
//! 4. "Chunk at" as opposed to serial generation
//! 5. Big Endian Wire encoding
//!
//! The crates listed above did not seem to reasonably support this complete
//! set of criteria. Therefore, we created our own implementation. This
//! implementation may not be a perfect match to Signal's implementation.
//! Fixes and corrections are always welcome.

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
#[cfg(not(feature = "std"))]
use core::iter;
#[cfg(feature = "std")]
use std::iter;

use g2p::g2p;

// This macro creates a type named GF16.
// 16 = GF(2^16), modulus 0x1100B matches Signal's primitive polynomial.
g2p!(GF16, 16, modulus: 0x1100B);

const BLOCK_SIZE: usize = 32; // Total bytes per chunk
const NUM_POLYS: usize = BLOCK_SIZE / 2;

/// As described in `erasure.rs`
/// a “chunk” of a message refers to a codeword of an erasure code
/// (u16, [u8; BLOCK_SIZE])
#[derive(Debug, Clone)]
pub struct Chunk {
    pub index: u16,
    pub data: [u8; BLOCK_SIZE],
}

#[derive(Debug, Clone)]
pub struct ErasureCodecEncode {
    // Stores the original 16 polynomials (coefficients)
    pub poly_coeffs: [Vec<GF16>; NUM_POLYS],
    pub k: usize,
    pub original_len: usize,
    pub next_index: u16,
}

impl ErasureCodecEncode {
    /// Creates a new encoder from a message
    pub fn new(message: &[u8]) -> Self {
        let original_len = message.len();
        let padding_needed = (BLOCK_SIZE - (original_len % BLOCK_SIZE)) % BLOCK_SIZE;
        let mut padded_msg = message.to_vec();
        padded_msg.extend(iter::repeat_n(0, padding_needed));

        let k = padded_msg.len() / BLOCK_SIZE;
        let mut coeffs_out: [Vec<GF16>; NUM_POLYS] = Default::default();
        for p in &mut coeffs_out {
            *p = Vec::with_capacity(k);
        }

        // We treat the message blocks as evaluation points at x = 0, 1, ..., k-1
        for p_idx in 0..NUM_POLYS {
            let mut xs = Vec::with_capacity(k);
            let mut ys = Vec::with_capacity(k);

            for (i, block) in padded_msg.chunks_exact(BLOCK_SIZE).enumerate() {
                let val = u16::from_be_bytes([block[p_idx * 2], block[p_idx * 2 + 1]]);
                xs.push(GF16::from(i as u16));
                ys.push(GF16::from(val));
            }
            // Transform Y-values (message) into polynomial coefficients
            coeffs_out[p_idx] = ErasureCodec::interpolate_alt(&xs, &ys);
        }

        Self {
            poly_coeffs: coeffs_out,
            k,
            original_len,
            next_index: 0,
        }
    }

    /// ENCODE: Evaluates the 16 parallel polynomials at `idx`
    /// Evaluates the 24 parallel polynomials at 'idx' to create a BLOCK_SIZE-byte chunk.
    pub fn chunk_at(&self, idx: u16) -> Chunk {
        let mut output = [0u8; BLOCK_SIZE];
        let x = GF16::from(idx);

        for p_idx in 0..NUM_POLYS {
            let mut result = GF16::from(0);
            // Evaluate using Horner's method
            for &c in self.poly_coeffs[p_idx].iter().rev() {
                result = result * x + c;
            }
            let bytes = u16::from(result).to_be_bytes();
            output[p_idx * 2] = bytes[0];
            output[p_idx * 2 + 1] = bytes[1];
        }
        Chunk {
            index: idx,
            data: output,
        }
    }

    /// ENCODE: Evaluates the 16 parallel polynomials at `self.next_index`
    /// by calling `chunk_at` then advances the value
    pub fn next_chunk(&mut self) -> Chunk {
        let idx = self.next_index;
        self.next_index += 1;
        self.chunk_at(idx)
    }
}

#[derive(Debug, Clone)]
struct Point {
    x: GF16,
    y: GF16,
}

#[derive(Debug, Clone)]
pub struct ErasureCodecDecode {
    received_points: [Vec<Point>; NUM_POLYS],
    original_len: usize,
    k: usize,
}

impl ErasureCodecDecode {
    pub fn new(original_len: usize) -> Self {
        let padding_needed = (BLOCK_SIZE - (original_len % BLOCK_SIZE)) % BLOCK_SIZE;
        let k = (original_len + padding_needed) / BLOCK_SIZE;
        Self {
            received_points: core::array::from_fn(|_| Vec::with_capacity(k)),
            original_len,
            k,
        }
    }

    pub fn add_points(&mut self, share: Chunk) {
        for p_idx in 0..NUM_POLYS {
            let Chunk {
                index: idx,
                data: chunk,
            } = share;
            let val = u16::from_be_bytes([chunk[p_idx * 2], chunk[p_idx * 2 + 1]]);
            self.insert_received_point_if_new(p_idx, idx, val);
        }
    }

    fn insert_received_point_if_new(&mut self, index: usize, x: u16, y: u16) {
        let vec = &mut self.received_points[index];

        match vec.binary_search_by(|p| p.x.0.cmp(&x).then(p.y.0.cmp(&y))) {
            Ok(_) => {} // Point already exists, do nothing
            Err(pos) => vec.insert(
                pos,
                Point {
                    x: GF16::from(x),
                    y: GF16::from(y),
                },
            ), // Insert at the correct position
        }
    }

    /// Returns the total number of Points (x,y pairs) currently stored
    /// across all parallel polynomials.
    pub fn total_points_collected(&self) -> usize {
        self.received_points.iter().map(|v| v.len()).sum()
    }

    /// Returns the absolute number of Points required to begin recovery.
    pub fn total_points_required(&self) -> usize {
        let k = self.original_len.div_ceil(BLOCK_SIZE); //(self.original_len + BLOCK_SIZE - 1) / BLOCK_SIZE;
        k * NUM_POLYS
    }

    pub fn can_recover(&self) -> bool {
        self.total_points_collected() >= self.total_points_required()
    }

    pub fn recover(&self) -> Option<Vec<u8>> {
        if !self.can_recover() {
            return None;
        }
        // We perform Lagrange interpolation for each of the 16 parallel polynomials
        let mut recovered_blocks = vec![[0u8; BLOCK_SIZE]; self.k];

        for p_idx in 0..NUM_POLYS {
            // Interpolate to find the same coefficients
            let coeffs = ErasureCodec::interpolate(&self.received_points[p_idx]);
            // To get original blocks, evaluate at x = 0, 1, ..., k-1
            for (i, recovered_block) in recovered_blocks.iter_mut().enumerate().take(self.k) {
                let mut eval = GF16::from(0);
                let x_target = GF16::from(i as u16);
                for &c in coeffs.iter().rev() {
                    eval = eval * x_target + c;
                }
                let bytes = u16::from(eval).to_be_bytes();
                recovered_block[p_idx * 2] = bytes[0];
                recovered_block[p_idx * 2 + 1] = bytes[1];
            }
        }
        let mut result = recovered_blocks.concat();
        result.truncate(self.original_len);
        Some(result)
    }

    /// DECODE: Recovers the original message from a set of shares
    /// shares: A slice of (index, 32-byte_chunk) pairs
    /// 'k' is the number of blocks (original_len / BLOCK_SIZE rounded up).
    pub fn recover_alt(&self, shares: &[Chunk]) -> Option<Vec<u8>> {
        if shares.len() < self.k {
            return None;
        }
        // We perform Lagrange interpolation for each of the 16 parallel polynomials
        let mut recovered_blocks = vec![[0u8; BLOCK_SIZE]; self.k];

        for p_idx in 0..NUM_POLYS {
            let mut xs = Vec::with_capacity(self.k);
            let mut ys = Vec::with_capacity(self.k);
            for Chunk {
                index: idx,
                data: chunk,
            } in shares.iter().take(self.k)
            {
                let val = u16::from_be_bytes([chunk[p_idx * 2], chunk[p_idx * 2 + 1]]);
                xs.push(GF16::from(*idx));
                ys.push(GF16::from(val));
            }

            // Interpolate to find the same coefficients
            let coeffs = ErasureCodec::interpolate_alt(&xs, &ys);

            // To get original blocks, evaluate at x = 0, 1, ..., k-1
            //for i in 0..self.k {
            for (i, recovered_block) in recovered_blocks.iter_mut().enumerate().take(self.k) {
                let mut eval = GF16::from(0);
                let x_target = GF16::from(i as u16);
                for &c in coeffs.iter().rev() {
                    eval = eval * x_target + c;
                }
                let bytes = u16::from(eval).to_be_bytes();
                recovered_block[p_idx * 2] = bytes[0];
                recovered_block[p_idx * 2 + 1] = bytes[1];
            }
        }

        let mut result = recovered_blocks.concat();
        result.truncate(self.original_len);
        Some(result)
    }
}

#[derive(Debug, Clone)]
struct ErasureCodec;

impl ErasureCodec {
    /// Internal Lagrange interpolation to find coefficients c0, c1...
    fn interpolate_alt(xs: &[GF16], ys: &[GF16]) -> Vec<GF16> {
        let k = xs.len();
        let mut coeffs = vec![GF16::from(0); k];
        for i in 0..k {
            let mut li = vec![GF16::from(0); k];
            li[0] = GF16::from(1);
            let mut denom = GF16::from(1);
            for j in 0..k {
                if i == j {
                    continue;
                }
                denom *= xs[i] + xs[j];
                let mut next_li = vec![GF16::from(0); k];
                for d in 0..k {
                    if li[d] == GF16::from(0) {
                        continue;
                    }
                    if d + 1 < k {
                        next_li[d + 1] += li[d];
                    }
                    next_li[d] += li[d] * xs[j];
                }
                li = next_li;
            }
            let weight = ys[i] / denom;
            for d in 0..k {
                coeffs[d] += li[d] * weight;
            }
        }
        coeffs
    }

    fn interpolate(points: &[Point]) -> Vec<GF16> {
        let k = points.len();
        let mut coeffs = vec![GF16::from(0); k];
        for i in 0..k {
            let mut li = vec![GF16::from(0); k];
            li[0] = GF16::from(1);
            let mut denom = GF16::from(1);
            for j in 0..k {
                if i == j {
                    continue;
                }
                denom *= points[i].x + points[j].x;
                let mut next_li = vec![GF16::from(0); k];
                for d in 0..k {
                    if li[d] == GF16::from(0) {
                        continue;
                    }
                    if d + 1 < k {
                        next_li[d + 1] += li[d];
                    }
                    next_li[d] += li[d] * points[j].x;
                }
                li = next_li;
            }
            let weight = points[i].y / denom;
            for d in 0..k {
                coeffs[d] += li[d] * weight;
            }
        }
        coeffs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to generate a test message
    fn generate_message(len: usize) -> Vec<u8> {
        // Using a simple hash-like transformation to ensure non-linearity
        (0..(len * BLOCK_SIZE))
            .map(|i| {
                let x = (i as u32).wrapping_mul(0x45d9f3b) ^ (i as u32 >> 16);
                (x % 256) as u8
            })
            .collect()
    }

    #[test]
    fn test_empty_message() {
        let message = b"";
        let codec = ErasureCodecEncode::new(message);
        let mut recovery = ErasureCodecDecode::new(0);
        recovery.add_points(codec.chunk_at(0));
        let recovered = recovery.recover();
        assert_eq!(recovered.unwrap().len(), 0);
    }
    #[test]
    fn test_empty_message2() {
        let message = b"";
        let codec = ErasureCodecEncode::new(message);
        let shares = vec![codec.chunk_at(0)];
        let recovered = ErasureCodecDecode::new(0).recover_alt(&shares);
        assert_eq!(recovered.unwrap().len(), 0);
    }

    #[test]
    fn test_signal_compatibility_workflow() {
        // 1. Variable length input (not a multiple of 48)
        let message = b"Signal Protocol PQ-Ratchet Test Message. This must be padded.";
        let original_len = message.len();

        // 2. Encode
        let codec = ErasureCodecEncode::new(message);
        let k = codec.k; // Number of shares needed

        // 3. Generate shares (0..k are systematic, k..n are parity)
        // We simulate losing the first two shares and using parity shares 10 and 11 instead.
        let mut shares = Vec::new();
        shares.push((2, codec.chunk_at(2))); // Systematic
        shares.push((10, codec.chunk_at(10))); // Parity
        shares.push((11, codec.chunk_at(11))); // Parity
        // ... assuming k=2 for this small message, but codec.k will calculate it.

        // Let's just grab 'k' shares from random indices
        let test_indices = vec![5, 0, 99, 3]; // Shuffled indices
        let mut recovery = ErasureCodecDecode::new(original_len);
        for i in 0..k {
            let idx = test_indices[i];
            recovery.add_points(codec.chunk_at(idx as u16));
        }

        // 4. Recover
        let recovered = recovery.recover();

        assert_eq!(message.to_vec(), recovered.unwrap());
    }
    #[test]
    fn test_signal_compatibility_workflow2() {
        // 1. Variable length input (not a multiple of 48)
        let message = b"Signal Protocol PQ-Ratchet Test Message. This must be padded.";
        let original_len = message.len();

        // 2. Encode
        let codec = ErasureCodecEncode::new(message);
        let k = codec.k; // Number of shares needed

        // 3. Generate shares (0..k are systematic, k..n are parity)
        // We simulate losing the first two shares and using parity shares 10 and 11 instead.
        let mut shares = Vec::new();
        shares.push((2, codec.chunk_at(2))); // Systematic
        shares.push((10, codec.chunk_at(10))); // Parity
        shares.push((11, codec.chunk_at(11))); // Parity
        // ... assuming k=2 for this small message, but codec.k will calculate it.

        // Let's just grab 'k' shares from random indices
        let mut robust_shares = Vec::new();
        let test_indices = vec![5, 0, 99, 3]; // Shuffled indices
        for i in 0..k {
            let idx = test_indices[i];
            robust_shares.push(codec.chunk_at(idx as u16));
        }

        // 4. Recover
        let recovered = ErasureCodecDecode::new(original_len).recover_alt(&robust_shares);

        assert_eq!(message.to_vec(), recovered.unwrap());
    }

    #[test]
    fn test_perfect_recovery() {
        let k = 4;
        let message = generate_message(k);
        let codec = ErasureCodecEncode::new(&message);

        // Generate exactly k chunks (0, 1, 2, 3)
        let mut recovery = ErasureCodecDecode::new(codec.original_len);
        for i in 0..k {
            recovery.add_points(codec.chunk_at(i as u16));
        }

        let recovered = recovery.recover();
        assert_eq!(message, recovered.unwrap(), "Failed simple recovery");
    }
    #[test]
    fn test_perfect_recovery2() {
        let k = 4;
        let message = generate_message(k);
        let codec = ErasureCodecEncode::new(&message);

        // Generate exactly k chunks (0, 1, 2, 3)
        let mut shares = Vec::new();
        for i in 0..k {
            shares.push(codec.chunk_at(i as u16));
        }

        let recovered = ErasureCodecDecode::new(codec.original_len).recover_alt(&shares);
        assert_eq!(message, recovered.unwrap(), "Failed simple recovery");
    }

    #[test]
    fn test_next_chunk() {
        let k = 3; // Need 3 chunks
        let message = generate_message(k);
        let mut codec = ErasureCodecEncode::new(&message);

        // We use non-sequential indices (simulating lost original data)
        // Indices: 0 (original), 5 (parity), 10 (parity)
        let mut recovery = ErasureCodecDecode::new(codec.original_len);
        recovery.add_points(codec.next_chunk());
        assert!(!recovery.can_recover());
        recovery.add_points(codec.next_chunk());
        assert!(!recovery.can_recover());
        recovery.add_points(codec.next_chunk());
        assert!(recovery.can_recover());

        let recovered = recovery.recover();
        assert_eq!(message, recovered.unwrap(), "Failed recovery with gaps");
    }

    #[test]
    fn test_out_of_order_chunks() {
        let k = 4;
        let message = generate_message(k);
        let codec = ErasureCodecEncode::new(&message);

        // Indices in random order: 3, 0, 2, 1
        let indices = vec![3, 0, 2, 1];
        let mut recovery = ErasureCodecDecode::new(codec.original_len);
        for i in indices {
            recovery.add_points(codec.chunk_at(i as u16));
        }

        let recovered = recovery.recover();
        assert_eq!(message, recovered.unwrap(), "Failed out-of-order recovery");
    }
    #[test]
    fn test_out_of_order_chunks2() {
        let k = 4;
        let message = generate_message(k);
        let codec = ErasureCodecEncode::new(&message);

        // Indices in random order: 3, 0, 2, 1
        let indices = vec![3, 0, 2, 1];
        let mut shares = Vec::new();
        for i in indices {
            shares.push(codec.chunk_at(i as u16));
        }

        let recovered = ErasureCodecDecode::new(codec.original_len).recover_alt(&shares);
        assert_eq!(message, recovered.unwrap(), "Failed out-of-order recovery");
    }

    #[test]
    fn test_recovery_with_parity_gaps() {
        let k = 3; // Need 3 chunks
        let message = generate_message(k);
        let codec = ErasureCodecEncode::new(&message);

        // We use non-sequential indices (simulating lost original data)
        // Indices: 0 (original), 5 (parity), 10 (parity)
        let mut recovery = ErasureCodecDecode::new(codec.original_len);
        recovery.add_points(codec.chunk_at(0));
        recovery.add_points(codec.chunk_at(5));
        recovery.add_points(codec.chunk_at(10));

        let recovered = recovery.recover();
        assert_eq!(message, recovered.unwrap(), "Failed recovery with gaps");
    }
    #[test]
    fn test_recovery_with_parity_gaps2() {
        let k = 3; // Need 3 chunks
        let message = generate_message(k);
        let codec = ErasureCodecEncode::new(&message);

        // We use non-sequential indices (simulating lost original data)
        // Indices: 0 (original), 5 (parity), 10 (parity)
        let shares = vec![codec.chunk_at(0), codec.chunk_at(5), codec.chunk_at(10)];

        let recovered = ErasureCodecDecode::new(codec.original_len).recover_alt(&shares);
        assert_eq!(message, recovered.unwrap(), "Failed recovery with gaps");
    }

    #[test]
    fn test_insufficient_shares_properly() {
        let k = 5;
        // Use high-entropy data so it's not a simple line/curve
        let message = generate_message(k * BLOCK_SIZE);
        let codec = ErasureCodecEncode::new(&message);

        // We only take 4 shares (we need 5)
        let mut recovery = ErasureCodecDecode::new(message.len());
        for i in 0..4 {
            recovery.add_points(codec.chunk_at(i as u16));
        }

        // Attempt recovery
        let recovered = recovery.recover();

        // Now left != right will pass because the 5th block
        // won't be "guessed" correctly by the lower-degree polynomial.
        assert_eq!(
            None, recovered,
            "Recovery should fail with insufficient entropy-rich shares"
        );
    }
    #[test]
    fn test_insufficient_shares_properly2() {
        let k = 5;
        // Use high-entropy data so it's not a simple line/curve
        let message = generate_message(k * BLOCK_SIZE);
        let codec = ErasureCodecEncode::new(&message);

        // We only take 4 shares (we need 5)
        let mut shares = Vec::new();
        for i in 0..4 {
            shares.push(codec.chunk_at(i as u16));
        }

        // Attempt recovery
        let recovered = ErasureCodecDecode::new(message.len()).recover_alt(&shares);

        // Now left != right will pass because the 5th block
        // won't be "guessed" correctly by the lower-degree polynomial.
        assert_eq!(
            None, recovered,
            "Recovery should fail with insufficient entropy-rich shares"
        );
    }
}

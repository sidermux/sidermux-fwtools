//! `no_std` firmware boot image codecs and checksum primitives for sidermux.
//!
//! > [!WARNING]
//! > **Beta software.** This project is pre-release and breaking changes may
//! > happen frequently between versions. Pin the exact version you depend on.
//!
//! This crate has no dependencies and performs no allocation. Each supported
//! device family ships its boot image codec as a module under [`families`],
//! behind its own cargo feature; the crate stays `no_std` with or without any
//! feature enabled.
//!
//! First supported family: Cyclone V (feature `cyclone-v`).
//!
//! # Checksums
//!
//! CRC-32/BZIP2 (the integrity tail used by the workspace's boot ROM image
//! formats) is
//! available one-shot or incrementally, so streamed verification never needs
//! the whole image in memory:
//!
//! ```
//! use sidermux_image::{Crc32Bzip2, crc32_bzip2};
//!
//! // Canonical catalog check value.
//! assert_eq!(crc32_bzip2(b"123456789"), 0xFC89_1918);
//!
//! let mut crc = Crc32Bzip2::new();
//! crc.update(b"12345");
//! crc.update(b"6789");
//! assert_eq!(crc.finalize(), 0xFC89_1918);
//! ```

#![cfg_attr(not(test), no_std)]

/// Family-specific boot image codecs, each behind its own cargo feature.
pub mod families {
    /// Boot ROM image header codec of the first supported family
    /// (feature `cyclone-v`).
    #[cfg(feature = "cyclone-v")]
    pub mod cyclone_v;
}

/// CRC-32/BZIP2 of `bytes` in one call: polynomial `0x04C1_1DB7`, init and
/// xor-out `0xFFFF_FFFF`, no bit reflection.
///
/// This is the integrity checksum used by the boot ROM image formats packaged
/// by this workspace. See [`Crc32Bzip2`] for chunked input.
#[must_use]
pub fn crc32_bzip2(bytes: &[u8]) -> u32 {
    let mut crc = Crc32Bzip2::new();
    crc.update(bytes);
    crc.finalize()
}

const POLYNOMIAL: u32 = 0x04C1_1DB7;

/// Incremental CRC-32/BZIP2, equivalent to [`crc32_bzip2`] but fed in chunks,
/// so streamed verification never needs the whole image in memory.
pub struct Crc32Bzip2 {
    state: u32,
}

impl Crc32Bzip2 {
    /// Starts a computation in the standard initial state.
    #[must_use]
    pub const fn new() -> Self {
        Self { state: 0xFFFF_FFFF }
    }

    /// Feeds `bytes` into the running CRC. Call repeatedly for chunked input.
    pub fn update(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.state ^= u32::from(byte) << 24;

            for _ in 0..8 {
                self.state = if self.state & 0x8000_0000 != 0 {
                    (self.state << 1) ^ POLYNOMIAL
                } else {
                    self.state << 1
                };
            }
        }
    }

    /// Consumes the computation and returns the final CRC value.
    #[must_use]
    pub fn finalize(self) -> u32 {
        !self.state
    }
}

impl Default for Crc32Bzip2 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::crc32_bzip2;

    #[test]
    fn check_value_matches_crc32_bzip2_catalog() {
        // Canonical check value for CRC-32/BZIP2 (a.k.a. CRC-32/AAL5,
        // CRC-32/B-C) from the standard CRC catalog.
        assert_eq!(crc32_bzip2(b"123456789"), 0xFC89_1918);
    }

    #[test]
    fn empty_input_hashes_to_zero() {
        assert_eq!(crc32_bzip2(b""), 0x0000_0000);
    }

    #[test]
    fn single_byte_vectors() {
        // Independently computed with a reference implementation of the same
        // polynomial/init/xor-out parameters.
        assert_eq!(crc32_bzip2(&[0x00]), 0xB1F7_404B);
        assert_eq!(crc32_bzip2(&[0xFF]), 0x0000_00FF);
    }

    #[test]
    fn incremental_hashing_matches_one_shot() {
        let data: Vec<u8> = (0..=255u8).cycle().take(5000).collect();
        let mut incremental = super::Crc32Bzip2::new();
        for chunk in data.chunks(7) {
            incremental.update(chunk);
        }
        assert_eq!(incremental.finalize(), crc32_bzip2(&data));
    }
}

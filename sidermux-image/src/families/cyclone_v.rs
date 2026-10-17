//! Boot ROM image header codec of the first supported family
//! (feature `cyclone-v`).
//!
//! The header is a fixed 12-byte, little-endian structure placed inside the
//! packaged ROM image; the host-side encoding rules live in
//! `sidermux-fwtools`.

/// A boot ROM image header: validation word, version, flags, declared length,
/// and header checksum.
pub struct Header {
    validation_word: u32,
    version: u8,
    flags: u8,
    length_words: u16,
    reserved: u16,
    checksum: u16,
}

impl Header {
    /// Serialized size in bytes.
    pub const SIZE: usize = 12;
    /// Byte offset of the header within the packaged ROM image.
    pub const OFFSET: usize = 0x40;

    /// Serializes the header in little-endian field order.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];

        bytes[0..4].copy_from_slice(&self.validation_word.to_le_bytes());
        bytes[4] = self.version;
        bytes[5] = self.flags;
        bytes[6..8].copy_from_slice(&self.length_words.to_le_bytes());
        bytes[8..10].copy_from_slice(&self.reserved.to_le_bytes());
        bytes[10..12].copy_from_slice(&self.checksum.to_le_bytes());

        bytes
    }

    /// Builds a header declaring `length_words` 32-bit words of payload and
    /// computes the header checksum (byte sum over the first ten bytes).
    #[must_use]
    pub fn new(length_words: u16) -> Self {
        let mut header = Self {
            validation_word: 0x3130_5341,
            version: 0,
            flags: 0,
            length_words,
            reserved: 0,
            checksum: 0,
        };

        let bytes = header.to_bytes();

        header.checksum = bytes[..10].iter().map(|&byte| u16::from(byte)).sum();

        header
    }

    /// Sets the header version byte.
    pub fn set_version(&mut self, version: u8) {
        self.version = version;
    }

    /// Sets the header flags byte.
    pub fn set_flags(&mut self, flags: u8) {
        self.flags = flags;
    }
}

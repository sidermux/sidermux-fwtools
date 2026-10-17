//! Cyclone V ROM header parsing and streamed integrity verification.
use serde::Serialize;
use sha2::{Digest, Sha256};
use sidermux_image::families::cyclone_v::Header;

use crate::{
    error::ImageError,
    inspect::BootRomInfo,
    kind::{Check, CheckStatus, CrcStatus},
    source::ImageSource,
};
const VALIDATION_WORD: u32 = 0x3130_5341;
const HEADER_OFFSET: u64 = Header::OFFSET as u64;
const HEADER_SIZE: u64 = Header::SIZE as u64;
const MIN_WINDOW: u64 = HEADER_OFFSET + HEADER_SIZE;
const CRC_SIZE: u64 = 4;
const BOOT_ENTRY_END: u64 = 0x50;
const ALIGN: u64 = 16;
const VERIFY_CHUNK: usize = 64 * 1024;

/// The first supported family's ROM header details as parsed from an image
/// window.
#[derive(Clone, Debug, Serialize)]
pub struct HeaderInfo {
    /// The validation word read from the header.
    pub validation_word: u32,
    /// Whether the validation word matches the family constant.
    pub validation_word_ok: bool,
    /// Header version byte.
    pub version: u8,
    /// Header flags byte.
    pub flags: u8,
    /// Declared payload length in 32-bit words.
    pub length_words: u16,
    /// Header checksum stored in the header.
    pub header_checksum: u16,
    /// Whether the stored checksum matches the computed byte sum.
    pub header_checksum_ok: bool,
}

struct BootRomLayout {
    /// Absolute offset of the image/slot start inside the source.
    base: u64,
    /// Bytes available at `base` (window size).
    window: u64,
    validation_word: u32,
    version: u8,
    flags: u8,
    length_words: u16,
    declared_len: usize,
    header_checksum: u16,
    header_checksum_ok: bool,
}

impl BootRomLayout {
    /// Reads and parses the 12-byte header window at `base`. Returns `None`
    /// when fewer than [`MIN_WINDOW`] bytes are available there.
    fn parse(
        src: &mut dyn ImageSource,
        base: u64,
        window: u64,
    ) -> Result<Option<Self>, ImageError> {
        if window < MIN_WINDOW {
            return Ok(None);
        }
        let header = src.read_vec_at(base + HEADER_OFFSET, HEADER_SIZE as usize)?;
        let stored_checksum = u16::from_le_bytes(header[10..12].try_into().expect("12 bytes read"));

        Ok(Some(Self {
            base,
            window,
            validation_word: u32::from_le_bytes(header[0..4].try_into().expect("12 bytes read")),
            version: header[4],
            flags: header[5],
            length_words: u16::from_le_bytes(header[6..8].try_into().expect("12 bytes read")),
            declared_len: usize::from(u16::from_le_bytes(
                header[6..8].try_into().expect("12 bytes read"),
            )) * 4,
            header_checksum: stored_checksum,
            header_checksum_ok: compute_header_checksum(&header) == Some(stored_checksum),
        }))
    }

    fn validation_word_ok(&self) -> bool {
        self.validation_word == VALIDATION_WORD
    }

    fn declared_len_ok(&self) -> bool {
        self.declared_len as u64 <= self.window
    }

    /// Offset of the CRC region relative to the window start.
    fn crc_offset(&self) -> Option<u64> {
        if self.declared_len >= CRC_SIZE as usize {
            Some(self.declared_len as u64 - CRC_SIZE)
        } else {
            None
        }
    }

    /// Converts the structural layout into report form, without reading any
    /// declared bytes.
    fn to_info(&self) -> BootRomInfo {
        BootRomInfo {
            checks: Vec::new(),
            declared_len: self.declared_len,
            declared_len_ok: self.declared_len_ok(),
            crc_offset: self.crc_offset(),
            crc32: None,
            crc_status: CrcStatus::NotChecked,
            payload_sha256: None,
            header: crate::inspect::HeaderDetails::CycloneV(HeaderInfo {
                validation_word: self.validation_word,
                validation_word_ok: self.validation_word_ok(),
                version: self.version,
                flags: self.flags,
                length_words: self.length_words,
                header_checksum: self.header_checksum,
                header_checksum_ok: self.header_checksum_ok,
            }),
        }
    }
}

fn compute_header_checksum(header: &[u8]) -> Option<u16> {
    // The checksum is the byte sum of the first ten header bytes (everything
    // before the checksum field itself), truncated to 16 bits.
    header
        .get(..10)
        .map(|head| head.iter().map(|&b| u16::from(b)).sum())
}

/// Streams the declared image through incremental CRC-32 and SHA-256, filling
/// the integrity fields of `info`. Reads exactly the declared range — never
/// the whole artifact.
fn verify_bootrom(src: &mut dyn ImageSource, layout: &BootRomLayout, info: &mut BootRomInfo) {
    // The CRC covers the declared image except its own 4 stored bytes; the
    // SHA-256 covers the full declared image.
    let Some(crc_offset) = layout.crc_offset() else {
        info.crc_status = CrcStatus::Unreadable;
        return;
    };
    if !layout.declared_len_ok() {
        info.crc_status = CrcStatus::Unreadable;
        return;
    }

    let crc_bytes = layout.declared_len as u64 - CRC_SIZE;
    let mut crc = sidermux_image::Crc32Bzip2::new();
    let mut sha = Sha256::new();
    let mut chunk = vec![0u8; VERIFY_CHUNK];
    let mut offset = 0u64;

    while offset < layout.declared_len as u64 {
        let remaining = layout.declared_len as u64 - offset;
        let n = chunk.len().min(remaining as usize);
        if src
            .read_exact_at(layout.base + offset, &mut chunk[..n])
            .is_err()
        {
            info.crc_status = CrcStatus::Unreadable;
            return;
        }
        sha.update(&chunk[..n]);
        let crc_part = n.min(crc_bytes.saturating_sub(offset) as usize);
        crc.update(&chunk[..crc_part]);
        offset += n as usize as u64;
    }

    info.payload_sha256 = Some(format!("{:x}", sha.finalize()));
    let stored = src
        .read_vec_at(layout.base + crc_offset, CRC_SIZE as usize)
        .ok()
        .map(|b| u32::from_le_bytes(b.try_into().expect("4 bytes read")));
    info.crc32 = stored;
    info.crc_status = match stored {
        Some(stored) if stored == crc.finalize() => CrcStatus::Passed,
        Some(_) => CrcStatus::Failed,
        None => CrcStatus::Unreadable,
    };
}

pub(crate) fn inspect_bootrom_in(
    src: &mut dyn ImageSource,
    base: u64,
    window: u64,
    verify: bool,
) -> Result<BootRomInfo, ImageError> {
    let layout = BootRomLayout::parse(src, base, window)?.ok_or(ImageError::TruncatedImage {
        needed: MIN_WINDOW as usize,
        actual: window as usize,
    })?;
    let mut info = layout.to_info();
    if verify {
        verify_bootrom(src, &layout, &mut info);
    }
    Ok(info)
}

/// The family's named checks for one parsed ROM image.
#[must_use]
pub fn bootrom_checks(info: &BootRomInfo) -> Vec<Check> {
    let header = info
        .header
        .as_cyclone_v()
        .expect("Cyclone V backend report");
    vec![
        Check::binary(
            "header version",
            header.version == 0,
            "Cyclone V requires ROM header version 0",
        ),
        Check::binary(
            "family image size",
            info.declared_len <= 0xF000,
            "declared image exceeds the Cyclone V boot limit",
        ),
        Check::binary(
            "validation word",
            header.validation_word_ok,
            format!(
                "expected 0x{VALIDATION_WORD:08X}, found 0x{:08X}",
                header.validation_word
            ),
        ),
        Check::binary(
            "header checksum",
            header.header_checksum_ok,
            format!(
                "stored 0x{:04X} does not match the computed sum of the header",
                header.header_checksum,
            ),
        ),
        Check::new(
            "declared length within window",
            if info.declared_len_ok {
                CheckStatus::Pass
            } else {
                CheckStatus::Fail
            },
            if info.declared_len_ok {
                format!("declared image is {} bytes", info.declared_len)
            } else {
                bootrom_truncation_detail(info)
            },
        ),
        match info.crc_offset {
            Some(offset) if offset >= BOOT_ENTRY_END => Check::new(
                "boot entry preserved",
                CheckStatus::Pass,
                format!(
                    "CRC sits at 0x{offset:X}, past the boot-entry instruction at 0x4C..0x{BOOT_ENTRY_END:X}"
                ),
            ),
            Some(offset) => Check::new(
                "boot entry preserved",
                CheckStatus::Fail,
                format!(
                    "CRC at 0x{offset:X}..0x{:X} overwrites the boot-entry instruction at 0x4C..0x{BOOT_ENTRY_END:X}",
                    offset + CRC_SIZE,
                ),
            ),
            None => Check::new(
                "boot entry preserved",
                CheckStatus::Fail,
                "declared image is too short to carry a CRC outside the protected region",
            ),
        },
        Check::new(
            "16-byte length alignment",
            if (info.declared_len as u64).is_multiple_of(ALIGN) {
                CheckStatus::Pass
            } else {
                CheckStatus::Warn
            },
            if (info.declared_len as u64).is_multiple_of(ALIGN) {
                format!("declared image is {} bytes", info.declared_len)
            } else {
                format!(
                    "declared image is {} bytes, not 16-byte aligned; still bootable if the CRC clears the boot entry, but off the packaging profile",
                    info.declared_len
                )
            },
        ),
        crc_check(info),
    ]
}

fn crc_check(info: &BootRomInfo) -> Check {
    match (info.crc32, info.crc_status) {
        (Some(stored), CrcStatus::Passed) => Check::new(
            "image CRC",
            CheckStatus::Pass,
            format!("stored 0x{stored:08X} matches the computed CRC32"),
        ),
        (Some(stored), CrcStatus::Failed) => Check::new(
            "image CRC",
            CheckStatus::Fail,
            format!(
                "stored 0x{stored:08X} does not match the CRC32 computed over the declared image"
            ),
        ),
        (_, CrcStatus::NotChecked) => Check::new(
            "image CRC",
            CheckStatus::Warn,
            "CRC not checked (integrity verification was skipped)",
        ),
        (_, CrcStatus::Unreadable) | (None, CrcStatus::Passed | CrcStatus::Failed) => Check::new(
            "image CRC",
            CheckStatus::Fail,
            "CRC region is not readable in the inspected window",
        ),
        (_, CrcStatus::NotApplicable) => Check::new(
            "image CRC",
            CheckStatus::Warn,
            "no boot-image CRC semantics for this data",
        ),
    }
}

fn bootrom_truncation_detail(info: &BootRomInfo) -> String {
    format!(
        "declared image is {} bytes (length_words {}), which does not fit the inspected window",
        info.declared_len,
        info.header.as_cyclone_v().unwrap().length_words,
    )
}

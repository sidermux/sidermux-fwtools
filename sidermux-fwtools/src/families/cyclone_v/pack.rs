use sidermux_image::families::cyclone_v::Header as PreloaderHeader;

use crate::error::ImageError;
const BOOT_OCRAM_MAX: u16 = 0xF000;

/// Boot-image contract for the raw (extracted) ELF payload:
///
/// | Range        | Required contents                |
/// | ------------ | -------------------------------- |
/// | `0x00..0x40` | Prefix (first-level entry code)  |
/// | `0x40..0x4C` | Boot ROM header                  |
/// | `0x4C..0x50` | Four-byte boot-entry instruction |
///
/// A payload smaller than this cannot satisfy the contract — padding could
/// not fabricate a valid entry instruction — so it is rejected rather than
/// padded.
pub(crate) const MIN_RAW_LEN: usize = 0x50;

/// Smallest completed image under the 16-byte-aligned packaging profile:
/// `align_up(MIN_RAW_LEN + 4, 16)`.
pub(crate) const MIN_PACKAGED_LEN: usize = 0x60;

const CRC_SIZE: usize = 4;
pub(crate) const ALIGN: usize = 16;

/// Encodes raw SPL bytes: writes the header into the reserved region, pads to
/// the 16-byte profile, and appends the CRC. The input must satisfy the raw
/// contract (prefix + reserved header region + boot-entry instruction).
pub(crate) fn pack_raw(preloader_bin: Vec<u8>) -> Result<Vec<u8>, ImageError> {
    if preloader_bin.len() < MIN_RAW_LEN {
        return Err(ImageError::InputTooShort {
            actual: preloader_bin.len(),
            needed: MIN_RAW_LEN,
        });
    }

    // Completed images are 16-byte aligned; the CRC occupies the last four
    // bytes of the aligned tail and covers everything before it, so it can
    // never reach back into the prefix, header, or boot-entry instruction.
    let final_len = encoded_length(preloader_bin.len())?;
    debug_assert!(final_len >= MIN_PACKAGED_LEN);

    let mut preloader_bin = preloader_bin;
    preloader_bin.resize(final_len, 0);

    let length_words = u16::try_from(final_len / 4).map_err(|_| ImageError::LengthOverflow)?;
    let header = PreloaderHeader::new(length_words);

    let start = PreloaderHeader::OFFSET;
    let end = start + PreloaderHeader::SIZE;
    preloader_bin[start..end].copy_from_slice(&header.to_bytes());

    let crc_offset = final_len - CRC_SIZE;
    let crc = sidermux_image::crc32_bzip2(&preloader_bin[..crc_offset]);
    preloader_bin[crc_offset..].copy_from_slice(&crc.to_le_bytes());

    tracing::debug!(
        image_len = final_len,
        length_words,
        header_offset = start,
        crc_offset,
        crc = format_args!("0x{crc:08X}"),
        "Packed preloader image",
    );

    Ok(preloader_bin)
}

/// Validate the completed size before allocating assembly or encoding buffers.
pub(crate) fn encoded_length(raw_len: usize) -> Result<usize, ImageError> {
    let final_len = raw_len
        .checked_add(CRC_SIZE)
        .and_then(|len| len.checked_add(ALIGN - 1))
        .map(|len| len & !(ALIGN - 1))
        .ok_or(ImageError::LengthOverflow)?;

    if final_len > usize::from(BOOT_OCRAM_MAX) {
        return Err(ImageError::ImageTooLarge {
            size: final_len,
            max: usize::from(BOOT_OCRAM_MAX),
        });
    }

    Ok(final_len)
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{BootImage, test_support::BOARD};

    /// Byte-exact fixture of a real vendor preloader header: validation word
    /// `AS01`, version 0, flags 0, length 0x2988 words, reserved 0, checksum
    /// 0x01A6. Taken from a production Cyclone V boot partition.
    const VENDOR_HEADER_FIXTURE: [u8; 12] = [
        0x41, 0x53, 0x30, 0x31, // validation word "AS01"
        0x00, // version
        0x00, // flags
        0x88, 0x29, // length in words (0x2988)
        0x00, 0x00, // reserved
        0xA6, 0x01, // header checksum (0x01A6)
    ];

    #[test]
    fn header_matches_vendor_fixture() {
        let header = PreloaderHeader::new(0x2988);
        assert_eq!(header.to_bytes(), VENDOR_HEADER_FIXTURE);
    }

    #[test]
    fn undersized_input_is_rejected() {
        // 0x20 bytes of payload cannot carry prefix + header + boot entry.
        let payload = [0x55u8; 0x20];
        let err = BootImage::from_raw_spl(BOARD, &payload).unwrap_err();
        assert!(matches!(
            err,
            ImageError::InputTooShort {
                actual: 0x20,
                needed: MIN_RAW_LEN
            }
        ));
    }

    #[test]
    fn minimum_input_yields_aligned_image_with_intact_entry() {
        let mut payload = vec![0u8; MIN_RAW_LEN];
        payload[..4].copy_from_slice(&[0xFE, 0xFF, 0xFF, 0xEA]); // prefix entry
        payload[0x4C..0x50].copy_from_slice(&[0xFE, 0xFF, 0xFF, 0xEA]); // boot entry
        let image =
            BootImage::from_elf(BOARD, &crate::test_support::elf_with_payload(&payload)[..])
                .unwrap();

        let bytes = image.as_bytes();
        // align_up(0x50 + 4, 16) = 0x60; the CRC lands at 0x5C..0x60, past
        // the boot-entry instruction at 0x4C..0x50.
        assert_eq!(bytes.len(), MIN_PACKAGED_LEN);
        assert_eq!(&bytes[..4], &[0xFE, 0xFF, 0xFF, 0xEA]);
        assert_eq!(&bytes[0x4C..0x50], &[0xFE, 0xFF, 0xFF, 0xEA]);
        assert!(bytes[0x50..0x5C].iter().all(|&b| b == 0));

        assert_integrity(bytes);
    }

    #[test]
    fn larger_images_are_aligned() {
        let mut payload = crate::test_support::spl_payload(0x300);
        // Filler everywhere except the protected regions: entry instructions
        // and the empty header reservation.
        payload[0x10..0x40].fill(0xA5);
        payload[0x50..].fill(0xA5);
        let image =
            BootImage::from_elf(BOARD, &crate::test_support::elf_with_payload(&payload)[..])
                .unwrap();

        let bytes = image.as_bytes();
        // align_up(0x300 + 4, 16) = 0x310.
        assert_eq!(bytes.len(), 0x310);
        // Payload is intact around the embedded header at 0x40..0x4C.
        assert_eq!(&bytes[..0x40], &payload[..0x40]);
        assert_eq!(&bytes[0x4C..0x300], &payload[0x4C..0x300]);
        // Alignment padding past the raw payload, before the CRC tail.
        assert!(bytes[0x300..0x30C].iter().all(|&b| b == 0));
        assert_integrity(bytes);
    }

    #[test]
    fn entry_opcodes_are_not_filtered() {
        for word in [0xE320_F000u32, 0, 0xE3A0_0000, 0xFFFF_FFFF] {
            let mut payload = vec![0u8; 0x60];
            payload[0x4C..0x50].copy_from_slice(&word.to_le_bytes());
            let elf = crate::test_support::elf_with_payload(&payload);
            let image = BootImage::from_elf(BOARD, &elf).unwrap();
            assert_eq!(&image.as_bytes()[0x4C..0x50], &word.to_le_bytes());
            assert_eq!(
                image.as_bytes(),
                BootImage::from_raw_spl(BOARD, &payload).unwrap().as_bytes()
            );
            assert_integrity(image.as_bytes());
        }
    }

    #[test]
    fn elf_wrapping_a_packaged_image_is_rejected_without_explicit_mode() {
        // A synthetic ELF whose payload is a complete packaged image.
        let packaged = packed_image(&spl_payload(0x100));
        let wrapped = crate::test_support::elf_with_payload(packaged.as_bytes());

        let err = BootImage::from_elf(BOARD, wrapped.as_slice()).unwrap_err();
        let ImageError::ElfContainsPackagedImage { declared_len, .. } = err else {
            panic!("expected ElfContainsPackagedImage, got {err:?}");
        };
        assert_eq!(declared_len, packaged.as_bytes().len());

        // Explicit packaged-payload mode adopts the declared bytes as-is.
        let adopted = BootImage::from_elf_packaged(BOARD, wrapped.as_slice()).unwrap();
        assert_eq!(adopted.as_bytes(), packaged.as_bytes());
    }

    #[test]
    fn adopt_preserves_declared_bytes_exactly() {
        let image = packed_image(&spl_payload(0x100));
        let adopted = BootImage::adopt_packaged(BOARD, image.as_bytes()).unwrap();
        assert_eq!(adopted.as_bytes(), image.as_bytes());
        // Wrapping an adopted image reproduces the same container bytes.
        assert_eq!(
            adopted.to_container().unwrap(),
            image.to_container().unwrap()
        );
    }

    #[test]
    fn adopt_rejects_unverified_input() {
        // All zeros with the right size: not a verified packaged image.
        assert!(matches!(
            BootImage::adopt_packaged(BOARD, &[0u8; 0x100]),
            Err(ImageError::NotVerifiedPackagedImage)
        ));
        // Raw SPL bytes (no header yet) are also not packaged input.
        assert!(matches!(
            BootImage::adopt_packaged(BOARD, &spl_payload(0x100)),
            Err(ImageError::NotVerifiedPackagedImage)
        ));
    }

    #[test]
    fn classify_payload_distinguishes_raw_from_packaged() {
        use crate::{PayloadKind, classify_payload};

        let image = packed_image(&spl_payload(0x100));
        assert_eq!(
            classify_payload(BOARD, image.as_bytes()),
            PayloadKind::PackagedRom
        );
        assert_eq!(
            classify_payload(BOARD, &spl_payload(0x100)),
            PayloadKind::Raw
        );

        // An arbitrary trailing word matching some CRC is not evidence.
        let mut junk = vec![0xDEu8; 0x100];
        junk[0xFC..0x100].copy_from_slice(&0xAB40_18B8u32.to_le_bytes());
        assert_eq!(classify_payload(BOARD, &junk), PayloadKind::Raw);
    }

    /// Packs a raw payload through the normal ELF path.
    fn packed_image(payload: &[u8]) -> BootImage {
        BootImage::from_elf(BOARD, &crate::test_support::elf_with_payload(payload)[..]).unwrap()
    }

    /// Raw SPL payload of `len` bytes (>= 0x50) with both entry branches.
    fn spl_payload(len: usize) -> Vec<u8> {
        crate::test_support::spl_payload(len)
    }

    /// Independent header/CRC verification shared by the packing tests.
    fn assert_integrity(bytes: &[u8]) {
        let header =
            &bytes[PreloaderHeader::OFFSET..PreloaderHeader::OFFSET + PreloaderHeader::SIZE];
        assert_eq!(&header[..4], b"AS01");

        let length_words = u16::from_le_bytes([header[6], header[7]]);
        assert_eq!(usize::from(length_words) * 4, bytes.len());

        let checksum = u16::from_le_bytes([header[10], header[11]]);
        assert_eq!(
            usize::from(checksum),
            header[..10].iter().map(|&b| usize::from(b)).sum::<usize>()
        );

        let stored_crc = u32::from_le_bytes(bytes[bytes.len() - 4..].try_into().unwrap());
        assert_eq!(
            sidermux_image::crc32_bzip2(&bytes[..bytes.len() - 4]),
            stored_crc,
        );
    }
}

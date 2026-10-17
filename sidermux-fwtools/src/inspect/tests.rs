use std::io;

use super::*;
use crate::test_support::BOARD;
const SLOT_SIZE: usize = 65536;
const MIN_WINDOW: u64 = 0x4C;
use crate::{BootImage, kind::CrcStatus};

/// Smallest payload that satisfies the packing contract (prefix + header +
/// boot-entry instruction), plus headroom.
fn min_payload() -> Vec<u8> {
    crate::test_support::spl_payload(0x60)
}

/// A minimal, structurally valid preloader image built by packing a tiny
/// hand-made payload through the normal pack path.
fn packed_image(payload: &[u8]) -> BootImage {
    BootImage::from_elf(BOARD, &crate::test_support::elf_with_payload(payload)[..]).unwrap()
}

/// Builds a boot image window with a given declared length: correct header
/// checksum, correct stored CRC, and a branch at the boot-entry slot. Used to
/// exercise CRC placement independently of what `pack` can produce.
fn hand_built_window(declared_len: usize) -> Vec<u8> {
    use sidermux_image::families::cyclone_v::Header as PreloaderHeader;

    let mut window = vec![0u8; declared_len];
    window[..4].copy_from_slice(&[0xFE, 0xFF, 0xFF, 0xEA]); // prefix entry
    if declared_len >= 0x50 {
        window[0x4C..0x50].copy_from_slice(&[0xFE, 0xFF, 0xFF, 0xEA]); // boot entry
    }

    let length_words = u16::try_from(declared_len / 4).unwrap();
    let mut header = PreloaderHeader::new(length_words).to_bytes();
    let checksum = header[..10].iter().map(|&b| u16::from(b)).sum::<u16>();
    header[10..12].copy_from_slice(&checksum.to_le_bytes());
    window[0x40..0x4C].copy_from_slice(&header);

    if declared_len >= 4 {
        let split = declared_len - 4;
        let crc = sidermux_image::crc32_bzip2(&window[..split]);
        window[split..].copy_from_slice(&crc.to_le_bytes());
    }
    window
}

#[test]
fn bootrom_parses_valid_image() {
    let payload = crate::test_support::spl_payload(0x200);
    let image = packed_image(&payload);
    let info = inspect_bootrom(BOARD, image.as_bytes()).unwrap();

    assert!(info.header.as_cyclone_v().unwrap().validation_word_ok);
    assert!(info.header.as_cyclone_v().unwrap().header_checksum_ok);
    assert_eq!(info.declared_len, image.as_bytes().len());
    assert_eq!(info.crc_status, CrcStatus::Passed);
    assert!(info.payload_sha256.is_some());
    assert_eq!(info.crc_offset, Some(image.as_bytes().len() as u64 - 4));
}

#[test]
fn bootrom_reports_corruption_instead_of_failing() {
    let payload = crate::test_support::spl_payload(0x80);
    let image = packed_image(&payload);
    let mut corrupted = image.as_bytes().to_vec();
    let mid = corrupted.len() / 2;
    corrupted[mid] ^= 0xFF;

    let info = inspect_bootrom(BOARD, &corrupted).unwrap();
    assert_eq!(info.crc_status, CrcStatus::Failed);
    // Readable metadata survives the corruption.
    assert_eq!(info.header.as_cyclone_v().unwrap().version, 0);
    assert_eq!(info.header.as_cyclone_v().unwrap().flags, 0);
    assert!(info.payload_sha256.is_some());

    // The check list reports the CRC failure instead of erroring out.
    let checks = bootrom_checks(&info);
    assert!(
        checks
            .iter()
            .any(|c| c.name == "image CRC" && c.status == CheckStatus::Fail)
    );
}

#[test]
fn bootrom_rejects_header_sized_windows_only() {
    assert!(matches!(
        inspect_bootrom(BOARD, &[0u8; MIN_WINDOW as usize - 1]),
        Err(ImageError::TruncatedImage { .. })
    ));
}

#[test]
fn crc_overlapping_boot_entry_is_flagged() {
    // A completed 0x50-byte image puts its CRC at 0x4C..0x50, overwriting the
    // boot-entry instruction — the failure mode of the pre-0x60 profile.
    let info = inspect_bootrom(BOARD, &hand_built_window(0x50)).unwrap();
    assert_eq!(info.crc_offset, Some(0x4C));
    assert_eq!(info.crc_status, CrcStatus::Passed); // the CRC itself is valid…

    let checks = bootrom_checks(&info);
    let entry = checks
        .iter()
        .find(|c| c.name == "boot entry preserved")
        .unwrap();
    assert_eq!(entry.status, CheckStatus::Fail);
    assert!(
        entry
            .detail
            .contains("overwrites the boot-entry instruction")
    );
}

#[test]
fn unaligned_but_bootable_image_warns() {
    // CRC at 0x50..0x54 clears the boot entry but is off the 16-byte profile.
    let info = inspect_bootrom(BOARD, &hand_built_window(0x54)).unwrap();
    assert_eq!(info.crc_offset, Some(0x50));

    let checks = bootrom_checks(&info);
    let entry = checks
        .iter()
        .find(|c| c.name == "boot entry preserved")
        .unwrap();
    assert_eq!(entry.status, CheckStatus::Pass);

    let align = checks
        .iter()
        .find(|c| c.name == "16-byte length alignment")
        .unwrap();
    assert_eq!(align.status, CheckStatus::Warn);
}

#[test]
fn aligned_packaged_image_passes_all_bootrom_checks() {
    let image = packed_image(&min_payload());
    let info = inspect_bootrom(BOARD, image.as_bytes()).unwrap();

    let checks = bootrom_checks(&info);
    let failed: Vec<_> = checks
        .iter()
        .filter(|c| c.status == CheckStatus::Fail)
        .collect();
    assert!(failed.is_empty(), "unexpected failed checks: {failed:?}");
    let warned: Vec<_> = checks
        .iter()
        .filter(|c| c.status == CheckStatus::Warn)
        .collect();
    assert!(warned.is_empty(), "unexpected warnings: {warned:?}");
}

#[test]
fn fast_mode_reports_not_checked() {
    let image = packed_image(&min_payload());
    let report = inspect_bytes(
        image.as_bytes(),
        &InspectOptions {
            board: None,
            verify: false,
            ..Default::default()
        },
    )
    .unwrap();

    let boot = report.bootrom.as_ref().unwrap();
    assert_eq!(boot.crc_status, CrcStatus::NotChecked);
    assert_eq!(boot.crc32, None);
    assert_eq!(boot.payload_sha256, None);

    let checks = bootrom_checks(boot);
    let crc = checks.iter().find(|c| c.name == "image CRC").unwrap();
    assert_eq!(crc.status, CheckStatus::Warn);
    assert!(crc.detail.contains("CRC not checked"));
}

#[test]
fn mkpimage_slots_are_identical_and_valid() {
    let payload = crate::test_support::spl_payload(0x300);
    let container = packed_image(&payload).to_container().unwrap();
    let info = inspect_container(BOARD, &container).unwrap();

    assert_eq!(info.slot_count, 4);
    assert_eq!(info.slot_size, SLOT_SIZE);
    assert_eq!(info.identical, Some(true));
    assert!(info.slots.iter().all(|s| s.crc_status == CrcStatus::Passed));
    assert!(
        info.slots
            .iter()
            .all(|s| s.header.as_cyclone_v().unwrap().validation_word_ok)
    );
}

#[test]
fn mkpimage_fast_mode_leaves_integrity_unchecked() {
    let container = packed_image(&crate::test_support::spl_payload(0x300))
        .to_container()
        .unwrap();
    let report = inspect_bytes(
        &container,
        &InspectOptions {
            board: None,
            kind: Some(ImageKind::Preloader),
            verify: false,
        },
    )
    .unwrap();

    let mkp = report.preloader.as_ref().unwrap();
    assert_eq!(mkp.identical, None);
    assert!(
        mkp.slots
            .iter()
            .all(|s| s.crc_status == CrcStatus::NotChecked)
    );

    let checks = container_checks(mkp);
    assert!(
        checks
            .iter()
            .any(|c| c.name == "slot CRCs" && c.status == CheckStatus::Warn)
    );
    assert!(
        checks
            .iter()
            .any(|c| c.name == "slots identical" && c.status == CheckStatus::Warn)
    );
}

#[test]
fn mkpimage_detects_differing_slots() {
    let payload = crate::test_support::spl_payload(0x300);
    let mut container = packed_image(&payload).to_container().unwrap();
    // Corrupt a byte inside slot 1's *declared* region (declared_len is
    // 0x310; bytes past it are CRC-exempt padding).
    container[SLOT_SIZE + 0x10] ^= 0xFF;

    let info = inspect_container(BOARD, &container).unwrap();
    assert_eq!(info.identical, Some(false));
    assert_eq!(info.slots[1].crc_status, CrcStatus::Failed);
    assert_eq!(info.slots[0].crc_status, CrcStatus::Passed);
}

#[test]
fn mkpimage_rejects_non_multiple_sizes() {
    assert!(matches!(
        inspect_container(BOARD, &vec![0u8; SLOT_SIZE + 4]),
        Err(ImageError::InvalidSlotSize { .. })
    ));
}

#[test]
fn sd_image_round_trip() {
    let payload = crate::test_support::spl_payload(0x400);
    let image = packed_image(&payload).to_sd_image().unwrap();
    let info = inspect_sd(BOARD, &image).unwrap();

    assert!(info.signature_ok);
    let a2 = info.boot_partition.expect("A2 partition must be found");
    assert_eq!(a2.start_lba, BOARD.storage.start_lba);
    assert_eq!(a2.sectors, BOARD.storage.partition_sectors);
    assert!(a2.within_file);

    let container = a2.container.expect("container must be found");
    assert_eq!(container.slot_count, 4);
    assert_eq!(container.identical, Some(true));
    assert!(
        container
            .slots
            .iter()
            .all(|s| s.crc_status == CrcStatus::Passed)
    );
}

#[test]
fn sd_image_reports_missing_boot_partition_as_check() {
    // Build a valid-looking MBR with only a FAT partition and no A2 entry.
    let mut raw = vec![0u8; 512];
    raw[510..512].copy_from_slice(&[0x55, 0xAA]);
    raw[0x1BE + 4] = 0x0B; // FAT32
    raw[0x1BE + 8..0x1BE + 12].copy_from_slice(&2048u32.to_le_bytes());
    raw[0x1BE + 12..0x1BE + 16].copy_from_slice(&1024u32.to_le_bytes());

    let info = inspect_sd(BOARD, &raw).unwrap();
    assert!(info.boot_partition.is_none());
    let checks = sd_checks(&info);
    assert!(
        checks
            .iter()
            .any(|c| c.name == "boot partition" && c.status == CheckStatus::Fail)
    );
}

#[test]
fn elf_report_carries_packaging_metadata() {
    let elf_bytes = crate::test_support::elf_with_payload(&min_payload());
    let info = inspect_elf(&elf_bytes).unwrap();

    assert_eq!(info.machine, elf::abi::EM_ARM);
    assert_eq!(info.class, "ELF32");
    assert_eq!(info.endian, "little");
    assert_eq!(info.segments.len(), 1);
    assert_eq!(info.segments[0].paddr, 0xFFFF_0000);
    assert_eq!(info.segments[0].vaddr, info.segments[0].paddr);
}

#[test]
fn detection_is_ambiguous_for_a_single_slot() {
    let slot = packed_image(&min_payload()).slot_bytes().unwrap();
    let kinds: Vec<ImageKind> = detect_kind(&slot).iter().map(|c| c.kind).collect();
    assert!(kinds.contains(&ImageKind::BootRom));
    assert!(kinds.contains(&ImageKind::Preloader));

    assert!(matches!(
        inspect_bytes(&slot, &InspectOptions::default()),
        Err(ImageError::AmbiguousImageFormat { .. })
    ));
}

#[test]
fn detection_resolves_sd_and_bootrom_unambiguously() {
    let sd = packed_image(&min_payload()).to_sd_image().unwrap();
    let kinds: Vec<ImageKind> = detect_kind(&sd).iter().map(|c| c.kind).collect();
    assert_eq!(kinds, vec![ImageKind::SdImage]);

    let bootrom = packed_image(&min_payload()).as_bytes().to_vec();
    let kinds: Vec<ImageKind> = detect_kind(&bootrom).iter().map(|c| c.kind).collect();
    // The packed image is 0x70 bytes: not a slot multiple, so only bootrom.
    assert_eq!(kinds, vec![ImageKind::BootRom]);
}

#[test]
fn detection_rejects_unknown_data() {
    assert!(detect_kind(&vec![0xDE; 4096]).is_empty());
    assert!(matches!(
        inspect_bytes(&vec![0xDE; 4096], &InspectOptions::default()),
        Err(ImageError::UnknownImageFormat)
    ));
}

#[test]
fn override_kind_inspects_without_detection() {
    let slot = packed_image(&min_payload()).slot_bytes().unwrap();
    let report = inspect_bytes(
        &slot,
        &InspectOptions {
            board: None,
            kind: Some(ImageKind::BootRom),
            verify: true,
        },
    )
    .unwrap();
    assert_eq!(report.input.kind, ImageKind::BootRom);
    assert_eq!(report.input.detected_by, DetectionSource::Override);
    assert!(report.bootrom.is_some());
}

#[test]
fn sd_checks_pass_for_generated_image() {
    let image = packed_image(&min_payload()).to_sd_image().unwrap();
    let report = inspect_bytes(
        &image,
        &InspectOptions {
            board: None,
            kind: Some(ImageKind::SdImage),
            verify: true,
        },
    )
    .unwrap();
    let failed: Vec<_> = report
        .checks
        .iter()
        .filter(|c| c.status == CheckStatus::Fail)
        .collect();
    assert!(failed.is_empty(), "unexpected failed checks: {failed:?}");
    assert_eq!(report.schema, 3);
}

// --- Read accounting --------------------------------------------------------
//
// A counting source proves the seek-based paths never load whole artifacts:
// structural SD inspection must read a few hundred bytes, and the integrity
// pass must stay bounded by the container (256 KiB), not the disk.

struct Counting<S> {
    inner: S,
    reads: std::cell::Cell<u64>,
    bytes: std::cell::Cell<u64>,
}

impl<S: ImageSource> ImageSource for Counting<S> {
    fn len(&self) -> io::Result<u64> {
        self.inner.len()
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        self.reads.set(self.reads.get() + 1);
        let n = self.inner.read_at(offset, buf)?;
        self.bytes.set(self.bytes.get() + n as u64);
        Ok(n)
    }
}

/// Builds a sparse 11 MiB SD image in a temporary file: MBR + a valid
/// four-slot container at LBA 2048, the rest untouched (holes).
/// Temporary file handle that removes the file on drop.
struct TempFile(std::path::PathBuf);
impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Builds a sparse 11 MiB SD image in a temporary file: MBR + a valid
/// four-slot container at LBA 2048, the rest untouched (holes).
fn sparse_sd_file() -> (TempFile, Vec<u8>) {
    use std::{
        io::Write as _,
        sync::atomic::{AtomicU32, Ordering},
    };

    static SEQ: AtomicU32 = AtomicU32::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);

    let image = packed_image(&min_payload()).to_sd_image().unwrap();
    let path = std::env::temp_dir().join(format!("cvgx-sd-{}-{n}-test.img", std::process::id()));
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&path)
        .expect("create temp sd image");
    // Write only the meaningful prefix: MBR + container (1 MiB + 256 KiB).
    let used = 1024 * 1024 + 256 * 1024;
    file.write_all(&image[..used]).expect("write sd image");
    file.set_len(image.len() as u64).expect("make sparse");
    (TempFile(path), image)
}

#[test]
fn structural_sd_inspection_reads_bounded_ranges() {
    use crate::source::FileSource;

    let (file, image) = sparse_sd_file();
    let handle = std::fs::File::open(&file.0).unwrap();
    let mut counting = Counting {
        inner: FileSource(handle),
        reads: std::cell::Cell::new(0),
        bytes: std::cell::Cell::new(0),
    };

    let report = inspect_source(
        &mut counting,
        &InspectOptions {
            board: None,
            kind: Some(ImageKind::SdImage),
            verify: false,
        },
    )
    .unwrap();
    assert!(report.sd.as_ref().unwrap().signature_ok);

    // Structural mode: MBR + slot header windows + blank probes.
    let read = counting.bytes.get();
    assert!(read < 8 * 1024, "structural mode read {read} bytes");
    assert!(
        (read as usize) < image.len(),
        "structural mode must not read the whole disk"
    );
}

#[test]
fn integrity_sd_inspection_stays_bounded_by_container() {
    use crate::source::FileSource;

    let (file, image) = sparse_sd_file();
    let handle = std::fs::File::open(&file.0).unwrap();
    let mut counting = Counting {
        inner: FileSource(handle),
        reads: std::cell::Cell::new(0),
        bytes: std::cell::Cell::new(0),
    };

    let report = inspect_source(
        &mut counting,
        &InspectOptions {
            board: None,
            kind: Some(ImageKind::SdImage),
            verify: true,
        },
    )
    .unwrap();
    let container = report.sd.as_ref().unwrap().boot_partition.as_ref().unwrap();
    assert_eq!(container.container.as_ref().unwrap().identical, Some(true));

    // Integrity mode reads the declared image ranges (≤ 256 KiB), far less
    // than the 11 MiB disk.
    let read = counting.bytes.get();
    assert!(read <= 512 * 1024, "integrity mode read {read} bytes");
    assert!(
        read < image.len() as u64 / 4,
        "integrity mode must not read the whole disk"
    );
}

#[test]
fn file_and_memory_inspection_agree() {
    let (file, image) = sparse_sd_file();
    let path = file.0.clone();
    let from_file = inspect_file(&path, &InspectOptions::default()).unwrap();
    let from_memory = inspect_bytes(&image, &InspectOptions::default()).unwrap();

    // Debug-string equality: the two paths must produce identical reports.
    assert_eq!(format!("{from_file:?}"), format!("{from_memory:?}"));
}

#[test]
fn explicit_kind_can_inspect_a_damaged_signature_with_one_backend() {
    let image = packed_image(&min_payload());
    let mut bytes = image.into_bytes();
    bytes[0x40] ^= 0xFF;
    let report = inspect_bytes(
        &bytes,
        &InspectOptions {
            board: None,
            kind: Some(ImageKind::BootRom),
            verify: true,
        },
    )
    .unwrap();
    assert!(
        report
            .checks
            .iter()
            .any(|check| check.name == "validation word" && check.status == CheckStatus::Fail)
    );
    assert_eq!(report.board, None);
}

#[test]
fn sd_container_scan_stops_before_later_stage_data() {
    let image = packed_image(&min_payload());
    let mut disk = image.to_sd_image().unwrap();
    let after_container =
        BOARD.storage.start_lba as usize * 512 + BOARD.storage.slot_size * BOARD.storage.slot_count;
    disk[after_container..after_container + BOARD.storage.slot_size].fill(0xA5);
    let report = inspect_bytes(&disk, &InspectOptions::default()).unwrap();
    let container = report
        .sd
        .unwrap()
        .boot_partition
        .unwrap()
        .container
        .unwrap();
    assert_eq!(container.slot_count, BOARD.storage.slot_count);
}

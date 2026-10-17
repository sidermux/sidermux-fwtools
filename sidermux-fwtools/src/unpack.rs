//! Extraction of packaged images into plain files.
//!
//! Unpacking shares the inspect parsing layer: the input is detected and
//! parsed into layouts, and only the selected byte ranges (the declared
//! images, the MBR) are read and written. Because each written buffer is
//! already in memory, the CRC is verified at zero extra I/O cost — extraction
//! itself proceeds even when checks fail.

use std::path::Path;

use serde::Serialize;

use crate::{
    board::BoardProfile,
    error::ImageError,
    inspect,
    inspect::Context,
    kind::{Check, CrcStatus, ImageKind},
    source::{FileSource, ImageSource},
};

/// What to extract when the input kind is ambiguous. `None` detects.
#[derive(Clone, Debug, Default)]
pub struct UnpackOptions {
    /// Selects the family backend and storage policy explicitly; `None`
    /// auto-detects and reports ambiguity instead of guessing.
    pub board: Option<&'static BoardProfile>,
    /// Skip detection and force a specific kind.
    pub kind: Option<ImageKind>,
}

/// One file written by [`unpack_image`].
#[derive(Clone, Debug, Serialize)]
pub struct UnpackedFile {
    /// File name relative to the output directory.
    pub name: String,
    /// Range of the source artifact the bytes came from.
    pub source_offset: u64,
    /// Written byte count.
    pub size: usize,
    /// Integrity status of the extracted declared image.
    pub crc_status: CrcStatus,
}

/// Result of an [`unpack_image`] run.
#[derive(Clone, Debug, Serialize)]
pub struct UnpackReport {
    /// The resolved input kind.
    pub kind: ImageKind,
    /// Absolute path of the output directory.
    pub output_dir: String,
    /// Files written, in write order.
    pub files: Vec<UnpackedFile>,
    /// Validation results for the extracted content.
    pub checks: Vec<Check>,
}

/// Unpacks a packaged image into `out_dir`.
///
/// - `bootrom` input → `bootrom.bin` (the declared image)
/// - `preloader` input → `slot0.bin`..`slotN.bin` (declared image per non-blank slot)
/// - `sd` input → `mbr.bin` plus the container slots
/// - `elf` input → [`ImageError::UnpackElfInput`]
pub fn unpack_image(
    input: impl AsRef<Path>,
    out_dir: impl AsRef<Path>,
    options: &UnpackOptions,
) -> Result<UnpackReport, ImageError> {
    let file = std::fs::File::open(input.as_ref())?;
    let mut src = FileSource(file);
    let size = src.len()?;

    let (context, kind, _) = inspect::resolve(
        &mut src,
        &inspect::InspectOptions {
            board: options.board,
            kind: options.kind,
            verify: true,
        },
    )?;
    if kind == ImageKind::Elf {
        return Err(ImageError::UnpackElfInput);
    }

    let ctx = context.ok_or(ImageError::NoBackend)?;
    let out_dir = out_dir.as_ref();
    std::fs::create_dir_all(out_dir)?;

    let mut report = UnpackReport {
        kind,
        output_dir: out_dir.display().to_string(),
        files: Vec::new(),
        checks: Vec::new(),
    };

    match kind {
        ImageKind::Elf => unreachable!("rejected above"),
        ImageKind::BootRom => {
            let info = inspect::inspect_bootrom_in(ctx, &mut src, 0, size, true)?;
            report.checks = inspect::bootrom_checks(&info);
            extract_window(
                ctx,
                &mut src,
                out_dir,
                "bootrom.bin",
                0,
                info.declared_len,
                &mut report,
            )?;
        }
        ImageKind::Preloader => {
            if size == 0 || !size.is_multiple_of(ctx.storage.slot_size as u64) {
                return Err(ImageError::InvalidSlotSize {
                    size: size as usize,
                    slot_size: ctx.storage.slot_size,
                });
            }
            let slot_count = size as usize / ctx.storage.slot_size;
            let mut checks = Vec::new();
            for i in 0..slot_count {
                let base = i as u64 * ctx.storage.slot_size as u64;
                if probe_blank(ctx, &mut src, base) {
                    continue;
                }
                let info = inspect::inspect_bootrom_in(
                    ctx,
                    &mut src,
                    base,
                    ctx.storage.slot_size as u64,
                    true,
                )?;
                if i == 0 {
                    checks = inspect::bootrom_checks(&info);
                }
                let name = format!("slot{i}.bin");
                extract_window(
                    ctx,
                    &mut src,
                    out_dir,
                    &name,
                    base,
                    info.declared_len,
                    &mut report,
                )?;
            }
            report.checks = checks;
        }
        ImageKind::SdImage => {
            let sd = inspect::parse_sd_in(ctx, &mut src, size, true)?;
            report.checks = inspect::sd_checks(&sd);
            let mut mbr = UnpackedFile {
                name: "mbr.bin".to_string(),
                source_offset: 0,
                size: 512,
                crc_status: CrcStatus::NotApplicable,
            };
            let bytes = src.read_vec_at(0, 512)?;
            std::fs::write(out_dir.join("mbr.bin"), &bytes)?;
            mbr.size = bytes.len();
            report.files.push(mbr);

            if let Some(a2) = sd.boot_partition.as_ref().filter(|a2| a2.within_file) {
                unpack_sd_container(ctx, &mut src, out_dir, a2, &mut report)?;
            }
        }
    }

    Ok(report)
}

/// Reads the declared image at `base` and writes it to `out_dir/name`.
/// The CRC is computed from the bytes already in hand — no extra I/O.
fn extract_window(
    ctx: Context,
    src: &mut dyn ImageSource,
    out_dir: &Path,
    name: &str,
    base: u64,
    declared_len: usize,
    report: &mut UnpackReport,
) -> Result<(), ImageError> {
    let bytes = src.read_vec_at(base, declared_len)?;
    let crc_status = crc_status_of(ctx, &bytes);

    let path = out_dir.join(name);
    std::fs::write(&path, &bytes)?;

    report.files.push(UnpackedFile {
        name: name.to_string(),
        source_offset: base,
        size: bytes.len(),
        crc_status,
    });
    Ok(())
}

/// CRC status of a declared image held in memory.
pub(crate) fn crc_status_of(ctx: Context, declared: &[u8]) -> CrcStatus {
    ctx.backend
        .inspect(
            &mut crate::source::BytesSource(declared),
            0,
            declared.len() as u64,
            true,
        )
        .map_or(CrcStatus::Unreadable, |info| info.crc_status)
}

/// Probe-reads the first bytes of a slot to decide whether it is blank.
fn probe_blank(ctx: Context, src: &mut dyn ImageSource, base: u64) -> bool {
    src.read_vec_at(base, ctx.backend.probe_len())
        .map_or(true, |probe| probe.iter().all(|&b| b == 0))
}

/// Writes the declared image of every non-blank container slot.
fn unpack_sd_container(
    ctx: Context,
    src: &mut dyn ImageSource,
    out_dir: &Path,
    a2: &crate::inspect::BootPartitionInfo,
    report: &mut UnpackReport,
) -> Result<(), ImageError> {
    let Some(container) = &a2.container else {
        return Ok(());
    };
    let base = u64::from(a2.start_lba) * 512;
    for (i, slot) in container.slots.iter().enumerate() {
        let slot_base = base + i as u64 * ctx.storage.slot_size as u64;
        if probe_blank(ctx, src, slot_base) {
            continue;
        }
        let name = format!("slot{i}.bin");
        extract_window(
            ctx,
            src,
            out_dir,
            &name,
            slot_base,
            slot.declared_len,
            report,
        )?;
    }
    Ok(())
}

#[cfg(all(test, feature = "cyclone-v"))]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::{BootImage, kind::CheckStatus, test_support::BOARD};

    fn packed_sd() -> Vec<u8> {
        let payload = crate::test_support::spl_payload(0x400);
        BootImage::from_elf(BOARD, &crate::test_support::elf_with_payload(&payload)[..])
            .unwrap()
            .to_sd_image()
            .unwrap()
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("cvgx-unpack-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn unpack_round_trips_sd_image() {
        let sd = packed_sd();
        let input = temp_dir("in");
        std::fs::create_dir_all(&input).unwrap();
        let input_path = input.join("system.sd.img");
        std::fs::write(&input_path, &sd).unwrap();

        let out = temp_dir("out");
        let report = unpack_image(&input_path, &out, &UnpackOptions::default()).unwrap();

        assert_eq!(report.kind, ImageKind::SdImage);
        let names: Vec<_> = report.files.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "mbr.bin",
                "slot0.bin",
                "slot1.bin",
                "slot2.bin",
                "slot3.bin"
            ]
        );
        // The MBR has no boot-image CRC semantics; every declared image
        // verifies.
        assert_eq!(report.files[0].crc_status, CrcStatus::NotApplicable);
        assert!(
            report
                .files
                .iter()
                .skip(1)
                .all(|f| f.crc_status == CrcStatus::Passed)
        );

        // The unpacked boot ROM must re-inspect exactly like the original
        // container's slot 0.
        let bootrom = std::fs::read(out.join("slot0.bin")).unwrap();
        let original = BootImage::from_elf(
            BOARD,
            &crate::test_support::elf_with_payload(&crate::test_support::spl_payload(0x400))[..],
        )
        .unwrap();
        assert_eq!(bootrom, original.as_bytes());

        let _ = std::fs::remove_dir_all(&input);
        let _ = std::fs::remove_dir_all(&out);
    }

    #[test]
    fn unpack_writes_corrupt_slots_and_reports_failure() {
        let mut sd = packed_sd();
        // Corrupt slot 0's declared region (container at 1 MiB).
        sd[1024 * 1024 + 0x10] ^= 0xFF;

        let input = temp_dir("in2");
        std::fs::create_dir_all(&input).unwrap();
        let input_path = input.join("broken.sd.img");
        std::fs::write(&input_path, &sd).unwrap();

        let out = temp_dir("out2");
        let report = unpack_image(&input_path, &out, &UnpackOptions::default()).unwrap();

        // Extraction still happened; the failing CRC is reported.
        let slot0 = report.files.iter().find(|f| f.name == "slot0.bin").unwrap();
        assert_eq!(slot0.crc_status, CrcStatus::Failed);
        // Declared image for the 0x400-byte payload: align_up(0x404, 16) = 0x410.
        assert_eq!(
            std::fs::metadata(out.join("slot0.bin")).unwrap().len() as usize,
            0x410
        );

        assert!(
            report
                .checks
                .iter()
                .any(|c| c.name == "container CRCs" && c.status == CheckStatus::Fail)
        );

        let _ = std::fs::remove_dir_all(&input);
        let _ = std::fs::remove_dir_all(&out);
    }

    #[test]
    fn unpack_rejects_elf_input() {
        let elf = crate::test_support::elf_with_payload(&crate::test_support::spl_payload(0x60));
        let dir = temp_dir("in3");
        std::fs::create_dir_all(&dir).unwrap();
        let input = dir.join("app.elf");
        std::fs::write(&input, &elf).unwrap();

        let out = temp_dir("out3");
        let err = unpack_image(&input, &out, &UnpackOptions::default()).unwrap_err();
        assert!(matches!(err, ImageError::UnpackElfInput));

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&out);
    }

    #[test]
    fn unpack_reports_ambiguity_for_single_slot() {
        let slot = BootImage::from_elf(
            BOARD,
            &crate::test_support::elf_with_payload(&crate::test_support::spl_payload(0x60))[..],
        )
        .unwrap()
        .slot_bytes()
        .unwrap();

        let dir = temp_dir("in4");
        std::fs::create_dir_all(&dir).unwrap();
        let input = dir.join("slot.bin");
        std::fs::write(&input, &slot).unwrap();

        let out = temp_dir("out4");
        let err = unpack_image(&input, &out, &UnpackOptions::default()).unwrap_err();
        assert!(matches!(err, ImageError::AmbiguousImageFormat { .. }));

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&out);
    }
}

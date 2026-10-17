//! Inspection of packaged boot images: detection, parsing, reports, and
//! integrity checks.
//!
//! Inputs are resolved to an envelope (`elf`, `bootrom`, `preloader`, `sd`)
//! and a family independently of board identity. Reports use schema 3, with
//! common source/check and container/partition data plus a typed, tagged
//! [`HeaderDetails`] variant for family-specific metadata. Verification
//! streams only declared bytes; corrupt readable metadata is reported through
//! failed [`Check`]s instead of being discarded.
use std::path::Path;

use serde::Serialize;

use crate::{
    backend::{FamilyBackend, families},
    board::{BoardProfile, StorageLayout},
    error::ImageError,
    kind::{Check, CheckStatus, CrcStatus, DetectionCandidate, DetectionSource, ImageKind},
    source::{BytesSource, FileSource, ImageSource},
};

const MBR_LEN: u64 = 512;
const MBR_PARTITION_TABLE: u64 = 0x1BE;
const VERIFY_CHUNK: usize = 64 * 1024;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Context {
    pub backend: &'static dyn FamilyBackend,
    pub storage: StorageLayout,
}
impl Context {
    pub fn board(board: &BoardProfile) -> Self {
        Self {
            backend: board.backend,
            storage: board.storage,
        }
    }
}

// ---------------------------------------------------------------------------
// Report types
// ---------------------------------------------------------------------------

/// ELF file metadata relevant to packaging.
#[derive(Clone, Debug, Serialize)]
pub struct ElfInfo {
    /// Raw `e_machine` value.
    pub machine: u16,
    /// Human-readable machine name from the ELF registry (e.g. `"EM_ARM"`).
    pub machine_name: String,
    /// ELF entry point address. Informational only: families define their own
    /// ROM entry contract.
    pub entry: u64,
    /// `"ELF32"` or `"ELF64"`.
    pub class: String,
    /// `"little"` or `"big"`.
    pub endian: String,
    /// Loadable (`PT_LOAD`) segments only.
    pub segments: Vec<ElfSegmentInfo>,
}

/// One loadable ELF segment.
#[derive(Clone, Debug, Serialize)]
pub struct ElfSegmentInfo {
    /// Segment type (`PT_LOAD`).
    pub p_type: u32,
    /// Segment flags (`PF_X`, `PF_W`, `PF_R`).
    pub flags: u32,
    /// Offset within the ELF file.
    pub offset: u64,
    /// Physical load address.
    pub paddr: u64,
    /// Virtual address.
    pub vaddr: u64,
    /// File-backed size in bytes.
    pub filesz: u64,
    /// Size in memory; may exceed `filesz` (BSS).
    pub memsz: u64,
}

/// Parsed Boot ROM header plus integrity status of one declared image
/// (standalone, one container slot, or one SD container slot).
///
/// Header details are supplied by the selected family backend.
/// Integrity fields ([`BootRomInfo::crc32`], [`BootRomInfo::crc_status`],
/// [`BootRomInfo::payload_sha256`]) are only filled when verification was
/// requested; otherwise the CRC is reported as not checked.
#[derive(Clone, Debug, Serialize)]
pub struct BootRomInfo {
    /// Family-specific header details.
    pub header: HeaderDetails,
    /// The family's named checks for this image.
    pub checks: Vec<Check>,
    /// Declared image length in bytes, as decoded by the family backend.
    pub declared_len: usize,
    /// Declared length lies fully within the inspected window.
    pub declared_len_ok: bool,
    /// Offset of the CRC region relative to the start of the image window.
    /// `None` when the declared image is too short to carry a CRC.
    pub crc_offset: Option<u64>,
    /// CRC32 (bzip2 flavour) stored in the image; read during verification.
    pub crc32: Option<u32>,
    pub crc_status: CrcStatus,
    /// SHA-256 over the declared image; only computed with verification.
    pub payload_sha256: Option<String>,
}

/// Header metadata belongs to its family. Add a variant when registering a new codec.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "family", content = "fields", rename_all = "kebab-case")]
#[non_exhaustive]
pub enum HeaderDetails {
    /// ROM header details of the first supported family.
    #[cfg(feature = "cyclone-v")]
    CycloneV(crate::families::cyclone_v::rom::HeaderInfo),
    #[cfg(test)]
    Test { tag: u32 },
}
impl HeaderDetails {
    /// Returns the header details when they belong to the first supported
    /// family.
    #[cfg(feature = "cyclone-v")]
    pub fn as_cyclone_v(&self) -> Option<&crate::families::cyclone_v::rom::HeaderInfo> {
        match self {
            Self::CycloneV(header) => Some(header),
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }
}

/// A vendor-compatible (mkpimage-style) container using the selected slot geometry.
#[derive(Clone, Debug, Serialize)]
pub struct ContainerInfo {
    /// Size of one boot slot in bytes.
    pub slot_size: usize,
    /// Number of slots parsed.
    pub slot_count: usize,
    /// `Some(true)` when every slot holds byte-identical content; `None` when
    /// integrity verification was not requested.
    pub identical: Option<bool>,
    /// One parsed report per slot, in slot order.
    pub slots: Vec<BootRomInfo>,
}

/// One MBR partition table entry.
#[derive(Clone, Debug, Serialize)]
pub struct PartitionInfo {
    /// Entry position in the table (0–3).
    pub index: usize,
    /// Boot flag set (`0x80`).
    pub bootable: bool,
    /// Partition type byte.
    pub partition_type: u8,
    /// First LBA of the partition.
    pub start_lba: u32,
    /// Partition length in 512-byte sectors.
    pub sectors: u32,
}

/// The boot partition of an SD image, matched by the profile's storage
/// policy.
#[derive(Clone, Debug, Serialize)]
pub struct BootPartitionInfo {
    /// First LBA of the partition.
    pub start_lba: u32,
    /// Partition length in 512-byte sectors.
    pub sectors: u32,
    /// The declared partition extent fits inside the inspected file.
    pub within_file: bool,
    /// Preloader container found at the partition start (the leading run of
    /// non-blank profile-sized slots).
    pub container: Option<ContainerInfo>,
}

/// Structural parse of an SD-card disk image.
#[derive(Clone, Debug, Serialize)]
pub struct SdImageInfo {
    /// The partition type the selected profile matches.
    pub boot_partition_type: u8,
    /// MBR boot signature (`0x55AA`) present at offset 510.
    pub signature_ok: bool,
    /// All non-empty MBR partition entries.
    pub partitions: Vec<PartitionInfo>,
    /// The profile's boot partition, when present.
    pub boot_partition: Option<BootPartitionInfo>,
}

/// Options for an inspection run.
#[derive(Clone, Debug)]
pub struct InspectOptions {
    /// Constrains the family backend and storage policy; `None` probes every
    /// compiled backend and reports ambiguity instead of guessing.
    pub board: Option<&'static BoardProfile>,
    /// Skip detection and force a specific kind.
    pub kind: Option<ImageKind>,
    /// Run the integrity pass: read the declared image bytes and verify the
    /// CRC (and compute the SHA-256). Verification is bounded by the
    /// container size, never by the size of an SD image.
    pub verify: bool,
}

impl Default for InspectOptions {
    fn default() -> Self {
        Self {
            board: None,
            kind: None,
            verify: true,
        }
    }
}

/// A successfully inspected input.
#[derive(Clone, Debug, Serialize)]
pub struct InspectReport {
    /// Report schema version (currently 3).
    pub schema: u32,
    /// Family identifier, when a family backend matched.
    pub family: Option<&'static str>,
    /// Boot image format identifier, when a family backend matched.
    pub format: Option<&'static str>,
    /// Explicitly selected board. Auto-detected reports leave this unset: a
    /// shared ROM signature cannot identify a physical board.
    pub board: Option<&'static str>,
    /// Input provenance and the resolved kind.
    pub input: InputInfo,
    /// ELF metadata, for `elf` inputs.
    pub elf: Option<ElfInfo>,
    /// ROM image report, for `bootrom` inputs.
    pub bootrom: Option<BootRomInfo>,
    /// Container report, for `preloader` inputs.
    pub preloader: Option<ContainerInfo>,
    /// Disk image report, for `sd` inputs.
    pub sd: Option<SdImageInfo>,
    /// Top-level validation results.
    pub checks: Vec<Check>,
}

/// Provenance and detection result for the inspected input.
#[derive(Clone, Debug, Serialize)]
pub struct InputInfo {
    /// Set by the caller when the file name is known.
    pub path: Option<String>,
    /// Input size in bytes.
    pub size: u64,
    /// The resolved image kind.
    pub kind: ImageKind,
    /// How the kind was determined.
    pub detected_by: DetectionSource,
}

// ---------------------------------------------------------------------------
// Structural layout parsing
// ---------------------------------------------------------------------------

pub(crate) fn inspect_bootrom_in(
    ctx: Context,
    src: &mut dyn ImageSource,
    base: u64,
    window: u64,
    verify: bool,
) -> Result<BootRomInfo, ImageError> {
    let mut info = ctx.backend.inspect(src, base, window, verify)?;
    info.checks = ctx.backend.checks(&info);
    Ok(info)
}
/// Parses `raw` as one declared ROM image using `board`'s family backend,
/// with integrity verification always enabled.
pub fn inspect_bootrom(board: &BoardProfile, raw: &[u8]) -> Result<BootRomInfo, ImageError> {
    inspect_bootrom_in(
        Context::board(board),
        &mut BytesSource(raw),
        0,
        raw.len() as u64,
        true,
    )
}
pub(crate) fn bootrom_checks(info: &BootRomInfo) -> Vec<Check> {
    info.checks.clone()
}

// ---------------------------------------------------------------------------
// MKPImage container parsing
// ---------------------------------------------------------------------------

/// Parses a vendor-compatible container of `slot_count` profile-sized slots starting
/// at `base`. Every slot is parsed structurally; integrity runs only when
/// `verify` is set.
fn parse_container_in(
    ctx: Context,
    src: &mut dyn ImageSource,
    base: u64,
    window: u64,
    verify: bool,
) -> Result<ContainerInfo, ImageError> {
    let slot_count = (window / ctx.storage.slot_size as u64) as usize;
    let mut slots = Vec::with_capacity(slot_count);
    for i in 0..slot_count {
        let slot_base = base + i as u64 * ctx.storage.slot_size as u64;
        let info = inspect_bootrom_in(ctx, src, slot_base, ctx.storage.slot_size as u64, verify)?;
        slots.push(info);
    }

    let identical = if verify {
        Some(slots_identical(ctx, src, base, slot_count)?)
    } else {
        None
    };

    Ok(ContainerInfo {
        slot_size: ctx.storage.slot_size,
        slot_count,
        identical,
        slots,
    })
}

/// Parses a standalone container using the selected slot geometry.
pub fn inspect_container(board: &BoardProfile, raw: &[u8]) -> Result<ContainerInfo, ImageError> {
    let ctx = Context::board(board);
    ctx.storage.validate()?;
    if raw.is_empty() || !raw.len().is_multiple_of(ctx.storage.slot_size) {
        return Err(ImageError::InvalidSlotSize {
            size: raw.len(),
            slot_size: ctx.storage.slot_size,
        });
    }
    let mut src = BytesSource(raw);
    parse_container_in(ctx, &mut src, 0, raw.len() as u64, true)
}

/// Streams slot 0 and each subsequent slot, comparing byte for byte.
fn slots_identical(
    ctx: Context,
    src: &mut dyn ImageSource,
    base: u64,
    slot_count: usize,
) -> Result<bool, ImageError> {
    if slot_count <= 1 {
        return Ok(true);
    }
    let slot_len = ctx.storage.slot_size as u64;
    let mut chunk = vec![0u8; VERIFY_CHUNK];
    let mut other = vec![0u8; VERIFY_CHUNK];
    let mut offset = 0u64;
    while offset < slot_len {
        let n = chunk.len().min((slot_len - offset) as usize);
        src.read_exact_at(base + offset, &mut chunk[..n])?;
        for i in 1..slot_count {
            src.read_exact_at(base + i as u64 * slot_len + offset, &mut other[..n])?;
            if chunk[..n] != other[..n] {
                return Ok(false);
            }
        }
        offset += n as u64;
    }
    Ok(true)
}

/// Counts the leading run of non-blank profile-sized slots starting at `base`.
///
/// Blankness is probed using the prefix length specified by the backend;
/// vendor containers zero blank slots entirely, so this is reliable for the
/// layouts produced by this crate and by mkpimage.
fn leading_non_blank_slots(
    ctx: Context,
    src: &mut dyn ImageSource,
    base: u64,
    window: u64,
) -> Result<usize, ImageError> {
    let slot_count = ((window / ctx.storage.slot_size as u64) as usize).min(ctx.storage.slot_count);
    for i in 0..slot_count {
        let probe = src.read_vec_at(
            base + i as u64 * ctx.storage.slot_size as u64,
            ctx.backend.probe_len(),
        )?;
        if probe.iter().all(|&b| b == 0) {
            return Ok(i);
        }
    }
    Ok(slot_count)
}

// ---------------------------------------------------------------------------
// SD card image parsing
// ---------------------------------------------------------------------------

/// Parses an SD-card disk image: MBR, partition table, and the preloader
/// container inside the selected boot partition. Reads the 512-byte MBR plus the
/// header window of each container slot — never the whole disk.
pub(crate) fn parse_sd_in(
    ctx: Context,
    src: &mut dyn ImageSource,
    size: u64,
    verify: bool,
) -> Result<SdImageInfo, ImageError> {
    if size < MBR_LEN {
        return Err(ImageError::TruncatedImage {
            needed: MBR_LEN as usize,
            actual: size as usize,
        });
    }

    let mbr = src.read_vec_at(0, MBR_LEN as usize)?;
    let signature_ok = mbr[510] == 0x55 && mbr[511] == 0xAA;

    let mut partitions = Vec::new();
    for index in 0..4u64 {
        let entry = MBR_PARTITION_TABLE + index * 16;
        let partition_type = mbr[entry as usize + 4];
        let start_lba = u32::from_le_bytes(
            mbr[entry as usize + 8..entry as usize + 12]
                .try_into()
                .unwrap(),
        );
        let sectors = u32::from_le_bytes(
            mbr[entry as usize + 12..entry as usize + 16]
                .try_into()
                .unwrap(),
        );
        if partition_type == 0 && start_lba == 0 && sectors == 0 {
            continue; // unused entry
        }
        partitions.push(PartitionInfo {
            index: index as usize,
            bootable: mbr[entry as usize] == 0x80,
            partition_type,
            start_lba,
            sectors,
        });
    }

    let boot_partition = partitions
        .iter()
        .find(|p| p.partition_type == ctx.storage.partition_type)
        .map(|p| parse_boot_partition(ctx, src, p, size, verify))
        .transpose()?;

    Ok(SdImageInfo {
        boot_partition_type: ctx.storage.partition_type,
        signature_ok,
        partitions,
        boot_partition,
    })
}

/// Parses an SD-card disk image from memory.
pub fn inspect_sd(board: &BoardProfile, raw: &[u8]) -> Result<SdImageInfo, ImageError> {
    board.storage.validate()?;
    let mut src = BytesSource(raw);
    parse_sd_in(Context::board(board), &mut src, raw.len() as u64, true)
}

/// Structural + (optionally) integrity parse of the selected boot partition's
/// preloader container.
fn parse_boot_partition(
    ctx: Context,
    src: &mut dyn ImageSource,
    partition: &PartitionInfo,
    size: u64,
    verify: bool,
) -> Result<BootPartitionInfo, ImageError> {
    let byte_start = u64::from(partition.start_lba) * 512;
    let byte_len = u64::from(partition.sectors) * 512;
    let within_file = byte_start
        .checked_add(byte_len)
        .is_some_and(|end| end <= size);

    let container = if within_file {
        let window = byte_len.min(size - byte_start);
        let slots = leading_non_blank_slots(ctx, src, byte_start, window)?;
        if slots > 0 {
            Some(parse_container_in(
                ctx,
                src,
                byte_start,
                slots as u64 * ctx.storage.slot_size as u64,
                verify,
            )?)
        } else {
            None
        }
    } else {
        None
    };

    Ok(BootPartitionInfo {
        start_lba: partition.start_lba,
        sectors: partition.sectors,
        within_file,
        container,
    })
}

// ---------------------------------------------------------------------------
// ELF parsing
// ---------------------------------------------------------------------------

/// Parses ELF metadata relevant to packaging. Unlike the binary formats, ELF
/// parsing needs the whole file in memory (deliberate exception: ELF inputs
/// are toolchain artifacts, not disk images).
pub fn inspect_elf(raw: &[u8]) -> Result<ElfInfo, ImageError> {
    let elf = elf::ElfBytes::<elf::endian::AnyEndian>::minimal_parse(raw)?;

    let segments = elf.segments().ok_or(ImageError::SegmentsError)?;
    let segments = segments
        .iter()
        .filter(|s| s.p_type == elf::abi::PT_LOAD)
        .map(|s| ElfSegmentInfo {
            p_type: s.p_type,
            flags: s.p_flags,
            offset: s.p_offset,
            paddr: s.p_paddr,
            vaddr: s.p_vaddr,
            filesz: s.p_filesz,
            memsz: s.p_memsz,
        })
        .collect();

    Ok(ElfInfo {
        machine: elf.ehdr.e_machine,
        machine_name: elf::to_str::e_machine_to_str(elf.ehdr.e_machine)
            .unwrap_or("unknown")
            .to_string(),
        entry: elf.ehdr.e_entry,
        class: match raw.get(4) {
            Some(1) => "ELF32".to_string(),
            Some(2) => "ELF64".to_string(),
            _ => format!("unknown ({:?})", raw.get(4)),
        },
        endian: match raw.get(5) {
            Some(1) => "little".to_string(),
            Some(2) => "big".to_string(),
            _ => format!("unknown ({:?})", raw.get(5)),
        },
        segments,
    })
}

// ---------------------------------------------------------------------------
// Format detection
// ---------------------------------------------------------------------------

fn detect_with(ctx: Context, size: u64, head: &[u8]) -> Vec<DetectionCandidate> {
    let mut candidates = Vec::new();
    if head.starts_with(b"\x7fELF") {
        candidates.push(DetectionCandidate {
            kind: ImageKind::Elf,
            reasons: vec!["ELF magic".into()],
        });
    }
    if head.get(510..512) == Some(&[0x55, 0xAA]) {
        candidates.push(DetectionCandidate {
            kind: ImageKind::SdImage,
            reasons: vec!["MBR signature".into()],
        });
    }
    if ctx.backend.has_signature(head) {
        if size <= ctx.storage.slot_size as u64 {
            candidates.push(DetectionCandidate {
                kind: ImageKind::BootRom,
                reasons: vec![format!("{} ROM signature", ctx.backend.format_id())],
            });
        }
        if size >= ctx.storage.slot_size as u64 && size.is_multiple_of(ctx.storage.slot_size as u64)
        {
            candidates.push(DetectionCandidate {
                kind: ImageKind::Preloader,
                reasons: vec!["ROM signature and slot geometry".into()],
            });
        }
    }
    candidates
}

/// Returns every format that compiled backends consider plausible for `raw`,
/// with the reasons for each.
///
/// Detection never guesses: an empty result means nothing matched, and
/// multiple entries mean the caller must select a backend or kind explicitly.
pub fn detect_kind(raw: &[u8]) -> Vec<DetectionCandidate> {
    let mut result = Vec::new();
    for backend in families() {
        let ctx = Context {
            backend: *backend,
            storage: backend.default_storage(),
        };
        for candidate in detect_with(ctx, raw.len() as u64, raw) {
            if !result
                .iter()
                .any(|other: &DetectionCandidate| other.kind == candidate.kind)
            {
                result.push(candidate);
            }
        }
    }
    if raw.starts_with(b"\x7fELF") && result.is_empty() {
        result.push(DetectionCandidate {
            kind: ImageKind::Elf,
            reasons: vec!["ELF magic".into()],
        });
    }
    result
}

pub(crate) fn resolve(
    src: &mut dyn ImageSource,
    options: &InspectOptions,
) -> Result<(Option<Context>, ImageKind, DetectionSource), ImageError> {
    resolve_backends(src, options, families())
}

pub(crate) fn resolve_backends(
    src: &mut dyn ImageSource,
    options: &InspectOptions,
    available: &[&'static dyn FamilyBackend],
) -> Result<(Option<Context>, ImageKind, DetectionSource), ImageError> {
    let size = src.len()?;
    let probe = options
        .board
        .map(|b| b.backend.probe_len())
        .unwrap_or_else(|| available.iter().map(|b| b.probe_len()).max().unwrap_or(0))
        .max(512);
    let head = src.read_vec_at(0, size.min(probe as u64) as usize)?;
    let detected_by = if options.kind.is_some() {
        DetectionSource::Override
    } else {
        DetectionSource::Auto
    };
    if options.kind == Some(ImageKind::Elf)
        || (options.kind.is_none() && head.starts_with(b"\x7fELF"))
    {
        return Ok((
            options.board.map(Context::board),
            ImageKind::Elf,
            detected_by,
        ));
    }
    let contexts: Vec<_> = if let Some(board) = options.board {
        vec![Context::board(board)]
    } else {
        available
            .iter()
            .map(|backend| Context {
                backend: *backend,
                storage: backend.default_storage(),
            })
            .collect()
    };
    if contexts.is_empty() {
        return Err(ImageError::NoBackend);
    }
    let mut matches = Vec::new();
    for ctx in contexts {
        ctx.storage.validate()?;
        if ctx.backend.probe_len() > ctx.storage.slot_size {
            return Err(ImageError::InvalidStorageLayout);
        }
        // For SD input, identify the family by a ROM signature in its boot
        // partition. An MBR alone cannot identify a SoC or physical board.
        let kinds = detect_with(ctx, size, &head);
        let is_sd = options.kind == Some(ImageKind::SdImage)
            || kinds.iter().any(|c| c.kind == ImageKind::SdImage);
        let mut evidence = ctx.backend.has_signature(&head);
        if is_sd && head.len() >= 512 {
            for index in 0..4 {
                let entry = 0x1BE + index * 16;
                if head[entry + 4] == ctx.storage.partition_type {
                    let lba = u32::from_le_bytes(head[entry + 8..entry + 12].try_into().unwrap());
                    let base = u64::from(lba) * 512;
                    if let Some(end) = base.checked_add(ctx.backend.probe_len() as u64)
                        && end <= size
                    {
                        evidence |= ctx
                            .backend
                            .has_signature(&src.read_vec_at(base, ctx.backend.probe_len())?);
                    }
                }
            }
        }
        let forced = options.kind.is_some() && (options.board.is_some() || available.len() == 1);
        if evidence || forced || (available.len() == 1 && is_sd) {
            let candidates = if let Some(kind) = options.kind {
                vec![kind]
            } else {
                kinds.iter().map(|c| c.kind).collect()
            };
            if !candidates.is_empty() {
                matches.push((ctx, candidates));
            }
        }
    }
    if matches.is_empty() {
        return Err(ImageError::UnknownImageFormat);
    }
    if matches.len() > 1 {
        return Err(ImageError::AmbiguousFamily(
            matches.iter().map(|(ctx, _)| ctx.backend.id()).collect(),
        ));
    }
    let (ctx, kinds) = matches.pop().unwrap();
    if kinds.len() != 1 {
        return Err(ImageError::AmbiguousImageFormat { candidates: kinds });
    }
    Ok((Some(ctx), kinds[0], detected_by))
}

// ---------------------------------------------------------------------------
// Report assembly
// ---------------------------------------------------------------------------

fn elf_checks(info: &ElfInfo) -> Vec<Check> {
    vec![Check::binary(
        "loadable segments",
        !info.segments.is_empty(),
        "no PT_LOAD segments",
    )]
}

fn container_checks(info: &ContainerInfo) -> Vec<Check> {
    let mut checks = Vec::new();
    if let Some(slot) = info.slots.first() {
        checks.extend(bootrom_checks(slot));
    }
    for (index, slot) in info.slots.iter().enumerate().skip(1) {
        checks.extend(
            slot.checks
                .iter()
                .filter(|check| check.status == CheckStatus::Fail)
                .map(|check| {
                    Check::new(
                        format!("slot {index}: {}", check.name),
                        check.status,
                        check.detail.clone(),
                    )
                }),
        );
    }
    let bad = info
        .slots
        .iter()
        .filter(|s| s.crc_status == CrcStatus::Failed || s.crc_status == CrcStatus::Unreadable)
        .count();
    let not_checked = info
        .slots
        .iter()
        .filter(|s| s.crc_status == CrcStatus::NotChecked)
        .count();

    if not_checked == info.slots.len() {
        checks.push(Check::new(
            "slot CRCs",
            CheckStatus::Warn,
            "CRC not checked (integrity verification was skipped)",
        ));
    } else {
        checks.push(Check::binary(
            "slot CRCs",
            bad == 0,
            format!("{bad} of {} slots fail the CRC check", info.slots.len()),
        ));
    }

    match info.identical {
        Some(true) => checks.push(Check::new(
            "slots identical",
            CheckStatus::Pass,
            "ok".to_string(),
        )),
        Some(false) => checks.push(Check::new(
            "slots identical",
            CheckStatus::Fail,
            "slots differ; the Boot ROM may reject fallback copies",
        )),
        None => checks.push(Check::new(
            "slots identical",
            CheckStatus::Warn,
            "not checked (integrity verification was skipped)",
        )),
    }

    checks
}

pub(crate) fn sd_checks(info: &SdImageInfo) -> Vec<Check> {
    let mut checks = vec![Check::binary(
        "MBR signature",
        info.signature_ok,
        "0x55AA boot signature missing at offset 510",
    )];

    let Some(a2) = &info.boot_partition else {
        checks.push(Check::binary(
            "boot partition",
            false,
            format!(
                "no boot partition of type 0x{:02X}",
                info.boot_partition_type
            ),
        ));
        return checks;
    };

    checks.push(Check::binary(
        "boot partition",
        true,
        format!("start LBA {}, {} sectors", a2.start_lba, a2.sectors),
    ));

    checks.push(Check::binary(
        "partition extent within file",
        a2.within_file,
        format!(
            "declared extent (LBA {} + {} sectors) extends past the end of the file",
            a2.start_lba, a2.sectors,
        ),
    ));

    match &a2.container {
        Some(container) => {
            let bad = container
                .slots
                .iter()
                .filter(|s| {
                    s.crc_status == CrcStatus::Failed || s.crc_status == CrcStatus::Unreadable
                })
                .count();
            let not_checked = container
                .slots
                .iter()
                .filter(|s| s.crc_status == CrcStatus::NotChecked)
                .count();
            if not_checked == container.slots.len() {
                checks.push(Check::new(
                    "container CRCs",
                    CheckStatus::Warn,
                    "CRC not checked (integrity verification was skipped)",
                ));
            } else {
                checks.push(Check::binary(
                    "container CRCs",
                    bad == 0,
                    format!(
                        "{bad} of {} slots fail the CRC check",
                        container.slots.len()
                    ),
                ));
            }

            match container.identical {
                Some(true) => checks.push(Check::new(
                    "container slots identical",
                    CheckStatus::Pass,
                    "ok".to_string(),
                )),
                Some(false) => checks.push(Check::new(
                    "container slots identical",
                    CheckStatus::Fail,
                    "slots differ; the Boot ROM may reject fallback copies",
                )),
                None => checks.push(Check::new(
                    "container slots identical",
                    CheckStatus::Warn,
                    "not checked (integrity verification was skipped)",
                )),
            }
        }
        None => {
            checks.push(Check::binary(
                "preloader container",
                false,
                "no boot container found at the start of the selected boot partition",
            ));
        }
    }

    checks
}

/// Parses `raw` as `kind`, or detects the kind when `None`.
///
/// Detection never guesses: when several formats plausibly match,
/// [`ImageError::AmbiguousImageFormat`] is returned listing them, and the
/// caller should ask for an explicit kind.
pub fn inspect_bytes(raw: &[u8], options: InspectOptions) -> Result<InspectReport, ImageError> {
    let mut src = BytesSource(raw);
    inspect_source(&mut src, options)
}

/// Inspects an image file. Binary formats are read with seeks and bounded
/// reads (headers, partition table, and — with verification — the declared
/// image ranges), so even multi-gigabyte SD images are never loaded whole.
/// ELF inputs are read into memory (see [`inspect_elf`]).
pub fn inspect_file(
    path: impl AsRef<Path>,
    options: InspectOptions,
) -> Result<InspectReport, ImageError> {
    let file = std::fs::File::open(path)?;
    let mut src = FileSource(file);
    inspect_source(&mut src, options)
}

fn inspect_source(
    src: &mut dyn ImageSource,
    options: InspectOptions,
) -> Result<InspectReport, ImageError> {
    let size = src.len()?;
    let (ctx, kind, detected_by) = resolve(src, &options)?;
    let mut report = InspectReport {
        schema: 3,
        family: ctx.map(|ctx| ctx.backend.id()),
        format: ctx.map(|ctx| ctx.backend.format_id()),
        board: options.board.map(|board| board.id),
        input: InputInfo {
            path: None,
            size,
            kind,
            detected_by,
        },
        elf: None,
        bootrom: None,
        preloader: None,
        sd: None,
        checks: Vec::new(),
    };

    match kind {
        ImageKind::Elf => {
            let raw = src.read_vec_at(0, size as usize)?;
            let info = inspect_elf(&raw)?;
            report.checks = elf_checks(&info);
            report.elf = Some(info);
        }
        ImageKind::BootRom => {
            let info = inspect_bootrom_in(
                ctx.ok_or(ImageError::NoBackend)?,
                src,
                0,
                size,
                options.verify,
            )?;
            report.checks = bootrom_checks(&info);
            report.bootrom = Some(info);
        }
        ImageKind::Preloader => {
            let ctx = ctx.ok_or(ImageError::NoBackend)?;
            if size == 0 || !size.is_multiple_of(ctx.storage.slot_size as u64) {
                return Err(ImageError::InvalidSlotSize {
                    size: size as usize,
                    slot_size: ctx.storage.slot_size,
                });
            }
            let info = parse_container_in(ctx, src, 0, size, options.verify)?;
            report.checks = container_checks(&info);
            report.preloader = Some(info);
        }
        ImageKind::SdImage => {
            let info = parse_sd_in(ctx.ok_or(ImageError::NoBackend)?, src, size, options.verify)?;
            report.checks = sd_checks(&info);
            report.sd = Some(info);
        }
    }

    Ok(report)
}

#[cfg(all(test, feature = "cyclone-v"))]
mod tests;

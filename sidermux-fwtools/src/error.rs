use thiserror::Error;

use crate::kind::ImageKind;

/// Errors from packaging, inspection, and unpacking operations.
#[derive(Error, Debug)]
pub enum ImageError {
    /// The requested board id is not compiled into this build.
    #[error(
        "unknown or unavailable board '{0}'; use `cargo sidermux boards` to list compiled profiles"
    )]
    UnknownBoard(String),
    /// No family backend is compiled into this build.
    #[error("no applicable family backend is compiled; enable a family or board Cargo feature")]
    NoBackend,
    /// Several compiled families match the input.
    #[error("multiple families match the input; select --board explicitly: {0:?}")]
    AmbiguousFamily(Vec<&'static str>),
    /// The board profile does not declare the requested input or output.
    #[error("board '{board}' does not support {capability}")]
    UnsupportedCapability {
        board: &'static str,
        capability: String,
    },
    /// The board's storage geometry is invalid.
    #[error("invalid board storage layout")]
    InvalidStorageLayout,
    /// The family's entry address or instruction size is misaligned.
    #[error("selected family entry address or instruction size has invalid alignment")]
    InvalidEntryAlignment,
    /// The ELF file could not be parsed.
    #[error("ELF Parse Error")]
    Elf(#[from] elf::ParseError),
    /// The ELF targets a different machine than the family accepts.
    #[error("Unsupported ELF machine")]
    UnsupportedMachine { actual: u16 },
    /// The ELF class or byte order does not match the family contract.
    #[error("unsupported ELF class or byte order for the selected family")]
    UnsupportedElfEncoding,
    /// The ELF section header table is unreadable.
    #[error("Unable to access ELF section headers")]
    SectionHeadersError,
    /// The ELF program header table is unreadable.
    #[error("Unable to access ELF segments")]
    SegmentsError,
    /// A load segment violates the family extraction contract.
    #[error("Invalid ELF segment: {0}")]
    InvalidSegment(#[from] ElfValidationError),
    /// The ELF has no file-backed load segments to extract.
    #[error("ELF contains no file-backed load segments")]
    NoLoadableSegments,
    /// A segment's file range or destination range is inconsistent.
    #[error("Recorded segment copy range is invalid")]
    InvalidCopyRange,
    /// A length computation overflowed.
    #[error("image length overflow")]
    LengthOverflow,
    /// The encoded image would exceed the family's boot size limit.
    #[error("boot image is {size} bytes, exceeding family boot limit of {max} bytes")]
    ImageTooLarge { size: usize, max: usize },
    /// The raw payload cannot hold the prefix, header, and boot-entry slot.
    #[error(
        "raw payload is {actual} bytes, but at least {needed} are required for the prefix, header, and boot-entry slot"
    )]
    InputTooShort { actual: usize, needed: usize },
    /// The ROM entry slot is not fully covered by executable file-backed
    /// ELF content.
    #[error(
        "the selected family ROM entry slot is not fully covered by executable file-backed ELF content"
    )]
    EntryNotExecutable,
    /// The DTB offset would overwrite the extracted ELF payload.
    #[error("DTB offset {offset:#x} overlaps the extracted ELF payload ({payload_len:#x} bytes)")]
    DtbOverlap { offset: usize, payload_len: usize },
    /// The supplied DTB lacks the FDT magic, a complete header, or a
    /// consistent declared total size.
    #[error(
        "invalid or truncated DTB: expected FDT magic, a complete header, and declared total size within the supplied bytes"
    )]
    InvalidDtb,
    /// The input ELF already contains a fully valid packaged image; wrapping
    /// it again would corrupt it.
    #[error(
        "the ELF payload is already a complete packaged ROM image ({declared_len} bytes, CRC 0x{crc32:08X}); double packaging would corrupt it. Pass the packaged image itself, or use --packaged to wrap it as-is"
    )]
    ElfContainsPackagedImage { declared_len: usize, crc32: u32 },
    /// The input does not satisfy the complete family ROM contract required
    /// for packaged-image adoption.
    #[error(
        "input is not a fully verified packaged ROM image (validation word, version, declared bounds, header checksum, boot-entry placement, and CRC must all pass)"
    )]
    NotVerifiedPackagedImage,
    /// The image is too short to read its boot ROM header.
    #[error(
        "file is {actual} bytes, but at least {needed} bytes are required to read the boot image header"
    )]
    TruncatedImage { needed: usize, actual: usize },
    /// The file size is not a whole number of boot slots.
    #[error(
        "file size {size} is not a multiple of the selected boot slot size ({slot_size} bytes)"
    )]
    InvalidSlotSize { size: usize, slot_size: usize },
    /// No input signature (ELF, MBR, or boot ROM header) matched.
    #[error("unrecognized image format: no ELF, MBR, or Boot ROM header signature found")]
    UnknownImageFormat,
    /// Several formats plausibly match; an explicit kind is required.
    #[error(
        "ambiguous image format: file matches multiple formats ({}); pass an explicit kind to disambiguate",
        .candidates.iter().map(|kind| kind.to_string()).collect::<Vec<_>>().join(", ")
    )]
    AmbiguousImageFormat { candidates: Vec<ImageKind> },
    /// The boot ROM validation word is missing or incorrect.
    #[error("invalid Boot ROM validation word: expected 0x31305341, found 0x{actual:08X}")]
    InvalidValidationWord { actual: u32 },
    /// The stored header checksum does not match the computed one.
    #[error("Boot ROM header checksum mismatch: stored 0x{stored:04X}, computed 0x{computed:04X}")]
    HeaderChecksumMismatch { stored: u16, computed: u16 },
    /// The stored CRC does not match the computed image CRC.
    #[error("CRC32 mismatch: stored 0x{stored:08X}, computed 0x{computed:08X}")]
    CrcMismatch { stored: u32, computed: u32 },
    /// The MBR has no partition matching the selected storage layout.
    #[error("no boot partition matching the selected storage layout found in the MBR")]
    NoBootPartition,
    /// ELF is a packaging source, not an unpack target.
    #[error(
        "unpack applies to Boot ROM images, containers, and SD card images, not ELF files (use pack)"
    )]
    UnpackElfInput,
    #[error("I/O error while reading the image")]
    Io(#[from] std::io::Error),
}

/// Failures of the family ELF extraction contract, from the shared extractor.
#[derive(Error, Debug)]
pub enum ElfValidationError {
    /// A segment's file range extends past the end of the ELF file.
    #[error("Invalid ELF Segment Source Range")]
    InvalidSourceRange {
        offset: u64,
        size: u64,
        file_len: usize,
    },
    /// `p_filesz` exceeds `p_memsz`, which ELF forbids.
    #[error("Corrupt size constraint: p_filesz ({filesz}) exceeds p_memsz ({memsz})")]
    SizeMismatch { filesz: u64, memsz: u64 },
    /// A load address lies outside the family's supported memory window.
    #[error("Load address 0x{addr:X} lies outside supported OCRAM range (0x{start:X}..0x{end:X})")]
    InvalidOcramAddress { addr: u64, start: u64, end: u64 },
    /// Two segments claim overlapping destination memory.
    #[error(
        "Overlapping destination segment detected: 0x{start_a:X}..0x{end_a:X} conflicts with 0x{start_b:X}..0x{end_b:X}"
    )]
    OverlappingSegments {
        start_a: u64,
        end_a: u64,
        start_b: u64,
        end_b: u64,
    },
    /// The ELF violates the family's load/execution address identity rule.
    #[error(
        "Load address (0x{load_addr:X}) and execution address (0x{exec_addr:X}) do not match contract requirements"
    )]
    ContractViolation { load_addr: u64, exec_addr: u64 },
    /// A segment's address range computation overflowed.
    #[error("Segment address range overflows: start={start:#x}, size={size:#x}")]
    AddressOverflow { start: u64, size: u64 },
    /// An address computation overflowed.
    #[error("Range overflow")]
    RangeOverflow,
}

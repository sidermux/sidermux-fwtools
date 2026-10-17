//! Board-aware firmware packaging and inspection for SoC FPGA boot images.
//!
//! This crate hosts the reusable packaging and inspection operations shared by
//! every supported device family. It never names a physical board directly:
//! behavior is selected through a [`board::BoardProfile`], which pairs a family
//! backend with declared capabilities and a storage policy.
//!
//! Cyclone V is the first supported family. Profiles included by default:
//! `cyclone-v-generic` and `de1-soc`. No additional hardware families are
//! claimed as supported.//!
//! # Architecture
//!
//! The workspace has three layers.
//! [`sidermux-image`](https://docs.rs/sidermux-image) provides allocation-free
//! codecs and checksum primitives; this crate provides host operations;
//! `cargo-sidermux` handles Clap parsing, output, tracing, and miette
//! diagnostics.
//!
//! # Family contracts versus board policy
//!
//! [`backend::FamilyBackend`] owns the ROM format identity, ELF load and entry
//! contract, encoded-length calculation, ROM encoding, signature probing,
//! streamed inspection, checks, and full packaged-image verification. The
//! shared ELF extractor validates source ranges, address ranges, overlap, and
//! executable file backing using its [`backend::ElfPolicy`]; it does not decode
//! instructions.
//!
//! [`board::BoardProfile`] selects a backend, input/output capabilities, and a
//! [`board::StorageLayout`]: slot size/count and MBR partition type/start/
//! length. Its family and format identifiers must match the backend. Profiles
//! describe file packaging policy; they do not initialize physical hardware or
//! identify a board from arbitrary firmware bytes.
//!
//! Family-specific addresses, header/version rules, image-size limits, and
//! encoding alignment live under each family's module — [`families::cyclone_v`]
//! for the first supported family. The current default storage policy is
//! shared by the compiled profiles; the common container/SD code consumes that
//! policy instead of family-specific constants.
//!
//! # Data flow
//!
//! ```text
//! profile + ELF -> validated load-image extraction
//!              -> optional explicit gap + DTB assembly
//!              -> family ROM header/padding/integrity encoding
//!              -> declared BootImage
//!              -> profile container or SD rendering
//!
//! profile + final raw SPL -> family encoding -> same rendering
//! profile + packaged image -> full family verification -> preserved declared bytes
//! ```
//!
//! [`BootImage`] retains its selected profile. Its constructors require
//! explicit selection, and rendering rejects unsupported profile capabilities.
//! Raw input has no executable-permission metadata; provenance is the caller's
//! obligation. DTB placement is supplied per firmware build, never inferred
//! from a board.
//!
//! Inspection resolves an envelope and family independently of board identity.
//! An explicit board constrains the backend and storage policy; otherwise the
//! compiled backend registry supplies candidates. Ambiguous family matches
//! require an explicit board; envelope ambiguity requires an explicit kind.
//! Generic ELF metadata does not require a backend. Reports use schema 3, with
//! common source/check and container/partition data plus a typed, tagged
//! [`inspect::HeaderDetails`] variant for family-specific metadata.
//!
//! The public [`source::ImageSource`] interface permits bounded reads and
//! seeking. Family ROM inspectors consume windows; shared code handles
//! file/memory sources, container traversal, MBR parsing, and unpacking. The
//! family integrity pass streams only declared bytes. Corrupt readable
//! metadata is reported with checks instead of requiring successful integrity
//! verification to inspect it.
//!
//! # Packaging example
//!
//! ```rust,ignore
//! use sidermux_fwtools::{BootImage, OutputFormat, board::board};
//!
//! let target = board("de1-soc")?;
//! let image = BootImage::from_elf(target, elf)?;
//! let disk = image.render(OutputFormat::Sd)?;
//! ```
//!
//! [`BootImage::from_elf`], [`BootImage::from_raw_spl`],
//! [`BootImage::from_elf_with_dtb`], and [`BootImage::adopt_packaged`] cover
//! the four input paths. [`extract_elf_load_image`] and
//! [`assemble_elf_with_dtb`] expose the pre-encoding stages. Input and output
//! capabilities are checked against the profile.
//!
//! # Adding a family
//!
//! 1. Add its `no_std` codec under `sidermux-image::families` behind a
//!    feature.
//! 2. Implement [`backend::FamilyBackend`] in a host family module. Supply ELF
//!    policy, probing, encoding, inspection, verification, and a valid default
//!    storage layout. Keep format-specific rules out of shared extraction and
//!    storage.
//! 3. Add a typed [`inspect::HeaderDetails`] variant, register the backend and
//!    a generic profile, and forward its feature through all three crates. Add
//!    human report rendering for its header details if desired.
//! 4. Test known independent format artifacts and failure cases, plus feature
//!    builds. Never advertise a family as supported solely because a synthetic
//!    backend test passes.
//!
//! # Adding a board
//!
//! Create a static profile using an existing backend, matching family/format
//! identifiers, declared capabilities, and validated storage geometry.
//! Register it under a board feature that enables its family feature. Forward
//! the feature through the CLI. No command-parser enum change is needed:
//! `--board` resolves through [`board::boards`], and `boards --json` exposes
//! the compiled capabilities.
//!
//! New profiles must test format availability, output layout, inspection, and
//! unpacking. The synthetic test backend demonstrates extension without any
//! production family features; it is not included in the public registry.
//!
//! # Cargo features
//!
//! | Cargo feature | Effect |
//! | --- | --- |
//! | `cyclone-v` | First supported family backend and `cyclone-v-generic` profile |
//! | `board-de1-soc` | DE1-SoC profile; enables `cyclone-v` |
//!
//! The host library and CLI enable both by default. `sidermux-image` defaults
//! to the first supported family's codec; it remains `no_std` with or without that feature.
//! Dependencies forward features explicitly, with dependency defaults
//! disabled:
//!
//! ```sh
//! cargo build -p cargo-sidermux --no-default-features --features cyclone-v
//! cargo build -p cargo-sidermux --no-default-features --features board-de1-soc
//! cargo check --workspace --no-default-features
//! ```
//!
//! A build without family features has an empty board registry.
//! Board-dependent operations return an actionable error; generic ELF metadata
//! remains available.
//!
//! # Testing and vendor comparison
//!
//! ```sh
//! cargo test --workspace
//! cargo test --workspace --no-default-features
//! cargo test --workspace --all-features
//! ```
//!
//! Normal tests need no network access or vendor SDK. A test-only backend uses
//! different ELF architecture/address rules, entry alignment, ROM header,
//! encoding alignment, slot geometry, and partition policy to exercise the
//! shared pipeline without claiming hardware support.
//!
//! Optional vendor oracle tests compare genuine ELF extraction to `objcopy`,
//! ELF-plus-DTB assembly to the vendor's raw binary, and packaging to
//! independent `mkimage` output. Each family owns its oracle: its test file,
//! artifact names, and environment variables are family-keyed, and no
//! fixtures are shared across families. The first supported family's oracle
//! supplies `u-boot-spl`, `u-boot-spl-nodtb.bin`, `u-boot-spl.bin`,
//! `u-boot-spl.dtb`, and `u-boot-spl.sfp` from the reference build:
//!
//! ```sh
//! SIDERMUX_CYCLONE_V_VENDOR_SPL_DIR=/path/to/vendor/build/spl \
//!   cargo test -p sidermux-fwtools --test vendor_cyclone_v -- --ignored
//! ```
//!
//! The pinned reference is Altera U-Boot commit
//! `b56517573b02f683018e4599e77338e757c6a288` (`socfpga_v2022.10`),
//! `socfpga_de1_soc_defconfig`, built with Arm GNU Toolchain 12.3.Rel1. These
//! tests default to its verified DTB offset `0xCF10`;
//! `SIDERMUX_CYCLONE_V_VENDOR_DTB_OFFSET` overrides that offset in decimal.
//! Vendor artifacts remain outside the source tree. No hardware boot test is
//! implied by byte-for-byte comparison.
//!
//! # Migration
//!
//! This is a clean pre-release rename: crate imports use `sidermux_image` and
//! `sidermux_fwtools`, and the command is `cargo sidermux`. No old-name
//! aliases are provided. Public packaging APIs now require a board;
//! inspection options accept an optional board. Inspection JSON consumers must
//! use schema 3, tagged header metadata, and `boot_partition` instead of the
//! old partition-specific field. The repository is hosted at
//! <https://github.com/sidermux/sidermux-fwtools>.
//!
//! # CLI
//!
//! The command-line frontend lives in the
//! [`cargo-sidermux`](https://docs.rs/cargo-sidermux) crate: install, output
//! formats, DTB rules, and inspection options are documented there.
pub mod backend;
#[cfg(test)]
mod backend_tests;
pub mod board;
#[cfg(all(test, feature = "cyclone-v"))]
mod compatibility_tests;
pub mod container;
pub mod error;
mod extract;
pub mod families;
pub mod inspect;
pub mod kind;
mod layout;
pub mod sd;
pub mod source;
pub mod unpack;

pub use board::{BoardProfile, OutputFormat};
pub use error::{ElfValidationError, ImageError};
pub use inspect::InspectReport;
pub use kind::{Check, CheckStatus, CrcStatus, DetectionCandidate, DetectionSource, ImageKind};

/// Extracts the load image from `elf` under `board`'s family ELF contract:
/// segments are validated against the policy (file backing, address window,
/// overlap, identity mapping) and the returned bytes are laid out at the
/// family load addresses, before any ROM encoding.
pub fn extract_elf_load_image(board: &BoardProfile, elf: &[u8]) -> Result<Vec<u8>, ImageError> {
    board.require_input(board::InputKind::Elf)?;
    extract::extract_preloader_bin(board.backend.elf_policy(), elf)
}

/// Zero-fill to the explicit image-relative offset, append DTB, then encode later.
///
/// Extracts the load image (see [`extract_elf_load_image`]), rejects input
/// that already verifies as a packaged image, zero-fills the gap to
/// `dtb_offset` (measured from image start), and appends `dtb`. The result is
/// the pre-encoding payload; [`BootImage::from_elf_with_dtb`] ROM-encodes it.
/// Overlapping offsets, overflow, and truncated or invalid DTBs are rejected.
pub fn assemble_elf_with_dtb(
    board: &BoardProfile,
    elf: &[u8],
    dtb: &[u8],
    dtb_offset: usize,
) -> Result<Vec<u8>, ImageError> {
    board.require_input(board::InputKind::Dtb)?;
    let mut raw = extract_elf_load_image(board, elf)?;
    reject_packaged_elf(board, &raw)?;
    if dtb_offset < raw.len() {
        return Err(ImageError::DtbOverlap {
            offset: dtb_offset,
            payload_len: raw.len(),
        });
    }
    let assembled_len = dtb_offset
        .checked_add(dtb.len())
        .ok_or(ImageError::LengthOverflow)?;
    board.backend.encoded_length(assembled_len)?;
    if dtb.len() < 40 || dtb[..4] != [0xD0, 0x0D, 0xFE, 0xED] {
        return Err(ImageError::InvalidDtb);
    }
    let total = u32::from_be_bytes(dtb[4..8].try_into().unwrap()) as usize;
    if !(40..=dtb.len()).contains(&total) {
        return Err(ImageError::InvalidDtb);
    }
    tracing::debug!(
        board = board.id,
        dtb_offset,
        dtb_len = dtb.len(),
        assembled_len,
        "Appending DTB before ROM encoding"
    );
    raw.resize(dtb_offset, 0);
    raw.extend_from_slice(dtb);
    Ok(raw)
}

fn verified_image(board: &BoardProfile, raw: &[u8]) -> Option<inspect::BootRomInfo> {
    let info = board
        .backend
        .inspect(&mut source::BytesSource(raw), 0, raw.len() as u64, true)
        .ok()?;
    board.backend.verified(&info).then_some(info)
}
fn reject_packaged_elf(board: &BoardProfile, raw: &[u8]) -> Result<(), ImageError> {
    if let Some(info) = verified_image(board, raw) {
        return Err(ImageError::ElfContainsPackagedImage {
            declared_len: info.declared_len,
            crc32: info.crc32.unwrap_or(0),
        });
    }
    Ok(())
}
/// What a raw payload looks like to the selected family's backend.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PayloadKind {
    /// Not recognized as a packaged image; it must be ROM-encoded before boot.
    Raw,
    /// Fully verifies as a packaged image; its declared bytes can be adopted
    /// as-is with [`BootImage::adopt_packaged`].
    PackagedRom,
}
/// Probes `raw` with `board`'s family backend to decide whether it is already
/// a complete packaged ROM image.
pub fn classify_payload(board: &BoardProfile, raw: &[u8]) -> PayloadKind {
    if verified_image(board, raw).is_some() {
        PayloadKind::PackagedRom
    } else {
        PayloadKind::Raw
    }
}

/// A family-encoded boot image, bound to the [`BoardProfile`] that produced
/// it.
///
/// Construction requires an explicit profile and rejects payloads the profile
/// does not declare as input; [`BootImage::render`] rejects output formats the
/// profile does not declare. The image itself is the declared ROM bytes —
/// header, payload, and integrity tail — ready for container or disk
/// rendering.
#[derive(Debug)]
pub struct BootImage {
    bytes: Vec<u8>,
    board: &'static BoardProfile,
}
impl BootImage {
    /// The encoded ROM image bytes (the declared image, unpadded).
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Consumes the image, returning the encoded bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
    /// The profile this image was built with.
    pub fn board(&self) -> &'static BoardProfile {
        self.board
    }
    #[cfg(all(test, feature = "cyclone-v"))]
    pub(crate) fn from_bytes(board: &'static BoardProfile, bytes: Vec<u8>) -> Self {
        Self { bytes, board }
    }
    /// Extracts the load image from an ELF under the family contract, rejects
    /// input that already verifies as packaged, and ROM-encodes it.
    pub fn from_elf(board: &'static BoardProfile, elf: &[u8]) -> Result<Self, ImageError> {
        let raw = extract_elf_load_image(board, elf)?;
        reject_packaged_elf(board, &raw)?;
        Self::encode(board, &raw)
    }
    /// ROM-encodes final raw firmware bytes as-is — for example a vendor SPL
    /// binary that already carries any appended device tree. Raw bytes carry
    /// no executable metadata; provenance is the caller's obligation.
    pub fn from_raw_spl(board: &'static BoardProfile, raw: &[u8]) -> Result<Self, ImageError> {
        board.require_input(board::InputKind::Raw)?;
        Self::encode(board, raw)
    }
    fn encode(board: &'static BoardProfile, raw: &[u8]) -> Result<Self, ImageError> {
        Ok(Self {
            bytes: board.backend.encode(raw)?,
            board,
        })
    }
    /// Assembles an ELF load image with an explicitly placed DTB (see
    /// [`assemble_elf_with_dtb`]), then ROM-encodes the result.
    pub fn from_elf_with_dtb(
        board: &'static BoardProfile,
        elf: &[u8],
        dtb: &[u8],
        offset: usize,
    ) -> Result<Self, ImageError> {
        Self::encode(board, &assemble_elf_with_dtb(board, elf, dtb, offset)?)
    }
    /// Adopts an already-packaged ROM image found inside an ELF, after full
    /// verification of the extracted payload.
    pub fn from_elf_packaged(board: &'static BoardProfile, elf: &[u8]) -> Result<Self, ImageError> {
        Self::adopt_packaged(board, &extract_elf_load_image(board, elf)?)
    }
    /// Adopts `raw` as a packaged image only when it fully verifies against
    /// the family contract — validation word, version, declared bounds, header
    /// checksum, boot-entry placement, and CRC. The declared bytes are
    /// preserved exactly.
    pub fn adopt_packaged(board: &'static BoardProfile, raw: &[u8]) -> Result<Self, ImageError> {
        board.require_input(board::InputKind::Packaged)?;
        let info = verified_image(board, raw).ok_or(ImageError::NotVerifiedPackagedImage)?;
        Ok(Self {
            bytes: raw[..info.declared_len].to_vec(),
            board,
        })
    }
    /// Renders the image as `format` — a bare ROM image, a redundant
    /// container, or a complete SD disk image — after checking the profile
    /// declares that output capability.
    pub fn render(&self, format: OutputFormat) -> Result<Vec<u8>, ImageError> {
        self.board.require_output(format)?;
        match format {
            OutputFormat::Bootrom => Ok(self.bytes.clone()),
            OutputFormat::Preloader => self.to_container(),
            OutputFormat::Sd => self.to_sd_image(),
        }
    }
}

#[cfg(all(test, feature = "cyclone-v"))]
pub(crate) mod test_support {
    pub const BOARD: &crate::board::BoardProfile = &crate::families::cyclone_v::GENERIC;
    /// Builds a minimal ELF32 little-endian ARM executable byte-by-byte, with
    /// a single `PT_LOAD` segment carrying `payload` at `0xFFFF_0000`.
    ///
    /// This is deliberately independent of the crate's own parser so that
    /// extraction tests exercise a structurally valid input that was not
    /// produced by the code under test.
    pub fn elf_with_payload(payload: &[u8]) -> Vec<u8> {
        const TEXT_OFFSET: u32 = 0x1000;
        const LOAD_ADDR: u32 = 0xFFFF_0000;

        let mut out = Vec::new();
        // ELF identification: ELF32, little-endian, SysV.
        out.extend_from_slice(&[0x7F, b'E', b'L', b'F', 1, 1, 1, 0]);
        out.extend_from_slice(&[0u8; 8]);
        // e_type = EXEC, e_machine = ARM, e_version = 1.
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&40u16.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        // e_entry, e_phoff, e_shoff, e_flags.
        out.extend_from_slice(&LOAD_ADDR.to_le_bytes());
        out.extend_from_slice(&52u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        // e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx.
        out.extend_from_slice(&52u16.to_le_bytes());
        out.extend_from_slice(&32u16.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&40u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        assert_eq!(out.len(), 52);

        // Program header: PT_LOAD at file offset 0x1000, mapped 1:1 into OCRAM.
        out.extend_from_slice(&1u32.to_le_bytes()); // p_type = PT_LOAD
        out.extend_from_slice(&TEXT_OFFSET.to_le_bytes()); // p_offset
        out.extend_from_slice(&LOAD_ADDR.to_le_bytes()); // p_vaddr
        out.extend_from_slice(&LOAD_ADDR.to_le_bytes()); // p_paddr
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes()); // p_filesz
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes()); // p_memsz
        out.extend_from_slice(&5u32.to_le_bytes()); // p_flags = R+X
        out.extend_from_slice(&0x1000u32.to_le_bytes()); // p_align
        assert_eq!(out.len(), 84);

        out.resize(TEXT_OFFSET as usize, 0);
        out.extend_from_slice(payload);
        out
    }

    /// Raw SPL payload of `len` bytes (>= 0x50) satisfying the packaging
    /// contract: prefix entry at 0, boot-entry instruction at 0x4C.
    pub fn spl_payload(len: usize) -> Vec<u8> {
        let mut p = vec![0u8; len.max(0x50)];
        p[..4].copy_from_slice(&[0xFE, 0xFF, 0xFF, 0xEA]);
        p[0x4C..0x50].copy_from_slice(&[0xFE, 0xFF, 0xFF, 0xEA]);
        p
    }
}

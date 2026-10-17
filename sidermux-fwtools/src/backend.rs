//! Family boot contracts. Backends own ROM semantics; shared code owns I/O.
use crate::{error::ImageError, inspect::BootRomInfo, kind::Check, source::ImageSource};

/// The family's ELF input contract: which executables are acceptable and
/// where they must load.
///
/// The shared extractor enforces this policy; it never decodes instructions.
#[derive(Clone, Copy, Debug)]
pub struct ElfPolicy {
    /// Required ELF class byte (`1` = ELF32, `2` = ELF64).
    pub class: u8,
    /// Required ELF data byte (`1` = little-endian, `2` = big-endian).
    pub endian: u8,
    /// Required `e_machine` value.
    pub machine: u16,
    /// Inclusive start of the loadable address window.
    pub load_start: u64,
    /// Exclusive end of the loadable address window.
    pub load_end: u64,
    /// Offset of the ROM entry slot relative to `load_start`.
    pub entry_offset: u64,
    /// Required alignment of the ROM entry address.
    pub instruction_alignment: u64,
    /// Instruction width of the entry slot, in bytes.
    pub instruction_size: usize,
    /// Whether load and execution addresses must be identical.
    pub require_identity_mapping: bool,
}

/// The family boot contract: format identity, ELF policy, encoding, and
/// inspection.
///
/// Implementations own all format-specific semantics — addresses, header and
/// version rules, size limits, alignment, and integrity — so shared pipeline
/// code stays format-agnostic.
pub trait FamilyBackend: std::fmt::Debug + Send + Sync {
    /// Family identifier, reported in inspection reports and JSON.
    fn id(&self) -> &'static str;
    /// Boot image format identifier, including its format version.
    fn format_id(&self) -> &'static str;
    /// The ELF input contract for this family.
    fn elf_policy(&self) -> ElfPolicy;
    /// A valid default storage layout, used when no board constrains one.
    fn default_storage(&self) -> crate::board::StorageLayout;
    /// Number of leading bytes needed to test [`FamilyBackend::has_signature`].
    fn probe_len(&self) -> usize;
    /// Whether the leading bytes look like this family's ROM header.
    fn has_signature(&self, head: &[u8]) -> bool;
    /// Validates a raw payload length and returns the encoded image length.
    fn encoded_length(&self, raw_len: usize) -> Result<usize, ImageError>;
    /// Adds the family header, alignment padding, and integrity tail.
    fn encode(&self, raw: &[u8]) -> Result<Vec<u8>, ImageError>;
    /// Parses one ROM image window into a report, running the integrity pass
    /// when `verify` is set.
    fn inspect(
        &self,
        source: &mut dyn ImageSource,
        base: u64,
        window: u64,
        verify: bool,
    ) -> Result<BootRomInfo, ImageError>;
    /// Named validation results derived from a parsed image.
    fn checks(&self, info: &BootRomInfo) -> Vec<Check>;
    /// Verify the complete ROM contract, not just a signature or CRC.
    fn verified(&self, info: &BootRomInfo) -> bool;
}

/// Every family backend compiled into this build. Empty when no family
/// feature is enabled.
pub fn families() -> &'static [&'static dyn FamilyBackend] {
    static REGISTERED: &[&dyn FamilyBackend] = &[
        #[cfg(feature = "cyclone-v")]
        &crate::families::cyclone_v::BACKEND,
    ];
    REGISTERED
}

//! Compiled board profiles: what a profile declares, and the registry that
//! resolves `--board` lookups. Profiles describe packaging, not hardware
//! initialization.
use crate::{backend::FamilyBackend, error::ImageError};
use serde::Serialize;

/// Input kinds a board profile may declare. Packaging entry points reject
/// payloads whose kind the profile does not declare.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum InputKind {
    /// ELF executables, extracted under the family ELF contract.
    Elf,
    /// Final raw firmware bytes, ROM-encoded as-is.
    Raw,
    /// Complete packaged ROM images, adopted after full verification.
    Packaged,
    /// ELF input with an explicitly placed device tree
    /// (see [`crate::assemble_elf_with_dtb`]).
    Dtb,
}

/// Output artifacts a board profile may declare.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    /// One declared ROM image, including its header and integrity data.
    Bootrom,
    /// A redundant multi-slot boot container.
    Preloader,
    /// A complete MBR disk image with a boot partition and container.
    Sd,
}

/// Board storage policy: boot slot geometry and MBR boot-partition placement.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct StorageLayout {
    /// Size of one boot slot in bytes.
    pub slot_size: usize,
    /// Number of slots in a container (redundant copies of the declared image).
    pub slot_count: usize,
    /// MBR partition type byte that marks the boot partition.
    pub partition_type: u8,
    /// First LBA of the boot partition.
    pub start_lba: u32,
    /// Length of the boot partition in 512-byte sectors.
    pub partition_sectors: u32,
}
impl StorageLayout {
    /// Rejects zero geometry, containers larger than their partition, and
    /// LBA overflow.
    pub fn validate(self) -> Result<(), ImageError> {
        let container = self
            .slot_size
            .checked_mul(self.slot_count)
            .ok_or(ImageError::LengthOverflow)?;
        if self.slot_size == 0
            || self.slot_count == 0
            || self.start_lba == 0
            || self.partition_type == 0
            || container as u64 > u64::from(self.partition_sectors) * 512
            || self.start_lba.checked_add(self.partition_sectors).is_none()
        {
            return Err(ImageError::InvalidStorageLayout);
        }
        Ok(())
    }
}

/// A compiled board: family backend plus declared capabilities and storage
/// policy.
///
/// Profiles describe file packaging policy only — they never initialize
/// physical hardware and cannot identify a board from arbitrary firmware
/// bytes.
#[derive(Debug, Serialize)]
pub struct BoardProfile {
    /// Registry identifier — the value passed to `--board` and [`board`].
    pub id: &'static str,
    /// Human-readable summary shown by `boards`.
    pub description: &'static str,
    /// Family identifier; must match the backend's [`FamilyBackend::id`].
    pub family: &'static str,
    /// Boot image format identifier; must match
    /// [`FamilyBackend::format_id`].
    pub format: &'static str,
    /// The family backend backing this profile.
    #[serde(skip)]
    pub backend: &'static dyn FamilyBackend,
    /// Input kinds packaging accepts for this board.
    pub inputs: &'static [InputKind],
    /// Output formats packaging may render for this board.
    pub outputs: &'static [OutputFormat],
    /// Storage geometry and partition policy.
    pub storage: StorageLayout,
}
impl BoardProfile {
    /// Errors when the profile does not declare the requested input kind.
    pub fn require_input(&self, input: InputKind) -> Result<(), ImageError> {
        if self.inputs.contains(&input) {
            Ok(())
        } else {
            Err(ImageError::UnsupportedCapability {
                board: self.id,
                capability: format!("{input:?} input"),
            })
        }
    }
    /// Errors when the profile does not declare the requested output format.
    pub fn require_output(&self, output: OutputFormat) -> Result<(), ImageError> {
        if self.outputs.contains(&output) {
            Ok(())
        } else {
            Err(ImageError::UnsupportedCapability {
                board: self.id,
                capability: format!("{output:?} output"),
            })
        }
    }
}
/// Every profile compiled into this build, in registration order. Empty when
/// no family feature is enabled.
pub fn boards() -> &'static [&'static BoardProfile] {
    static REGISTERED: &[&BoardProfile] = &[
        #[cfg(feature = "cyclone-v")]
        &crate::families::cyclone_v::GENERIC,
        #[cfg(feature = "board-de1-soc")]
        &crate::families::cyclone_v::DE1_SOC,
    ];
    REGISTERED
}
/// Resolves a profile by registry id, or errors with
/// [`ImageError::UnknownBoard`].
pub fn board(id: &str) -> Result<&'static BoardProfile, ImageError> {
    boards()
        .iter()
        .copied()
        .find(|board| board.id == id)
        .ok_or_else(|| ImageError::UnknownBoard(id.to_owned()))
}

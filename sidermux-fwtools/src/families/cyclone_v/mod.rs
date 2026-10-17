//! The currently supported Cyclone V boot family, with explicit board policy.
mod pack;
pub mod rom;
use crate::{
    backend::{ElfPolicy, FamilyBackend},
    board::{BoardProfile, InputKind, OutputFormat, StorageLayout},
    error::ImageError,
    inspect::BootRomInfo,
    kind::{Check, CrcStatus},
    source::ImageSource,
};

pub const STORAGE: StorageLayout = StorageLayout {
    slot_size: 65536,
    slot_count: 4,
    partition_type: 0xA2,
    start_lba: 2048,
    partition_sectors: 20480,
};
#[derive(Debug)]
pub struct CycloneV;
pub static BACKEND: CycloneV = CycloneV;
const INPUTS: &[InputKind] = &[
    InputKind::Elf,
    InputKind::Raw,
    InputKind::Packaged,
    InputKind::Dtb,
];
const OUTPUTS: &[OutputFormat] = &[
    OutputFormat::Bootrom,
    OutputFormat::Preloader,
    OutputFormat::Sd,
];
pub static GENERIC: BoardProfile = BoardProfile {
    id: "cyclone-v-generic",
    description: "Cyclone V ROM image and default SD layout",
    family: "cyclone-v",
    format: "cyclone-v-rom-v0",
    backend: &BACKEND,
    inputs: INPUTS,
    outputs: OUTPUTS,
    storage: STORAGE,
};
#[cfg(feature = "board-de1-soc")]
pub static DE1_SOC: BoardProfile = BoardProfile {
    id: "de1-soc",
    description: "Terasic DE1-SoC; validated with vendor SPL artifacts",
    family: "cyclone-v",
    format: "cyclone-v-rom-v0",
    backend: &BACKEND,
    inputs: INPUTS,
    outputs: OUTPUTS,
    storage: STORAGE,
};
impl FamilyBackend for CycloneV {
    fn id(&self) -> &'static str {
        "cyclone-v"
    }
    fn format_id(&self) -> &'static str {
        "cyclone-v-rom-v0"
    }
    fn elf_policy(&self) -> ElfPolicy {
        ElfPolicy {
            class: 1,
            endian: 1,
            machine: elf::abi::EM_ARM,
            load_start: 0xFFFF0000,
            load_end: 0xFFFFF000,
            entry_offset: 0x4C,
            instruction_alignment: 4,
            instruction_size: 4,
            require_identity_mapping: true,
        }
    }
    fn default_storage(&self) -> StorageLayout {
        STORAGE
    }
    fn probe_len(&self) -> usize {
        0x4C
    }
    fn has_signature(&self, head: &[u8]) -> bool {
        head.get(0x40..0x44) == Some(b"AS01")
    }
    fn encoded_length(&self, raw_len: usize) -> Result<usize, ImageError> {
        pack::encoded_length(raw_len)
    }
    fn encode(&self, raw: &[u8]) -> Result<Vec<u8>, ImageError> {
        pack::encoded_length(raw.len())?;
        pack::pack_raw(raw.to_vec())
    }
    fn inspect(
        &self,
        source: &mut dyn ImageSource,
        base: u64,
        window: u64,
        verify: bool,
    ) -> Result<BootRomInfo, ImageError> {
        rom::inspect_bootrom_in(source, base, window, verify)
    }
    fn checks(&self, info: &BootRomInfo) -> Vec<Check> {
        rom::bootrom_checks(info)
    }
    fn verified(&self, info: &BootRomInfo) -> bool {
        let Some(header) = info.header.as_cyclone_v() else {
            return false;
        };
        header.validation_word_ok
            && header.version == 0
            && header.header_checksum_ok
            && info.declared_len_ok
            && info.declared_len <= 0xF000
            && info.crc_status == CrcStatus::Passed
            && info.crc_offset.is_some_and(|offset| offset >= 0x50)
    }
}

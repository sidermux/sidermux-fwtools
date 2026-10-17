use elf::{ElfBytes, endian::AnyEndian, segment::ProgramHeader};

use crate::{
    backend::ElfPolicy,
    error::{ElfValidationError, ImageError},
    layout::SegmentLayout,
};

#[tracing::instrument(skip(raw), fields(file_len = raw.len()))]
pub(crate) fn extract_preloader_bin(policy: ElfPolicy, raw: &[u8]) -> Result<Vec<u8>, ImageError> {
    let elf = ElfBytes::<AnyEndian>::minimal_parse(raw)?;

    if raw.get(4) != Some(&policy.class) || raw.get(5) != Some(&policy.endian) {
        return Err(ImageError::UnsupportedElfEncoding);
    }

    tracing::debug!(
        machine = elf.ehdr.e_machine,
        entry = format_args!("0x{:08X}", elf.ehdr.e_entry),
        "Parsed ELF header",
    );

    if elf.ehdr.e_machine != policy.machine {
        return Err(ImageError::UnsupportedMachine {
            actual: elf.ehdr.e_machine,
        });
    }
    let segments = elf.segments().ok_or(ImageError::SegmentsError)?;
    let mut layout = SegmentLayout::default();
    let mut load_count = 0usize;
    let rom_entry = policy
        .load_start
        .checked_add(policy.entry_offset)
        .ok_or(ImageError::LengthOverflow)?;
    if policy.instruction_alignment == 0
        || policy.instruction_size == 0
        || !rom_entry.is_multiple_of(policy.instruction_alignment)
        || !(policy.instruction_size as u64).is_multiple_of(policy.instruction_alignment)
    {
        return Err(ImageError::InvalidEntryAlignment);
    }
    let entry_end = rom_entry
        .checked_add(policy.instruction_size as u64)
        .ok_or(ImageError::LengthOverflow)?;
    if rom_entry < policy.load_start || entry_end > policy.load_end {
        return Err(ImageError::EntryNotExecutable);
    }
    let mut executable_ranges = Vec::new();

    for phdr in segments.iter().filter(|s| s.p_type == elf::abi::PT_LOAD) {
        tracing::trace!(
            offset = phdr.p_offset,
            paddr = phdr.p_paddr,
            vaddr = phdr.p_vaddr,
            filesz = phdr.p_filesz,
            memsz = phdr.p_memsz,
            "Validating load segment",
        );

        validate_phdr(policy, &mut layout, &phdr, raw.len())?;
        if phdr.p_flags & elf::abi::PF_X != 0 {
            let file_end = phdr.p_paddr.checked_add(phdr.p_filesz).ok_or(
                ElfValidationError::AddressOverflow {
                    start: phdr.p_paddr,
                    size: phdr.p_filesz,
                },
            )?;
            executable_ranges.push((phdr.p_paddr, file_end));
        }
        let source_end = phdr.p_offset.checked_add(phdr.p_filesz).unwrap();
        layout.add_segment(policy.load_start, &phdr, source_end)?;

        load_count += 1;
    }

    tracing::debug!(segments = load_count, "Processed ELF load segments");

    if load_count == 0 {
        return Err(ImageError::NoLoadableSegments);
    }
    executable_ranges.sort_unstable();
    let mut covered_until = rom_entry;
    for (start, end) in executable_ranges {
        if start <= covered_until && end > covered_until {
            covered_until = end;
        }
    }
    if covered_until < entry_end {
        return Err(ImageError::EntryNotExecutable);
    }
    layout.extract(raw)
}

fn validate_phdr(
    policy: ElfPolicy,
    layout: &mut SegmentLayout,
    phdr: &ProgramHeader,
    file_len: usize,
) -> Result<(), ElfValidationError> {
    let invalid_source = || ElfValidationError::InvalidSourceRange {
        offset: phdr.p_offset,
        size: phdr.p_filesz,
        file_len,
    };

    let source_end = phdr
        .p_offset
        .checked_add(phdr.p_filesz)
        .ok_or_else(invalid_source)?;

    if source_end > file_len as u64 {
        return Err(invalid_source());
    }

    if phdr.p_filesz > phdr.p_memsz {
        return Err(ElfValidationError::SizeMismatch {
            filesz: phdr.p_filesz,
            memsz: phdr.p_memsz,
        });
    }

    if policy.require_identity_mapping && phdr.p_vaddr != phdr.p_paddr {
        return Err(ElfValidationError::ContractViolation {
            load_addr: phdr.p_paddr,
            exec_addr: phdr.p_vaddr,
        });
    }

    if phdr.p_memsz == 0 {
        return Ok(());
    }

    let mem_start = phdr.p_paddr;
    let mem_end =
        mem_start
            .checked_add(phdr.p_memsz)
            .ok_or(ElfValidationError::AddressOverflow {
                start: mem_start,
                size: phdr.p_memsz,
            })?;

    if mem_start < policy.load_start || mem_end > policy.load_end {
        return Err(ElfValidationError::InvalidOcramAddress {
            addr: mem_start,
            start: policy.load_start,
            end: policy.load_end,
        });
    }

    for &(start, end) in &layout.memory_ranges {
        if mem_start < end && start < mem_end {
            return Err(ElfValidationError::OverlappingSegments {
                start_a: mem_start,
                end_a: mem_end,
                start_b: start,
                end_b: end,
            });
        }
    }

    if source_end > file_len as u64 {
        return Err(invalid_source());
    }

    Ok(())
}

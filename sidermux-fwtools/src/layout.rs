use std::ops::Range;

use elf::segment::ProgramHeader;

use crate::error::{ElfValidationError, ImageError};

struct SegmentCopy {
    src: Range<usize>,
    dst: Range<usize>,
}

#[derive(Default)]
pub(crate) struct SegmentLayout {
    pub(crate) memory_ranges: Vec<(u64, u64)>,
    copies: Vec<SegmentCopy>,
    raw_length: usize,
}

impl SegmentLayout {
    pub(crate) fn add_segment(
        &mut self,
        load_start: u64,
        phdr: &ProgramHeader,
        source_end: u64,
    ) -> Result<(), ElfValidationError> {
        let mem_start = phdr.p_paddr;
        let mem_end =
            mem_start
                .checked_add(phdr.p_memsz)
                .ok_or(ElfValidationError::AddressOverflow {
                    start: mem_start,
                    size: phdr.p_memsz,
                })?;

        let copy: Option<SegmentCopy> = if phdr.p_filesz != 0 {
            let destination_start = phdr
                .p_paddr
                .checked_sub(load_start)
                .ok_or(ElfValidationError::RangeOverflow)?;

            let destination_end = destination_start
                .checked_add(phdr.p_filesz)
                .ok_or(ElfValidationError::RangeOverflow)?;

            let to_usize =
                |value: u64| usize::try_from(value).map_err(|_| ElfValidationError::RangeOverflow);

            Some(SegmentCopy {
                src: to_usize(phdr.p_offset)?..to_usize(source_end)?,
                dst: to_usize(destination_start)?..to_usize(destination_end)?,
            })
        } else {
            None
        };

        self.memory_ranges.push((mem_start, mem_end));
        if let Some(copy) = copy {
            tracing::trace!(
                src = ?copy.src,
                dst = ?copy.dst,
                "Recording ELF segment copy",
            );

            self.raw_length = self.raw_length.max(copy.dst.end);
            self.copies.push(copy);
        }

        Ok(())
    }

    pub(crate) fn extract(&self, elf_bytes: &[u8]) -> Result<Vec<u8>, ImageError> {
        if self.copies.is_empty() {
            return Err(ImageError::NoLoadableSegments);
        }

        let mut output = vec![0u8; self.raw_length];

        for copy in &self.copies {
            tracing::trace!(
                src = ?copy.src,
                dst = ?copy.dst,
                elf_len = elf_bytes.len(),
                output_len = output.len(),
                "Copying ELF segment",
            );

            let source = elf_bytes
                .get(copy.src.clone())
                .ok_or(ImageError::InvalidCopyRange)?;

            let destination = output
                .get_mut(copy.dst.clone())
                .ok_or(ImageError::InvalidCopyRange)?;

            if source.len() != destination.len() {
                return Err(ImageError::InvalidCopyRange);
            }

            destination.copy_from_slice(source);
        }

        Ok(output)
    }
}

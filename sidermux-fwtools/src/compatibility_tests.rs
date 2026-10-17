use crate::{
    BootImage,
    ImageError,
    assemble_elf_with_dtb,
    extract_elf_load_image,
    test_support::{BOARD, elf_with_payload, spl_payload},
};

fn dtb() -> Vec<u8> {
    // Minimal FDT: header, reservation terminator, empty root node, FDT_END.
    let words = [0xD00D_FEEDu32, 72, 56, 72, 40, 17, 16, 0, 0, 16];
    let mut bytes: Vec<_> = words.into_iter().flat_map(u32::to_be_bytes).collect();
    bytes.extend_from_slice(&[0; 16]);
    for word in [1u32, 0, 2, 9] {
        bytes.extend_from_slice(&word.to_be_bytes());
    }
    bytes
}

fn set_phdr(elf: &mut [u8], field: usize, value: u32) {
    elf[52 + field..56 + field].copy_from_slice(&value.to_le_bytes());
}

#[test]
fn entry_requires_executable_file_backing() {
    let payload = spl_payload(0x100);
    let mut elf = elf_with_payload(&payload);
    set_phdr(&mut elf, 24, 4); // read-only, not executable
    assert!(matches!(
        extract_elf_load_image(BOARD, &elf),
        Err(ImageError::EntryNotExecutable)
    ));

    for filesz in [0, 0x4C, 0x4D, 0x4E, 0x4F] {
        let mut elf = elf_with_payload(&payload);
        set_phdr(&mut elf, 16, filesz); // remainder is only BSS
        assert!(matches!(
            extract_elf_load_image(BOARD, &elf),
            Err(ImageError::EntryNotExecutable)
        ));
    }
    let elf = elf_with_payload(&payload[..0x4C]);
    assert!(matches!(
        extract_elf_load_image(BOARD, &elf),
        Err(ImageError::EntryNotExecutable)
    ));
}

// Two file-backed executable segments. Their addresses determine whether the
// entry slot has a gap, partial coverage, or complete adjacent coverage.
fn split_elf(first_len: u32, second_start: u32) -> Vec<u8> {
    let mut elf = elf_with_payload(&spl_payload(0x100));
    elf[44..46].copy_from_slice(&2u16.to_le_bytes());
    set_phdr(&mut elf, 16, first_len);
    set_phdr(&mut elf, 20, first_len);
    let mut phdr = elf[52..84].to_vec();
    phdr[4..8].copy_from_slice(&0x2000u32.to_le_bytes());
    phdr[8..12].copy_from_slice(&(0xFFFF_0000 + second_start).to_le_bytes());
    phdr[12..16].copy_from_slice(&(0xFFFF_0000 + second_start).to_le_bytes());
    phdr[16..20].copy_from_slice(&0x20u32.to_le_bytes());
    phdr[20..24].copy_from_slice(&0x20u32.to_le_bytes());
    phdr[28..32].copy_from_slice(&1u32.to_le_bytes());
    elf[84..116].copy_from_slice(&phdr);
    elf.resize(0x2020, 0xA5);
    elf
}

#[test]
fn extraction_padding_cannot_supply_entry_but_adjacent_executable_bytes_can() {
    assert!(matches!(
        extract_elf_load_image(BOARD, &split_elf(0x4C, 0x50)),
        Err(ImageError::EntryNotExecutable)
    ));
    assert!(matches!(
        extract_elf_load_image(BOARD, &split_elf(0x4E, 0x50)),
        Err(ImageError::EntryNotExecutable)
    ));
    let elf = split_elf(0x4E, 0x4E);
    assert!(extract_elf_load_image(BOARD, &elf).is_ok());
    let mut non_executable_half = elf;
    non_executable_half[108..112].copy_from_slice(&4u32.to_le_bytes());
    assert!(matches!(
        extract_elf_load_image(BOARD, &non_executable_half),
        Err(ImageError::EntryNotExecutable)
    ));
}

#[test]
fn extraction_does_not_append_bss_or_use_debugger_entry() {
    let payload = spl_payload(0x100);
    let mut elf = elf_with_payload(&payload);
    set_phdr(&mut elf, 20, 0x200);
    elf[24..28].copy_from_slice(&0xFFFF_0080u32.to_le_bytes());
    assert_eq!(extract_elf_load_image(BOARD, &elf).unwrap(), payload);
}

#[test]
fn only_little_endian_elf32_arm_is_supported() {
    let mut elf = elf_with_payload(&spl_payload(0x100));
    elf[5] = 2;
    for (offset, size) in [
        (16, 2),
        (18, 2),
        (20, 4),
        (24, 4),
        (28, 4),
        (32, 4),
        (36, 4),
        (40, 2),
        (42, 2),
        (44, 2),
        (46, 2),
        (48, 2),
        (50, 2),
    ] {
        elf[offset..offset + size].reverse();
    }
    assert!(matches!(
        extract_elf_load_image(BOARD, &elf),
        Err(ImageError::UnsupportedElfEncoding)
    ));
    let mut elf = elf_with_payload(&spl_payload(0x100));
    elf[18..20].copy_from_slice(&3u16.to_le_bytes());
    assert!(matches!(
        extract_elf_load_image(BOARD, &elf),
        Err(ImageError::UnsupportedMachine { .. })
    ));
}

#[test]
fn dtb_is_assembled_before_rom_length_and_crc() {
    let payload = spl_payload(0x100);
    let elf = elf_with_payload(&payload);
    let mut tree = dtb();
    tree.extend_from_slice(&[0xAB; 3]); // retain supplied bytes beyond totalsize
    for offset in [0x100, 0x144, 0x201] {
        let mut expected = payload.clone();
        expected.resize(offset, 0);
        expected.extend_from_slice(&tree);
        assert_eq!(
            assemble_elf_with_dtb(BOARD, &elf, &tree, offset).unwrap(),
            expected
        );
        let packed = BootImage::from_elf_with_dtb(BOARD, &elf, &tree, offset).unwrap();
        assert_eq!(
            packed.as_bytes(),
            BootImage::from_raw_spl(BOARD, &expected)
                .unwrap()
                .as_bytes()
        );
        let end = packed.as_bytes().len() - 4;
        assert_eq!(
            u32::from_le_bytes(packed.as_bytes()[end..].try_into().unwrap()),
            sidermux_image::crc32_bzip2(&packed.as_bytes()[..end])
        );
    }
}

#[test]
fn invalid_dtb_assembly_is_rejected_before_allocation() {
    let elf = elf_with_payload(&spl_payload(0x100));
    let tree = dtb();
    assert!(matches!(
        assemble_elf_with_dtb(BOARD, &elf, &tree, 0xFF),
        Err(ImageError::DtbOverlap { .. })
    ));
    assert!(matches!(
        assemble_elf_with_dtb(BOARD, &elf, &tree, usize::MAX),
        Err(ImageError::LengthOverflow)
    ));
    assert!(matches!(
        assemble_elf_with_dtb(BOARD, &elf, &tree, 0xF000),
        Err(ImageError::ImageTooLarge { .. })
    ));
    // Payload fits OCRAM, but the alignment/CRC tail would exceed its limit.
    assert!(matches!(
        assemble_elf_with_dtb(BOARD, &elf, &tree, 0xF000 - tree.len()),
        Err(ImageError::ImageTooLarge { .. })
    ));
    for invalid in [
        vec![],
        tree[..39].to_vec(),
        tree[..tree.len() - 1].to_vec(),
        vec![0; 72],
    ] {
        assert!(matches!(
            assemble_elf_with_dtb(BOARD, &elf, &invalid, 0x100),
            Err(ImageError::InvalidDtb)
        ));
    }
    let mut invalid = tree;
    invalid[4..8].copy_from_slice(&39u32.to_be_bytes());
    assert!(matches!(
        assemble_elf_with_dtb(BOARD, &elf, &invalid, 0x100),
        Err(ImageError::InvalidDtb)
    ));
}

#[test]
fn dtb_cannot_bypass_double_packaging_guard() {
    let packed = BootImage::from_raw_spl(BOARD, &spl_payload(0x100)).unwrap();
    let elf = elf_with_payload(packed.as_bytes());
    assert!(matches!(
        assemble_elf_with_dtb(BOARD, &elf, &dtb(), 0x200),
        Err(ImageError::ElfContainsPackagedImage { .. })
    ));
}

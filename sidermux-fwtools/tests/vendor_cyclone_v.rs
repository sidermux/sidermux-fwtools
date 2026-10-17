#![cfg(feature = "cyclone-v")]
//! Vendor oracle tests for the first supported family. Point
//! SIDERMUX_CYCLONE_V_VENDOR_SPL_DIR at the pinned vendor build's spl/
//! directory (see the crate documentation). Each family owns its own oracle
//! file and environment variables; no fixtures are shared across families.
use sidermux_fwtools::families::cyclone_v::GENERIC;
use std::path::PathBuf;
const BOARD: &sidermux_fwtools::BoardProfile = &GENERIC;

use sidermux_fwtools::{BootImage, assemble_elf_with_dtb, extract_elf_load_image};

fn read(name: &str) -> Vec<u8> {
    let dir = std::env::var_os("SIDERMUX_CYCLONE_V_VENDOR_SPL_DIR").expect(
        "set SIDERMUX_CYCLONE_V_VENDOR_SPL_DIR to the pinned vendor build's spl/ directory",
    );
    std::fs::read(PathBuf::from(dir).join(name)).unwrap()
}

fn dtb_offset() -> usize {
    std::env::var("SIDERMUX_CYCLONE_V_VENDOR_DTB_OFFSET")
        .map(|offset| offset.parse().expect("DTB offset must be decimal"))
        .unwrap_or(0xCF10) // pinned build: nodtb length + __bss_size, not SPL_PAD_TO
}

#[test]
#[ignore = "requires independently built vendor SPL artifacts"]
fn vendor_nop_at_rom_entry_is_accepted() {
    let raw = read("u-boot-spl-nodtb.bin");
    assert_eq!(&raw[0x4C..0x50], &0xE320_F000u32.to_le_bytes());
    assert!(BootImage::from_elf(BOARD, &read("u-boot-spl")).is_ok());
}

#[test]
#[ignore = "requires independently built vendor SPL artifacts"]
fn genuine_elf_extraction_matches_vendor_objcopy() {
    assert_eq!(
        extract_elf_load_image(BOARD, &read("u-boot-spl")).unwrap(),
        read("u-boot-spl-nodtb.bin")
    );
}

#[test]
#[ignore = "requires independently built vendor SPL artifacts"]
fn elf_plus_dtb_matches_vendor_prepackaging_binary() {
    let raw = assemble_elf_with_dtb(
        BOARD,
        &read("u-boot-spl"),
        &read("u-boot-spl.dtb"),
        dtb_offset(),
    )
    .unwrap();
    assert_eq!(raw, read("u-boot-spl.bin"));
}

#[test]
#[ignore = "requires independently built vendor SPL artifacts"]
fn raw_and_assembled_packaging_match_independent_mkimage() {
    let vendor = read("u-boot-spl.sfp");
    let declared = usize::from(u16::from_le_bytes(vendor[0x46..0x48].try_into().unwrap())) * 4;
    let raw_image = BootImage::from_raw_spl(BOARD, &read("u-boot-spl.bin")).unwrap();
    let assembled = BootImage::from_elf_with_dtb(
        BOARD,
        &read("u-boot-spl"),
        &read("u-boot-spl.dtb"),
        dtb_offset(),
    )
    .unwrap();
    assert_eq!(raw_image.as_bytes(), &vendor[..declared]);
    assert_eq!(assembled.as_bytes(), &vendor[..declared]);
}

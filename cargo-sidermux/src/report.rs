//! Human-readable rendering of [`InspectReport`]s.
//!
//! Reports go to stdout (they are the command's output, not diagnostics);
//! only failed and warned checks are highlighted inline.

use std::fmt::Write;

use sidermux_fwtools::{
    InspectReport,
    kind::{Check, CheckStatus, CrcStatus},
    unpack::UnpackReport,
};

fn render_checks(out: &mut String, checks: &[Check]) {
    let passed = checks
        .iter()
        .filter(|c| c.status == CheckStatus::Pass)
        .count();
    let failed = checks
        .iter()
        .filter(|c| c.status == CheckStatus::Fail)
        .count();
    let warned = checks
        .iter()
        .filter(|c| c.status == CheckStatus::Warn)
        .count();

    let _ = writeln!(
        out,
        "  checks: {passed} passed, {failed} failed, {warned} warnings",
    );

    for check in checks.iter().filter(|c| c.status != CheckStatus::Pass) {
        let marker = match check.status {
            CheckStatus::Fail => "FAIL",
            CheckStatus::Warn => "warn",
            CheckStatus::Pass => unreachable!("filtered above"),
        };
        let _ = writeln!(out, "    {marker}: {} - {}", check.name, check.detail);
    }
}

// A single cohesive renderer: the human report interleaves section layout
// and wording, so splitting it adds indirection, not clarity.
#[allow(clippy::too_many_lines)]
pub fn render(report: &InspectReport) -> String {
    let mut out = String::new();
    let input = &report.input;
    let _ = writeln!(
        &mut out,
        "{}: {} ({} bytes, detected as {} by {})",
        match report.input.kind {
            sidermux_fwtools::ImageKind::Elf => "ELF image",
            sidermux_fwtools::ImageKind::BootRom => "Boot ROM image",
            sidermux_fwtools::ImageKind::Preloader => "boot-slot container",
            sidermux_fwtools::ImageKind::SdImage => "SD card image",
        },
        input.path.as_deref().unwrap_or("<stdin>"),
        input.size,
        report.input.kind,
        match report.input.detected_by {
            sidermux_fwtools::DetectionSource::Auto => "detection",
            sidermux_fwtools::DetectionSource::Override => "explicit kind",
        },
    );

    let _ = writeln!(
        &mut out,
        "  family: {}, format: {}, board: {}",
        report.family.unwrap_or("unidentified"),
        report.format.unwrap_or("unidentified"),
        report.board.unwrap_or("not specified")
    );
    if let Some(elf) = &report.elf {
        let _ = writeln!(
            &mut out,
            "  machine: {} ({}), class: {}, endian: {}, entry: 0x{entry:08X}",
            elf.machine_name,
            elf.machine,
            elf.class,
            elf.endian,
            entry = elf.entry,
        );
        let _ = writeln!(&mut out, "  loadable segments: {}", elf.segments.len());
        for (i, seg) in elf.segments.iter().enumerate() {
            let _ = writeln!(
                &mut out,
                "    #{i} offset=0x{offset:X} paddr=0x{paddr:08X} vaddr=0x{vaddr:08X} filesz={filesz} memsz={memsz}",
                offset = seg.offset,
                paddr = seg.paddr,
                vaddr = seg.vaddr,
                filesz = seg.filesz,
                memsz = seg.memsz,
            );
        }
    }

    if let Some(boot) = &report.bootrom {
        render_bootrom(&mut out, boot);
    }

    if let Some(mkp) = &report.preloader {
        let _ = writeln!(
            &mut out,
            "  slot size: {}, slots: {}, identical: {}",
            mkp.slot_size,
            mkp.slot_count,
            identical_text(mkp.identical),
        );
        for (i, slot) in mkp.slots.iter().enumerate() {
            let _ = writeln!(
                &mut out,
                "  slot {i}: declared_len={} crc32={}",
                slot.declared_len,
                crc_text(slot.crc32, slot.crc_status),
            );
        }
    }

    if let Some(sd) = &report.sd {
        let _ = writeln!(
            &mut out,
            "  MBR signature: {}",
            if sd.signature_ok { "ok" } else { "MISSING" },
        );
        let _ = writeln!(&mut out, "  partitions: {}", sd.partitions.len());
        for part in &sd.partitions {
            let _ = writeln!(
                &mut out,
                "    #{} type=0x{:02X}{} start={} sectors={}",
                part.index,
                part.partition_type,
                if part.bootable { " bootable" } else { "" },
                part.start_lba,
                part.sectors,
            );
        }
        if let Some(a2) = &sd.boot_partition {
            let _ = writeln!(
                &mut out,
                "  boot partition: start LBA {}, {} sectors, extent within file: {}",
                a2.start_lba,
                a2.sectors,
                if a2.within_file { "yes" } else { "NO" },
            );
            if let Some(container) = &a2.container {
                let _ = writeln!(
                    &mut out,
                    "    container: {} slots, identical: {}",
                    container.slot_count,
                    identical_text(container.identical),
                );
                let bad = container
                    .slots
                    .iter()
                    .filter(|s| s.crc_status == CrcStatus::Failed)
                    .count();
                let unchecked = container
                    .slots
                    .iter()
                    .filter(|s| s.crc_status == CrcStatus::NotChecked)
                    .count();
                if unchecked == container.slots.len() {
                    let _ = writeln!(&mut out, "    container CRCs: not checked");
                } else if bad == 0 {
                    let _ = writeln!(&mut out, "    container CRCs: all ok");
                } else {
                    let _ = writeln!(&mut out, "    container CRCs: {bad} failing slots");
                }
            } else {
                let _ = writeln!(&mut out, "    container: none found at partition start");
            }
        }
    }

    render_checks(&mut out, &report.checks);
    out
}

fn crc_text(crc32: Option<u32>, status: CrcStatus) -> String {
    match (crc32, status) {
        (Some(crc), CrcStatus::Passed) => format!("0x{crc:08X} (ok)"),
        (Some(crc), CrcStatus::Failed) => format!("0x{crc:08X} (MISMATCH)"),
        (Some(crc), CrcStatus::NotChecked) => format!("0x{crc:08X} (not checked)"),
        (Some(crc), CrcStatus::Unreadable) => format!("0x{crc:08X} (unreadable region)"),
        (_, CrcStatus::NotChecked) => "not checked".to_string(),
        (_, CrcStatus::Unreadable) => "unreadable".to_string(),
        (_, CrcStatus::NotApplicable) => "n/a".to_string(),
        (None, _) => "-".to_string(),
    }
}

fn identical_text(identical: Option<bool>) -> &'static str {
    match identical {
        Some(true) => "yes",
        Some(false) => "NO",
        None => "not checked",
    }
}

fn render_bootrom(out: &mut String, boot: &sidermux_fwtools::inspect::BootRomInfo) {
    #[cfg(feature = "cyclone-v")]
    if let Some(header) = boot.header.as_cyclone_v() {
        let _ = writeln!(
            out,
            "  validation word: 0x{:08X} ({})",
            header.validation_word,
            if header.validation_word_ok {
                "ok"
            } else {
                "INVALID"
            },
        );
        let _ = writeln!(
            out,
            "  header: version={} flags={} length_words={} declared_len={} checksum=0x{:04X} ({})",
            header.version,
            header.flags,
            header.length_words,
            boot.declared_len,
            header.header_checksum,
            if header.header_checksum_ok {
                "ok"
            } else {
                "MISMATCH"
            },
        );
    }
    let _ = writeln!(out, "  declared image: {} bytes", boot.declared_len);
    let crc = crc_text(boot.crc32, boot.crc_status);
    let _ = writeln!(out, "  CRC-32: {crc}");
    if let Some(sha) = &boot.payload_sha256 {
        let _ = writeln!(out, "  SHA-256 (declared image): {sha}");
    }
}

/// Human-readable rendering of an [`UnpackReport`].
pub fn render_unpack(report: &UnpackReport) -> String {
    let mut out = String::new();
    let _ = writeln!(
        &mut out,
        "Unpacked {} image into {} ({} files)",
        report.kind,
        report.output_dir,
        report.files.len(),
    );

    for file in &report.files {
        let crc = match file.crc_status {
            CrcStatus::Passed => "ok",
            CrcStatus::Failed => "MISMATCH",
            CrcStatus::NotChecked => "not checked",
            CrcStatus::Unreadable => "unreadable",
            CrcStatus::NotApplicable => "n/a",
        };
        let _ = writeln!(
            &mut out,
            "  {}: {} bytes from offset 0x{:X}, CRC {}",
            file.name, file.size, file.source_offset, crc,
        );
    }

    render_checks(&mut out, &report.checks);
    out
}

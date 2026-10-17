//! A deliberately different format exercises shared code without production
//! family features. It is a software test format, not hardware support.
use crate::{
    BootImage, Check, CheckStatus, CrcStatus, ImageError, ImageKind,
    backend::{ElfPolicy, FamilyBackend},
    board::{BoardProfile, InputKind, OutputFormat, StorageLayout},
    extract_elf_load_image,
    inspect::{self, BootRomInfo, HeaderDetails, InspectOptions},
    source::ImageSource,
};

#[derive(Debug)]
struct TestBackend(&'static str);
static BACKEND: TestBackend = TestBackend("test-only");
const STORAGE: StorageLayout = StorageLayout {
    slot_size: 128,
    slot_count: 2,
    partition_type: 0xDA,
    start_lba: 8,
    partition_sectors: 2,
};
const INPUTS: &[InputKind] = &[
    InputKind::Elf,
    InputKind::Raw,
    InputKind::Packaged,
    InputKind::Dtb,
];
static BOARD: BoardProfile = BoardProfile {
    id: "test-only",
    description: "synthetic backend",
    family: "test-only",
    format: "test-rom",
    backend: &BACKEND,
    inputs: INPUTS,
    outputs: &[
        OutputFormat::Bootrom,
        OutputFormat::Preloader,
        OutputFormat::Sd,
    ],
    storage: STORAGE,
};

impl FamilyBackend for TestBackend {
    fn id(&self) -> &'static str {
        self.0
    }
    fn format_id(&self) -> &'static str {
        "test-rom"
    }
    fn elf_policy(&self) -> ElfPolicy {
        ElfPolicy {
            class: 1,
            endian: 1,
            machine: 243,
            load_start: 0x1000,
            load_end: 0x2000,
            entry_offset: 0x20,
            instruction_alignment: 2,
            instruction_size: 2,
            require_identity_mapping: false,
        }
    }
    fn default_storage(&self) -> StorageLayout {
        STORAGE
    }
    fn probe_len(&self) -> usize {
        8
    }
    fn has_signature(&self, head: &[u8]) -> bool {
        head.starts_with(b"TEST")
    }
    fn encoded_length(&self, len: usize) -> Result<usize, ImageError> {
        let len = len.checked_add(11).ok_or(ImageError::LengthOverflow)? & !7;
        if len > 128 {
            return Err(ImageError::ImageTooLarge {
                size: len,
                max: 128,
            });
        }
        Ok(len)
    }
    fn encode(&self, raw: &[u8]) -> Result<Vec<u8>, ImageError> {
        if raw.len() < 0x22 {
            return Err(ImageError::InputTooShort {
                actual: raw.len(),
                needed: 0x22,
            });
        }
        let len = self.encoded_length(raw.len())?;
        let mut image = raw.to_vec();
        image.resize(len, 0);
        image[..4].copy_from_slice(b"TEST");
        image[4..8].copy_from_slice(&(len as u32).to_le_bytes());
        let crc = sidermux_image::crc32_bzip2(&image[..len - 4]);
        image[len - 4..].copy_from_slice(&crc.to_le_bytes());
        Ok(image)
    }
    fn inspect(
        &self,
        src: &mut dyn ImageSource,
        base: u64,
        window: u64,
        verify: bool,
    ) -> Result<BootRomInfo, ImageError> {
        if window < 8 {
            return Err(ImageError::TruncatedImage {
                needed: 8,
                actual: window as usize,
            });
        }
        let mut header = [0; 8];
        src.read_exact_at(base, &mut header)?;
        let len = u32::from_le_bytes(header[4..8].try_into().unwrap()) as usize;
        let valid_len = len >= 0x28 && len as u64 <= window && len <= 128;
        let mut info = BootRomInfo {
            header: HeaderDetails::Test {
                tag: u32::from_le_bytes(header[..4].try_into().unwrap()),
            },
            checks: vec![],
            declared_len: len,
            declared_len_ok: valid_len,
            crc_offset: len.checked_sub(4).map(|v| v as u64),
            crc32: None,
            crc_status: CrcStatus::NotChecked,
            payload_sha256: None,
        };
        if verify {
            info.crc_status = CrcStatus::Unreadable;
            if valid_len {
                let mut bytes = vec![0; len];
                src.read_exact_at(base, &mut bytes)?;
                let stored = u32::from_le_bytes(bytes[len - 4..].try_into().unwrap());
                info.crc32 = Some(stored);
                info.crc_status = if stored == sidermux_image::crc32_bzip2(&bytes[..len - 4]) {
                    CrcStatus::Passed
                } else {
                    CrcStatus::Failed
                };
            }
        }
        Ok(info)
    }
    fn checks(&self, info: &BootRomInfo) -> Vec<Check> {
        vec![Check::binary(
            "test format",
            self.verified(info),
            "invalid test image",
        )]
    }
    fn verified(&self, info: &BootRomInfo) -> bool {
        matches!(info.header, HeaderDetails::Test { tag } if tag == u32::from_le_bytes(*b"TEST"))
            && info.declared_len_ok
            && info.crc_status == CrcStatus::Passed
    }
}
fn elf() -> Vec<u8> {
    let mut bytes = include_bytes!("../tests/fixtures/fixture.elf").to_vec();
    bytes[18..20].copy_from_slice(&243u16.to_le_bytes());
    bytes[24..28].copy_from_slice(&0x3000u32.to_le_bytes());
    bytes[60..64].copy_from_slice(&0x3000u32.to_le_bytes());
    bytes[64..68].copy_from_slice(&0x1000u32.to_le_bytes());
    bytes
}

#[test]
fn alternative_backend_controls_extraction_encoding_and_storage() {
    let elf = elf();
    let raw = extract_elf_load_image(&BOARD, &elf).unwrap();
    assert_eq!(raw, elf[0x1000..0x1054]);
    let image = BootImage::from_elf(&BOARD, &elf).unwrap();
    assert_eq!(image.as_bytes().len(), 88);
    assert!(image.as_bytes().starts_with(b"TEST"));
    let container = image.render(OutputFormat::Preloader).unwrap();
    assert_eq!(container.len(), 256);
    assert_eq!(&container[..128], &container[128..]);
    let sd = image.render(OutputFormat::Sd).unwrap();
    assert_eq!(sd.len(), 5120);
    assert_eq!(sd[0x1C2], 0xDA);
    assert_eq!(&sd[4096..4352], &container);
    let report = inspect::inspect_bytes(
        &sd,
        InspectOptions {
            board: Some(&BOARD),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(report.schema, 3);
    assert_eq!(report.family, Some("test-only"));
    assert_eq!(report.board, Some("test-only"));
    assert!(report.checks.iter().all(|c| c.status != CheckStatus::Fail));
    let part = report.sd.unwrap().boot_partition.unwrap();
    assert_eq!(part.start_lba, 8);
    assert_eq!(part.container.unwrap().slot_count, 2);
    assert_eq!(
        BootImage::adopt_packaged(&BOARD, &container)
            .unwrap()
            .as_bytes(),
        image.as_bytes()
    );
}

#[test]
fn alternative_backend_controls_entry_coverage_and_alignment() {
    let mut elf = elf();
    elf[68..72].copy_from_slice(&0x21u32.to_le_bytes());
    assert!(matches!(
        extract_elf_load_image(&BOARD, &elf),
        Err(ImageError::EntryNotExecutable)
    ));
    #[derive(Debug)]
    struct BadAlignment;
    impl FamilyBackend for BadAlignment {
        fn id(&self) -> &'static str {
            "bad-align"
        }
        fn format_id(&self) -> &'static str {
            "test-rom"
        }
        fn elf_policy(&self) -> ElfPolicy {
            let mut p = BACKEND.elf_policy();
            p.entry_offset = 0x21;
            p
        }
        fn default_storage(&self) -> StorageLayout {
            STORAGE
        }
        fn probe_len(&self) -> usize {
            8
        }
        fn has_signature(&self, h: &[u8]) -> bool {
            BACKEND.has_signature(h)
        }
        fn encoded_length(&self, l: usize) -> Result<usize, ImageError> {
            BACKEND.encoded_length(l)
        }
        fn encode(&self, r: &[u8]) -> Result<Vec<u8>, ImageError> {
            BACKEND.encode(r)
        }
        fn inspect(
            &self,
            s: &mut dyn ImageSource,
            b: u64,
            w: u64,
            v: bool,
        ) -> Result<BootRomInfo, ImageError> {
            BACKEND.inspect(s, b, w, v)
        }
        fn checks(&self, i: &BootRomInfo) -> Vec<Check> {
            BACKEND.checks(i)
        }
        fn verified(&self, i: &BootRomInfo) -> bool {
            BACKEND.verified(i)
        }
    }
    static BAD: BadAlignment = BadAlignment;
    let board = BoardProfile {
        backend: &BAD,
        ..BOARD
    };
    assert!(matches!(
        extract_elf_load_image(&board, &super::backend_tests::elf()),
        Err(ImageError::InvalidEntryAlignment)
    ));
}

#[test]
fn board_capabilities_and_unknown_profiles_are_reported() {
    static LIMITED: BoardProfile = BoardProfile {
        id: "limited",
        description: "test",
        family: "test-only",
        format: "test-rom",
        backend: &BACKEND,
        inputs: &[InputKind::Raw],
        outputs: &[OutputFormat::Bootrom],
        storage: STORAGE,
    };
    assert!(matches!(
        BootImage::from_elf(&LIMITED, &elf()),
        Err(ImageError::UnsupportedCapability { .. })
    ));
    let image = BootImage::from_raw_spl(&LIMITED, &[0; 0x30]).unwrap();
    assert!(matches!(
        image.render(OutputFormat::Sd),
        Err(ImageError::UnsupportedCapability { .. })
    ));
    static SD_ONLY: BoardProfile = BoardProfile {
        id: "sd-only",
        description: "test",
        family: "test-only",
        format: "test-rom",
        backend: &BACKEND,
        inputs: &[InputKind::Raw],
        outputs: &[OutputFormat::Sd],
        storage: STORAGE,
    };
    let image = BootImage::from_raw_spl(&SD_ONLY, &[0; 0x30]).unwrap();
    assert!(image.render(OutputFormat::Sd).is_ok());
    assert!(matches!(
        image.to_container(),
        Err(ImageError::UnsupportedCapability { .. })
    ));
    assert!(matches!(
        crate::board::board("does-not-exist"),
        Err(ImageError::UnknownBoard(_))
    ));
}

#[test]
fn alternative_backend_unpack_uses_profile_slot_offsets() {
    let image = BootImage::from_elf(&BOARD, &elf()).unwrap();
    let dir = std::env::temp_dir().join(format!("sidermux-backend-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let input = dir.join("test.img");
    std::fs::write(&input, image.to_sd_image().unwrap()).unwrap();
    let output = dir.join("out");
    let report = crate::unpack::unpack_image(
        &input,
        &output,
        crate::unpack::UnpackOptions {
            board: Some(&BOARD),
            kind: None,
        },
    )
    .unwrap();
    assert_eq!(report.kind, ImageKind::SdImage);
    assert_eq!(report.files.len(), 3);
    for index in 0..2 {
        assert_eq!(
            std::fs::read(output.join(format!("slot{index}.bin"))).unwrap(),
            image.as_bytes()
        );
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn multiple_matching_families_require_a_board_override() {
    static OTHER: TestBackend = TestBackend("other-test");
    let image = BootImage::from_elf(&BOARD, &elf()).unwrap();
    let mut src = crate::source::BytesSource(image.as_bytes());
    assert!(matches!(
        inspect::resolve_backends(&mut src, &InspectOptions::default(), &[&BACKEND, &OTHER]),
        Err(ImageError::AmbiguousFamily(_))
    ));
    let mut src = crate::source::BytesSource(image.as_bytes());
    let (ctx, kind, _) = inspect::resolve_backends(
        &mut src,
        &InspectOptions {
            board: Some(&BOARD),
            ..Default::default()
        },
        &[&BACKEND, &OTHER],
    )
    .unwrap();
    assert_eq!(ctx.unwrap().backend.id(), "test-only");
    assert_eq!(kind, ImageKind::BootRom);
}

#[test]
fn no_family_features_leave_generic_elf_inspection_available() {
    let image = BootImage::from_elf(&BOARD, &elf()).unwrap();
    let mut src = crate::source::BytesSource(image.as_bytes());
    assert!(matches!(
        inspect::resolve_backends(&mut src, &InspectOptions::default(), &[]),
        Err(ImageError::NoBackend)
    ));
    let report = inspect::inspect_bytes(&elf(), InspectOptions::default()).unwrap();
    assert_eq!(report.schema, 3);
    assert_eq!(report.board, None);
    assert_eq!(report.family, None);
}

//! Integration tests for the `cargo sidermux pack` subcommand.
#![cfg(feature = "cyclone-v")]
use std::{
    path::PathBuf,
    process::{Command, Output},
    sync::atomic::{AtomicUsize, Ordering},
};

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "sidermux-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_cargo-sidermux"))
            .current_dir(&self.0)
            .args(args)
            .args(["--board", "cyclone-v-generic"])
            .output()
            .unwrap()
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn dtb() -> Vec<u8> {
    let mut bytes: Vec<u8> = [0xD00D_FEEDu32, 72, 56, 72, 40, 17, 16, 0, 0, 16]
        .into_iter()
        .flat_map(u32::to_be_bytes)
        .collect();
    bytes.extend_from_slice(&[0; 16]);
    bytes.extend([1u32, 0, 2, 9].into_iter().flat_map(u32::to_be_bytes));
    bytes
}

#[test]
fn cli_assembles_dtb_and_packages_final_raw_binary_identically() {
    let dir = TestDir::new();
    let mut elf = include_bytes!("../../sidermux-fwtools/tests/fixtures/fixture.elf").to_vec();
    elf[0x104C..0x1050].copy_from_slice(&0xE320_F000u32.to_le_bytes());
    std::fs::write(dir.0.join("spl.elf"), &elf).unwrap();
    let tree = dtb();
    std::fs::write(dir.0.join("spl.dtb"), &tree).unwrap();
    let mut raw = elf[0x1000..0x1054].to_vec();
    raw.resize(0x100, 0);
    raw.extend_from_slice(&tree);
    std::fs::write(dir.0.join("spl.bin"), &raw).unwrap();

    for format in ["bootrom", "preloader", "sd"] {
        for offset in ["0x100", "256"] {
            let result = dir.run(&[
                "pack",
                "spl.elf",
                "--dtb",
                "spl.dtb",
                "--dtb-offset",
                offset,
                "--format",
                format,
                "--output",
                "assembled.bin",
            ]);
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            let result = dir.run(&["pack", "spl.bin", "--format", format, "--output", "raw.bin"]);
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert_eq!(
                std::fs::read(dir.0.join("assembled.bin")).unwrap(),
                std::fs::read(dir.0.join("raw.bin")).unwrap()
            );
        }
    }
}

#[test]
fn invalid_dtb_options_never_write_an_output() {
    let dir = TestDir::new();
    std::fs::write(dir.0.join("raw.bin"), vec![0u8; 0x100]).unwrap();
    std::fs::write(
        dir.0.join("spl.elf"),
        include_bytes!("../../sidermux-fwtools/tests/fixtures/fixture.elf"),
    )
    .unwrap();
    std::fs::write(dir.0.join("spl.dtb"), dtb()).unwrap();
    let cases: &[&[&str]] = &[
        &["spl.elf", "--dtb", "spl.dtb"],
        &["spl.elf", "--dtb-offset", "256"],
        &[
            "spl.elf",
            "--dtb",
            "spl.dtb",
            "--dtb-offset",
            "256",
            "--packaged",
        ],
        &["raw.bin", "--dtb", "spl.dtb", "--dtb-offset", "256"],
        &["spl.elf", "--dtb", "spl.dtb", "--dtb-offset", "0x10"],
        &["spl.elf", "--dtb", "spl.dtb", "--dtb-offset", "0xF000"],
        &["spl.elf", "--dtb", "spl.dtb", "--dtb-offset", "0x"],
        &[
            "spl.elf",
            "--dtb",
            "spl.dtb",
            "--dtb-offset",
            "184467440737095516160",
        ],
    ];
    for args in cases {
        let mut command = vec!["pack"];
        command.extend_from_slice(args);
        command.extend_from_slice(&["--output", "output.bin"]);
        let result = dir.run(&command);
        assert!(!result.status.success(), "unexpected success for {args:?}");
        assert_ne!(result.stderr, b"");
        assert!(!dir.0.join("output.bin").exists());
    }
}

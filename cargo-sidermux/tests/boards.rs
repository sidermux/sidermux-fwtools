//! Integration tests for the `cargo sidermux boards` subcommand.
use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_cargo-sidermux"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn board_listing_reflects_compiled_features() {
    let output = run(&["boards", "--json"]);
    assert!(output.status.success());
    let profiles: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let profiles = profiles.as_array().unwrap();
    assert_eq!(
        profiles.len(),
        usize::from(cfg!(feature = "cyclone-v")) + usize::from(cfg!(feature = "board-de1-soc"))
    );
    for profile in profiles {
        assert_eq!(profile["family"], "cyclone-v");
        assert_eq!(profile["format"], "cyclone-v-rom-v0");
        assert_eq!(profile["storage"]["slot_count"], 4);
        assert!(
            profile["inputs"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("dtb"))
        );
        assert!(profile.get("backend").is_none());
    }
}

#[test]
fn pack_requires_an_explicit_board() {
    let result = run(&["pack", "input.elf", "--output", "output.img"]);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("--board"));
}

#[test]
fn unavailable_board_produces_a_diagnostic() {
    let result = run(&[
        "pack",
        "input.elf",
        "--board",
        "not-compiled",
        "--output",
        "output.img",
    ]);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("unknown or unavailable board"));
}

#[test]
fn cargo_subcommand_name_is_sidermux() {
    let result = run(&["sidermux", "--version"]);
    assert!(result.status.success());
    assert!(String::from_utf8_lossy(&result.stdout).starts_with("cargo-sidermux "));
}

#[test]
fn elf_json_has_no_inferred_board_or_family() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../sidermux-fwtools/tests/fixtures/fixture.elf"
    );
    let result = run(&["inspect", fixture, "--json"]);
    assert!(result.status.success());
    let value: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["schema"], 3);
    assert!(value["board"].is_null());
    assert!(value["family"].is_null());
}

#[cfg(feature = "cyclone-v")]
#[test]
fn compiled_profiles_preserve_output_and_do_not_get_auto_identified() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../sidermux-fwtools/tests/fixtures/fixture.elf"
    );
    let dir = std::env::temp_dir().join(format!("sidermux-profiles-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let output = dir.join("bootrom.bin");
    let output_str = output.to_str().unwrap();
    for board in ["cyclone-v-generic", "de1-soc"] {
        if board == "de1-soc" && !cfg!(feature = "board-de1-soc") {
            continue;
        }
        let packed = run(&[
            "pack", fixture, "--board", board, "--format", "bootrom", "--output", output_str,
        ]);
        assert!(
            packed.status.success(),
            "{}",
            String::from_utf8_lossy(&packed.stderr)
        );
        let inspected = run(&["inspect", output_str, "--json"]);
        assert!(inspected.status.success());
        let value: serde_json::Value = serde_json::from_slice(&inspected.stdout).unwrap();
        assert!(value["board"].is_null());
        assert_eq!(value["family"], "cyclone-v");
        assert_eq!(value["bootrom"]["header"]["family"], "cyclone-v");
        let explicit = run(&["inspect", output_str, "--board", board, "--json"]);
        let value: serde_json::Value = serde_json::from_slice(&explicit.stdout).unwrap();
        assert_eq!(value["board"], board);
    }
    std::fs::remove_dir_all(dir).unwrap();
}

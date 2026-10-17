//! `cargo sidermux` packages, inspects, and unpacks SoC FPGA boot images.
//!
//! > [!WARNING]
//! > **Beta software.** This project is pre-release and breaking changes may
//! > happen frequently between versions. Pin the exact version you depend on.
//!
//! First supported family: Cyclone V (boards `cyclone-v-generic`, `de1-soc`).
//!
//! # Install
//!
//! ```sh
//! cargo install --path cargo-sidermux
//! ```
//!
//! # Boards
//!
//! ```sh
//! cargo sidermux boards
//! cargo sidermux boards --json
//! ```
//!
//! Default builds include `cyclone-v-generic` and `de1-soc`. Both use the
//! same family ROM codec and current default storage layout. The DE1-SoC path
//! has been compared against vendor SPL artifacts. Profiles describe
//! packaging; they do not generate board initialization, FPGA configuration,
//! or firmware.
//!
//! # Packing
//!
//! Packaging requires an explicit board:
//!
//! ```sh
//! cargo sidermux pack bootloader.elf --board cyclone-v-generic --output system.sd.img
//! cargo sidermux pack u-boot-spl.bin --board de1-soc --format preloader --output preloader-mkpimage.bin
//! cargo sidermux pack bootloader.elf --board cyclone-v-generic --format bootrom --output bootloader.bin
//! ```
//!
//! `--format` defaults to `sd`. Available formats depend on the selected
//! profile:
//!
//! | Format | Contents | Write directly to the whole SD card? |
//! | --- | --- | --- |
//! | `bootrom` | One declared ROM image, including header and integrity data | No |
//! | `preloader` | Redundant boot-slot container | No; goes inside a boot partition |
//! | `sd` | Complete MBR disk image with boot partition and container | Yes |
//!
//! For the two current profiles, a container contains four zero-padded 64 KiB
//! slots. SD output is 11 MiB: an MBR and a 10 MiB partition of type `0xA2`
//! starting at LBA 2048. These storage defaults belong to profiles, not the
//! shared pipeline or every future family.
//!
//! # Inputs and appended DTBs
//!
//! ELF input is extracted from file-backed load segments at the selected
//! family's load addresses. Executable file bytes must cover its entire ROM
//! entry slot; BSS and extraction padding cannot supply entry instructions.
//!
//! For the first supported family, the supported input is ELF32
//! little-endian ARM with a word-aligned ROM entry at `0xFFFF004C`. A NOP at
//! that address is accepted: no instruction whitelist is used. ELF `e_entry`
//! does not replace the ROM entry. The header occupies `0x40..0x4C`; encoding
//! adds 16-byte alignment and the CRC-32/BZIP2 tail without overwriting the
//! entry slot.
//!
//! The simplest vendor input is the final raw SPL passed to the vendor ROM
//! image tool, such as `u-boot-spl.bin`. This already includes any appended
//! device tree. Raw bytes carry no executable metadata, so the caller must
//! supply a genuine SPL with its header reservation intact.
//!
//! When the DTB was appended after ELF linking, provide it explicitly:
//!
//! ```sh
//! cargo sidermux pack u-boot-spl --board de1-soc \
//!   --dtb u-boot-spl.dtb --dtb-offset 0xCF10 \
//!   --format preloader --output preloader-mkpimage.bin
//! ```
//!
//! `--dtb` and `--dtb-offset` require each other. The offset is measured from
//! image start, accepts decimal or hexadecimal, and must come from the actual
//! firmware build. The tool extracts the ELF, zero-fills the gap, appends the
//! DTB, then encodes the ROM header, final padding, and CRC. Invalid or
//! truncated DTBs, overlapping offsets, overflow, and oversized images are
//! rejected.
//!
//! The vendor build tested here concatenates 51,916 extracted bytes, 1,092
//! zero bytes from `__bss_size`, and a 2,074-byte DTB, placing the DTB at
//! `0xCF10`. This is not a universal U-Boot rule; `CONFIG_SPL_PAD_TO` does not
//! determine that placement. Profiles do not infer it.
//!
//! A fully verified packaged ROM image is adopted with its declared bytes
//! preserved. An ELF containing an already-packaged image is rejected unless
//! `--packaged` explicitly selects adoption. DTB options apply only to
//! unpackaged ELF input and conflict with `--packaged`.
//!
//! # Inspection and unpacking
//!
//! ```sh
//! cargo sidermux inspect system.sd.img
//! cargo sidermux inspect system.sd.img --json
//! cargo sidermux inspect system.sd.img --board de1-soc --no-verify
//! cargo sidermux unpack system.sd.img --output unpacked/
//! ```
//!
//! Inspection and unpacking probe compiled backends automatically. `--board`
//! selects a backend and storage policy explicitly. `--kind` with
//! `elf`, `bootrom`, `preloader`, or `sd` resolves ambiguity between
//! envelopes, such as a padded single
//! slot that is both a ROM image and a one-slot container. If multiple
//! families match, select `--board`; the tool does not guess. A shared ROM
//! signature cannot identify a physical board, so automatically detected
//! reports leave `board` unset. Generic ELF metadata inspection also works
//! without any family backend.
//!
//! Inspection JSON uses **schema 3**, with `family`, `format`, and optional
//! `board` metadata. Family-specific header fields live under the tagged
//! `header` details. Container geometry and boot-partition information are
//! reported independently of the family. Integrity verification is enabled by
//! default; `--no-verify` reports it as unchecked. Corruption is represented
//! by failed checks rather than discarded metadata.
//!
//! Binary inspection uses seeks and bounded reads. Structural SD inspection
//! reads headers and partition metadata; verification streams declared images
//! and compares boot slots without loading the whole disk. ELF inputs are read
//! into memory for parsing.
//!
//! Unpacking shares inspection parsers and writes `bootrom.bin`, `slotN.bin`,
//! or `mbr.bin` plus slots, depending on input. It reports integrity failures
//! while preserving extractable corrupt bytes. ELF is a packaging source and
//! is not an unpack target.
//!
//! # Logging and diagnostics
//!
//! Reports and JSON go to stdout. Operational logs use tracing on stderr; `-v`
//! enables debug details and `-vv` trace details. `RUST_LOG` overrides those
//! levels. Application errors use miette diagnostics.
//!
//! The underlying library API is documented in
//! [`sidermux-fwtools`](https://docs.rs/sidermux-fwtools).
mod report;

use std::{
    io::{self, IsTerminal, Write},
    path::{Path, PathBuf},
};

use clap::{ArgAction, Parser, Subcommand, ValueEnum};
use miette::{GraphicalReportHandler, GraphicalTheme, IntoDiagnostic, Result, WrapErr};
use sidermux_fwtools::{
    BootImage,
    board::{self, OutputFormat},
    inspect,
    kind::ImageKind,
    unpack,
};
use tracing_subscriber::EnvFilter;

const FORMATS_HELP: &str = "\
Output formats (availability and layout depend on --board):
  bootrom    One declared ROM image, with its family header and integrity data.
  preloader  Redundant boot-slot container for the selected board.
  sd         Complete MBR disk image with the selected board's boot container.
Use `cargo sidermux boards` to list compiled profiles and capabilities.";

#[derive(Debug, Parser)]
#[command(name = "cargo-sidermux", version, about, after_help = FORMATS_HELP)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Increase operational detail: ELF properties, image sizes, checksum
    /// results, SD layout (-v); copy ranges, padding decisions, detailed
    /// diagnostics (-vv). Logs go to stderr.
    #[arg(short, long, action = ArgAction::Count, global = true)]
    verbose: u8,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// List compiled board profiles, capabilities, and storage defaults.
    Boards {
        #[arg(long)]
        json: bool,
    },
    /// Package an ELF, raw SPL bytes, or a packaged ROM image into a Boot
    /// ROM image, container, or SD card image.
    Pack {
        /// ELF (load segments are extracted), raw SPL bytes
        /// (header/padding/CRC are appended), or a complete packaged ROM
        /// image (its declared bytes are preserved and only wrapped).
        input: PathBuf,

        #[arg(long)]
        board: String,

        /// Output format (see the format table below).
        #[arg(short, long, default_value = "sd")]
        format: FormatArg,

        #[arg(short, long)]
        output: PathBuf,

        /// Explicit packaged-payload mode: treat the input (or the ELF's
        /// extracted payload) as a complete packaged ROM image — preserve
        /// its declared bytes and wrap only, never re-encode. Required for
        /// ELFs whose payload is already a packaged image.
        #[arg(long)]
        packaged: bool,

        /// Append a DTB to an unpackaged ELF before header and CRC encoding.
        #[arg(long, requires = "dtb_offset", conflicts_with = "packaged")]
        dtb: Option<PathBuf>,

        /// DTB byte offset from image start (decimal or 0x hex). Obtain this
        /// from the vendor build; the intervening gap is filled with zeros.
        #[arg(long, requires = "dtb", conflicts_with = "packaged", value_parser = parse_offset)]
        dtb_offset: Option<usize>,
    },

    /// Report the structure and integrity of an ELF or packaged image.
    ///
    /// Reports go to stdout; pass --json for machine-readable output.
    /// Integrity verification (CRC) runs by default and reads only the
    /// declared image ranges; pass --no-verify for a fast structural
    /// inspection, which reports the CRC as not checked.
    Inspect {
        input: PathBuf,
        #[arg(long)]
        board: Option<String>,

        /// Emit the report as JSON.
        #[arg(long)]
        json: bool,

        /// Skip integrity verification (CRC is reported as not checked).
        #[arg(long)]
        no_verify: bool,

        /// Skip format detection and force a specific kind.
        #[arg(long)]
        kind: Option<KindArg>,
    },

    /// Write the unpacked contents of a packaged image to a directory.
    ///
    /// Produces bootrom.bin, per-slot slotN.bin files, and the MBR, reading
    /// only the byte ranges actually written. Each file's CRC is verified
    /// from the bytes in hand; extraction proceeds even when checks fail.
    Unpack {
        input: PathBuf,
        #[arg(long)]
        board: Option<String>,

        /// Directory to write the unpacked files into (created if missing).
        #[arg(short, long)]
        output: PathBuf,

        /// Skip format detection and force a specific kind.
        #[arg(long)]
        kind: Option<KindArg>,
    },
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum FormatArg {
    /// One header/CRC-completed Boot ROM image.
    Bootrom,
    /// Redundant boot-slot container using the selected board layout.
    Preloader,
    /// Complete MBR disk image using the selected board layout.
    Sd,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum KindArg {
    Elf,
    Bootrom,
    Preloader,
    Sd,
}

impl From<KindArg> for ImageKind {
    fn from(kind: KindArg) -> Self {
        match kind {
            KindArg::Elf => Self::Elf,
            KindArg::Bootrom => Self::BootRom,
            KindArg::Preloader => Self::Preloader,
            KindArg::Sd => Self::SdImage,
        }
    }
}

fn init_logging(verbose: u8) {
    let filter = match std::env::var("RUST_LOG") {
        // An explicit RUST_LOG always wins over -v.
        Ok(_) => EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        Err(_) => EnvFilter::new(match verbose {
            0 => "info",
            1 => "debug",
            _ => "trace",
        }),
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(io::stderr)
        .with_ansi(io::stderr().is_terminal())
        .without_time()
        .with_target(false)
        .compact()
        .init();
}

fn render_error(err: &miette::Report) {
    let theme = if io::stderr().is_terminal() {
        GraphicalTheme::unicode()
    } else {
        GraphicalTheme::unicode_nocolor()
    };
    let handler = GraphicalReportHandler::new().with_theme(theme);
    let mut rendered = String::new();

    if handler.render_report(&mut rendered, err.as_ref()).is_ok() {
        eprint!("{rendered}");
    } else {
        eprintln!("{err:?}");
    }
}

fn main() {
    let mut args: Vec<_> = std::env::args_os().collect();

    if args.get(1).is_some_and(|arg| arg == "sidermux") {
        args.remove(1);
    }

    let cli = Cli::parse_from(args);
    init_logging(cli.verbose);

    let exit_code = match run(cli) {
        Ok(()) => 0,
        Err(err) => {
            render_error(&err);
            1
        }
    };

    std::process::exit(exit_code);
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Boards { json } => {
            let mut out = io::stdout().lock();
            if json {
                writeln!(
                    out,
                    "{}",
                    serde_json::to_string_pretty(board::boards()).into_diagnostic()?
                )
                .into_diagnostic()?;
            } else {
                for profile in board::boards() {
                    writeln!(out, "{}: {} (family {}, format {}; inputs {:?}; outputs {:?}; slots {} x {} bytes; partition 0x{:02X} at LBA {}, {} sectors)",
                        profile.id, profile.description, profile.family, profile.format, profile.inputs, profile.outputs,
                        profile.storage.slot_count, profile.storage.slot_size, profile.storage.partition_type,
                        profile.storage.start_lba, profile.storage.partition_sectors).into_diagnostic()?;
                }
            }
            out.flush().into_diagnostic()
        }
        Command::Pack {
            input,
            board,
            format,
            output,
            packaged,
            dtb,
            dtb_offset,
        } => handle_pack(
            &board,
            &input,
            format,
            &output,
            packaged,
            dtb.as_deref().zip(dtb_offset),
        ),
        Command::Inspect {
            input,
            board,
            json,
            no_verify,
            kind,
        } => handle_inspect(&input, board.as_deref(), json, no_verify, kind),
        Command::Unpack {
            input,
            board,
            output,
            kind,
        } => handle_unpack(&input, board.as_deref(), &output, kind),
    }
}

fn read_file(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("Failed to read {}", path.display()))
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes)
        .into_diagnostic()
        .wrap_err_with(|| format!("Failed to write {}", path.display()))
}

fn is_elf(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes[..4] == [0x7F, b'E', b'L', b'F']
}

fn parse_offset(value: &str) -> std::result::Result<usize, String> {
    let parsed = if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        usize::from_str_radix(hex, 16)
    } else {
        value.parse()
    };
    parsed.map_err(|_| "expected a nonnegative byte offset in decimal or 0x hexadecimal".to_owned())
}

fn handle_pack(
    board_id: &str,
    input: &Path,
    format: FormatArg,
    output: &Path,
    packaged: bool,
    dtb: Option<(&Path, usize)>,
) -> Result<()> {
    let board = board::board(board_id).into_diagnostic()?;
    let bytes = read_file(input)?;

    if dtb.is_some() && !is_elf(&bytes) {
        return Err(miette::miette!(
            "--dtb requires an unpackaged ELF input; pass the vendor's final raw SPL without DTB options"
        ));
    }

    let load = |bytes: &[u8]| -> miette::Result<BootImage> {
        if is_elf(bytes) {
            if let Some((path, offset)) = dtb {
                BootImage::from_elf_with_dtb(board, bytes, &read_file(path)?, offset)
            } else if packaged {
                BootImage::from_elf_packaged(board, bytes)
            } else {
                BootImage::from_elf(board, bytes)
            }
        } else {
            match sidermux_fwtools::classify_payload(board, bytes) {
                sidermux_fwtools::PayloadKind::PackagedRom => {
                    BootImage::adopt_packaged(board, bytes)
                }
                sidermux_fwtools::PayloadKind::Raw => BootImage::from_raw_spl(board, bytes),
            }
        }
        .into_diagnostic()
    };

    let preloader_image =
        load(&bytes).wrap_err_with(|| format!("Failed to package {}", input.display()))?;

    let rendered = preloader_image
        .render(match format {
            FormatArg::Bootrom => OutputFormat::Bootrom,
            FormatArg::Preloader => OutputFormat::Preloader,
            FormatArg::Sd => OutputFormat::Sd,
        })
        .into_diagnostic()?;

    write_file(output, &rendered)?;

    tracing::info!(
        input = %input.display(),
        format = ?format,
        packaged_input = packaged,
        board = board.id,
        family = board.backend.id(),
        output = %output.display(),
        image_len = rendered.len(),
        "Packaging complete",
    );

    Ok(())
}

fn handle_inspect(
    input: &Path,
    board_id: Option<&str>,
    json: bool,
    no_verify: bool,
    kind: Option<KindArg>,
) -> Result<()> {
    let options = inspect::InspectOptions {
        board: board_id.map(board::board).transpose().into_diagnostic()?,
        kind: kind.map(ImageKind::from),
        verify: !no_verify,
    };

    let mut parsed = inspect::inspect_file(input, &options)
        .into_diagnostic()
        .wrap_err_with(|| format!("Failed to inspect {}", input.display()))?;
    parsed.input.path = Some(input.display().to_string());

    let stdout = io::stdout();
    let mut out = stdout.lock();
    if json {
        let json = serde_json::to_string_pretty(&parsed)
            .into_diagnostic()
            .wrap_err("Failed to serialize the inspection report")?;
        writeln!(out, "{json}").into_diagnostic()?;
    } else {
        write!(out, "{}", report::render(&parsed)).into_diagnostic()?;
    }
    out.flush().into_diagnostic()?;

    Ok(())
}

fn handle_unpack(
    input: &Path,
    board_id: Option<&str>,
    output: &Path,
    kind: Option<KindArg>,
) -> Result<()> {
    let options = unpack::UnpackOptions {
        board: board_id.map(board::board).transpose().into_diagnostic()?,
        kind: kind.map(ImageKind::from),
    };

    let report = unpack::unpack_image(input, output, &options)
        .into_diagnostic()
        .wrap_err_with(|| format!("Failed to unpack {}", input.display()))?;

    let stdout = io::stdout();
    let mut out = stdout.lock();
    write!(out, "{}", report::render_unpack(&report)).into_diagnostic()?;
    out.flush().into_diagnostic()?;

    Ok(())
}

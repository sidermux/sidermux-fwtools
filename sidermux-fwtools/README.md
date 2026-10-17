<div align="center">
  <picture>
    <source
      media="(prefers-color-scheme: dark)"
      srcset="https://raw.githubusercontent.com/sidermux/sidermux-assets/main/icons/icon-transparent.svg"
    >
    <img
      alt="sidermux-fwtools"
      src="https://raw.githubusercontent.com/sidermux/sidermux-assets/main/icons/icon-light.svg"
      width="96"
    >
  </picture>

  <p>
    <strong><code>sidermux-fwtools</code></strong> —
    board-aware firmware packaging, inspection, and unpacking for SoC FPGA
    boot images.
  </p>

  <p>
    <a href="https://docs.rs/sidermux-fwtools">Documentation</a>
    ·
    <a href="https://github.com/sidermux/sidermux-fwtools">Workspace</a>
  </p>
</div>

> [!WARNING]
> **Beta software.** This project is pre-release and breaking changes may
> happen frequently between versions. Pin the exact version you depend on.

---

The host library of the sidermux firmware tools workspace. Family backends
own the boot ROM contract — ELF policy, encoding, probing, inspection, and
verification — while board profiles pair a backend with declared input/output
capabilities and a storage layout. Shared operations stay format-agnostic;
profiles describe packaging, never hardware initialization.

First supported family: Cyclone V (profiles `cyclone-v-generic`, `de1-soc`).

## Usage

```rust
use sidermux_fwtools::{BootImage, OutputFormat, board::board};

let target = board("de1-soc")?;
let image = BootImage::from_elf(target, elf)?;
let disk = image.render(OutputFormat::Sd)?;
```

## Features

| Feature | Effect |
| --- | --- |
| `cyclone-v` | Family backend and `cyclone-v-generic` profile |
| `board-de1-soc` | `de1-soc` profile; enables `cyclone-v` |

Both are enabled by default. A build without family features has an empty
board registry; generic ELF metadata inspection remains available.

## Documentation

Architecture, data flow, and extension guides (adding a family or board)
live in the [API docs](https://docs.rs/sidermux-fwtools). For the
command-line frontend, see
[`cargo-sidermux`](https://docs.rs/cargo-sidermux).

## License

MIT or Apache 2.0. Copyright © 2026 sidermux.

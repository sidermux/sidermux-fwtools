<div align="center">
  <picture>
    <source
      media="(prefers-color-scheme: dark)"
      srcset="https://raw.githubusercontent.com/sidermux/sidermux-assets/main/icons/icon-transparent.svg"
    >
    <img
      alt="cargo-sidermux"
      src="https://raw.githubusercontent.com/sidermux/sidermux-assets/main/icons/icon-light.svg"
      width="96"
    >
  </picture>

  <p>
    <strong><code>cargo-sidermux</code></strong> —
    package, inspect, and unpack SoC FPGA boot images from cargo.
  </p>

  <p>
    <a href="https://docs.rs/cargo-sidermux">Documentation</a>
    ·
    <a href="https://github.com/sidermux/sidermux-fwtools">Workspace</a>
  </p>
</div>

> [!WARNING]
> **Beta software.** This project is pre-release and breaking changes may
> happen frequently between versions. Pin the exact version you depend on.

---

The command-line frontend of the sidermux firmware tools workspace: pack
ELFs or raw firmware into boot ROM images, containers, and SD card images;
inspect and verify them; and unpack them back into plain files.

First supported family: Cyclone V (boards `cyclone-v-generic`, `de1-soc`).

## Install

```sh
cargo install --path cargo-sidermux
```

## Usage

```sh
cargo sidermux boards
cargo sidermux pack bootloader.elf --board cyclone-v-generic --output system.sd.img
cargo sidermux inspect system.sd.img
cargo sidermux unpack system.sd.img --output unpacked/
```

`--format` selects `bootrom`, `preloader`, or `sd` (default). Availability
and layout depend on the selected board. DTB options, packaged-image
adoption, JSON output, and ambiguity rules are documented in
[the API docs](https://docs.rs/cargo-sidermux) and `cargo sidermux --help`.

## License

MIT or Apache 2.0. Copyright © 2026 sidermux.

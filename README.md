<div align="center">
  <picture>
    <source
      media="(prefers-color-scheme: dark)"
      srcset="https://raw.githubusercontent.com/sidermux/sidermux-assets/main/logos/logo-horizontal.svg"
    >
    <img
      alt="sidermux-fwtools"
      src="https://raw.githubusercontent.com/sidermux/sidermux-assets/main/logos/logo-horizontal-light.svg"
      width="420"
    >
  </picture>

  <p>
    <strong>Firmware packaging, inspection, and unpacking for SoC FPGA boot images.</strong>
  </p>

  <p>
    <a href="https://docs.rs/sidermux-fwtools">Documentation</a>
  </p>
</div>

> [!WARNING]
> **Beta software.** This project is pre-release and breaking changes may
> happen frequently between versions. Pin the exact version you depend on.

---

Cyclone V is the first supported family. Current profiles: `cyclone-v-generic`
and `de1-soc`. The design separates reusable host operations from family boot
contracts and board storage policy; no additional hardware families are claimed
as supported.

## Install

```sh
cargo install --path cargo-sidermux
```

## Quick start

```sh
cargo sidermux boards
cargo sidermux pack bootloader.elf --board cyclone-v-generic --output system.sd.img
cargo sidermux inspect system.sd.img
cargo sidermux unpack system.sd.img --output unpacked/
```

## Workspace

```text
sidermux-fwtools/
├── sidermux-image/       # no_std image codecs and checksum primitives
├── sidermux-fwtools/     # host library, family backends, and board profiles
└── cargo-sidermux/       # cargo sidermux CLI
```

## Documentation

The full documentation — architecture, extension points, CLI reference, and
feature flags — lives in the Rust API docs, published on docs.rs:

- [`sidermux-fwtools`](https://docs.rs/sidermux-fwtools) — packaging and
  inspection API, architecture and extension guide
- [`sidermux-image`](https://docs.rs/sidermux-image) — `no_std` codecs
- [`cargo-sidermux`](https://docs.rs/cargo-sidermux) — CLI reference

Or read them locally:

```sh
cargo doc --workspace --no-deps --open
```

## License

MIT or Apache 2.0. Copyright © 2026 sidermux.

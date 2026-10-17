<div align="center">
  <picture>
    <source
      media="(prefers-color-scheme: dark)"
      srcset="https://raw.githubusercontent.com/sidermux/sidermux-assets/main/icons/icon-transparent.svg"
    >
    <img
      alt="sidermux-image"
      src="https://raw.githubusercontent.com/sidermux/sidermux-assets/main/icons/icon-light.svg"
      width="96"
    >
  </picture>

  <p>
    <strong><code>sidermux-image</code></strong> —
    <code>no_std</code> firmware boot image codecs and checksum primitives.
  </p>

  <p>
    <a href="https://docs.rs/sidermux-image">Documentation</a>
    ·
    <a href="https://github.com/sidermux/sidermux-fwtools">Workspace</a>
  </p>
</div>

---

Dependency-free, allocation-free primitives for reading and writing device
boot images. Each supported family ships its codec as a module under
[`families`], behind its own cargo feature; checksums are available in any
configuration.

First supported family: Cyclone V (feature `cyclone-v`).

## Usage

```rust
use sidermux_image::{Crc32Bzip2, crc32_bzip2};

// Canonical CRC-32/BZIP2 check value.
assert_eq!(crc32_bzip2(b"123456789"), 0xFC89_1918);

// Incremental hashing for streamed verification.
let mut crc = Crc32Bzip2::new();
crc.update(b"12345");
crc.update(b"6789");
assert_eq!(crc.finalize(), 0xFC89_1918);
```

## Features

| Feature | Effect |
| --- | --- |
| `cyclone-v` (default) | Boot ROM image header codec of the first supported family |

The crate stays `no_std` with or without any feature enabled.

## License

MIT or Apache 2.0. Copyright © 2026 sidermux.

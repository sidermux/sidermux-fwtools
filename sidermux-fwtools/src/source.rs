//! Byte sources for image parsing.
//!
//! Parsing works against [`ImageSource`] so the same code paths serve
//! in-memory buffers (zero-copy borrowed views) and files (seek + bounded
//! reads). Nothing here loads a whole artifact: callers read exactly the
//! ranges their inspection mode needs.

use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom},
};

/// Positionally addressed reads over an artifact.
///
/// Parsing works against [`ImageSource`] so the same code paths serve
/// in-memory buffers (zero-copy borrowed views) and files (seek + bounded
/// reads). Nothing here loads a whole artifact: callers read exactly the
/// ranges their inspection mode needs.
pub trait ImageSource {
    /// Total size of the artifact in bytes. Must not read the contents.
    fn len(&self) -> io::Result<u64>;

    fn is_empty(&self) -> io::Result<bool> {
        self.len().map(|len| len == 0)
    }

    /// Reads up to `buf.len()` bytes starting at `offset`; returns the number
    /// of bytes read (short only at end of artifact).
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<usize>;

    /// Reads exactly `buf.len()` bytes at `offset`, or fails with
    /// `UnexpectedEof`.
    fn read_exact_at(&mut self, mut offset: u64, mut buf: &mut [u8]) -> io::Result<()> {
        while !buf.is_empty() {
            match self.read_at(offset, buf)? {
                0 => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
                n => {
                    offset += n as u64;
                    buf = &mut buf[n..];
                }
            }
        }
        Ok(())
    }

    /// Reads `len` bytes at `offset` into a fresh buffer. Only for bounded,
    /// structural reads (headers, partition tables) — never for whole
    /// artifacts.
    fn read_vec_at(&mut self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        self.read_exact_at(offset, &mut buf)?;
        Ok(buf)
    }
}

/// In-memory source: all reads are borrowed slices, never copies.
pub(crate) struct BytesSource<'a>(pub &'a [u8]);

impl ImageSource for BytesSource<'_> {
    fn len(&self) -> io::Result<u64> {
        Ok(self.0.len() as u64)
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let offset = usize::try_from(offset)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "offset out of range"))?;
        if offset >= self.0.len() || buf.is_empty() {
            return Ok(0);
        }
        let n = buf.len().min(self.0.len() - offset);
        buf[..n].copy_from_slice(&self.0[offset..offset + n]);
        Ok(n)
    }
}

/// File source: seeks and bounded reads; the file is never loaded whole.
pub(crate) struct FileSource(pub File);

impl ImageSource for FileSource {
    fn len(&self) -> io::Result<u64> {
        self.0.metadata().map(|meta| meta.len())
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        self.0.seek(SeekFrom::Start(offset))?;
        self.0.read(buf)
    }
}

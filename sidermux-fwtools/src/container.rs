//! Container rendering: redundant multi-slot boot containers.
use crate::{BootImage, board::OutputFormat, error::ImageError};
impl BootImage {
    /// The declared image zero-padded into one full boot slot.
    pub fn slot_bytes(&self) -> Result<Vec<u8>, ImageError> {
        self.board().require_output(OutputFormat::Preloader)?;
        self.padded_slot()
    }
    fn padded_slot(&self) -> Result<Vec<u8>, ImageError> {
        let storage = self.board().storage;
        storage.validate()?;
        if self.as_bytes().len() > storage.slot_size {
            return Err(ImageError::ImageTooLarge {
                size: self.as_bytes().len(),
                max: storage.slot_size,
            });
        }
        let mut slot = vec![0u8; storage.slot_size];
        slot[..self.as_bytes().len()].copy_from_slice(self.as_bytes());
        Ok(slot)
    }
    /// Renders the redundant boot container: `slot_count` identical,
    /// zero-padded slots, per the profile's storage layout.
    pub fn to_container(&self) -> Result<Vec<u8>, ImageError> {
        self.board().require_output(OutputFormat::Preloader)?;
        self.build_container()
    }
    pub(crate) fn build_container(&self) -> Result<Vec<u8>, ImageError> {
        let slot = self.padded_slot()?;
        let count = self.board().storage.slot_count;
        let mut container = Vec::with_capacity(
            slot.len()
                .checked_mul(count)
                .ok_or(ImageError::LengthOverflow)?,
        );
        for _ in 0..count {
            container.extend_from_slice(&slot);
        }
        Ok(container)
    }
}
#[cfg(all(test, feature = "cyclone-v"))]
mod tests {
    use super::*;
    use crate::test_support::BOARD;
    const SLOT_SIZE: usize = 65536;
    const SLOT_COUNT: usize = 4;

    fn image_of_len(len: usize) -> BootImage {
        BootImage::from_bytes(BOARD, vec![0xA5u8; len])
    }

    #[test]
    fn slot_is_padded_to_64k() {
        let image = image_of_len(0x40);
        let slot = image.slot_bytes().unwrap();
        assert_eq!(slot.len(), SLOT_SIZE);
        assert!(slot[..0x40].iter().all(|&b| b == 0xA5));
        assert!(slot[0x40..].iter().all(|&b| b == 0));
    }

    #[test]
    fn full_size_declared_image_is_not_padded() {
        let image = image_of_len(0xF000);
        let slot = image.slot_bytes().unwrap();
        assert_eq!(slot.len(), SLOT_SIZE);
        // The declared image fills its entire span; only the tail past the
        // declared length (not covered by header or CRC) is zero padding.
        assert!(slot[..0xF000].iter().all(|&b| b == 0xA5));
        assert!(slot[0xF000..].iter().all(|&b| b == 0));
    }

    #[test]
    fn container_is_four_identical_slots() {
        let container = image_of_len(0x100).to_container().unwrap();
        assert_eq!(container.len(), SLOT_SIZE * SLOT_COUNT);
        for i in 0..SLOT_COUNT {
            assert_eq!(
                container[i * SLOT_SIZE..(i + 1) * SLOT_SIZE],
                container[..SLOT_SIZE]
            );
        }
    }
}

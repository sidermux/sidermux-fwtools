//! SD card image rendering: an MBR plus the profile's boot container.
use crate::{BootImage, board::OutputFormat, error::ImageError};
/// Size of one LBA sector.
pub const SECTOR_SIZE: usize = 512;
/// File offset of the first MBR partition entry.
pub const MBR_PARTITION_ENTRY_OFFSET: usize = 0x1BE;
impl BootImage {
    /// Renders a complete MBR disk image: the profile's boot partition
    /// (type, start LBA, length) described in the MBR, the `0x55AA` boot
    /// signature at offset 510, and the boot container at the partition
    /// start.
    pub fn to_sd_image(&self) -> Result<Vec<u8>, ImageError> {
        self.board().require_output(OutputFormat::Sd)?;
        let storage = self.board().storage;
        storage.validate()?;
        let total = u64::from(storage.start_lba) + u64::from(storage.partition_sectors);
        let len =
            usize::try_from(total * SECTOR_SIZE as u64).map_err(|_| ImageError::LengthOverflow)?;
        let offset = usize::try_from(u64::from(storage.start_lba) * SECTOR_SIZE as u64)
            .map_err(|_| ImageError::LengthOverflow)?;
        let container = self.build_container()?;
        let mut image = vec![0u8; len];
        let entry = MBR_PARTITION_ENTRY_OFFSET;
        image[entry + 4] = storage.partition_type;
        image[entry + 8..entry + 12].copy_from_slice(&storage.start_lba.to_le_bytes());
        image[entry + 12..entry + 16].copy_from_slice(&storage.partition_sectors.to_le_bytes());
        image[510..512].copy_from_slice(&[0x55, 0xAA]);
        image[offset..offset + container.len()].copy_from_slice(&container);
        Ok(image)
    }
}
#[cfg(all(test, feature = "cyclone-v"))]
mod tests {
    use super::*;
    use crate::test_support::BOARD;
    const START_LBA: u32 = 2048;
    const PARTITION_SECTORS: u32 = 20480;
    const PARTITION_OFFSET: usize = 1024 * 1024;
    const DISK_IMAGE_SIZE: usize = 11 * 1024 * 1024;
    const PARTITION_TYPE_A2: u8 = 0xA2;

    #[test]
    fn layout_constants_are_consistent() {
        assert_eq!(DISK_IMAGE_SIZE, 11 * 1024 * 1024);
        assert_eq!(PARTITION_OFFSET, 1024 * 1024);
        assert_eq!(PARTITION_SECTORS as usize * SECTOR_SIZE, 10 * 1024 * 1024);
    }

    #[test]
    fn mbr_describes_partition_within_file() {
        let image = BootImage::from_bytes(BOARD, vec![0; 0x100])
            .to_sd_image()
            .unwrap();
        assert_eq!(image.len(), DISK_IMAGE_SIZE);

        assert_eq!(&image[510..512], &[0x55, 0xAA]);

        let entry = &image[MBR_PARTITION_ENTRY_OFFSET..MBR_PARTITION_ENTRY_OFFSET + 16];
        assert_eq!(entry[0], 0x00); // no boot flag
        assert_eq!(entry[4], PARTITION_TYPE_A2);
        let start_lba = u32::from_le_bytes(entry[8..12].try_into().unwrap());
        let sectors = u32::from_le_bytes(entry[12..16].try_into().unwrap());
        assert_eq!(start_lba, START_LBA);
        assert_eq!(sectors, PARTITION_SECTORS);
        assert!((start_lba as usize + sectors as usize) * SECTOR_SIZE <= image.len());
    }

    #[test]
    fn container_sits_at_partition_start() {
        let image = BootImage::from_bytes(BOARD, vec![0x5A; 0x100])
            .to_sd_image()
            .unwrap();
        let slot = &image[PARTITION_OFFSET..PARTITION_OFFSET + BOARD.storage.slot_size];
        assert!(slot[..0x100].iter().all(|&b| b == 0x5A));
        // All four slots are present and identical.
        let slot_size = BOARD.storage.slot_size;
        for i in 1..BOARD.storage.slot_count {
            let next =
                &image[PARTITION_OFFSET + i * slot_size..PARTITION_OFFSET + (i + 1) * slot_size];
            assert_eq!(next, slot);
        }
    }
}

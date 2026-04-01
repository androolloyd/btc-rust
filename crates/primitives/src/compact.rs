/// Compact representation of a 256-bit target value (nBits field in block header).
///
/// The compact format is a 4-byte encoding where:
/// - The first byte is the "exponent" (number of bytes in the target)
/// - The remaining 3 bytes are the "mantissa" (most significant digits)
///
/// target = mantissa * 2^(8*(exponent-3))
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct CompactTarget(pub u32);

impl CompactTarget {
    /// Maximum target for difficulty 1 (mainnet)
    pub const MAX_TARGET: CompactTarget = CompactTarget(0x1d00ffff);

    pub fn from_u32(bits: u32) -> Self {
        CompactTarget(bits)
    }

    pub fn to_u32(self) -> u32 {
        self.0
    }

    /// Expand compact target to a 256-bit target value (as [u8; 32], big-endian)
    pub fn to_target(self) -> [u8; 32] {
        let mut target = [0u8; 32];
        let exponent = (self.0 >> 24) as usize;
        let mut mantissa = self.0 & 0x00ffffff;

        // Handle negative flag (bit 23 of mantissa)
        if mantissa != 0 && (self.0 & 0x00800000) != 0 {
            return target; // negative target = 0
        }

        if exponent == 0 {
            return target;
        }

        // The compact format represents: mantissa * 256^(exponent-3)
        // mantissa is a 3-byte big-endian number
        // Place mantissa bytes at the right position in big-endian target
        if exponent <= 3 {
            mantissa >>= 8 * (3 - exponent);
            target[31] = (mantissa & 0xff) as u8;
            if exponent >= 2 {
                target[30] = ((mantissa >> 8) & 0xff) as u8;
            }
            if exponent >= 3 {
                target[29] = ((mantissa >> 16) & 0xff) as u8;
            }
        } else {
            // exponent > 3: mantissa occupies 3 bytes starting at position (32 - exponent)
            let start = 32usize.saturating_sub(exponent);
            if start < 32 {
                target[start] = ((mantissa >> 16) & 0xff) as u8;
            }
            if start + 1 < 32 {
                target[start + 1] = ((mantissa >> 8) & 0xff) as u8;
            }
            if start + 2 < 32 {
                target[start + 2] = (mantissa & 0xff) as u8;
            }
        }

        target
    }

    /// Check if a hash (internal byte order) meets this target
    pub fn hash_meets_target(&self, hash: &[u8; 32]) -> bool {
        let target = self.to_target();
        // Compare big-endian: hash reversed (display order) vs target (big-endian)
        // Internal hash byte order is little-endian, so reverse for comparison
        for i in 0..32 {
            let hash_byte = hash[31 - i];
            match hash_byte.cmp(&target[i]) {
                std::cmp::Ordering::Less => return true,
                std::cmp::Ordering::Greater => return false,
                std::cmp::Ordering::Equal => continue,
            }
        }
        true // equal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_target() {
        let compact = CompactTarget::MAX_TARGET; // 0x1d00ffff
        let target = compact.to_target();
        // Compact 0x1d00ffff = 0x00ffff * 256^(0x1d-3) = 0x00ffff * 256^26
        // Big-endian target: 00000000 00FFFF00 00000000 00000000 ...
        assert_eq!(target[0], 0x00);
        assert_eq!(target[1], 0x00);
        assert_eq!(target[2], 0x00);
        assert_eq!(target[3], 0x00); // first mantissa byte is 0x00
        assert_eq!(target[4], 0xff); // second mantissa byte
        assert_eq!(target[5], 0xff); // third mantissa byte
        assert_eq!(target[6], 0x00); // rest are zero
    }

    #[test]
    fn test_compact_roundtrip_display() {
        let compact = CompactTarget(0x1b0404cb);
        let target = compact.to_target();
        // Should produce a valid target with non-zero bytes
        assert!(target.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_compact_zero_exponent() {
        let compact = CompactTarget(0x00123456);
        let target = compact.to_target();
        assert_eq!(target, [0u8; 32]);
    }

    #[test]
    fn test_compact_negative_flag() {
        // If bit 23 of mantissa is set and mantissa != 0, target should be 0
        let compact = CompactTarget(0x01800000);
        let target = compact.to_target();
        assert_eq!(target, [0u8; 32]);
    }

    #[test]
    fn test_compact_exponent_1() {
        let compact = CompactTarget(0x01000042);
        let target = compact.to_target();
        // exponent=1, mantissa=0x000042, shifted right by 8*(3-1)=16
        // So mantissa >> 16 = 0, target[31] = 0
        assert_eq!(target[31], 0);
    }

    #[test]
    fn test_compact_exponent_2() {
        let compact = CompactTarget(0x02004200);
        let target = compact.to_target();
        // exponent=2, mantissa=0x004200, shifted right by 8*(3-2)=8
        // mantissa >> 8 = 0x42, but then only lower bits used
        // target[31] = (mantissa >> 0) & 0xff after shifting = (0x004200 >> 8) & 0xff = 0x42
        // target[30] = (mantissa >> 8 >> 8) & 0xff = 0
        // Actually: mantissa >>= 8 => mantissa = 0x0042
        // target[31] = mantissa & 0xff = 0x42
        // exponent >= 2 => target[30] = (mantissa >> 8) & 0xff = 0x00
        assert_eq!(target[31], 0x42);
    }

    #[test]
    fn test_compact_exponent_3() {
        let compact = CompactTarget(0x03420000);
        let target = compact.to_target();
        // exponent=3, mantissa=0x420000
        // target[29] = 0x42
        assert_eq!(target[29], 0x42);
    }

    #[test]
    fn test_compact_from_u32_to_u32() {
        let compact = CompactTarget::from_u32(0xDEADBEEF);
        assert_eq!(compact.to_u32(), 0xDEADBEEF);
    }

    #[test]
    fn test_hash_meets_target_equal() {
        let compact = CompactTarget(0x1d00ffff);
        let target = compact.to_target();
        // Build a hash that equals the target exactly (should return true)
        let mut hash = [0u8; 32];
        // Target is big-endian, hash is little-endian (reversed)
        for i in 0..32 {
            hash[31 - i] = target[i];
        }
        assert!(compact.hash_meets_target(&hash));
    }

    #[test]
    fn test_hash_meets_target_less() {
        let compact = CompactTarget(0x1d00ffff);
        // Hash of all zeros (lowest possible) should meet any target
        let hash = [0u8; 32];
        assert!(compact.hash_meets_target(&hash));
    }

    #[test]
    fn test_hash_meets_target_greater() {
        let compact = CompactTarget(0x1d00ffff);
        // Hash of all 0xFF (highest possible) should not meet target
        let hash = [0xffu8; 32];
        assert!(!compact.hash_meets_target(&hash));
    }

    #[test]
    fn test_compact_default() {
        let compact = CompactTarget::default();
        assert_eq!(compact.to_u32(), 0);
    }

    #[test]
    fn test_compact_large_exponent() {
        // exponent = 32, mantissa = 0x000100
        // start = 32 - 32 = 0
        // target[0] = (mantissa >> 16) & 0xff = 0
        // target[1] = (mantissa >> 8) & 0xff = 0x01
        // target[2] = mantissa & 0xff = 0x00
        let compact = CompactTarget(0x20000100);
        let target = compact.to_target();
        assert_eq!(target[1], 0x01);
    }
}

use std::io::{self, Read, Write};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EncodeError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("invalid data: {0}")]
    InvalidData(String),
    #[error("varint too large")]
    VarIntTooLarge,
    #[error("unexpected end of data")]
    UnexpectedEof,
}

/// A type that can be serialised into the Bitcoin consensus wire format.
pub trait Encodable {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<usize, EncodeError>;

    fn encoded_size(&self) -> usize {
        let mut counter = CountWriter(0);
        self.encode(&mut counter).unwrap_or(0);
        counter.0
    }
}

/// A type that can be deserialised from the Bitcoin consensus wire format.
pub trait Decodable: Sized {
    fn decode<R: Read>(reader: &mut R) -> Result<Self, EncodeError>;
}

/// Encode a value to bytes
pub fn encode<T: Encodable>(value: &T) -> Vec<u8> {
    let mut buf = Vec::with_capacity(value.encoded_size());
    value.encode(&mut buf).expect("encoding to vec should not fail");
    buf
}

/// Decode a value from bytes
pub fn decode<T: Decodable>(bytes: &[u8]) -> Result<T, EncodeError> {
    let mut cursor = io::Cursor::new(bytes);
    T::decode(&mut cursor)
}

/// A variable-length integer encoding used throughout the Bitcoin wire protocol (1, 3, 5, or 9 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VarInt(pub u64);

impl VarInt {
    pub fn encoded_size(self) -> usize {
        match self.0 {
            0..=0xfc => 1,
            0xfd..=0xffff => 3,
            0x10000..=0xffff_ffff => 5,
            _ => 9,
        }
    }
}

impl Encodable for VarInt {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<usize, EncodeError> {
        match self.0 {
            v @ 0..=0xfc => {
                writer.write_all(&[v as u8])?;
                Ok(1)
            }
            v @ 0xfd..=0xffff => {
                writer.write_all(&[0xfd])?;
                writer.write_all(&(v as u16).to_le_bytes())?;
                Ok(3)
            }
            v @ 0x10000..=0xffff_ffff => {
                writer.write_all(&[0xfe])?;
                writer.write_all(&(v as u32).to_le_bytes())?;
                Ok(5)
            }
            v => {
                writer.write_all(&[0xff])?;
                writer.write_all(&v.to_le_bytes())?;
                Ok(9)
            }
        }
    }
}

impl Decodable for VarInt {
    fn decode<R: Read>(reader: &mut R) -> Result<Self, EncodeError> {
        let first = reader.read_u8()?;
        let value = match first {
            0xff => reader.read_u64_le()?,
            0xfe => reader.read_u32_le()? as u64,
            0xfd => reader.read_u16_le()? as u64,
            n => n as u64,
        };
        Ok(VarInt(value))
    }
}

impl From<usize> for VarInt {
    fn from(v: usize) -> Self {
        VarInt(v as u64)
    }
}

/// Extension trait for reading Bitcoin-encoded primitives
pub trait ReadExt: Read {
    fn read_u8(&mut self) -> Result<u8, EncodeError> {
        let mut buf = [0u8; 1];
        self.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    fn read_u16_le(&mut self) -> Result<u16, EncodeError> {
        let mut buf = [0u8; 2];
        self.read_exact(&mut buf)?;
        Ok(u16::from_le_bytes(buf))
    }

    fn read_u32_le(&mut self) -> Result<u32, EncodeError> {
        let mut buf = [0u8; 4];
        self.read_exact(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    fn read_i32_le(&mut self) -> Result<i32, EncodeError> {
        let mut buf = [0u8; 4];
        self.read_exact(&mut buf)?;
        Ok(i32::from_le_bytes(buf))
    }

    fn read_u64_le(&mut self) -> Result<u64, EncodeError> {
        let mut buf = [0u8; 8];
        self.read_exact(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    fn read_i64_le(&mut self) -> Result<i64, EncodeError> {
        let mut buf = [0u8; 8];
        self.read_exact(&mut buf)?;
        Ok(i64::from_le_bytes(buf))
    }

    fn read_bytes(&mut self, len: usize) -> Result<Vec<u8>, EncodeError> {
        let mut buf = vec![0u8; len];
        self.read_exact(&mut buf)?;
        Ok(buf)
    }

    fn read_hash256(&mut self) -> Result<[u8; 32], EncodeError> {
        let mut buf = [0u8; 32];
        self.read_exact(&mut buf)?;
        Ok(buf)
    }
}

impl<R: Read + ?Sized> ReadExt for R {}

/// Extension trait for writing Bitcoin-encoded primitives
pub trait WriteExt: Write {
    fn write_u8(&mut self, v: u8) -> Result<usize, EncodeError> {
        self.write_all(&[v])?;
        Ok(1)
    }

    fn write_u16_le(&mut self, v: u16) -> Result<usize, EncodeError> {
        self.write_all(&v.to_le_bytes())?;
        Ok(2)
    }

    fn write_u32_le(&mut self, v: u32) -> Result<usize, EncodeError> {
        self.write_all(&v.to_le_bytes())?;
        Ok(4)
    }

    fn write_i32_le(&mut self, v: i32) -> Result<usize, EncodeError> {
        self.write_all(&v.to_le_bytes())?;
        Ok(4)
    }

    fn write_u64_le(&mut self, v: u64) -> Result<usize, EncodeError> {
        self.write_all(&v.to_le_bytes())?;
        Ok(8)
    }

    fn write_i64_le(&mut self, v: i64) -> Result<usize, EncodeError> {
        self.write_all(&v.to_le_bytes())?;
        Ok(8)
    }
}

impl<W: Write + ?Sized> WriteExt for W {}

// Implement Encodable/Decodable for standard integer types
macro_rules! impl_int_encodable {
    ($ty:ty, $read:ident, $write:ident, $size:expr) => {
        impl Encodable for $ty {
            fn encode<W: Write>(&self, writer: &mut W) -> Result<usize, EncodeError> {
                writer.$write(*self)
            }
            fn encoded_size(&self) -> usize { $size }
        }
        impl Decodable for $ty {
            fn decode<R: Read>(reader: &mut R) -> Result<Self, EncodeError> {
                reader.$read()
            }
        }
    };
}

impl_int_encodable!(u8, read_u8, write_u8, 1);
impl_int_encodable!(u16, read_u16_le, write_u16_le, 2);
impl_int_encodable!(u32, read_u32_le, write_u32_le, 4);
impl_int_encodable!(i32, read_i32_le, write_i32_le, 4);
impl_int_encodable!(u64, read_u64_le, write_u64_le, 8);
impl_int_encodable!(i64, read_i64_le, write_i64_le, 8);

impl Encodable for Vec<u8> {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<usize, EncodeError> {
        let vi = VarInt(self.len() as u64);
        let mut written = vi.encode(writer)?;
        writer.write_all(self)?;
        written += self.len();
        Ok(written)
    }
}

/// Maximum size for a single decoded byte vector (32 MB — matches P2P max payload)
const MAX_VEC_DECODE_SIZE: usize = 32 * 1024 * 1024;

impl Decodable for Vec<u8> {
    fn decode<R: Read>(reader: &mut R) -> Result<Self, EncodeError> {
        let len = VarInt::decode(reader)?.0 as usize;
        if len > MAX_VEC_DECODE_SIZE {
            return Err(EncodeError::InvalidData(
                format!("vec length {} exceeds maximum {}", len, MAX_VEC_DECODE_SIZE)
            ));
        }
        reader.read_bytes(len)
    }
}

/// Helper to count bytes written without allocating
pub struct CountWriter(pub usize);

impl Write for CountWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0 += buf.len();
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_single_byte() {
        for v in 0..=0xfcu64 {
            let vi = VarInt(v);
            let encoded = encode(&vi);
            assert_eq!(encoded.len(), 1);
            assert_eq!(encoded[0], v as u8);

            let decoded: VarInt = decode(&encoded).unwrap();
            assert_eq!(decoded, vi);
        }
    }

    #[test]
    fn test_varint_two_byte() {
        let vi = VarInt(0xfd);
        let encoded = encode(&vi);
        assert_eq!(encoded, vec![0xfd, 0xfd, 0x00]);
        let decoded: VarInt = decode(&encoded).unwrap();
        assert_eq!(decoded, vi);

        let vi = VarInt(0xffff);
        let encoded = encode(&vi);
        assert_eq!(encoded, vec![0xfd, 0xff, 0xff]);
    }

    #[test]
    fn test_varint_four_byte() {
        let vi = VarInt(0x10000);
        let encoded = encode(&vi);
        assert_eq!(encoded[0], 0xfe);
        assert_eq!(encoded.len(), 5);
        let decoded: VarInt = decode(&encoded).unwrap();
        assert_eq!(decoded, vi);
    }

    #[test]
    fn test_varint_eight_byte() {
        let vi = VarInt(0x1_0000_0000);
        let encoded = encode(&vi);
        assert_eq!(encoded[0], 0xff);
        assert_eq!(encoded.len(), 9);
        let decoded: VarInt = decode(&encoded).unwrap();
        assert_eq!(decoded, vi);
    }

    #[test]
    fn test_u32_roundtrip() {
        let val: u32 = 0xDEADBEEF;
        let encoded = encode(&val);
        assert_eq!(encoded, vec![0xEF, 0xBE, 0xAD, 0xDE]); // little-endian
        let decoded: u32 = decode(&encoded).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn test_vec_u8_roundtrip() {
        let data = vec![0x01, 0x02, 0x03, 0x04];
        let encoded = encode(&data);
        assert_eq!(encoded, vec![0x04, 0x01, 0x02, 0x03, 0x04]);
        let decoded: Vec<u8> = decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_varint_encoded_size() {
        assert_eq!(VarInt(0).encoded_size(), 1);
        assert_eq!(VarInt(0xfc).encoded_size(), 1);
        assert_eq!(VarInt(0xfd).encoded_size(), 3);
        assert_eq!(VarInt(0xffff).encoded_size(), 3);
        assert_eq!(VarInt(0x10000).encoded_size(), 5);
        assert_eq!(VarInt(0xffff_ffff).encoded_size(), 5);
        assert_eq!(VarInt(0x1_0000_0000).encoded_size(), 9);
    }

    #[test]
    fn test_varint_from_usize() {
        let vi = VarInt::from(42usize);
        assert_eq!(vi.0, 42);
    }

    #[test]
    fn test_u8_roundtrip() {
        let val: u8 = 0xAB;
        let encoded = encode(&val);
        assert_eq!(encoded, vec![0xAB]);
        let decoded: u8 = decode(&encoded).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn test_u16_roundtrip() {
        let val: u16 = 0xBEEF;
        let encoded = encode(&val);
        assert_eq!(encoded, vec![0xEF, 0xBE]);
        let decoded: u16 = decode(&encoded).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn test_i32_roundtrip() {
        let val: i32 = -42;
        let encoded = encode(&val);
        let decoded: i32 = decode(&encoded).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn test_u64_roundtrip() {
        let val: u64 = 0xDEADBEEFCAFEBABE;
        let encoded = encode(&val);
        let decoded: u64 = decode(&encoded).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn test_i64_roundtrip() {
        let val: i64 = -999_999_999;
        let encoded = encode(&val);
        let decoded: i64 = decode(&encoded).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn test_count_writer() {
        let mut counter = CountWriter(0);
        counter.write_all(b"hello").unwrap();
        counter.flush().unwrap();
        assert_eq!(counter.0, 5);
    }

    #[test]
    fn test_encodable_encoded_size() {
        let val: u32 = 42;
        assert_eq!(val.encoded_size(), 4);
        let vi = VarInt(0xfd);
        assert_eq!(vi.encoded_size(), 3);
    }

    #[test]
    fn test_encode_decode_helpers() {
        let val: u32 = 12345;
        let bytes = encode(&val);
        let decoded: u32 = decode(&bytes).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn test_vec_decode_too_large() {
        // Create a varint encoding for a length > MAX_VEC_DECODE_SIZE
        let mut buf = Vec::new();
        VarInt(33 * 1024 * 1024).encode(&mut buf).unwrap();
        let result = decode::<Vec<u8>>(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_error_display() {
        let e1 = EncodeError::Io(io::Error::new(io::ErrorKind::Other, "test"));
        assert!(format!("{}", e1).contains("test"));
        let e2 = EncodeError::InvalidData("bad data".into());
        assert!(format!("{}", e2).contains("bad data"));
        let e3 = EncodeError::VarIntTooLarge;
        assert!(format!("{}", e3).contains("varint"));
        let e4 = EncodeError::UnexpectedEof;
        assert!(format!("{}", e4).contains("end"));
    }
}

#[derive(Debug)]
pub struct BitsBuffer {
    buf: Vec<u8>,
    last: usize,
    w_pos: usize,
    r_pos: usize,
}

impl Default for BitsBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl BitsBuffer {
    /// Builds a new empty [BitsBuffer]. Write ops append data to the end
    /// of the internal buffer and reads start form the beginning.
    pub fn new() -> Self {
        BitsBuffer {
            buf: vec![],
            last: 0,
            w_pos: 0,
            r_pos: 0,
        }
    }

    /// Builds a [BitsBuffer] from a bytes slice. Subsequent write ops
    /// append to the buffer while reads start form the beginning.
    pub fn from_raw_bytes(bytes: &[u8]) -> Self {
        BitsBuffer {
            buf: bytes.to_owned(),
            last: bytes.len() * 8,
            w_pos: bytes.len() * 8,
            r_pos: 0,
        }
    }

    /// Consumes the buffer and returns the inner bytes as a Vec.
    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }

    /// Returns the current reading position in the buffer.
    /// Note that the reading position is expressed in bits.
    pub fn read_pos(&self) -> usize {
        self.r_pos
    }

    /// Returns the current write position in the buffer.
    /// Note that the write position is expressed in bits.
    pub fn write_pos(&self) -> usize {
        self.w_pos
    }

    /// Sets the reading position in the buffer (expressed in bits).
    /// Returns a an error variant if the provided reading position
    /// is beyond the buffer length.
    pub fn set_read_pos(&mut self, r_pos: usize) {
        if r_pos > self.last {
            panic!("read pos >= buffer len")
        }
        self.r_pos = r_pos;
    }

    /// Sets the write position in the buffer (expressed in bits).
    /// Returns a an error variant if the provided write position
    /// is beyond the buffer length.
    pub fn set_write_pos(&mut self, w_pos: usize) {
        if w_pos > self.last {
            panic!("write pos >= buffer len")
        }
        self.w_pos = w_pos;
    }

    /// Reads and returns a certain number of bits, reading from the underlying
    /// buffer. `n` represent the number of bits to be read, and it can range
    /// from 1 to 8 bits. After the method call the reading positions is
    /// advanced by `n`.
    ///
    /// # Panics
    /// Panics if `n > 8`.
    pub fn read_bits(&mut self, n: u8) -> Option<u8> {
        assert!(n <= 8);
        if n == 0 {
            return Some(0);
        }

        // Make sure we have enough data to be read.
        if self.r_pos + (n as usize) > self.last {
            return None;
        }

        // Decide if the current byte as enough remaining bits to
        // serve the current read. If not, we need to read from
        // both the current and the next byte.
        let bytes_offset = self.r_pos / 8;
        let bits_offset = self.r_pos % 8;
        let remaining_bits = (8 - bits_offset) as u8;
        let read;

        if n <= remaining_bits {
            let bits_masked = self.buf[bytes_offset] & ((1_u16 << remaining_bits) - 1) as u8;
            read = bits_masked >> (remaining_bits - n);
        } else {
            let first = self.buf[bytes_offset] & ((1_u16 << remaining_bits) - 1) as u8;
            let first = first << (n - remaining_bits);
            let second = self.buf[bytes_offset + 1] >> (8 - (n - remaining_bits));
            read = first | second;
        }

        self.r_pos += n as usize;
        Some(read)
    }

    /// Reads and return 8 bits as an `u8` from the underlying buffer.
    /// After the method call the reading positions is advanced by 8.
    pub fn read_u8(&mut self) -> Option<u8> {
        self.read_bits(8)
    }

    /// Reads and return 16 bits as an `u16` from the underlying buffer.
    /// After the method call the reading positions is advanced by 16.
    pub fn read_u16(&mut self) -> Option<u16> {
        if self.r_pos + 16 > self.last {
            None
        } else {
            let first = (self.read_bits(8).unwrap() as u16) << 8;
            let second = self.read_bits(8).unwrap() as u16;
            Some(first | second)
        }
    }

    /// Reads and return 32 bits as an `u32` from the underlying buffer.
    /// After the method call the reading positions is advanced by 32.
    pub fn read_u32(&mut self) -> Option<u32> {
        if self.r_pos + 32 > self.last {
            None
        } else {
            let first = (self.read_bits(8).unwrap() as u32) << 24;
            let second = (self.read_bits(8).unwrap() as u32) << 16;
            let third = (self.read_bits(8).unwrap() as u32) << 8;
            let fourth = self.read_bits(8).unwrap() as u32;
            Some(first | second | third | fourth)
        }
    }

    /// Reads and return a certain amount of bytes from the underlying
    /// buffer as an array of u8. The function is generic over the
    /// number of bytes (N). After the method call the reading
    /// positions is advanced by N * 8.
    pub fn read_bytes<const N: usize>(&mut self) -> Option<[u8; N]> {
        if self.r_pos + N * 8 > self.last {
            return None;
        }
        let mut buf = [0; N];
        for i in 0..N {
            let byte = self.read_u8().unwrap();
            buf[i] = byte;
        }
        Some(buf)
    }

    /// Reads and return a certain amount of bytes from the underlying
    /// buffer as a Vec of u8. The function requires the number of
    /// bytes to be read. After the method call the reading
    /// positions is advanced by n * 8.
    pub fn read_bytes_vec(&mut self, n: usize) -> Option<Vec<u8>> {
        if self.r_pos + n * 8 > self.last {
            return None;
        }
        let mut buf = Vec::with_capacity(n);
        for _ in 0..n {
            let byte = self.read_u8().unwrap();
            buf.push(byte);
        }
        Some(buf)
    }

    /// Writes a certain number of bits to the underlying buffer, appending
    /// them. The `n` argument represents the number of bits to be read from
    /// the `bits` byte, `n` can range from 0 to 8 bits. After the method call
    /// further `n` bits are available to read.
    ///
    /// # Panics
    /// Panics if `n > 8`.
    pub fn write_bits(&mut self, bits: u8, n: u8) {
        assert!(n <= 8 && n > 0);
        let bits = bits & ((1_u16 << n) - 1) as u8;

        // Enlarge buffer if needed.
        if self.buf.len() * 8 - (self.w_pos) < n as usize {
            self.buf.push(0);
        }

        let avail_bits_current = 8 - (self.w_pos % 8) as u8;
        if n <= avail_bits_current {
            // Write ONLY in current byte.
            let bits_eraser = (((1_u16 << n) - 1) as u8) << (avail_bits_current - n);
            let bits_shifted = bits << (avail_bits_current - n);
            self.buf[self.w_pos / 8] &= !bits_eraser;
            self.buf[self.w_pos / 8] |= bits_shifted;
        } else {
            // Write in BOTH current and NEXT byte.
            let first_bits_shifted = bits >> (n - avail_bits_current);
            let first_bits_eraser = ((1_u16 << avail_bits_current) - 1) as u8;
            self.buf[self.w_pos / 8] &= !first_bits_eraser;
            self.buf[self.w_pos / 8] |= first_bits_shifted;

            let second_bits_shifted = bits & ((1_u16 << (n - avail_bits_current)) - 1) as u8;
            let second_bits_shifted = second_bits_shifted << (8 - (n - avail_bits_current));
            let second_bits_eraser = ((1_u16 << (n - avail_bits_current)) - 1) as u8;
            let second_bits_eraser = second_bits_eraser << (8 - (n - avail_bits_current));
            self.buf[(self.w_pos / 8) + 1] &= !second_bits_eraser;
            self.buf[(self.w_pos / 8) + 1] |= second_bits_shifted;
        }

        self.w_pos += n as usize;
        if self.w_pos > self.last {
            self.last = self.w_pos;
        }
    }

    /// Writes 8 bits from an `u8` from the underlying buffer. After
    /// the method call further 8 bits are available to be read.
    pub fn write_u8(&mut self, n: u8) {
        self.write_bits(n, 8);
    }

    /// Writes 16 bits from an `u16` from the underlying buffer. After
    /// the method call further 16 bits are available to be read.
    pub fn write_u16(&mut self, n: u16) {
        self.write_bits((n >> 8) as u8, 8);
        self.write_bits(n as u8, 8);
    }

    /// Writes 32 bits from an `u32` from the underlying buffer. After
    /// the method call further 32 bits are available to be read.
    pub fn write_u32(&mut self, n: u32) {
        self.write_bits((n >> 24) as u8, 8);
        self.write_bits((n >> 16) as u8, 8);
        self.write_bits((n >> 8) as u8, 8);
        self.write_bits(n as u8, 8);
    }

    /// Writes the bytes (u8) provided in the passed slice into
    /// the underlying buffer. After the method call, further
    /// `bytes.len() * 8` bits are available to be read.
    pub fn write_bytes(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.write_u8(*byte);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::shared::buffer::BitsBuffer;

    macro_rules! assert_buf {
        ($buffer:expr, $slice:expr, $last:expr, $r_pos:expr, $w_pos:expr) => {
            assert_eq!($buffer.buf, $slice);
            assert_eq!($buffer.last, $last);
            assert_eq!($buffer.r_pos, $r_pos);
            assert_eq!($buffer.w_pos, $w_pos);
        };
    }

    #[test]
    fn test_read_bits() {
        let mut buf = BitsBuffer::from_raw_bytes(&[0b00001010, 0b10000001, 0b01000011, 0b00100010]);
        let starting_buf = [0b00001010, 0b10000001, 0b01000011, 0b00100010];
        assert_buf!(buf, starting_buf, 32, 0, 32);

        assert_eq!(buf.read_bits(7), Some(0b0000101));
        assert_buf!(buf, starting_buf, 32, 7, 32);
        assert_eq!(buf.read_u8(), Some(0b01000000));
        assert_buf!(buf, starting_buf, 32, 15, 32);
        assert_eq!(buf.read_bits(1), Some(0b1));
        assert_buf!(buf, starting_buf, 32, 16, 32);
        assert_eq!(buf.read_bits(5), Some(0b01000));
        assert_buf!(buf, starting_buf, 32, 21, 32);
        assert_eq!(buf.read_bits(5), Some(0b01100));
        assert_buf!(buf, starting_buf, 32, 26, 32);
        assert_eq!(buf.read_bits(4), Some(0b1000));
        assert_buf!(buf, starting_buf, 32, 30, 32);

        assert_eq!(buf.read_bits(4), None);
        assert_buf!(buf, starting_buf, 32, 30, 32);
        assert_eq!(buf.read_bits(3), None);
        assert_buf!(buf, starting_buf, 32, 30, 32);
        assert_eq!(buf.read_bits(2), Some(0b10));
        assert_buf!(buf, starting_buf, 32, 32, 32);
        assert_eq!(buf.read_bits(1), None);
        assert_buf!(buf, starting_buf, 32, 32, 32);
    }

    #[test]
    fn test_read_bytes() {
        let mut buf = BitsBuffer::from_raw_bytes(&[0b00001010, 0b10000001, 0b01000011, 0b00100010]);
        let starting_buf = [0b00001010, 0b10000001, 0b01000011, 0b00100010];
        assert_buf!(buf, starting_buf, 32, 0, 32);
        assert_eq!(buf.read_bytes::<3>(), Some([0b00001010, 0b10000001, 0b01000011]));
        assert_buf!(buf, starting_buf, 32, 24, 32);
        assert_eq!(buf.read_bytes::<1>(), Some([0b00100010]));
        assert_buf!(buf, starting_buf, 32, 32, 32);
        assert_eq!(buf.read_bytes::<1>(), None);
        assert_buf!(buf, starting_buf, 32, 32, 32);
    }

    #[test]
    fn test_read_bytes_vec() {
        let mut buf = BitsBuffer::from_raw_bytes(&[0b00001010, 0b10000001, 0b01000011, 0b00100010]);
        let starting_buf = [0b00001010, 0b10000001, 0b01000011, 0b00100010];
        assert_buf!(buf, starting_buf, 32, 0, 32);
        assert_eq!(buf.read_bytes_vec(3), Some(vec![0b00001010, 0b10000001, 0b01000011]));
        assert_buf!(buf, starting_buf, 32, 24, 32);
        assert_eq!(buf.read_bytes_vec(1), Some(vec![0b00100010]));
        assert_buf!(buf, starting_buf, 32, 32, 32);
    }

    #[test]
    fn test_read_pos() {
        let mut buf = BitsBuffer::from_raw_bytes(&[0b0001_0100, 0b0001_1000, 0b0110_1000, 0b0100_0000]);
        assert_buf!(buf, [0b0001_0100, 0b0001_1000, 0b0110_1000, 0b0100_0000], 32, 0, 32);

        assert_eq!(buf.read_bits(8), Some(0b0001_0100));
        assert_buf!(buf, [0b0001_0100, 0b0001_1000, 0b0110_1000, 0b0100_0000], 32, 8, 32);
        buf.set_read_pos(0);
        assert_eq!(buf.read_bits(8), Some(0b0001_0100));
        assert_buf!(buf, [0b0001_0100, 0b0001_1000, 0b0110_1000, 0b0100_0000], 32, 8, 32);
        buf.set_read_pos(8);
        assert_eq!(buf.read_bits(8), Some(0b0001_1000));
        assert_buf!(buf, [0b0001_0100, 0b0001_1000, 0b0110_1000, 0b0100_0000], 32, 16, 32);
        buf.set_read_pos(15);
        assert_eq!(buf.read_bits(8), Some(0b0_0110_100));
        assert_buf!(buf, [0b0001_0100, 0b0001_1000, 0b0110_1000, 0b0100_0000], 32, 23, 32);
        buf.set_read_pos(32);
        assert_eq!(buf.read_bits(1), None);
        assert_buf!(buf, [0b0001_0100, 0b0001_1000, 0b0110_1000, 0b0100_0000], 32, 32, 32);
    }

    #[test]
    #[should_panic]
    fn test_read_pos_invalid() {
        let mut buf = BitsBuffer::from_raw_bytes(&[0b0001_0100, 0b0001_1000, 0b0110_1000, 0b0100_0000]);
        assert_buf!(buf, [0b0001_0100, 0b0001_1000, 0b0110_1000, 0b0100_0000], 32, 0, 32);
        buf.set_read_pos(33);
    }

    #[test]
    fn test_write_bits() {
        let mut buf = BitsBuffer::new();
        assert_buf!(buf, [] as [u8; 0], 0, 0, 0);

        buf.write_bits(0b1, 6);
        assert_buf!(buf, [0b0000_0100], 6, 0, 6);
        buf.write_bits(0b1, 6);
        assert_buf!(buf, [0b0000_0100, 0b0001_0000], 12, 0, 12);
        buf.write_bits(0b10_0001, 6);
        assert_buf!(buf, [0b0000_0100, 0b0001_1000, 0b0100_0000], 18, 0, 18);
        buf.write_bits(0b1010_0001, 8);
        assert_buf!(buf, [0b0000_0100, 0b0001_1000, 0b0110_1000, 0b0100_0000], 26, 0, 26);

        let mut buf = BitsBuffer::new();
        assert_buf!(buf, [] as [u8; 0], 0, 0, 0);

        buf.write_u8(0b10000000);
        assert_buf!(buf, [0b1000_0000], 8, 0, 8);
        buf.write_u8(0b10101111);
        assert_buf!(buf, [0b1000_0000, 0b10101111], 16, 0, 16);
        buf.write_u8(0b11110001);
        assert_buf!(buf, [0b1000_0000, 0b10101111, 0b11110001], 24, 0, 24);
    }

    #[test]
    fn test_write_bytes() {
        let mut buf = BitsBuffer::new();
        assert_buf!(buf, [] as [u8; 0], 0, 0, 0);

        buf.write_bytes(&[0b10000000]);
        assert_buf!(buf, [0b1000_0000], 8, 0, 8);
        buf.write_bytes(&[0b10101111, 0b10101111]);
        assert_buf!(buf, [0b1000_0000, 0b10101111, 0b10101111], 24, 0, 24);
        buf.write_bytes(&[0b11110001]);
        assert_buf!(buf, [0b1000_0000, 0b10101111, 0b10101111, 0b11110001], 32, 0, 32);
    }

    #[test]
    fn test_write_pos() {
        let mut buf = BitsBuffer::from_raw_bytes(&[0b0001_0100, 0b0001_1000, 0b0110_1000, 0b0100_0000]);
        assert_buf!(buf, [0b0001_0100, 0b0001_1000, 0b0110_1000, 0b0100_0000], 32, 0, 32);

        buf.set_write_pos(0);
        assert_buf!(buf, [0b0001_0100, 0b0001_1000, 0b0110_1000, 0b0100_0000], 32, 0, 0);

        buf.write_bits(0b1110_11, 6);
        assert_buf!(buf, [0b1110_1100, 0b0001_1000, 0b0110_1000, 0b0100_0000], 32, 0, 6);
        buf.write_bits(0b10, 2);
        assert_buf!(buf, [0b1110_1110, 0b0001_1000, 0b0110_1000, 0b0100_0000], 32, 0, 8);
        buf.write_bits(0b1000, 4);
        assert_buf!(buf, [0b1110_1110, 0b1000_1000, 0b0110_1000, 0b0100_0000], 32, 0, 12);
        buf.write_bits(0b1001_1001, 8);
        assert_buf!(buf, [0b1110_1110, 0b1000_1001, 0b1001_1000, 0b0100_0000], 32, 0, 20);
        buf.write_bits(0b1001_1001, 8);
        assert_buf!(buf, [0b1110_1110, 0b1000_1001, 0b1001_1001, 0b1001_0000], 32, 0, 28);
        buf.write_bits(0b1001_1001, 8);
        assert_buf!(
            buf,
            [0b1110_1110, 0b1000_1001, 0b1001_1001, 0b1001_1001, 0b1001_0000],
            36,
            0,
            36
        );
        buf.write_bits(0b100, 3);
        assert_buf!(
            buf,
            [0b1110_1110, 0b1000_1001, 0b1001_1001, 0b1001_1001, 0b1001_1000],
            39,
            0,
            39
        );
        buf.write_bits(0b0, 1);
        assert_buf!(
            buf,
            [0b1110_1110, 0b1000_1001, 0b1001_1001, 0b1001_1001, 0b1001_1000],
            40,
            0,
            40
        );
    }

    #[test]
    #[should_panic]
    fn test_write_pos_invalid() {
        let mut buf = BitsBuffer::from_raw_bytes(&[0b0001_0100, 0b0001_1000, 0b0110_1000, 0b0100_0000]);
        assert_buf!(buf, [0b0001_0100, 0b0001_1000, 0b0110_1000, 0b0100_0000], 32, 0, 32);
        buf.set_write_pos(33);
    }

    #[test]
    fn test_write_and_read() {
        let mut buf = BitsBuffer::from_raw_bytes(&[]);
        assert_buf!(buf, [] as [u8; 0], 0, 0, 0);

        buf.write_bits(0b1, 6);
        assert_buf!(buf, [0b0000_0100], 6, 0, 6);
        buf.write_bits(0b1, 6);
        assert_buf!(buf, [0b0000_0100, 0b0001_0000], 12, 0, 12);
        buf.write_bits(0b1, 6);
        assert_buf!(buf, [0b0000_0100, 0b0001_0000, 0b0100_0000], 18, 0, 18);
        buf.write_bits(0b1, 5);
        assert_buf!(buf, [0b0000_0100, 0b0001_0000, 0b0100_0010], 23, 0, 23);

        assert_eq!(buf.read_bits(2), Some(0b00));
        assert_buf!(buf, [0b0000_0100, 0b0001_0000, 0b0100_0010], 23, 2, 23);
        assert_eq!(buf.read_bits(4), Some(0b0001));
        assert_buf!(buf, [0b0000_0100, 0b0001_0000, 0b0100_0010], 23, 6, 23);
        assert_eq!(buf.read_bits(6), Some(0b000001));
        assert_buf!(buf, [0b0000_0100, 0b0001_0000, 0b0100_0010], 23, 12, 23);
        assert_eq!(buf.read_bits(6), Some(0b000001));
        assert_buf!(buf, [0b0000_0100, 0b0001_0000, 0b0100_0010], 23, 18, 23);
        assert_eq!(buf.read_bits(4), Some(0b0));
        assert_buf!(buf, [0b0000_0100, 0b0001_0000, 0b0100_0010], 23, 22, 23);
        assert_eq!(buf.read_bits(4), None);
        assert_buf!(buf, [0b0000_0100, 0b0001_0000, 0b0100_0010], 23, 22, 23);
        assert_eq!(buf.read_bits(3), None);
        assert_buf!(buf, [0b0000_0100, 0b0001_0000, 0b0100_0010], 23, 22, 23);
        assert_eq!(buf.read_bits(2), None);
        assert_buf!(buf, [0b0000_0100, 0b0001_0000, 0b0100_0010], 23, 22, 23);
        assert_eq!(buf.read_bits(1), Some(0b1));
        assert_buf!(buf, [0b0000_0100, 0b0001_0000, 0b0100_0010], 23, 23, 23);
        assert_eq!(buf.read_bits(1), None);
        assert_buf!(buf, [0b0000_0100, 0b0001_0000, 0b0100_0010], 23, 23, 23);

        buf.write_bits(0b1010, 4);
        assert_buf!(buf, [0b100, 0b0001_0000, 0b0100_0011, 0b0100_0000], 27, 23, 27);
        assert_eq!(buf.read_bits(6), None);
        assert_buf!(buf, [0b100, 0b0001_0000, 0b0100_0011, 0b0100_0000], 27, 23, 27);
        assert_eq!(buf.read_bits(5), None);
        assert_buf!(buf, [0b100, 0b0001_0000, 0b0100_0011, 0b0100_0000], 27, 23, 27);
        assert_eq!(buf.read_bits(3), Some(0b101));
        assert_buf!(buf, [0b100, 0b0001_0000, 0b0100_0011, 0b0100_0000], 27, 26, 27);
        assert_eq!(buf.read_bits(2), None);
        assert_buf!(buf, [0b100, 0b0001_0000, 0b0100_0011, 0b0100_0000], 27, 26, 27);
        assert_eq!(buf.read_bits(1), Some(0b0));
        assert_buf!(buf, [0b100, 0b0001_0000, 0b0100_0011, 0b0100_0000], 27, 27, 27);
        assert_eq!(buf.read_bits(1), None);
        assert_buf!(buf, [0b100, 0b0001_0000, 0b0100_0011, 0b0100_0000], 27, 27, 27);
    }
}

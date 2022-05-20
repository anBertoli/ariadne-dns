pub struct BitsBuffer {
    buf: Vec<u8>,
    last: usize,
    pos: usize,
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
        BitsBuffer { buf: vec![], last: 0, pos: 0 }
    }

    /// Builds a [BitsBuffer] from a bytes slice. Subsequent write ops
    /// append to the buffer while reads start form the beginning.
    pub fn from_raw_bytes(bytes: &[u8]) -> Self {
        BitsBuffer {
            buf: bytes.to_owned(),
            last: bytes.len() * 8,
            pos: 0,
        }
    }

    /// Consumes the buffer and returns the inner bytes as a Vec.
    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }

    /// Returns the current reading position in the buffer.
    /// Note that the reading position is expressed in bits.
    pub fn read_pos(&self) -> usize {
        self.pos
    }

    /// Sets the reading position in the buffer (expressed in bits).
    /// Returns a an error variant if the provided reading position
    /// is beyond the buffer length.
    pub fn set_read_pos(&mut self, n: usize) -> Result<(), ()> {
        if self.pos > self.last {
            return Err(());
        }
        self.pos = n;
        Ok(())
    }

    /// Reads and returns a certain number of bits, reading from the underlying
    /// buffer. `n` represent the number of bits to be read, and it can range
    /// from 1 to 8 bits. After the method call the reading positions is
    /// advanced by `n`.
    ///
    /// # Panics
    /// Panics if `n > 8`.
    pub fn read_bits(&mut self, n: u8) -> Option<u8> {
        // Make sure the input is valid and
        // we have enough data to be read.
        assert!(n <= 8);
        if n == 0 {
            return Some(0);
        }
        if self.pos + (n as usize) > self.last {
            return None;
        }

        // Decide if the current byte as enough remaining bits to
        // serve the current read. If not, we need to read from
        // both the current and the next byte.
        let bytes_offset = self.pos / 8;
        let bits_offset = self.pos % 8;
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

        self.pos += n as usize;
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
        if self.pos + 16 > self.last {
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
        if self.pos + 32 > self.last {
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
        if self.pos + N * 8 > self.last {
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
        if self.pos + n * 8 > self.last {
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
        // Make sure the input is valid and extend
        // the internal buffer if we ended the space.
        assert!(n <= 8);
        if n == 0 {
            return;
        }
        if self.last == self.buf.len() * 8 {
            self.buf.push(0);
        }

        // Ensure that all the needed space is present in the
        // current byte. If not, write to both the current and
        // the next byte.
        let bits_masked = bits & ((1_u16 << n) - 1) as u8;
        let available_bits = 8 - (self.last % 8) as u8;

        if n <= available_bits as u8 {
            let bits_masked = bits_masked << (available_bits - n);
            *self.buf.last_mut().unwrap() |= bits_masked;
        } else {
            let last = self.buf.len() - 1;
            self.buf.push(0);

            let first_bits_masked = bits_masked >> (n - available_bits);
            let second_bits_masked = bits_masked & ((1_u16 << n - available_bits) - 1) as u8;
            let second_bits_masked = second_bits_masked << (8 - (n - available_bits));
            self.buf[last] |= first_bits_masked;
            self.buf[last + 1] |= second_bits_masked;
        }

        self.last += n as usize;
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

use crate::shared::buffer::*;

macro_rules! assert_buf {
    ($buffer:expr, $slice:expr, $last:expr, $pos:expr) => {
        assert_eq!($buffer.buf, $slice);
        assert_eq!($buffer.last, $last);
        assert_eq!($buffer.pos, $pos);
    };
}

#[test]
fn test_read() {
    let mut buf = BitsBuffer::from_raw_bytes(&[10, 129, 67, 34]);
    let in_buf = [0b00001010, 0b10000001, 0b01000011, 0b00100010];
    assert_buf!(buf, in_buf, 32, 0);

    assert_eq!(buf.read_bits(7), Some(0b0000101));
    assert_buf!(buf, in_buf, 32, 7);
    assert_eq!(buf.read_u8(), Some(0b01000000));
    assert_buf!(buf, in_buf, 32, 15);
    assert_eq!(buf.read_bits(1), Some(0b1));
    assert_buf!(buf, in_buf, 32, 16);
    assert_eq!(buf.read_bits(5), Some(0b01000));
    assert_buf!(buf, in_buf, 32, 21);
    assert_eq!(buf.read_bits(5), Some(0b01100));
    assert_buf!(buf, in_buf, 32, 26);
    assert_eq!(buf.read_bits(4), Some(0b1000));
    assert_buf!(buf, in_buf, 32, 30);

    assert_eq!(buf.read_bits(4), None);
    assert_buf!(buf, in_buf, 32, 30);
    assert_eq!(buf.read_bits(3), None);
    assert_buf!(buf, in_buf, 32, 30);
    assert_eq!(buf.read_bits(2), Some(0b10));
    assert_buf!(buf, in_buf, 32, 32);
    assert_eq!(buf.read_bits(1), None);
    assert_buf!(buf, in_buf, 32, 32);
}

#[test]
fn test_write_single_bytes() {
    let mut buf = BitsBuffer::from_raw_bytes(&[]);
    assert_buf!(buf, [], 0, 0);

    buf.write_u8(0b10000000);
    assert_buf!(buf, [0b1000_0000], 8, 0);
    buf.write_u8(0b10101111);
    assert_buf!(buf, [0b1000_0000, 0b10101111], 16, 0);
    buf.write_u8(0b11110001);
    assert_buf!(buf, [0b1000_0000, 0b10101111, 0b11110001], 24, 0);
}

#[test]
fn test_write_bits() {
    let mut buf = BitsBuffer::from_raw_bytes(&[]);
    assert_buf!(buf, [], 0, 0);

    buf.write_bits(0b1, 6);
    assert_buf!(buf, [0b0000_0100], 6, 0);
    buf.write_bits(0b1, 6);
    assert_buf!(buf, [0b0000_0100, 0b0001_0000], 12, 0);
    buf.write_bits(0b10_0001, 6);
    assert_buf!(buf, [0b0000_0100, 0b0001_1000, 0b0100_0000], 18, 0);
    buf.write_bits(0b1010_0001, 8);
    assert_buf!(buf, [0b100, 0b0001_1000, 0b0110_1000, 0b0100_0000], 26, 0);
}

#[test]
fn test_write_and_read() {
    let mut buf = BitsBuffer::from_raw_bytes(&[]);
    assert_buf!(buf, [], 0, 0);

    buf.write_bits(0b1, 6);
    assert_buf!(buf, [0b0000_0100], 6, 0);
    buf.write_bits(0b1, 6);
    assert_buf!(buf, [0b0000_0100, 0b0001_0000], 12, 0);
    buf.write_bits(0b1, 6);
    assert_buf!(buf, [0b0000_0100, 0b0001_0000, 0b0100_0000], 18, 0);
    buf.write_bits(0b1, 5);
    assert_buf!(buf, [0b0000_0100, 0b0001_0000, 0b0100_0010], 23, 0);

    assert_eq!(buf.read_bits(2), Some(0b00));
    assert_buf!(buf, [0b0000_0100, 0b0001_0000, 0b0100_0010], 23, 2);
    assert_eq!(buf.read_bits(4), Some(0b0001));
    assert_buf!(buf, [0b0000_0100, 0b0001_0000, 0b0100_0010], 23, 6);
    assert_eq!(buf.read_bits(6), Some(0b000001));
    assert_buf!(buf, [0b0000_0100, 0b0001_0000, 0b0100_0010], 23, 12);
    assert_eq!(buf.read_bits(6), Some(0b000001));
    assert_buf!(buf, [0b0000_0100, 0b0001_0000, 0b0100_0010], 23, 18);
    assert_eq!(buf.read_bits(4), Some(0b0));
    assert_buf!(buf, [0b0000_0100, 0b0001_0000, 0b0100_0010], 23, 22);
    assert_eq!(buf.read_bits(4), None);
    assert_buf!(buf, [0b0000_0100, 0b0001_0000, 0b0100_0010], 23, 22);
    assert_eq!(buf.read_bits(3), None);
    assert_buf!(buf, [0b0000_0100, 0b0001_0000, 0b0100_0010], 23, 22);
    assert_eq!(buf.read_bits(2), None);
    assert_buf!(buf, [0b0000_0100, 0b0001_0000, 0b0100_0010], 23, 22);
    assert_eq!(buf.read_bits(1), Some(0b1));
    assert_buf!(buf, [0b0000_0100, 0b0001_0000, 0b0100_0010], 23, 23);
    assert_eq!(buf.read_bits(1), None);
    assert_buf!(buf, [0b0000_0100, 0b0001_0000, 0b0100_0010], 23, 23);

    buf.write_bits(0b1010, 4);
    assert_buf!(buf, [0b100, 0b0001_0000, 0b0100_0011, 0b0100_0000], 27, 23);
    assert_eq!(buf.read_bits(6), None);
    assert_buf!(buf, [0b100, 0b0001_0000, 0b0100_0011, 0b0100_0000], 27, 23);
    assert_eq!(buf.read_bits(5), None);
    assert_buf!(buf, [0b100, 0b0001_0000, 0b0100_0011, 0b0100_0000], 27, 23);
    assert_eq!(buf.read_bits(3), Some(0b101));
    assert_buf!(buf, [0b100, 0b0001_0000, 0b0100_0011, 0b0100_0000], 27, 26);
    assert_eq!(buf.read_bits(2), None);
    assert_buf!(buf, [0b100, 0b0001_0000, 0b0100_0011, 0b0100_0000], 27, 26);
    assert_eq!(buf.read_bits(1), Some(0b0));
    assert_buf!(buf, [0b100, 0b0001_0000, 0b0100_0011, 0b0100_0000], 27, 27);
    assert_eq!(buf.read_bits(1), None);
    assert_buf!(buf, [0b100, 0b0001_0000, 0b0100_0011, 0b0100_0000], 27, 27);
}

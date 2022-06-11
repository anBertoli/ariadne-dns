use crate::shared::buffer::*;
use crate::shared::dns::errors::*;
use std::str;

/// Decode a character string, reading the bytes from the provided buffer.
/// Both the string length and non-UTF-8 values are checked.
pub fn decode_character_string(buffer: &mut BitsBuf) -> Result<String, ParsingErr> {
    let len_byte = check_end(buffer.read_u8())?;
    let str_bytes = check_end(buffer.read_bytes_vec(len_byte as usize))?;
    if str_bytes.len() > 255 {
        return Err(ParsingErr::StringCharErr("string len > 255".to_string()));
    }
    match str::from_utf8(&str_bytes) {
        Err(_) => Err(ParsingErr::StringCharErr("not utf-8".to_string())),
        Ok(str) => Ok(str.to_string()),
    }
}

/// Encode a character string returning a vector of bytes. Validation
/// is performed checking the length (Rust strings are already UTF-8).
pub fn encode_character_string(string: &str) -> Result<Vec<u8>, ParsingErr> {
    let len = string.len();
    if len > 255 {
        return Err(ParsingErr::StringCharErr("string len > 255".to_string()));
    }
    let mut bytes = Vec::with_capacity(len + 1);
    bytes.push(len as u8);
    bytes.extend(string.as_bytes());
    Ok(bytes)
}

pub fn is_valid_character_string(s: &str, quoted: bool) -> bool {
    if quoted {
        s.chars().all(|ch| ch.is_ascii())
    } else {
        s.chars().all(|ch| ch.is_ascii() && ch != ' ')
    }
}

pub fn check_end<T>(opt: Option<T>) -> Result<T, ParsingErr> {
    match opt {
        None => Err(ParsingErr::BytesEnd),
        Some(v) => Ok(v),
    }
}

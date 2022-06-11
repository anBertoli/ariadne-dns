use crate::shared::buffer::*;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display, Formatter};
use std::str;

/// A wrapper for domain names. The [`Name`] struct is used to hold valid
/// absolute domain names. This is the invariant that must be guaranteed
/// in every method that creates or modifies names. [`Name`] implements
/// `AsRef<str>`, so a reference to the inner string can be easily obtained.  
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Name(String);

impl AsRef<str> for Name {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Display for Name {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl Name {
    const POINTER_MASK: u16 = 0b00111111_11111111;
    const LABEL_MASK: u8 = 0b11000000;
    const MAX_REDIR: u16 = 15;

    /// Creates a [`Name`] from the passed string. The string must be a valid
    /// absolute domain name.
    pub fn from_string(s: &str) -> Result<Self, NameErr> {
        validate_name(s)?;
        Ok(Self(s.to_string()))
    }

    /// Creates a [`Name`] parsing its binary representation (a series of labels,
    /// divided by a length byte). There's a max number of jumps allowed (for
    /// security reasons).
    pub fn from_bytes(buffer: &mut BitsBuf) -> Result<Self, NameErr> {
        let mut name_bytes: Vec<u8> = Vec::with_capacity(100);
        let mut pos_after_jump: usize = 0;
        let mut n_jumps: u16 = 0;

        loop {
            let len_byte = check_end(buffer.read_u8())?;
            match len_byte & Self::LABEL_MASK {
                // Pointer type. Set the next read pos to the referenced
                // part. After jumps, the position must be re-set.
                0b11000000 => {
                    match n_jumps {
                        v if v > Self::MAX_REDIR => return Err(NameErr::MaxRedir),
                        0 => pos_after_jump = buffer.read_pos() + 8,
                        _ => {}
                    }
                    let second_byte = check_end(buffer.read_u8())? as u16;
                    let jump_pos = (((len_byte as u16) << 8) | second_byte) & Self::POINTER_MASK;
                    let jump_pos = jump_pos * 8;
                    buffer.set_read_pos(jump_pos as usize);
                    n_jumps += 1;
                }
                // Normal label type. Could be found either after
                // a pointer redirection or the very first time.
                0b00000000 => {
                    if len_byte > 63 {
                        return Err(NameErr::LongLabel);
                    }
                    if len_byte == 0 {
                        name_bytes.push('.' as u8);
                        break;
                    }
                    if !name_bytes.is_empty() {
                        name_bytes.push('.' as u8);
                    }
                    let label_bytes = check_end(buffer.read_bytes_vec(len_byte as usize))?;
                    name_bytes.extend(label_bytes);
                    if name_bytes.len() > 255 {
                        return Err(NameErr::LongName);
                    }
                }
                // Starting bits are 10 or 01. These are reserved
                // for later use. We treat this as an error.
                _ => return Err(NameErr::MalformedLabel("wrong starting bits")),
            }
        }

        // Re-set the position if we followed a pointer.
        if pos_after_jump > 0 {
            buffer.set_read_pos(pos_after_jump);
        }

        match str::from_utf8(&name_bytes) {
            Err(_) => Err(NameErr::MalformedName("not UTF-8")),
            Ok(name) => {
                validate_name(&name)?;
                Ok(Self(name.to_string()))
            }
        }
    }

    /// Encode and return a domain [`Name`] in its binary representation
    /// (a series of labels, divided by a length byte).
    pub fn to_bytes(&self) -> Vec<u8> {
        debug_assert!(validate_name(&self.0).is_ok());
        let mut vec = Vec::with_capacity(self.0.len());
        for n in self.0.split('.') {
            let n_bytes = n.as_bytes();
            vec.push(n_bytes.len() as u8);
            vec.extend(n_bytes);
        }
        vec
    }
}

// Validate the string to check if it's a valid (absolute) domain
// name. Both name and labels are validated.
fn validate_name(name: &str) -> Result<(), NameErr> {
    if name == "." {
        return Ok(());
    }
    if name.len() > 255 {
        return Err(NameErr::LongName);
    }
    if !name.ends_with('.') {
        return Err(NameErr::RelativeName);
    }
    if name.starts_with('.') {
        return Err(NameErr::MalformedName("starts with dot"));
    }
    if name.contains("..") {
        return Err(NameErr::MalformedName("double dot in name"));
    }
    let name = &name[..name.len() - 1];
    for label in name.split('.') {
        if label.len() == 0 {
            return Err(NameErr::MalformedLabel("empty label"));
        }
        validate_label(label)?;
    }
    Ok(())
}

// Validate the label, checking both its length and the characters.
// The label must already be non empty.
fn validate_label(label: &str) -> Result<(), NameErr> {
    if label.len() == 0 {
        return Err(NameErr::MalformedLabel("empty label"));
    }
    let first = label.chars().next().unwrap();
    let last = label.chars().last().unwrap();
    if !first.is_ascii_alphanumeric() {
        return Err(NameErr::MalformedLabel("must start with alphanumeric"));
    }
    if !last.is_ascii_alphanumeric() {
        return Err(NameErr::MalformedLabel("must end with alphanumeric"));
    }
    let between = label.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '-');
    if !between {
        return Err(NameErr::MalformedLabel("must contain alphanumeric or '-'"));
    }
    Ok(())
}

fn check_end<T>(opt: Option<T>) -> Result<T, NameErr> {
    match opt {
        None => Err(NameErr::BytesEnd),
        Some(v) => Ok(v),
    }
}

impl Name {
    /// Reports if the [`Name`] is owned by the top node of the passed zone.
    /// The zone must be a valid name to ensure a correct comparison.
    pub fn is_in_zone_root(&self, zone: &Self) -> bool {
        self == zone
    }

    /// Reports if the [`Name`] is contained in the passed zone. The zone
    /// must be a valid name to ensure a correct comparison.
    pub fn is_in_zone(&self, zone: &Self) -> bool {
        let mut name_labels = self.0.rsplit('.');
        let zone_labels = zone.0.rsplit('.');
        for zl in zone_labels {
            let nl = match name_labels.next() {
                None => return false,
                Some(v) => v,
            };
            if nl != zl {
                return false;
            }
        }
        true
    }

    /// Reports if the [`Name`] is contained in the passed authoritative zone,
    /// but not in any of the sub zones. The zones must be valid names to
    /// ensure a correct comparison.
    pub fn is_only_in_auth_zone(&self, auth_zone: &Self, sub_zones: &[Self]) -> bool {
        if !self.is_in_zone(auth_zone) {
            return false;
        }
        for sub_zone in sub_zones {
            if self.is_in_zone(sub_zone) {
                return false;
            }
        }
        true
    }
}

/// Errors returned by the [`Name`] creation and validation processes.
#[derive(Debug, Clone)]
pub enum NameErr {
    BytesEnd,
    MaxRedir,
    PointerOutOfBonds,
    RelativeName,
    LongName,
    MalformedName(&'static str),
    LongLabel,
    MalformedLabel(&'static str),
}

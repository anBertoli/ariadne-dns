use crate::nameserver::zones::tokens::*;
use crate::shared::dns;
use std::io;

/// The [ParseErr] with a string describing the context of the error.
pub type ParseErrCtx = (ParseErr, String);

/// Errors returned during the zone files parsing process.
#[derive(Debug)]
pub enum ParseErr {
    // Errors from the tokenizer.
    UnexpectedToken(Token),
    MalformedToken(TokenErr),
    ReadingErr(io::Error),

    // Wrong data in zone file.
    MalformedData(String),
    TtlTooLow(u32),

    // Logic/consistency errors.
    UnexpectedRecord(String),
    NameNotInRootNode(String),
    NameNotInZone(String),
    MalformedZone(String),
}

impl From<TokenErr> for ParseErr {
    fn from(err: TokenErr) -> Self {
        match err {
            TokenErr::ReadErr(err) => ParseErr::ReadingErr(err),
            _ => ParseErr::MalformedToken(err),
        }
    }
}

impl From<dns::NameErr> for ParseErr {
    fn from(err: dns::NameErr) -> Self {
        ParseErr::MalformedData(format!("invalid name, {:?}", err))
    }
}

/// Returns an error is the passed string is not an absolute domain name.
pub fn ensure_absolute_name(name: &str) -> Result<(), ParseErr> {
    if name.ends_with('.') {
        Ok(())
    } else {
        let err_msg = format!("absolute name wanted, got: '{}'", name);
        Err(ParseErr::MalformedData(err_msg))
    }
}

/// Returns an error if the passed name is not contained in the zone.
pub fn ensure_name_in_zone(name: &dns::Name, zone: &dns::Name) -> Result<(), ParseErr> {
    if name.is_in_zone(zone) {
        Ok(())
    } else {
        Err(ParseErr::NameNotInZone(name.to_string()))
    }
}

/// Ensures that the passed domain name is contained in the first zone (usually
/// the auth zone), but not in any of the other passed zones (usually sub zones).
pub fn ensure_name_in_auth_zone(name: &dns::Name, zone: &dns::Name, sub_zones: &[dns::Name]) -> Result<(), ParseErr> {
    if name.is_only_in_auth_zone(zone, sub_zones) {
        Ok(())
    } else {
        Err(ParseErr::NameNotInZone(name.to_string()))
    }
}

/// Returns an error if the class is not supported.
pub fn ensure_class_is_supported(class: &dns::Class) -> Result<(), ParseErr> {
    if class.is_supported() {
        Ok(())
    } else {
        let err_msg = format!("class '{:?}' not supported", class);
        Err(ParseErr::MalformedData(err_msg))
    }
}

/// Returns an error if the TTL is less than the minimum.
pub fn ensure_min_ttl(min_ttl: u32, ttl: u32) -> Result<(), ParseErr> {
    if ttl >= min_ttl {
        Ok(())
    } else {
        Err(ParseErr::TtlTooLow(ttl))
    }
}

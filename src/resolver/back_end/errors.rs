use crate::shared::dns;
use std::io;

/// A [LookupErr] with a string explaining the context of the error.
pub type LookupErrCtx = (String, LookupErr);

/// Errors encountered when performing a lookup. Some of them are
/// related to IO or parsing messages, while others are logic errors.  
#[derive(Debug)]
pub enum LookupErr {
    IO(io::Error),
    UnexpectedRespCode(dns::RespCode),
    UnexpectedEmptyResp,
    MalformedResp(String),

    ZonesLoop,
    CnamesLoop,
    UnexpectedCname,
    MaxCnameRedir,

    // Error resolving a sub-lookup,
    // usually resolving a NS name.
    SubLookupErr(Box<LookupErrCtx>),
}

impl From<io::Error> for LookupErr {
    fn from(io_err: io::Error) -> Self {
        LookupErr::IO(io_err)
    }
}

use crate::shared::dns::class::*;
use crate::shared::dns::header::*;
use crate::shared::dns::name::*;
use crate::shared::dns::types::*;

/// Enum representing errors related to dns messages decoding. Different
/// variants represent errors coming from different parts of the dns message.
#[derive(Debug)]
pub enum MessageErr {
    HeaderErr(ParsingErr),
    QuestionErr(usize, ParsingErr),
    AnswerErr(usize, ParsingErr),
    AuthorityErr(usize, ParsingErr),
    AdditionalErr(usize, ParsingErr),
}

impl MessageErr {
    pub fn inner_err(&self) -> ParsingErr {
        match self {
            MessageErr::HeaderErr(err) => err.clone(),
            MessageErr::QuestionErr(_, err) => err.clone(),
            MessageErr::AnswerErr(_, err) => err.clone(),
            MessageErr::AuthorityErr(_, err) => err.clone(),
            MessageErr::AdditionalErr(_, err) => err.clone(),
        }
    }
}

/// Errors generated during messages decoding. Different variants
/// represent errors of different nature, from invalid formatted
/// messages to logic/consistency errors inside a message.
#[derive(Debug, Clone)]
pub enum ParsingErr {
    UnsupportedType(RecordType),
    UnexpectedType(RecordType),
    UnknownType(u16),
    UnsupportedClass(Class),
    UnknownClass(u16),
    UnknownOpCode(u8),
    UnsupportedOpCode(OpCode),
    UnknownRespCode(u8),
    DataLenMismatch,
    BytesEnd,

    DomainNameErr(NameErr),
    StringCharErr(String),
}

impl From<NameErr> for ParsingErr {
    fn from(ne: NameErr) -> Self {
        match ne {
            NameErr::BytesEnd => ParsingErr::BytesEnd,
            v => ParsingErr::DomainNameErr(v),
        }
    }
}

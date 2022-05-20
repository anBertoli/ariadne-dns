use crate::shared::buffer::*;
use crate::shared::dns::class::*;
use crate::shared::dns::errors::*;
use crate::shared::dns::name::*;
use crate::shared::dns::types::*;
use crate::shared::dns::utils::*;

/// Questions present in the question section of DNS messages. They refer to
/// a specific node of the name system, asking for a certain type of records.
/// The class support is limited to the internet class.
#[derive(Debug, Clone)]
pub struct Question {
    pub node: Name,
    pub record_type: RecordType,
    pub class: Class,
}

impl Question {
    /// Decode a dns message [`Question`] from the bytes read from the passed
    /// buffer. Unsupported types/classes are detected and the function proper
    /// errors in this case. Unknown records types still cause the bytes of that
    /// question to be consumed (and an error is returned as usual).
    pub fn decode_from_buf(buffer: &mut BitsBuffer) -> Result<Question, ParsingErr> {
        let node = Name::from_bytes(buffer)?;
        let record_type = decode_record_type(buffer)?;
        let class = decode_class(check_end(buffer.read_u16())?)?;
        Ok(Question { node, record_type, class })
    }

    /// Decode a dns message [`Question`] from the passed bytes slice. It's
    /// a wrapper function that allows decoding the question from raw bytes,
    /// opposed to [Question::decode_from_buf] method which needs a buffer.
    pub fn decode_from_bytes(bytes: &[u8]) -> Result<Question, ParsingErr> {
        let mut buf = BitsBuffer::from_raw_bytes(bytes);
        Question::decode_from_buf(&mut buf)
    }

    /// Encode a dns message [`Question`] to raw bytes, writing them into the
    /// provided buffer. This function panics if some unsupported class or types
    /// are provided (to maintain invariants about supported features).
    pub fn encode_to_buf(&self, buffer: &mut BitsBuffer) -> Result<(), ParsingErr> {
        assert!(self.record_type.is_supported_for_question());
        assert!(self.class.is_supported());

        let name = self.node.to_bytes();
        buffer.write_bytes(&name);
        buffer.write_u16(self.record_type.to_num());
        buffer.write_u16(self.class.to_num());
        Ok(())
    }
}

fn decode_record_type(buffer: &mut BitsBuffer) -> Result<RecordType, ParsingErr> {
    match RecordType::from_num(check_end(buffer.read_u16())?) {
        Ok(v) if !v.is_supported_for_question() => Err(ParsingErr::UnsupportedType(v)),
        Ok(v) => Ok(v),
        Err(n) => {
            check_end(buffer.read_u16())?;
            Err(ParsingErr::UnknownType(n))
        }
    }
}

fn decode_class(cl: u16) -> Result<Class, ParsingErr> {
    match Class::from_num(cl) {
        Err(c) => Err(ParsingErr::UnknownClass(c)),
        Ok(c) if !c.is_supported() => Err(ParsingErr::UnsupportedClass(c)),
        Ok(c) => Ok(c),
    }
}

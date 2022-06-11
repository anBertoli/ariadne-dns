use crate::shared::buffer::*;
use crate::shared::dns::errors::*;
use crate::shared::dns::utils::*;
use rand::Rng;

/// Header of dns messages. This type can be generated manually
/// or obtained decoding it from raw bytes. The `Default` trait
/// is implemented to generate an empty header with a random id.
#[derive(Debug, Clone)]
pub struct Header {
    pub id: u16,
    pub query_resp: bool,
    pub op_code: OpCode,
    pub auth_answer: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub z: u8,
    pub resp_code: RespCode,
    pub questions_count: u16,
    pub answers_count: u16,
    pub authorities_count: u16,
    pub additionals_count: u16,
}

impl Default for Header {
    fn default() -> Self {
        Header {
            id: rand::thread_rng().gen::<u16>(),
            query_resp: false,
            op_code: OpCode::STD,
            auth_answer: false,
            truncated: false,
            recursion_desired: false,
            recursion_available: false,
            z: 0,
            resp_code: RespCode::NoError,
            questions_count: 0,
            answers_count: 0,
            authorities_count: 0,
            additionals_count: 0,
        }
    }
}

impl Header {
    /// Decode a dns message [`Header`] from the bytes read from the provided buffer.
    /// Unsupported op/resp codes are detected and an appropriate error is returned.
    pub fn decode_from_buf(buffer: &mut BitsBuf) -> Result<Header, ParsingErr> {
        let id = check_end(buffer.read_u16())?;
        let query_resp = check_end(buffer.read_bits(1))? == 1;
        let op_code = decode_op_code(check_end(buffer.read_bits(4))?, true)?;
        let auth_answer = check_end(buffer.read_bits(1))? == 1;
        let truncated = check_end(buffer.read_bits(1))? == 1;
        let recursion_desired = check_end(buffer.read_bits(1))? == 1;
        let recursion_available = check_end(buffer.read_bits(1))? == 1;
        let z = check_end(buffer.read_bits(3))?;
        let resp_code = decode_resp_code(check_end(buffer.read_bits(4))?)?;
        let questions_count = check_end(buffer.read_u16())?;
        let answers_count = check_end(buffer.read_u16())?;
        let authorities_count = check_end(buffer.read_u16())?;
        let additionals_count = check_end(buffer.read_u16())?;
        Ok(Header {
            id,
            query_resp,
            op_code,
            auth_answer,
            truncated,
            recursion_desired,
            recursion_available,
            z,
            resp_code,
            questions_count,
            answers_count,
            authorities_count,
            additionals_count,
        })
    }

    /// Decode a dns message [`Header`] from the passed bytes slice. It is a
    /// wrapper around [Header::decode_from_buf] method which needs a buffer.
    pub fn decode_from_bytes(bytes: &[u8]) -> Result<Header, ParsingErr> {
        let mut buffer = BitsBuf::from_raw_bytes(bytes);
        Header::decode_from_buf(&mut buffer)
    }

    /// Encode a dns [`Header`] to raw bytes, writing them into the provided
    /// buffer. The function panics if some unsupported op codes are provided
    /// (this helps maintaining invariants about supported features).
    pub fn encode_to_buf(&self, buffer: &mut BitsBuf) {
        assert!(self.op_code.is_supported());
        buffer.write_u16(self.id);
        buffer.write_bits(self.query_resp as u8, 1);
        buffer.write_bits(self.op_code.to_num(), 4);
        buffer.write_bits(self.auth_answer as u8, 1);
        buffer.write_bits(self.truncated as u8, 1);
        buffer.write_bits(self.recursion_desired as u8, 1);
        buffer.write_bits(self.recursion_available as u8, 1);
        buffer.write_bits(self.z, 3);
        buffer.write_bits(self.resp_code.to_num(), 4);
        buffer.write_u16(self.questions_count);
        buffer.write_u16(self.answers_count);
        buffer.write_u16(self.authorities_count);
        buffer.write_u16(self.additionals_count);
    }
}

fn decode_op_code(op_code: u8, allow_unsupported: bool) -> Result<OpCode, ParsingErr> {
    let op_code = match OpCode::from_num(op_code) {
        Err(n) => return Err(ParsingErr::UnknownOpCode(n)),
        Ok(v) => v,
    };
    if !op_code.is_supported() && !allow_unsupported {
        Err(ParsingErr::UnsupportedOpCode(op_code))
    } else {
        Ok(op_code)
    }
}

fn decode_resp_code(resp_code: u8) -> Result<RespCode, ParsingErr> {
    match RespCode::from_num(resp_code) {
        Err(err) => Err(ParsingErr::UnknownRespCode(err)),
        Ok(v) => Ok(v),
    }
}

impl Header {
    /// Determine if a [`Header`] contains values supported by the implementation.
    pub fn is_supported(&self) -> Result<(), ParsingErr> {
        decode_op_code(self.op_code.to_num(), false)?;
        Ok(())
    }

    /// Tells if a [`Header`] represents a request.
    pub fn is_request(&self) -> bool {
        self.query_resp == false
    }
}

/// The response code is a code present in the [`Header`] and it's used
/// to inform the client about the outcome of the query.
#[derive(Debug, Clone, Copy)]
pub enum RespCode {
    NoError,
    FormErr,
    ServFail,
    NxDomain,
    NotImp,
    Refused,
}

impl RespCode {
    fn from_num(n: u8) -> Result<Self, u8> {
        match n {
            0 => Ok(RespCode::NoError),
            1 => Ok(RespCode::FormErr),
            2 => Ok(RespCode::ServFail),
            3 => Ok(RespCode::NxDomain),
            4 => Ok(RespCode::NotImp),
            5 => Ok(RespCode::Refused),
            _ => Err(n),
        }
    }

    fn to_num(&self) -> u8 {
        match self {
            RespCode::NoError => 0,
            RespCode::FormErr => 1,
            RespCode::ServFail => 2,
            RespCode::NxDomain => 3,
            RespCode::NotImp => 4,
            RespCode::Refused => 5,
        }
    }
}

/// The operation code is present in the header and specifies the type
/// of operation the DNS server should perform on behalf of the client.
#[derive(Debug, Clone, Copy)]
pub enum OpCode {
    STD,
    INV,
    STS,
}

impl OpCode {
    /// Try to generate a [`OpCode`] from its raw number representation.
    pub fn from_num(n: u8) -> Result<Self, u8> {
        match n {
            0 => Ok(OpCode::STD),
            1 => Ok(OpCode::INV),
            2 => Ok(OpCode::STS),
            n => Err(n),
        }
    }

    /// Convert a [`OpCode`] to its raw number representation.
    pub fn to_num(&self) -> u8 {
        match self {
            OpCode::STD => 0,
            OpCode::INV => 1,
            OpCode::STS => 2,
        }
    }

    /// Try to generate a [`OpCode`] from its raw string representation.
    fn is_supported(&self) -> bool {
        match self {
            OpCode::STD => true,
            _ => false,
        }
    }
}

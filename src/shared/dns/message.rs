use crate::shared::buffer::*;
use crate::shared::dns::errors::*;
use crate::shared::dns::header::*;
use crate::shared::dns::questions::*;
use crate::shared::dns::records::*;

/// Represents a complete dns message. Contains the [`Header`], which fields
/// must be concordant with the [`Question`]s and [`Record`]s carried in the other
/// message fields ().
#[derive(Debug)]
pub struct Message {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    pub additionals: Vec<Record>,
}

impl Message {
    /// Decode a dns [`Message`] from the provided bytes. Unsupported features are
    /// detected and the function returns proper parsing errors. Unknown records
    /// types still cause its record/question bytes to be consumed. In general we
    /// want to make sure no unsupported features enters or exits the system.
    pub fn decode_from_bytes(bytes: &[u8]) -> Result<Message, MessageErr> {
        let mut buffer = BitsBuffer::from_raw_bytes(&bytes);

        let header = match Header::decode_from_buf(&mut buffer) {
            Err(err) => return Err(MessageErr::HeaderErr(err)),
            Ok(header) => header,
        };
        if let Err(err) = header.is_supported() {
            return Err(MessageErr::HeaderErr(err));
        }

        let mut questions = Vec::with_capacity(header.questions_count as usize);
        let mut answers = Vec::with_capacity(header.answers_count as usize);
        let mut authorities = Vec::with_capacity(header.authorities_count as usize);
        let mut additionals = Vec::with_capacity(header.additionals_count as usize);

        for i in 0..header.questions_count as usize {
            let decoded_question = Question::decode_from_buf(&mut buffer);
            match decoded_question {
                Err(ParsingErr::UnknownType(_)) => continue,
                Err(err) => return Err(MessageErr::QuestionErr(i, err)),
                Ok(v) => questions.push(v),
            };
        }
        for i in 0..header.answers_count as usize {
            let decoded_answer = Record::decode_from_buf(&mut buffer);
            match decoded_answer {
                Err(ParsingErr::UnknownType(_)) => continue,
                Err(err) => return Err(MessageErr::AnswerErr(i, err)),
                Ok(v) => answers.push(v),
            };
        }
        for i in 0..header.authorities_count as usize {
            let decoded_authority = Record::decode_from_buf(&mut buffer);
            match decoded_authority {
                Err(ParsingErr::UnknownType(_)) => continue,
                Err(err) => return Err(MessageErr::AuthorityErr(i, err)),
                Ok(v) => authorities.push(v),
            };
        }
        for i in 0..header.additionals_count as usize {
            let decoded_additional = Record::decode_from_buf(&mut buffer);
            match decoded_additional {
                Err(ParsingErr::UnknownType(_)) => continue,
                Err(err) => return Err(MessageErr::AdditionalErr(i, err)),
                Ok(v) => additionals.push(v),
            };
        }

        Ok(Message {
            header,
            questions,
            answers,
            authorities,
            additionals,
        })
    }

    /// Encode a dns [`Message`] to raw bytes, returning a bytes vector. The
    /// function panics if some unsupported class or types are provided (to
    /// maintain invariants about supported features).
    pub fn encode_to_bytes(&self) -> Result<Vec<u8>, MessageErr> {
        let mut buffer = BitsBuffer::new();
        self.header.encode_to_buf(&mut buffer);

        for i in 0..self.header.questions_count as usize {
            match self.questions[i].encode_to_buf(&mut buffer) {
                Err(err) => return Err(MessageErr::QuestionErr(i, err)),
                Ok(v) => v,
            }
        }
        for i in 0..self.header.answers_count as usize {
            match self.answers[i].encode_to_buf(&mut buffer) {
                Err(err) => return Err(MessageErr::AnswerErr(i, err)),
                Ok(v) => v,
            }
        }
        for i in 0..self.header.authorities_count as usize {
            match self.authorities[i].encode_to_buf(&mut buffer) {
                Err(err) => return Err(MessageErr::AuthorityErr(i, err)),
                Ok(v) => v,
            }
        }
        for i in 0..self.header.additionals_count as usize {
            match self.additionals[i].encode_to_buf(&mut buffer) {
                Err(err) => return Err(MessageErr::AdditionalErr(i, err)),
                Ok(v) => v,
            }
        }

        Ok(buffer.into_vec())
    }
}

impl Message {
    pub fn id(&self) -> u16 {
        self.header.id
    }
}

use crate::nameserver::zones::errors::*;
use crate::nameserver::zones::parser::*;
use crate::nameserver::zones::parser_auth::*;
use crate::nameserver::zones::tokens::*;
use crate::nameserver::zones::utils::*;
use crate::shared::{dns, log};

#[derive(Debug)]
struct SubParsingState<'a> {
    pub zone: &'a dns::Name,
    pub current_ttl: u32,
    pub current_file: &'a str,
    pub min_ttl: u32,
}

/// Parse the zone file related to a sub zone of the zone managed by the nameserver.
/// A [`Zone`] object is returned, holding the zone records. The sub zone can only
/// contain NS records at the top node and A records related to those nameservers.
pub fn parse_sub_zone_file(params: SubParsingParams) -> Result<Zone, ParseErrCtx> {
    log::info!("Parsing sub zone {:?}", params.file_path);
    let mut tokenizer = match Tokenizer::from_file(&params.file_path) {
        Err(err) => return Err((ParseErr::ReadingErr(err), params.file_path.to_string())),
        Ok(v) => v,
    };

    let mut parsing_state = SubParsingState {
        zone: &params.zone,
        current_ttl: params.starting_ttl,
        current_file: &params.file_path,
        min_ttl: params.min_ttl,
    };

    parse_entries(&mut tokenizer, &mut parsing_state)
}

/// Parse a sub zone file and returns the parsed [`Zone`] records. No directives are
/// allowed for subzones. Domain names returned are validated and normalized in the
/// absolute form.
fn parse_entries(tokenizer: &mut Tokenizer, state: &mut SubParsingState) -> Result<Zone, ParseErrCtx> {
    let mut sub_zone_records = Zone::new(state.zone);
    loop {
        // Peek only. All tokens are needed to parse the file entry.
        let line = tokenizer.line();
        let next_token = tokenizer.peek();
        let next_token = match next_token {
            Err(err) => return Err((err.into(), format!("{}, line: {}", state.current_file, line))),
            Ok(Token::End) => break,
            Ok(v) => v,
        };

        // Analyze the first token and start the record parsing.
        let line = tokenizer.line();
        let record = match &next_token {
            Token::String(_) => parse_record(tokenizer, &state),
            Token::At => parse_record(tokenizer, &state),
            Token::Blank => parse_record(tokenizer, &state),
            _ => {
                let err_msg = format!("{}, line: {}", state.current_file, line);
                return Err((ParseErr::UnexpectedToken(next_token), err_msg));
            }
        };

        match record {
            Err(err) => return Err((err, format!("{}, line: {}", state.current_file, line))),
            Ok(record) => {
                log::debug!("Line {}: {:?}", line, record);
                state.current_ttl = *record.ttl();
                sub_zone_records.insert(record);
            }
        };
    }

    Ok(sub_zone_records)
}

/// Parse and validate a 'record' entry, returning a [dns::Record]. Records starting
/// with blank or '@' are assigned to the last stated origin.
fn parse_record(tokenizer: &mut Tokenizer, state: &SubParsingState) -> Result<dns::Record, ParseErr> {
    let node = match tokenizer.next() {
        Ok(Token::Blank) => state.zone.clone(),
        Ok(Token::At) => state.zone.clone(),
        Ok(Token::String(mut node)) => {
            let node = adjust_name(&state.zone, &mut node)?;
            ensure_name_in_zone(&node, &state.zone)?;
            node
        }
        _ => unreachable!(),
    };

    // Parse and validate TTL, class and record type.
    let (ttl, class) = parse_ttl_class(tokenizer)?;
    let class = class.unwrap_or(dns::Class::IN);
    let ttl = ttl.unwrap_or(state.current_ttl);
    ensure_class_is_supported(&class)?;
    ensure_min_ttl(state.min_ttl, ttl)?;

    let record_type = tokenizer.next_after_blanks()?;
    let record_type = match record_type {
        Token::String(s) => s,
        _ => return Err(ParseErr::UnexpectedToken(record_type)),
    };

    // Only NS and A records are allowed.
    let record_data = (node, class, ttl);
    let record = match dns::RecordType::from_str(&record_type) {
        Ok(dns::RecordType::A) => parse_a_record(tokenizer, record_data)?,
        Ok(dns::RecordType::NS) => {
            ensure_name_in_zone(&record_data.0, state.zone)?;
            parse_ns_record(tokenizer, &state.zone, record_data)?
        }
        Ok(v) => {
            let err_msg = format!("record type not supported for sub zone: '{:?}'", v);
            return Err(ParseErr::UnexpectedRecord(err_msg));
        }
        Err(_) => {
            let err_msg = format!("unknown type found: {}", record_type);
            return Err(ParseErr::MalformedData(err_msg));
        }
    };

    let next = tokenizer.next_after_blanks()?;
    match next {
        Token::NewLine => Ok(record),
        Token::End => Ok(record),
        _ => Err(ParseErr::UnexpectedToken(next)),
    }
}

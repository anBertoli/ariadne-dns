use crate::nameserver::zones::errors::*;
use crate::nameserver::zones::parser::*;
use crate::nameserver::zones::tokens::*;
use crate::nameserver::zones::utils::*;
use crate::shared::dns;
use std::net;
use std::str::FromStr;

/// Representation of the different types of entries expected in a zone file.
#[derive(Debug)]
enum ZoneEntry {
    Origin(dns::Name),
    Include(String, dns::Name),
    Record(dns::Record),
}

#[derive(Debug)]
struct AuthParsingState<'a> {
    pub zone: &'a dns::Name,
    pub sub_zones: &'a [dns::Name],
    pub current_file: &'a str,
    pub current_orig: dns::Name,
    pub current_ttl: u32,
    pub min_ttl: u32,
}

/// Parse the zone file related to the authoritative zone managed by the nameserver.
/// A [`Zone`] object is returned, holding the zone records. The zone file could use
/// the 'include' directive further files.
pub fn parse_auth_zone_file(conf: &ParsingParams) -> Result<Zone, ParseErrCtx> {
    log::info!("Parsing authoritative zone file {:?}", conf.file_path);
    let mut tokenizer = match Tokenizer::from_file(&conf.file_path) {
        Err(err) => return Err((ParseErr::ReadingErr(err), conf.file_path.to_string())),
        Ok(v) => v,
    };

    let subzones_nodes: Vec<dns::Name> = conf.sub_zones.iter().map(|s| s.zone.clone()).collect();
    let mut parsing_state = AuthParsingState {
        zone: &conf.zone,
        sub_zones: subzones_nodes.as_slice(),
        current_file: &conf.file_path,
        current_orig: conf.zone.clone(),
        current_ttl: conf.starting_ttl,
        min_ttl: 0,
    };

    let soa_record = parse_starting_soa_record(&mut tokenizer, &mut parsing_state);
    let soa_record = match soa_record {
        Err(err) => return Err((err, "parsing SOA record".to_string())),
        Ok(soa) => {
            log::debug!("Starting SOA: {:?}", soa);
            soa
        }
    };

    let mut zone = parse_entries(&mut tokenizer, &mut parsing_state)?;
    zone.insert(soa_record);
    Ok(zone)
}

/// Parse a 'included' zone file and return the parsed [`Zone`] records. The parsing
/// state of the parent file is used to set the child parsing starting state. Anyway,
/// the parent parsing state is left untouched.
fn parse_included_file(file_path: String, origin: dns::Name, p_state: &AuthParsingState) -> Result<Zone, ParseErrCtx> {
    log::info!("Including {:?}", file_path);
    let mut tokenizer = match Tokenizer::from_file(&file_path) {
        Err(err) => return Err((ParseErr::ReadingErr(err), p_state.current_file.to_string())),
        Ok(v) => v,
    };

    let mut child_state = AuthParsingState {
        zone: p_state.zone,
        sub_zones: p_state.sub_zones,
        current_file: &file_path,
        current_orig: origin,
        current_ttl: p_state.current_ttl,
        min_ttl: p_state.min_ttl,
    };

    parse_entries(&mut tokenizer, &mut child_state)
}

/// Parse a zone file and returns the parsed [`Zone`] records. Other files could be
/// included when the 'include' directive is found (with recursive process). Domain
/// names returned are validated and normalized in the absolute form.
fn parse_entries(tokenizer: &mut Tokenizer, state: &mut AuthParsingState) -> Result<Zone, ParseErrCtx> {
    let mut zone_records = Zone::new(state.zone);
    loop {
        // Peek only. All tokens are needed to parse the file entry.
        let line = tokenizer.line();
        let next_token = tokenizer.peek();
        let next_token = match next_token {
            Err(err) => return Err((err.into(), format!("{}, line: {}", state.current_file, line))),
            Ok(Token::End) => break,
            Ok(v) => v,
        };

        // Analyze the first token and start the proper parsing process.
        let line = tokenizer.line();
        let entry = match &next_token {
            Token::OriginDir => parse_origin(tokenizer, &state),
            Token::IncludeDir => parse_include(tokenizer, &state),
            Token::String(_) => parse_record(tokenizer, &state),
            Token::At => parse_record(tokenizer, &state),
            Token::Blank => parse_record(tokenizer, &state),
            _ => Err(ParseErr::UnexpectedToken(next_token)),
        };
        let entry = match entry {
            Err(err) => return Err((err, format!("{}, line: {}", state.current_file, line))),
            Ok(entry) => entry,
        };

        // Take the correct action based on the entry type.
        log::debug!("Line {}: {:?}", line, entry);
        match entry {
            ZoneEntry::Origin(origin) => state.current_orig = origin,
            ZoneEntry::Include(filename, origin) => {
                let included_records = parse_included_file(filename, origin, state)?;
                zone_records.extend(included_records);
            }
            ZoneEntry::Record(record) => {
                state.current_ttl = *record.ttl();
                zone_records.insert(record)
            }
        };
    }

    Ok(zone_records)
}

/// Parse and validate an 'origin' directive, returning the related [ZoneEntry::Origin].
fn parse_origin(tokenizer: &mut Tokenizer, state: &AuthParsingState) -> Result<ZoneEntry, ParseErr> {
    assert!(matches!(tokenizer.next(), Ok(Token::OriginDir)));

    let origin = tokenizer.next_after_blanks()?;
    let origin = if let Token::String(origin) = origin {
        ensure_absolute_name(&origin)?;
        let origin = dns::Name::from_string(&origin)?;
        ensure_name_in_auth_zone(&origin, state.zone, state.sub_zones)?;
        origin
    } else {
        return Err(ParseErr::UnexpectedToken(origin));
    };

    let newline = tokenizer.next_after_blanks()?;
    match newline {
        Token::NewLine => Ok(ZoneEntry::Origin(origin)),
        Token::End => Ok(ZoneEntry::Origin(origin)),
        _ => Err(ParseErr::UnexpectedToken(newline)),
    }
}

/// Parse and validate an 'include' directive, returning the related [ZoneEntry::Include].
fn parse_include(tokenizer: &mut Tokenizer, state: &AuthParsingState) -> Result<ZoneEntry, ParseErr> {
    assert!(matches!(tokenizer.next(), Ok(Token::IncludeDir)));

    let file_name = tokenizer.next_after_blanks()?;
    let file_name = match file_name {
        Token::Number(n) => n.to_string(),
        Token::String(s) => s,
        _ => return Err(ParseErr::UnexpectedToken(file_name)),
    };

    let mut domain_or_newline = tokenizer.next_after_blanks()?;
    let origin = if let Token::String(mut name) = domain_or_newline {
        domain_or_newline = tokenizer.next_after_blanks()?;
        let name = adjust_name(&state.current_orig, &mut name)?;
        ensure_name_in_auth_zone(&name, state.zone, state.sub_zones)?;
        name
    } else {
        state.current_orig.clone()
    };

    // Here should be newline/end in any case.
    match domain_or_newline {
        Token::NewLine => Ok(ZoneEntry::Include(file_name, origin)),
        Token::End => Ok(ZoneEntry::Include(file_name, origin)),
        _ => Err(ParseErr::UnexpectedToken(domain_or_newline)),
    }
}

/// Parse and validate a 'record' entry, returning the related [ZoneEntry::Record].
/// Records starting with blank or '@' are assigned to the last stated origin.
fn parse_record(tokenizer: &mut Tokenizer, state: &AuthParsingState) -> Result<ZoneEntry, ParseErr> {
    let node = match tokenizer.next() {
        Ok(Token::Blank) => state.current_orig.clone(),
        Ok(Token::At) => state.current_orig.clone(),
        Ok(Token::String(mut name)) => {
            let name = adjust_name(&state.current_orig, &mut name)?;
            ensure_name_in_auth_zone(&name, state.zone, state.sub_zones)?;
            name
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
    let record_type = match dns::RecordType::from_str(&record_type) {
        Err(_) => {
            let err_msg = format!("unknown type: {}", record_type);
            return Err(ParseErr::MalformedData(err_msg));
        }
        Ok(v) if !v.is_supported_for_records() => {
            let err_msg = format!("type not supported: {:?}", record_type);
            return Err(ParseErr::UnexpectedRecord(err_msg));
        }
        Ok(v) => v,
    };

    // Parse the record data and compose the complete record.
    let record_data = (node, class, ttl);
    let record = match record_type {
        dns::RecordType::A => parse_a_record(tokenizer, record_data)?,
        dns::RecordType::NS => parse_ns_record(tokenizer, &state.current_orig, record_data)?,
        dns::RecordType::CNAME => parse_cname_record(tokenizer, &state.current_orig, record_data)?,
        dns::RecordType::WKS => parse_wks_record(tokenizer, record_data)?,
        dns::RecordType::PTR => parse_ptr_record(tokenizer, record_data)?,
        dns::RecordType::HINFO => parse_hinfo_record(tokenizer, record_data)?,
        dns::RecordType::MX => parse_mx_record(tokenizer, &state.current_orig, record_data)?,
        dns::RecordType::TXT => parse_txt_record(tokenizer, record_data)?,
        dns::RecordType::SOA => {
            let err_msg = "SOA should be present only at the top of the zone file";
            return Err(ParseErr::UnexpectedRecord(err_msg.to_string()));
        }
        _ => unreachable!(),
    };

    let next = tokenizer.next_after_blanks()?;
    match next {
        Token::NewLine => Ok(ZoneEntry::Record(record)),
        Token::End => Ok(ZoneEntry::Record(record)),
        _ => Err(ParseErr::UnexpectedToken(next)),
    }
}

type RecData = (dns::Name, dns::Class, u32);

pub fn parse_a_record(tokens: &mut Tokenizer, rec_data: RecData) -> Result<dns::Record, ParseErr> {
    let ip = tokens.next_after_blanks()?;
    let address = if let Token::String(s) = &ip {
        match net::Ipv4Addr::from_str(&s) {
            Err(err) => return Err(ParseErr::MalformedData(err.to_string())),
            Ok(ip) => ip.octets(),
        }
    } else {
        return Err(ParseErr::UnexpectedToken(ip));
    };

    Ok(dns::Record::A {
        node: rec_data.0,
        class: rec_data.1,
        ttl: rec_data.2,
        data_len: 0,
        address,
    })
}

pub fn parse_ns_record(tokens: &mut Tokenizer, origin: &dns::Name, rec_data: RecData) -> Result<dns::Record, ParseErr> {
    let name = tokens.next_after_blanks()?;
    let name = if let Token::String(mut s) = name {
        let s = adjust_name(origin, &mut s)?;
        s
    } else {
        return Err(ParseErr::UnexpectedToken(name));
    };

    Ok(dns::Record::NS {
        node: rec_data.0,
        class: rec_data.1,
        ttl: rec_data.2,
        data_len: 0,
        name,
    })
}

fn parse_cname_record(tokens: &mut Tokenizer, origin: &dns::Name, rec_data: RecData) -> Result<dns::Record, ParseErr> {
    let name = tokens.next_after_blanks()?;
    let name = match name {
        Token::At => origin.clone(),
        Token::String(mut s) => {
            let s = adjust_name(origin, &mut s)?;
            s
        }
        _ => return Err(ParseErr::UnexpectedToken(name)),
    };

    Ok(dns::Record::CNAME {
        node: rec_data.0,
        class: rec_data.1,
        ttl: rec_data.2,
        data_len: 0,
        name,
    })
}

fn parse_soa_record(tokens: &mut Tokenizer, origin: &dns::Name, rec_data: RecData) -> Result<dns::Record, ParseErr> {
    let token = tokens.next_after_blanks()?;
    let ns_name = if let Token::String(mut name) = token {
        let name = adjust_name(origin, &mut name)?;
        name
    } else {
        return Err(ParseErr::UnexpectedToken(token));
    };

    let token = tokens.next_after_blanks()?;
    let mail_name = if let Token::String(mut name) = token {
        let name = adjust_name(origin, &mut name)?;
        name
    } else {
        return Err(ParseErr::UnexpectedToken(token));
    };

    let mut zone_auth_params = [0_u32; 5];
    for i in 0..5 {
        let next = tokens.next_after_blanks()?;
        if let Token::Number(n) = next {
            zone_auth_params[i] = n;
        } else {
            return Err(ParseErr::UnexpectedToken(next));
        }
    }

    Ok(dns::Record::SOA {
        node: rec_data.0,
        class: rec_data.1,
        ttl: rec_data.2,
        data_len: 0,
        ns_name: ns_name,
        ml_name: mail_name,
        serial: zone_auth_params[0],
        refresh: zone_auth_params[1],
        retry: zone_auth_params[2],
        expire: zone_auth_params[3],
        minimum: zone_auth_params[4],
    })
}

fn parse_wks_record(tokenizer: &mut Tokenizer, rec_data: RecData) -> Result<dns::Record, ParseErr> {
    let ip = tokenizer.next_after_blanks()?;
    let address = if let Token::String(s) = &ip {
        match net::Ipv4Addr::from_str(&s) {
            Err(err) => return Err(ParseErr::MalformedData(err.to_string())),
            Ok(ip) => ip.octets(),
        }
    } else {
        return Err(ParseErr::UnexpectedToken(ip));
    };

    // TODO: only TCP and UDP are supported, but
    // should be good for 99% of the cases.
    let protocol = tokenizer.next_after_blanks()?;
    let protocol = if let Token::String(pr) = protocol {
        match pr.to_uppercase().as_ref() {
            "TCP" => 6,
            "UDP" => 17,
            _ => return Err(ParseErr::MalformedData(pr)),
        }
    } else {
        return Err(ParseErr::UnexpectedToken(protocol));
    };

    // TODO: complete this part, determine how ports are specified in WKS records.
    discard_strings_until_newline(tokenizer)?;
    Ok(dns::Record::WKS {
        node: rec_data.0,
        class: rec_data.1,
        ttl: rec_data.2,
        data_len: 0,
        address,
        protocol,
        ports: vec![],
    })
}

fn parse_ptr_record(tokenizer: &mut Tokenizer, rec_data: RecData) -> Result<dns::Record, ParseErr> {
    let next = tokenizer.next_after_blanks()?;
    let name = if let Token::String(s) = next {
        ensure_absolute_name(&s)?;
        dns::Name::from_string(&s)?
    } else {
        return Err(ParseErr::UnexpectedToken(next));
    };

    Ok(dns::Record::PTR {
        node: rec_data.0,
        class: rec_data.1,
        ttl: rec_data.2,
        data_len: 0,
        name,
    })
}

fn parse_hinfo_record(tokenizer: &mut Tokenizer, rec_data: RecData) -> Result<dns::Record, ParseErr> {
    let next = tokenizer.next_after_blanks()?;
    let cpu = parse_char_string(next)?;
    let next = tokenizer.next_after_blanks()?;
    let os = parse_char_string(next)?;
    Ok(dns::Record::HINFO {
        node: rec_data.0,
        class: rec_data.1,
        ttl: rec_data.2,
        data_len: 0,
        cpu,
        os,
    })
}

fn parse_mx_record(tokens: &mut Tokenizer, origin: &dns::Name, rec_data: RecData) -> Result<dns::Record, ParseErr> {
    let next = tokens.next_after_blanks()?;
    let priority = if let Token::Number(num) = next {
        num.try_into().or(Err(ParseErr::MalformedData(num.to_string())))?
    } else {
        return Err(ParseErr::UnexpectedToken(next));
    };

    let next = tokens.next_after_blanks()?;
    let name = if let Token::String(mut mail) = next {
        let mail = adjust_name(origin, &mut mail)?;
        mail
    } else {
        return Err(ParseErr::UnexpectedToken(next));
    };

    Ok(dns::Record::MX {
        node: rec_data.0,
        class: rec_data.1,
        ttl: rec_data.2,
        data_len: 0,
        priority,
        name,
    })
}

fn parse_txt_record(tokenizer: &mut Tokenizer, rec_data: RecData) -> Result<dns::Record, ParseErr> {
    let mut txts = vec![];
    loop {
        let next = tokenizer.peek_after_blanks()?;
        match next {
            Token::NewLine => break,
            Token::End => break,
            tok => {
                tokenizer.next_after_blanks().unwrap();
                let txt = parse_char_string(tok)?;
                txts.push(txt);
            }
        };
    }

    Ok(dns::Record::TXT {
        node: rec_data.0,
        class: rec_data.1,
        ttl: rec_data.2,
        data_len: 0,
        txts,
    })
}

/// Parse the mandatory first SOA record and sets some defaults on the [AuthParsingState]
/// passed in. The class is required, while absent TTL and node default to the current ones
/// in parsing parameters. The SOA must be owned by the top node of the zone.
fn parse_starting_soa_record(tokenizer: &mut Tokenizer, state: &mut AuthParsingState) -> Result<dns::Record, ParseErr> {
    let node = match tokenizer.next()? {
        Token::String(mut name) => adjust_name(&state.zone, &mut name)?,
        Token::Blank => state.zone.clone(),
        Token::At => state.zone.clone(),
        v => return Err(ParseErr::UnexpectedToken(v)),
    };
    if &node != state.zone {
        return Err(ParseErr::NameNotInRootNode(node.to_string()));
    }

    // Parse TTL, class and record type of the record.
    let (ttl, class) = parse_ttl_class(tokenizer)?;
    let class = class.ok_or(ParseErr::MalformedData("class required".to_string()))?;
    let ttl = ttl.unwrap_or(state.current_ttl);
    ensure_class_is_supported(&class)?;

    let record_type = tokenizer.next_after_blanks()?;
    let record_type = match record_type {
        Token::String(s) => s,
        _ => return Err(ParseErr::UnexpectedToken(record_type)),
    };
    match dns::RecordType::from_str(&record_type) {
        Ok(dns::RecordType::SOA) => (),
        Err(n) => {
            let err_msg = format!("unknown record type found: {}", n);
            return Err(ParseErr::MalformedData(err_msg));
        }
        Ok(v) => {
            let err_msg = format!("{:?} type found, but SOA expected", v);
            return Err(ParseErr::UnexpectedRecord(err_msg));
        }
    };

    // Parse the SOA record data, make sure the SOA record itself has a
    // valid TTL, save the minimum ttl in the parsing state for later use.
    let soa_record = parse_soa_record(tokenizer, state.zone, (node, class, ttl))?;
    match soa_record {
        dns::Record::SOA { ttl, minimum, .. } => {
            ensure_min_ttl(minimum, ttl)?;
            state.min_ttl = minimum;
        }
        _ => unreachable!(),
    };

    // Closing records tokens.
    let next = tokenizer.next_after_blanks()?;
    match next {
        Token::NewLine => Ok(soa_record),
        Token::End => Ok(soa_record),
        _ => Err(ParseErr::UnexpectedToken(next)),
    }
}

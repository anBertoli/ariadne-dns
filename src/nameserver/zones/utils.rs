use crate::nameserver::zones::errors::*;
use crate::nameserver::zones::tokens::*;
use crate::shared::dns;

/// Parse the TTL and [`dns::class`] from one of the following formats: \[ttl] \[class]
/// or \[class] \[ttl], both optionals. It consumes only the tokens strictly needed,
/// leaving untouched the next ones (the record type).   
pub fn parse_ttl_class(tokenizer: &mut Tokenizer) -> Result<(Option<u32>, Option<dns::Class>), ParseErr> {
    let next_token = tokenizer.peek_after_blanks()?;

    // Try the ttl [class] format.
    if let Token::Number(n) = next_token {
        tokenizer.next().unwrap(); // discard the peeked token
        let class_or_type = tokenizer.peek_after_blanks()?;
        return if let Ok(class) = try_to_class(&class_or_type) {
            tokenizer.next().unwrap();
            Ok((Some(n), Some(class)))
        } else {
            Ok((Some(n), None))
        };
    }

    // Try the class [ttl] format. We expect a string in any case since
    // even if we don't have the class we should find the record type.
    let class_or_type = match next_token {
        Token::String(s) => s,
        _ => return Err(ParseErr::UnexpectedToken(next_token)),
    };

    if let Ok(class) = dns::Class::from_string(&class_or_type) {
        tokenizer.next().unwrap();
        let ttl_or_type = tokenizer.peek_after_blanks()?;
        return if let Ok(ttl) = try_to_ttl(&ttl_or_type) {
            tokenizer.next().unwrap();
            Ok((Some(ttl), Some(class)))
        } else {
            Ok((None, Some(class)))
        };
    }

    // No class, no TTL.
    Ok((None, None))
}

fn try_to_ttl(token: &Token) -> Result<u32, ()> {
    if let Token::Number(n) = token {
        Ok(*n)
    } else {
        Err(())
    }
}

fn try_to_class(token: &Token) -> Result<dns::Class, ()> {
    if let Token::String(s) = token {
        return match dns::Class::from_string(s) {
            Err(_) => Err(()),
            Ok(v) => Ok(v),
        };
    }
    Err(())
}

/// Replace "@" with the current origin, or return the absolute form
/// oth the passed name. The name is also validated.
pub fn adjust_name(current_origin: &dns::Name, name: &mut String) -> Result<dns::Name, ParseErr> {
    if name == "@" {
        return Ok(current_origin.clone());
    }
    if !name.ends_with('.') {
        name.push('.');
        name.push_str(current_origin.as_ref());
    }
    match dns::Name::from_string(name) {
        Ok(name) => Ok(name),
        Err(err) => Err(err)?,
    }
}

/// Parse the passed token as a character string. Validate it before returning.
pub fn parse_char_string(token: Token) -> Result<String, ParseErr> {
    let (is_valid, str) = match token {
        Token::String(s) => (dns::is_valid_character_string(&s, false), s),
        Token::QString(s) => (dns::is_valid_character_string(&s, true), s),
        _ => return Err(ParseErr::UnexpectedToken(token)),
    };
    if !is_valid {
        Err(ParseErr::MalformedData(str))
    } else {
        Ok(str)
    }
}

/// Consume string tokens from the [Tokenizer] and discard them until a newline
/// token is found. It's an error finding a non-string token before the newline.
pub fn discard_strings_until_newline(tokenizer: &mut Tokenizer) -> Result<(), ParseErr> {
    loop {
        let token = tokenizer.peek_after_blanks()?;
        match token {
            Token::NewLine => break,
            Token::End => break,
            Token::String(_) => {
                tokenizer.next_after_blanks().unwrap();
                continue;
            }
            _ => return Err(ParseErr::UnexpectedToken(token)),
        }
    }
    Ok(())
}

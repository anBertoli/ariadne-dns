use std::fs;
use std::io::{self, BufRead, BufReader};

/// The different types of tokens returned by the [`Tokenizer`].
#[derive(Debug, Clone)]
pub enum Token {
    OriginDir,
    IncludeDir,
    QString(String),
    String(String),
    Number(u32),
    Blank,
    NewLine,
    End,
    At,
}

/// The [`Tokenizer`] is use to parse [`Token`]s, reading from a zone file
/// (reads are buffered). This object handles multiline records and tokens
/// can be peeked without consuming them.
pub struct Tokenizer {
    buffered_file: io::Lines<BufReader<fs::File>>,
    line_chars: Vec<char>,
    peeked: Vec<Token>,
    multiline: bool,
    line: usize,
    pos: usize,
}

impl Tokenizer {
    /// Generate a [`Tokenizer`] ready to parse a file. Note that the file is
    /// opened inside the constructor, but no reads are performed yet.
    pub fn from_file(path: &str) -> Result<Self, io::Error> {
        let file = match fs::File::open(path) {
            Err(err) => return Err(err),
            Ok(v) => v,
        };
        Ok(Tokenizer {
            buffered_file: io::BufReader::new(file).lines(),
            line_chars: vec![],
            peeked: vec![],
            multiline: false,
            line: 0,
            pos: 0,
        })
    }

    /// Return the next token, starting from the position saved in the [`Tokenizer`]
    /// state. Peeked tokens are returned before parsing new ones. When the tokenizer
    /// is in a multiline context newline tokens are skipped.
    pub fn next(&mut self) -> Result<Token, TokenErr> {
        if self.line == 0 {
            // Bootstrap the tokenizer only at the first call,
            // load a new line but don't return newlines tokens.
            let new_line_load = self.load_new_line()?;
            if let None = new_line_load {
                return if self.multiline {
                    Err(TokenErr::MlMissingClose)
                } else {
                    Ok(Token::End)
                };
            }
        }

        if self.peeked.len() >= 1 {
            return Ok(self.peeked.remove(0));
        }

        if self.line_chars.len() == self.pos {
            let new_line_load = self.load_new_line()?;
            if let None = new_line_load {
                return if self.multiline {
                    Err(TokenErr::MlMissingClose)
                } else {
                    Ok(Token::End)
                };
            }
            if !self.multiline {
                return Ok(Token::NewLine);
            }
        }

        // Parse the token. Note that some branches only consume
        // some characters and invoke 'next' recursively.
        match self.line_chars[self.pos] {
            ' ' | '\t' => Ok(self.process_whitespace()),
            '$' => self.process_directive(),
            '"' => self.process_quoted_string(),
            '(' => {
                self.process_multi_line()?;
                self.next()
            }
            ')' => {
                self.process_close_multi()?;
                self.next()
            }
            ';' => {
                self.process_comment();
                self.next()
            }
            _ => self.process_string_or_number(),
        }
    }

    /// Utility method. Consume all blank tokens until a different one is found.
    /// That [`Token`] is finally returned.
    pub fn next_after_blanks(&mut self) -> Result<Token, TokenErr> {
        loop {
            let next = self.next()?;
            match next {
                Token::Blank => continue,
                v => return Ok(v),
            }
        }
    }

    /// Peek the next [`Token`] without consuming it. Only one token ahead can be peeked.
    pub fn peek(&mut self) -> Result<Token, TokenErr> {
        let next = self.next()?;
        self.peeked.push(next.clone());
        Ok(next)
    }

    /// Utility method. Consume all blank tokens until a different one is found. That
    /// [`Token`] is returned without consuming it. Only one token ahead can be peeked.
    pub fn peek_after_blanks(&mut self) -> Result<Token, TokenErr> {
        let next = self.next_after_blanks()?;
        self.peeked.push(next.clone());
        Ok(next)
    }

    /// Returns the number of the line currently being parsed (number in file).
    pub fn line(&self) -> usize {
        self.line
    }

    // Load the next line from the underlying source or signal the end of
    // the file. Empty lines or lines with comments only are skipped.
    fn load_new_line(&mut self) -> Result<Option<()>, io::Error> {
        loop {
            let line = match self.buffered_file.next() {
                None => return Ok(None),
                Some(line) => {
                    self.line += 1;
                    line?
                }
            };
            let clean_line = line.trim();
            if !clean_line.is_empty() && !clean_line.starts_with(';') {
                self.line_chars = line.chars().collect();
                self.pos = 0;
                return Ok(Some(()));
            }
        }
    }

    // Consume all consecutive whitespaces and return the corresponding token.
    fn process_whitespace(&mut self) -> Token {
        assert!(self.line_chars[self.pos].is_whitespace());
        for _ in self.pos..self.line_chars.len() {
            let ch = self.line_chars[self.pos];
            if ch.is_whitespace() {
                self.pos += 1;
            } else {
                break;
            }
        }
        Token::Blank
    }

    // Parse a directive token (either origin or include) and return it.
    fn process_directive(&mut self) -> Result<Token, TokenErr> {
        assert_eq!(self.line_chars[self.pos], '$');
        let mut directive = String::from('$');
        self.pos += 1;

        for _ in self.pos..self.line_chars.len() {
            let ch = self.line_chars[self.pos];
            if ch == '\\' {
                let ch = self.parse_escape()?;
                directive.push(ch);
                continue;
            }
            if ch == ';' || ch == '(' || ch == ')' {
                break;
            }
            if ch.is_whitespace() {
                break;
            }
            directive.push(ch);
            self.pos += 1;
        }

        match directive.as_ref() {
            "$ORIGIN" => Ok(Token::OriginDir),
            "$INCLUDE" => Ok(Token::IncludeDir),
            _ => Err(TokenErr::DirMalformed(directive)),
        }
    }

    // Parse a quoted string and return the corresponding token.
    fn process_quoted_string(&mut self) -> Result<Token, TokenErr> {
        assert_eq!(self.line_chars[self.pos], '"');
        self.pos += 1;

        let mut string = String::with_capacity(20);
        let mut closed = false;

        for _ in self.pos..self.line_chars.len() {
            let ch = self.line_chars[self.pos];
            if ch == '\\' {
                let ch = self.parse_escape()?;
                string.push(ch);
                continue;
            }
            if ch == '"' {
                closed = true;
                self.pos += 1;
                break;
            }
            string.push(ch);
            self.pos += 1;
        }

        if closed {
            Ok(Token::QString(string))
        } else {
            Err(TokenErr::QStrNotClosed(string))
        }
    }

    // Consume and validate '(', starting a new multiline context.
    fn process_multi_line(&mut self) -> Result<(), TokenErr> {
        assert_eq!(self.line_chars[self.pos], '(');
        if self.multiline {
            Err(TokenErr::MlUnexpectedOpen)
        } else {
            self.multiline = true;
            self.pos += 1;
            Ok(())
        }
    }

    // Consume and validate ')', closing a new multiline context.
    fn process_close_multi(&mut self) -> Result<(), TokenErr> {
        assert_eq!(self.line_chars[self.pos], ')');
        if !self.multiline {
            Err(TokenErr::MlUnexpectedClose)
        } else {
            self.multiline = false;
            self.pos += 1;
            Ok(())
        }
    }

    // Parse a string or a number and return the corresponding token.
    fn process_string_or_number(&mut self) -> Result<Token, TokenErr> {
        let mut str = String::with_capacity(20);

        for _ in self.pos..self.line_chars.len() {
            let ch = self.line_chars[self.pos];
            if ch == '\\' {
                let ch = self.parse_escape()?;
                str.push(ch);
                continue;
            }
            if ch == '(' || ch == ')' || ch == ';' {
                break;
            }
            if ch.is_whitespace() {
                break;
            }
            self.pos += 1;
            str.push(ch);
        }

        if str == "@" {
            return Ok(Token::At);
        }
        match str.parse::<u32>() {
            Err(_) => Ok(Token::String(str)),
            Ok(n) => Ok(Token::Number(n)),
        }
    }

    // Consume a comment, that is, the entire remaining line.
    fn process_comment(&mut self) {
        assert_eq!(self.line_chars[self.pos], ';');
        self.pos = self.line_chars.len();
    }

    fn parse_escape(&mut self) -> Result<char, TokenErr> {
        assert_eq!(self.line_chars[self.pos], '\\');
        if self.pos + 1 >= self.line_chars.len() {
            return Err(TokenErr::InvalidEscape);
        }
        let ch_esc = Ok(self.line_chars[self.pos + 1]);
        self.pos += 2;
        ch_esc
    }
}

/// Errors eventually returned during the parsing process performed by the [`Tokenizer`].
#[derive(Debug)]
pub enum TokenErr {
    DirMalformed(String),
    QStrNotClosed(String),
    MlUnexpectedOpen,
    MlUnexpectedClose,
    MlMissingClose,
    InvalidEscape,
    ReadErr(io::Error),
}

impl From<io::Error> for TokenErr {
    fn from(err: io::Error) -> Self {
        TokenErr::ReadErr(err)
    }
}

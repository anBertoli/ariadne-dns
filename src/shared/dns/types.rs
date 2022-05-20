/// Enum representing all possible record types cited in RFC 1034/1035.
/// Not all of them are supported, those ones don't have a counterpart
/// in the [Record] enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordType {
    A,
    NS,
    MD, // not supported, obsolete
    MF, // not supported, obsolete
    CNAME,
    SOA,
    MB,   // not supported, experimental
    MG,   // not supported, experimental
    MR,   // not supported, experimental
    NULL, // not supported, experimental
    WKS,
    PTR,
    HINFO,
    MINFO, // not supported, experimental
    MX,
    TXT,
    AXFR,  // not supported, zone transfers
    MAILB, // not supported, obsolete
    MAILA, // not supported, obsolete
    WC,    // wildcard
}

impl RecordType {
    /// Try to generate a [`RecordType`] from its raw number representation.
    pub fn from_num(n: u16) -> Result<RecordType, u16> {
        match n {
            1 => Ok(RecordType::A),
            2 => Ok(RecordType::NS),
            3 => Ok(RecordType::MD),
            4 => Ok(RecordType::MF),
            5 => Ok(RecordType::CNAME),
            6 => Ok(RecordType::SOA),
            7 => Ok(RecordType::MB),
            8 => Ok(RecordType::MG),
            9 => Ok(RecordType::MR),
            10 => Ok(RecordType::NULL),
            11 => Ok(RecordType::WKS),
            12 => Ok(RecordType::PTR),
            13 => Ok(RecordType::HINFO),
            14 => Ok(RecordType::MINFO),
            15 => Ok(RecordType::MX),
            16 => Ok(RecordType::TXT),
            252 => Ok(RecordType::AXFR),
            253 => Ok(RecordType::MAILB),
            254 => Ok(RecordType::MAILA),
            255 => Ok(RecordType::WC),
            n => Err(n),
        }
    }

    /// Convert a [`RecordType`] to its raw number representation.
    pub fn to_num(&self) -> u16 {
        match self {
            RecordType::A => 1,
            RecordType::NS => 2,
            RecordType::MD => 3,
            RecordType::MF => 4,
            RecordType::CNAME => 5,
            RecordType::SOA => 6,
            RecordType::MB => 7,
            RecordType::MG => 8,
            RecordType::MR => 9,
            RecordType::NULL => 10,
            RecordType::WKS => 11,
            RecordType::PTR => 12,
            RecordType::HINFO => 13,
            RecordType::MINFO => 14,
            RecordType::MX => 15,
            RecordType::TXT => 16,
            RecordType::AXFR => 252,
            RecordType::MAILB => 253,
            RecordType::MAILA => 254,
            RecordType::WC => 255,
        }
    }

    /// Try to generate a [`RecordType`] from its raw string representation.
    pub fn from_str(s: &str) -> Result<RecordType, &str> {
        match s {
            "A" => Ok(RecordType::A),
            "NS" => Ok(RecordType::NS),
            "MD" => Ok(RecordType::MD),
            "MF" => Ok(RecordType::MF),
            "CNAME" => Ok(RecordType::CNAME),
            "SOA" => Ok(RecordType::SOA),
            "MB" => Ok(RecordType::MB),
            "MG" => Ok(RecordType::MG),
            "MR" => Ok(RecordType::MR),
            "NULL" => Ok(RecordType::NULL),
            "WKS" => Ok(RecordType::WKS),
            "PTR" => Ok(RecordType::PTR),
            "HINFO" => Ok(RecordType::HINFO),
            "MINFO" => Ok(RecordType::MINFO),
            "MX" => Ok(RecordType::MX),
            "TXT" => Ok(RecordType::TXT),
            "AXFR" => Ok(RecordType::AXFR),
            "MAILA" => Ok(RecordType::MAILA),
            "MAILB" => Ok(RecordType::MAILB),
            "*" => Ok(RecordType::WC),
            s => Err(s),
        }
    }

    /// Convert a [`RecordType`] to its raw string representation.
    pub fn to_str(&self) -> &'static str {
        match self {
            RecordType::A => "A",
            RecordType::NS => "NS",
            RecordType::MD => "MD",
            RecordType::MF => "MF",
            RecordType::CNAME => "CNAME",
            RecordType::SOA => "SOA",
            RecordType::MB => "MB",
            RecordType::MG => "MG",
            RecordType::MR => "MR",
            RecordType::NULL => "NULL",
            RecordType::WKS => "WKS",
            RecordType::PTR => "PTR",
            RecordType::HINFO => "HINFO",
            RecordType::MINFO => "MINFO",
            RecordType::MX => "MX",
            RecordType::TXT => "TXT",
            RecordType::AXFR => "AXFR",
            RecordType::MAILB => "MAILB",
            RecordType::MAILA => "MAILA",
            RecordType::WC => "*",
        }
    }
}

impl RecordType {
    /// Determine if a [`RecordType`] is generally supported in
    /// records (expect for questions, use the specific method).
    pub fn is_supported_for_records(&self) -> bool {
        if self.is_obsolete() || self.is_experimental() {
            return false;
        }
        match self {
            RecordType::AXFR => false,
            RecordType::MAILB => false,
            RecordType::MAILA => false,
            RecordType::WC => false,
            _ => true,
        }
    }

    /// Determine if a [`RecordType`] is supported for questions.
    pub fn is_supported_for_question(&self) -> bool {
        if self.is_obsolete() || self.is_experimental() {
            return false;
        }
        match self {
            RecordType::AXFR => false,
            RecordType::MAILB => false,
            RecordType::MAILA => false,
            RecordType::WC => false,
            _ => true,
        }
    }

    // Determine if a [`RecordType`] is obsolete as reported by RFCs.
    fn is_obsolete(&self) -> bool {
        match self {
            RecordType::MD => true,
            RecordType::MF => true,
            RecordType::MAILA => true,
            _ => false,
        }
    }

    // Determine if a [`RecordType`] is experimental as reported by RFCs.
    fn is_experimental(&self) -> bool {
        match self {
            RecordType::MB => true,
            RecordType::MG => true,
            RecordType::MR => true,
            RecordType::NULL => true,
            RecordType::MINFO => true,
            _ => false,
        }
    }
}
